use std::path::PathBuf;

use workload_spec::{SecretMount, SecretRef, SecretTarget};

/// Tests that SecretRef serialization never leaks secret values — only
/// references (paths / names) appear in the JSON.
mod secrets {
    use super::*;

    #[test]
    fn local_file_serializes_path_only() {
        let mount = SecretMount {
            source: SecretRef::LocalFile {
                path: PathBuf::from("api-key"),
            },
            target: SecretTarget::EnvVar { name: "API_KEY".into() },
        };

        let json = serde_json::to_string(&mount).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Externally tagged: the variant is the key, fields nest beneath it.
        let source = &parsed["source"]["local_file"];
        assert!(source.is_object(), "source must be the local_file variant");

        // Path reference appears
        assert!(json.contains("api-key"), "path reference must be in JSON");

        // No value bytes under any common field names
        assert!(source.get("value").is_none(), "secret value must not appear in JSON");
        assert!(source.get("contents").is_none(), "secret contents must not appear in JSON");
        assert!(source.get("data").is_none(), "secret data must not appear in JSON");
        assert!(source.get("bytes").is_none(), "secret bytes must not appear in JSON");
    }

    #[test]
    fn cluster_secret_serializes_name_only() {
        let mount = SecretMount {
            source: SecretRef::Cluster {
                name: "cluster-db-password".into(),
            },
            target: SecretTarget::File {
                path: PathBuf::from("/run/secrets/db"),
                mode: 0o600,
            },
        };

        let json = serde_json::to_string(&mount).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let source = &parsed["source"]["cluster"];
        assert!(source.is_object(), "source must be the cluster variant");
        assert_eq!(source["name"], "cluster-db-password");

        assert!(source.get("value").is_none(), "secret value must not appear in JSON");
        assert!(source.get("data").is_none(), "secret data must not appear in JSON");
    }

    #[test]
    fn env_var_target_serializes_name_not_value() {
        let target = SecretTarget::EnvVar {
            name: "DATABASE_PASSWORD".into(),
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let inner = &parsed["env_var"];
        assert!(inner.is_object(), "target must be the env_var variant");
        assert_eq!(inner["name"], "DATABASE_PASSWORD");
        assert!(inner.get("value").is_none(), "secret value must not appear in target JSON");
    }

    #[test]
    fn file_target_serializes_path_and_mode_not_content() {
        let target = SecretTarget::File {
            path: PathBuf::from("/run/secrets/tls.crt"),
            mode: 0o400,
        };
        let json = serde_json::to_string(&target).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let inner = &parsed["file"];
        assert!(inner.is_object(), "target must be the file variant");
        assert!(json.contains("tls.crt"), "target path must be in JSON");
        assert!(inner.get("content").is_none(), "file content must not appear");
        assert!(inner.get("bytes").is_none(), "file bytes must not appear");
    }

    #[test]
    fn local_file_round_trips_without_modification() {
        let original = SecretMount {
            source: SecretRef::LocalFile {
                path: PathBuf::from("secrets/api-key"),
            },
            target: SecretTarget::File {
                path: PathBuf::from("/run/secrets/api"),
                mode: 0o400,
            },
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SecretMount = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cluster_round_trips_without_modification() {
        let original = SecretMount {
            source: SecretRef::Cluster {
                name: "stripe-api-key".into(),
            },
            target: SecretTarget::EnvVar {
                name: "STRIPE_SECRET_KEY".into(),
            },
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: SecretMount = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn debug_output_contains_only_path_reference_not_value() {
        let mount = SecretMount {
            source: SecretRef::LocalFile {
                path: PathBuf::from("api-key"),
            },
            target: SecretTarget::EnvVar { name: "KEY".into() },
        };

        let debug = format!("{mount:?}");
        // The path reference appears
        assert!(debug.contains("api-key"), "path must be in Debug output");
        // The type names are correct (no phantom value fields)
        assert!(debug.contains("SecretMount"), "SecretMount in debug");
        assert!(debug.contains("LocalFile"), "LocalFile in debug");
        // No base64-like long strings that might indicate encoded value content
        // (structural — SecretRef::LocalFile has no value field, so nothing to leak)
        for part in debug.split_whitespace() {
            assert!(
                part.len() < 128,
                "suspiciously long token in Debug output (possible value leak?): {part}"
            );
        }
    }
}
