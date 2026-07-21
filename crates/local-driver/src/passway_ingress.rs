//! Passway public-ingress appliance bring-up primitives (R600-F5 / W273).
//!
//! The passway L7 ingress (W267/R594) terminates TLS for the fleet's public
//! `*.yah.dev` traffic. This module lowers the operator-facing knobs (domain,
//! listener, upstreams) into the containerd [`Workload`] yubaba deploys — the
//! **cert-consuming** shape R600 exists to produce:
//!
//! - It declares two [`SecretRef::Cluster`] → [`SecretTarget::File`] mounts for
//!   the fleet-shared cert + key (raft-replicated by the single ACME issuer,
//!   R600-F3; materialized to a host tmpfs bind at admission, R600-F6;
//!   re-rendered + graceful-upgraded on rotation, R600-F4/F7/F9).
//! - It runs passway in `PASSWAY_TLS_MODE=manual`, pointing `PASSWAY_TLS_CERT`
//!   / `PASSWAY_TLS_KEY` at those mounts. **No `PASSWAY_ACME_*` env is set** —
//!   per-node self-issuance is dropped by construction, so the Let's Encrypt
//!   duplicate-certificate rate limit disappears (the W273 payoff). ACME
//!   collapses to the elected issuer's job alone.
//!
//! Placement: the appliance marks itself `archetype = Appliance` (pinned /
//! non-drainable) and `requires_taint() == PUBLIC_IP_TAINT`, so a future
//! scheduler (R572-F5) can place it only on machines carrying the `public-ip`
//! taint. Until that scheduler + the machine-TOML `taints` field (R572-F3)
//! land, the deploy verb targets the public-IP node explicitly; the annotation
//! is the agreed-upon contract both sides read once enforcement exists.
//!
//! Networking: host-networked infra-tier, exactly like the cloud
//! mesofact-runner — passway binds the node's public `:443` directly, so it
//! needs the host netns (the guarded `yah.network=host` escape hatch, honoured
//! only for `tier="infra"`). The upstreams it forwards to are reached over the
//! WireGuard mesh.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use workload_spec::{
    EnvValue, EnvVar, ExposeSpec, HealthProbe, Healthcheck, ImageRef, LifecycleArchetype,
    MeshExpose, MeshIdent, Millis, NamespaceId, ResourceLimits, RestartPolicy, SchemaVersion,
    SecretMount, SecretRef, SecretTarget, StopPolicy, TenantId, TierTag, VolumeMount, Workload,
    WorkloadSpec, HOST_NETWORK_ANNOTATION, HOST_NETWORK_VALUE, PUBLIC_IP_TAINT,
    REQUIRES_TAINT_ANNOTATION,
};

/// DNS name + mesh identity of the passway ingress workload. Contains
/// `"passway"` so `cloud.ha_diagnose`'s ingress probe (which matches idents
/// by that substring) recognises it.
pub const INGRESS_WORKLOAD_NAME: &str = "passway-ingress";

/// Container-side TLS listener address when the caller doesn't override it.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:443";

/// Container-side TLS port. Mesh-exposed and TCP-probed for liveness.
const TLS_PORT: u16 = 443;

/// Container path the shared cert chain is mounted at (mode `0o400`).
const CERT_MOUNT_PATH: &str = "/run/secrets/tls.crt";
/// Container path the shared private key is mounted at (mode `0o400`).
const KEY_MOUNT_PATH: &str = "/run/secrets/tls.key";

/// pingora's per-instance pid file — the target for kamaji's graceful-upgrade
/// `SIGQUIT`. Lives under a writable tmpfs the image provides.
const PID_FILE: &str = "/run/passway/pingora.pid";
/// pingora's per-instance graceful-upgrade fd-handoff socket.
const UPGRADE_SOCK: &str = "/run/passway/upgrade.sock";

/// Default passway binary path inside the image (no `ENTRYPOINT` reliance:
/// `build_oci_spec` ignores the image CMD/ENTRYPOINT and runs `command`
/// directly, so it must be spelled out).
const DEFAULT_COMMAND: &str = "/usr/local/bin/passway";

/// Cluster-secret key holding the AES-256-GCM-sealed cert chain for `domain`.
/// Mirrors what the R600-F3 issuer writes (`tls/<domain>/cert`).
fn cert_secret_name(domain: &str) -> String {
    format!("tls/{domain}/cert")
}

/// Cluster-secret key holding the sealed private key for `domain`
/// (`tls/<domain>/key`, written key-first/cert-last by the issuer).
fn key_secret_name(domain: &str) -> String {
    format!("tls/{domain}/key")
}

/// Caller-supplied passway ingress bring-up parameters. The `yah cloud ingress`
/// deploy verb builds this from flags/component config, then lowers it to the
/// yubaba workload payload via [`Self::into_container_workload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswayIngressSpec {
    /// Base/wildcard domain whose fleet-shared cert this ingress consumes, e.g.
    /// `"yah.dev"`. The cluster-secret keys are `tls/<domain>/cert` and
    /// `tls/<domain>/key` (R600-F3).
    pub domain: String,

    /// TLS listener address. Defaults to [`DEFAULT_LISTEN`] (`0.0.0.0:443`).
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Upstream mesh endpoints (`host:port`) passway round-robins across.
    /// Reached over the WireGuard mesh; empty is valid (passway fail-ready-503s
    /// until records populate).
    #[serde(default)]
    pub upstreams: Vec<String>,

    /// Speak TLS to upstreams. Default `false` — the mesh is already encrypted.
    #[serde(default)]
    pub upstream_tls: bool,

    /// Override the passway binary invocation. Defaults to
    /// `["/usr/local/bin/passway"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

impl PasswayIngressSpec {
    /// Lower this ingress spec into a containerd [`Workload`] yubaba can deploy.
    ///
    /// The result is the W273 cert-consuming shape: host-networked infra-tier,
    /// `Appliance` archetype, `public-ip` taint requirement, two Cluster→File
    /// cert/key secret mounts, and `PASSWAY_TLS_MODE=manual` with **no**
    /// `PASSWAY_ACME_*` env.
    ///
    /// `image` is the content-addressed passway image (operator-supplied, same
    /// as the mesofact-runner digest).
    pub fn into_container_workload(&self, image: ImageRef) -> Workload {
        let env = vec![
            literal_env("PASSWAY_LISTEN", self.listen.clone()),
            // Consume the shared mount instead of self-issuing — the whole point.
            literal_env("PASSWAY_TLS_MODE", "manual".into()),
            literal_env("PASSWAY_TLS_CERT", CERT_MOUNT_PATH.into()),
            literal_env("PASSWAY_TLS_KEY", KEY_MOUNT_PATH.into()),
            literal_env("PASSWAY_UPSTREAMS", self.upstreams.join(",")),
            literal_env(
                "PASSWAY_UPSTREAM_TLS",
                if self.upstream_tls { "true" } else { "false" }.into(),
            ),
            // Per-instance paths so kamaji's graceful-upgrade fd-handoff
            // (R600-F4/F7/F9) targets the right pingora process on rotation.
            literal_env("PASSWAY_PID_FILE", PID_FILE.into()),
            literal_env("PASSWAY_UPGRADE_SOCK", UPGRADE_SOCK.into()),
        ];

        let secrets = vec![
            cluster_file_secret(cert_secret_name(&self.domain), CERT_MOUNT_PATH),
            cluster_file_secret(key_secret_name(&self.domain), KEY_MOUNT_PATH),
        ];

        let mut annotations = HashMap::new();
        // Bind the public :443 on the host — guarded escape hatch, infra-only.
        annotations.insert(
            HOST_NETWORK_ANNOTATION.to_string(),
            HOST_NETWORK_VALUE.to_string(),
        );
        // Place only on a publicly-routable node (enforced once R572-F5 lands).
        annotations.insert(
            REQUIRES_TAINT_ANNOTATION.to_string(),
            PUBLIC_IP_TAINT.to_string(),
        );

        let grace = Millis::from_secs(5);

        let spec = WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: INGRESS_WORKLOAD_NAME.into(),
            image,
            tier: TierTag("infra".into()),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            replicas: 1,
            command: Some(
                self.command
                    .clone()
                    .unwrap_or_else(|| vec![DEFAULT_COMMAND.into()]),
            ),
            entrypoint: None,
            workdir: None,
            user: None,
            env,
            secrets,
            volumes: Vec::<VolumeMount>::new(),
            resources: ResourceLimits {
                memory_mb: 256,
                cpu_millis: 512,
                ephemeral_storage_mb: 256,
            },
            depends_on: vec![],
            healthcheck: Some(Healthcheck {
                // :443 speaks TLS, so a plaintext HttpGet probe would fail the
                // handshake — a bare TCP connect is the right liveness signal.
                probe: HealthProbe::TcpConnect { port: TLS_PORT },
                interval: Millis::from_secs(10),
                timeout: Millis::from_secs(2),
                initial_delay: Millis::from_secs(10),
                failure_threshold: 3,
            }),
            // Appliance = pinned/non-drainable; always restart the ingress.
            restart_policy: RestartPolicy::Always,
            archetype: Some(LifecycleArchetype::Appliance),
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: grace,
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(INGRESS_WORKLOAD_NAME.into()),
                    ports: vec![TLS_PORT],
                    allow_from: vec![],
                },
                // passway terminates TLS itself on the public :443 — this is NOT
                // a yubaba CF-managed route, so leave `public` unset.
                public: None,
                operator: None,
            },
            labels: HashMap::new(),
            annotations,
        };

        Workload::Container(spec)
    }
}

fn literal_env(name: &str, value: String) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: EnvValue::Literal { value },
    }
}

fn cluster_file_secret(name: String, mount_path: &str) -> SecretMount {
    SecretMount {
        source: SecretRef::Cluster { name },
        target: SecretTarget::File {
            path: mount_path.into(),
            mode: 0o400,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image() -> ImageRef {
        ImageRef {
            registry: "localhost".into(),
            repository: "passway".into(),
            tag: "r600f5".into(),
            digest: workload_spec::testing::test_digest(),
        }
    }

    fn sample_spec() -> PasswayIngressSpec {
        PasswayIngressSpec {
            domain: "yah.dev".into(),
            listen: DEFAULT_LISTEN.into(),
            upstreams: vec!["yah-marketing.pdx:8080".into(), "yah-dashboard.pdx:8080".into()],
            upstream_tls: false,
            command: None,
        }
    }

    fn lower(spec: &PasswayIngressSpec) -> WorkloadSpec {
        let Workload::Container(s) = spec.into_container_workload(sample_image()) else {
            panic!("expected a Container workload");
        };
        s
    }

    fn env_val<'a>(spec: &'a WorkloadSpec, name: &str) -> Option<&'a str> {
        spec.env.iter().find(|e| e.name == name).and_then(|e| match &e.value {
            EnvValue::Literal { value } => Some(value.as_str()),
            _ => None,
        })
    }

    #[test]
    fn consumes_shared_cert_via_two_cluster_file_mounts() {
        let spec = lower(&sample_spec());
        assert_eq!(spec.secrets.len(), 2, "cert + key");

        let cert = &spec.secrets[0];
        assert_eq!(
            cert.source,
            SecretRef::Cluster {
                name: "tls/yah.dev/cert".into()
            }
        );
        assert_eq!(
            cert.target,
            SecretTarget::File {
                path: CERT_MOUNT_PATH.into(),
                mode: 0o400
            }
        );

        let key = &spec.secrets[1];
        assert_eq!(
            key.source,
            SecretRef::Cluster {
                name: "tls/yah.dev/key".into()
            }
        );
        assert_eq!(
            key.target,
            SecretTarget::File {
                path: KEY_MOUNT_PATH.into(),
                mode: 0o400
            }
        );
    }

    #[test]
    fn runs_manual_tls_pointing_at_the_mounts() {
        let spec = lower(&sample_spec());
        assert_eq!(env_val(&spec, "PASSWAY_TLS_MODE"), Some("manual"));
        assert_eq!(env_val(&spec, "PASSWAY_TLS_CERT"), Some(CERT_MOUNT_PATH));
        assert_eq!(env_val(&spec, "PASSWAY_TLS_KEY"), Some(KEY_MOUNT_PATH));
    }

    #[test]
    fn drops_self_issuance_no_acme_env() {
        let spec = lower(&sample_spec());
        // The W273 payoff: not a single ACME knob, so a stale var can't
        // re-enable per-node issuance.
        assert!(
            !spec.env.iter().any(|e| e.name.starts_with("PASSWAY_ACME")),
            "ingress must carry no PASSWAY_ACME_* env"
        );
        assert_ne!(env_val(&spec, "PASSWAY_TLS_MODE"), Some("acme"));
    }

    #[test]
    fn upstreams_join_into_one_env() {
        let spec = lower(&sample_spec());
        assert_eq!(
            env_val(&spec, "PASSWAY_UPSTREAMS"),
            Some("yah-marketing.pdx:8080,yah-dashboard.pdx:8080")
        );
        assert_eq!(env_val(&spec, "PASSWAY_UPSTREAM_TLS"), Some("false"));
    }

    #[test]
    fn upgrade_wiring_present_for_graceful_reload() {
        let spec = lower(&sample_spec());
        assert_eq!(env_val(&spec, "PASSWAY_PID_FILE"), Some(PID_FILE));
        assert_eq!(env_val(&spec, "PASSWAY_UPGRADE_SOCK"), Some(UPGRADE_SOCK));
        // PASSWAY_UPGRADE is set by kamaji ONLY on the replacement process, never
        // baked into the steady-state spec.
        assert!(!spec.env.iter().any(|e| e.name == "PASSWAY_UPGRADE"));
    }

    #[test]
    fn is_public_ip_appliance_on_host_network() {
        let spec = lower(&sample_spec());
        assert_eq!(spec.archetype, Some(LifecycleArchetype::Appliance));
        assert_eq!(spec.requires_taint(), Some(PUBLIC_IP_TAINT));
        assert!(spec.wants_host_network());
        assert_eq!(spec.tier.0, "infra");
    }

    #[test]
    fn ha_diagnose_can_find_it_by_ident() {
        let spec = lower(&sample_spec());
        assert!(spec.expose.mesh.identity.0.to_lowercase().contains("passway"));
        assert_eq!(spec.expose.mesh.ports, vec![443]);
    }

    #[test]
    fn command_defaults_and_overrides() {
        let spec = lower(&sample_spec());
        assert_eq!(spec.command.as_deref().unwrap(), [DEFAULT_COMMAND]);

        let mut custom = sample_spec();
        custom.command = Some(vec!["/usr/bin/tini".into(), "--".into(), "/bin/passway".into()]);
        let spec = lower(&custom);
        assert_eq!(
            spec.command.as_deref().unwrap(),
            ["/usr/bin/tini", "--", "/bin/passway"]
        );
    }

    #[test]
    fn lowered_spec_passes_shape_validation() {
        let spec = lower(&sample_spec());
        workload_spec::validate::shape(&spec).expect("ingress spec passes shape validation");
    }

    #[test]
    fn spec_round_trips_through_serde_with_defaults() {
        let json = r#"{ "domain": "yah.dev", "upstreams": ["a.pdx:8080"] }"#;
        let spec: PasswayIngressSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.listen, DEFAULT_LISTEN);
        assert!(!spec.upstream_tls);
        assert!(spec.command.is_none());
        assert_eq!(spec.upstreams, vec!["a.pdx:8080".to_string()]);
    }
}
