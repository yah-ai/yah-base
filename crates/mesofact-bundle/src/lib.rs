//! The W272 **mesofact bundle** format — the content-addressed unit a mesofact
//! app distributes as, plus (behind the `store` feature) the R2 blob store that
//! publishes and materializes it.
//!
//! A bundle is one immutable, content-addressed directory shape:
//!
//! ```text
//! <bundle>/
//!   manifest.toml                     # identity + runtime selection
//!   app/                              # routes/config + built TS/assets
//!   bins/<triple>/serve               # ONLY when runtime = "self"
//! ```
//!
//! ```toml
//! # manifest.toml
//! schema_version = 1
//! name    = "yah-marketing"
//! runtime = "mesofact/0.8.18"   # vanilla: resolve stock runtime from node cache
//! # runtime = "self"            # custom: bins/<triple>/serve ships in the bundle
//!
//! [content]
//! "app/mesofact.routes.ts" = "b3f1…"   # path → blake3, one row per file
//! ```
//!
//! There is exactly one format; "vanilla" is the degenerate case where
//! `runtime = "mesofact/<ver>"` and no `bins/` are carried. Immutability is the
//! whole coherence story: any change produces a new [`BundleManifest::digest`],
//! "update" is publish-new-digest + drain-old, and rollback is a pointer flip.
//!
//! This crate is deliberately light: the default feature set is serde + blake3
//! + toml only, so the `mesofact-build` subcamp (R599-F2, a separate Cargo
//! workspace) can link it to *emit* manifests without dragging the object-store
//! / reqwest stack across the boundary. The `store` feature adds that surface
//! for the cloud publish path (R599) and kamaji node materialize (R599-F4).
//!
//! Home of R599-F1 (the W272 bundle format + store) — the canonical `@yah:`
//! ticket annotation lives in `oss/yubaba/crates/cloud/src/release_manifest.rs`
//! to keep one block per ID; see W272 for the design.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "store")]
mod store;
#[cfg(feature = "store")]
pub use store::{materialize_bundle, publish_bundle, BundleCache, PublishReport};

/// Bundle-manifest schema version. Bumping this is a wire-format change: the
/// materialize side rejects a manifest whose `schema_version` it does not know.
pub const SCHEMA_VERSION: u32 = 1;

/// Error surface for parsing / hashing a bundle manifest. The `store` feature
/// adds I/O + object-store variants (see `store.rs`).
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// `manifest.toml` failed to parse.
    #[error("malformed bundle manifest: {0}")]
    Manifest(String),

    /// A manifest carried a `schema_version` this build doesn't understand.
    #[error("unsupported bundle schema_version {found} (this build speaks {SCHEMA_VERSION})")]
    SchemaVersion { found: u32 },

    /// A `runtime = "..."` string was neither `self` nor `mesofact/<version>`.
    #[error("unrecognized bundle runtime {0:?} (expected \"self\" or \"mesofact/<version>\")")]
    Runtime(String),

    /// Bytes hashed to a different digest than the manifest recorded. Carries
    /// the offending path (or blob key) plus both hashes.
    #[error("blake3 mismatch for {what}: manifest says {expected}, bytes hash to {actual}")]
    HashMismatch {
        what: String,
        expected: String,
        actual: String,
    },

    /// Filesystem or object-store failure (only constructed under `store`).
    #[error("bundle io: {0}")]
    Io(String),

    /// A blob referenced by the manifest was absent from the store during
    /// materialize (only constructed under `store`).
    #[error("missing blob {key} for path {path:?} while materializing bundle")]
    MissingBlob { key: String, path: String },
}

/// A BLAKE3 content hash: exactly 64 lowercase ASCII hex digits.
///
/// The content-address key for every file in a bundle *and* for the bundle's
/// own manifest digest. Deserialization rejects anything that isn't 64 hex
/// chars, and normalizes to lowercase so `blob_key` is stable regardless of how
/// a hand-authored manifest cased its hashes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BundleHash(String);

impl BundleHash {
    /// Wrap a hex string, validating shape (64 hex chars) and lowercasing.
    pub fn parse(s: impl Into<String>) -> Result<Self, BundleError> {
        let s = s.into();
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(BundleError::Manifest(format!(
                "blake3 hash must be exactly 64 hex digits, got {s:?}"
            )));
        }
        Ok(BundleHash(s.to_ascii_lowercase()))
    }

    /// The BLAKE3 hash of `bytes`, as a [`BundleHash`].
    pub fn of(bytes: &[u8]) -> Self {
        BundleHash(blake3::hash(bytes).to_hex().to_string())
    }

    /// Borrow the hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BundleHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for BundleHash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BundleHash {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        BundleHash::parse(s).map_err(serde::de::Error::custom)
    }
}

/// Which runtime serves a bundle — the `runtime = "..."` manifest field.
///
/// Serialized as a single string: `"self"` for a bundle that ships its own
/// `bins/<triple>/serve`, or `"mesofact/<version>"` for a vanilla bundle that
/// resolves the stock `mesofact serve` runtime from the node's runtime cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleRuntime {
    /// Vanilla: resolve the stock `mesofact serve` runtime asset of this
    /// version from the node cache. No binaries in the bundle.
    Mesofact { version: String },

    /// Custom: the bundle carries `bins/<triple>/serve` and is served by its
    /// own binary. No node runtime asset is resolved.
    SelfContained,
}

impl BundleRuntime {
    /// The wire string form (`"self"` or `"mesofact/<version>"`).
    pub fn as_wire(&self) -> String {
        match self {
            BundleRuntime::SelfContained => "self".to_string(),
            BundleRuntime::Mesofact { version } => format!("mesofact/{version}"),
        }
    }

    /// Parse the wire string form.
    pub fn parse(s: &str) -> Result<Self, BundleError> {
        if s == "self" {
            return Ok(BundleRuntime::SelfContained);
        }
        if let Some(version) = s.strip_prefix("mesofact/") {
            if !version.is_empty() {
                return Ok(BundleRuntime::Mesofact {
                    version: version.to_string(),
                });
            }
        }
        Err(BundleError::Runtime(s.to_string()))
    }

    /// Whether the bundle ships its own serve binaries (`runtime = "self"`).
    pub fn is_self_contained(&self) -> bool {
        matches!(self, BundleRuntime::SelfContained)
    }
}

impl Serialize for BundleRuntime {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_wire())
    }
}

impl<'de> Deserialize<'de> for BundleRuntime {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        BundleRuntime::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// The parsed `manifest.toml` at a bundle's root — the bundle's identity plus
/// the per-file content map that makes it content-addressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Wire-format version. Always [`SCHEMA_VERSION`] today.
    pub schema_version: u32,

    /// Human-readable bundle name, e.g. `"yah-marketing"`. Not part of the
    /// content-address surface beyond the digest — two bundles with the same
    /// bytes but different names have different digests.
    pub name: String,

    /// Runtime selection (`"self"` / `"mesofact/<ver>"`).
    pub runtime: BundleRuntime,

    /// Every file the bundle carries, keyed by its path *within the bundle*
    /// (e.g. `"app/dist/index.html"`, `"bins/x86_64-unknown-linux-musl/serve"`)
    /// mapped to its BLAKE3 content hash. Sorted (BTreeMap) so the manifest
    /// serialization — and therefore the digest — is deterministic.
    #[serde(default)]
    pub content: BTreeMap<String, BundleHash>,
}

impl BundleManifest {
    /// Parse a `manifest.toml` string, rejecting an unknown schema version.
    pub fn from_toml_str(s: &str) -> Result<Self, BundleError> {
        let manifest: BundleManifest =
            toml::from_str(s).map_err(|e| BundleError::Manifest(e.to_string()))?;
        if manifest.schema_version != SCHEMA_VERSION {
            return Err(BundleError::SchemaVersion {
                found: manifest.schema_version,
            });
        }
        Ok(manifest)
    }

    /// Serialize back to `manifest.toml` form.
    pub fn to_toml_string(&self) -> Result<String, BundleError> {
        toml::to_string_pretty(self).map_err(|e| BundleError::Manifest(e.to_string()))
    }

    /// The bundle's content-address: a BLAKE3 digest over the manifest's
    /// identity + content map.
    ///
    /// Computed over a canonical, order-stable byte encoding (not the TOML text,
    /// which whitespace/comments could perturb): `schema_version`, `name`, the
    /// runtime wire string, then every `(path, hash)` pair in sorted path order.
    /// Any change to any file's bytes (its hash), the name, the runtime, or the
    /// file set flips the digest — that immutability is what makes rollback a
    /// pointer flip and eviction a no-invalidation affair (W272 §1).
    pub fn digest(&self) -> BundleHash {
        let mut hasher = blake3::Hasher::new();
        // Domain-separate + length-prefix every field so no two distinct
        // manifests can collide by field-boundary ambiguity.
        let mut feed = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        feed(b"yah-mesofact-bundle/v1");
        feed(&self.schema_version.to_le_bytes());
        feed(self.name.as_bytes());
        feed(self.runtime.as_wire().as_bytes());
        feed(&(self.content.len() as u64).to_le_bytes());
        // BTreeMap iterates in sorted key order — deterministic.
        for (path, hash) in &self.content {
            feed(path.as_bytes());
            feed(hash.as_str().as_bytes());
        }
        BundleHash(hasher.finalize().to_hex().to_string())
    }
}

/// Object-store key for a content blob: `blobs/<blake3>`. Every file across
/// every bundle dedupes on this key — two bundles sharing a byte-identical file
/// share the one blob.
pub fn blob_key(hash: &BundleHash) -> String {
    format!("blobs/{}", hash.as_str())
}

/// Object-store key for a bundle manifest: `manifests/<digest>`. Immutable —
/// the digest is derived from the manifest, so re-publishing an identical
/// bundle writes the same key with the same bytes.
pub fn manifest_key(digest: &BundleHash) -> String {
    format!("manifests/{}", digest.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(s: &str) -> BundleHash {
        BundleHash::of(s.as_bytes())
    }

    fn sample() -> BundleManifest {
        let mut content = BTreeMap::new();
        content.insert("app/index.html".to_string(), hash_of("<html>"));
        content.insert("app/mesofact.routes.ts".to_string(), hash_of("routes"));
        BundleManifest {
            schema_version: SCHEMA_VERSION,
            name: "yah-marketing".to_string(),
            runtime: BundleRuntime::Mesofact {
                version: "0.8.18".to_string(),
            },
            content,
        }
    }

    #[test]
    fn hash_rejects_non_hex_and_wrong_length() {
        assert!(BundleHash::parse("zz").is_err());
        assert!(BundleHash::parse("g".repeat(64)).is_err());
        assert!(BundleHash::parse("a".repeat(63)).is_err());
        assert!(BundleHash::parse("A".repeat(64)).is_ok()); // hex, gets lowercased
        assert_eq!(BundleHash::parse("A".repeat(64)).unwrap().as_str(), "a".repeat(64));
    }

    #[test]
    fn runtime_round_trips_both_forms() {
        assert_eq!(BundleRuntime::parse("self").unwrap(), BundleRuntime::SelfContained);
        assert_eq!(
            BundleRuntime::parse("mesofact/0.8.18").unwrap(),
            BundleRuntime::Mesofact { version: "0.8.18".into() }
        );
        assert_eq!(BundleRuntime::SelfContained.as_wire(), "self");
        assert_eq!(
            BundleRuntime::Mesofact { version: "1.2.3".into() }.as_wire(),
            "mesofact/1.2.3"
        );
        // Malformed runtimes reject.
        assert!(BundleRuntime::parse("mesofact/").is_err());
        assert!(BundleRuntime::parse("caddy").is_err());
    }

    #[test]
    fn manifest_round_trips_through_toml() {
        let m = sample();
        let text = m.to_toml_string().unwrap();
        let back = BundleManifest::from_toml_str(&text).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn manifest_parses_the_doc_shape() {
        let h = "a".repeat(64);
        let text = format!(
            r#"
schema_version = 1
name = "yah-marketing"
runtime = "mesofact/0.8.18"

[content]
"app/mesofact.routes.ts" = "{h}"
"#
        );
        let m = BundleManifest::from_toml_str(&text).unwrap();
        assert_eq!(m.name, "yah-marketing");
        assert!(matches!(m.runtime, BundleRuntime::Mesofact { .. }));
        assert_eq!(m.content.len(), 1);
    }

    #[test]
    fn unknown_schema_version_is_rejected() {
        let text = r#"schema_version = 999
name = "x"
runtime = "self"
"#;
        assert!(matches!(
            BundleManifest::from_toml_str(text),
            Err(BundleError::SchemaVersion { found: 999 })
        ));
    }

    #[test]
    fn digest_is_deterministic_and_order_independent() {
        // Insertion order differs but BTreeMap normalizes — same digest.
        let mut a = BTreeMap::new();
        a.insert("z".to_string(), hash_of("1"));
        a.insert("a".to_string(), hash_of("2"));
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), hash_of("2"));
        b.insert("z".to_string(), hash_of("1"));
        let ma = BundleManifest { content: a, ..sample() };
        let mb = BundleManifest { content: b, ..sample() };
        assert_eq!(ma.digest(), mb.digest());
    }

    #[test]
    fn digest_changes_when_any_field_changes() {
        let base = sample();
        let d0 = base.digest();

        // Different file bytes (hash) → different digest.
        let mut c = base.content.clone();
        c.insert("app/index.html".to_string(), hash_of("<html>changed"));
        assert_ne!(BundleManifest { content: c, ..sample() }.digest(), d0);

        // Different name → different digest.
        assert_ne!(BundleManifest { name: "other".into(), ..sample() }.digest(), d0);

        // Different runtime → different digest.
        assert_ne!(
            BundleManifest { runtime: BundleRuntime::SelfContained, ..sample() }.digest(),
            d0
        );

        // Extra file → different digest.
        let mut c2 = base.content.clone();
        c2.insert("app/extra.js".to_string(), hash_of("x"));
        assert_ne!(BundleManifest { content: c2, ..sample() }.digest(), d0);
    }

    #[test]
    fn key_layout_is_stable() {
        let h = hash_of("blob");
        assert_eq!(blob_key(&h), format!("blobs/{h}"));
        assert_eq!(manifest_key(&h), format!("manifests/{h}"));
    }
}
