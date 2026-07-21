//! Pluggable secret resolver for [`crate::SecretRef`] values.
//!
//! The trait lives in `workload-spec` so consumers can construct specs and
//! invoke the resolver without linking yubaba's containerd client. Yubaba
//! provides the production impl in `crates/yah/yubaba/src/secrets.rs`.

use std::path::PathBuf;

use thiserror::Error;

use crate::SecretRef;

/// Errors returned by [`SecretResolver::resolve`].
#[derive(Debug, Error)]
pub enum SecretError {
    /// The referenced secret file does not exist in the yubaba secret store.
    #[error("secret not found at {path}")]
    NotFound { path: PathBuf },

    /// `SecretRef::Cluster` reached a resolver that has no cluster backing —
    /// e.g. the per-machine `LocalFileResolver`, which cannot decrypt cluster
    /// secrets. The fleet resolver (yubaba's `ClusterResolver`) handles the
    /// `Cluster` arm; this error means the wrong resolver was used.
    #[error("cluster secrets require a cluster-backed resolver")]
    ClusterNotImplemented,

    /// The referenced cluster secret is not present in the local raft replica
    /// (never written, or deleted). Fails closed — nothing is served.
    #[error("cluster secret {name} not found in the local raft replica")]
    ClusterNotFound { name: String },

    /// Decryption or authentication of a cluster secret failed — a wrong
    /// node-local KEK, a truncated/tampered record, or a malformed nonce. Fails
    /// closed; the message carries only the logical name, never key or
    /// ciphertext bytes.
    #[error("cluster secret {name} failed to decrypt")]
    ClusterDecrypt { name: String },

    /// The node-local cluster KEK could not be loaded (missing, unreadable, or
    /// not exactly 32 bytes). Fails closed; `reason` is a generic diagnostic
    /// and never contains key material.
    #[error("cluster KEK unavailable: {reason}")]
    Kek { reason: String },

    /// I/O error reading the secret file.
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Resolves a [`SecretRef`] to its raw byte content.
///
/// The trait is defined here (in `workload-spec`) so callers don't need to
/// link yubaba. Yubaba's `LocalFileResolver` reads from the per-machine secret
/// store at `/var/lib/yah/yubaba/secrets/`. Tests use an inline `FakeResolver`.
pub trait SecretResolver {
    fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError>;
}
