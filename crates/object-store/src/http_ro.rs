//! Unauthenticated, read-only object store over plain HTTPS (R599-T5).
//!
//! The read leg of a **content-addressed** store needs no credential, and
//! giving it one is a net loss. Integrity comes from the content address, not
//! from the transport: `yah_mesofact_bundle::materialize_bundle` verifies the
//! manifest hashes to the requested digest and that every blob hashes to its
//! recorded blake3 before writing anything to disk. A hostile origin, a
//! compromised CDN, or a corrupted cache cannot inject bytes — the hash check
//! fails. Authentication would add only confidentiality, which published
//! bundles do not need.
//!
//! What that buys, and why it is the posture rather than a shortcut:
//!
//! - **Nodes hold no secrets.** A node bootstraps with nothing to provision,
//!   rotate, or leak. Compare the alternative: a write-capable R2 key on every
//!   box in the fleet, which would let any compromised node overwrite the
//!   release store it reads from.
//! - **Anything can serve it** — an R2 custom domain, a CDN edge, an nginx on
//!   the LAN, a peer node's cache (W272 §2's peer-to-peer mirroring), a USB
//!   stick in an air-gapped room. The bytes are self-verifying, so the
//!   transport is interchangeable.
//! - **It caches.** Immutable, content-addressed keys are the ideal CDN object:
//!   infinite TTL, no invalidation protocol, free cold-start acceleration.
//!
//! This is the same split OCI registries (anonymous pull / authenticated push),
//! Nix binary caches, and the Go module proxy all landed on: public immutable
//! bytes, credentialed publish, trust anchored in the digest. The write half
//! stays in [`crate::R2ObjectStore`] and lives only on the publisher.
//!
//! Accordingly the mutating half of [`ObjectStore`] is not emulated here — it
//! returns [`Error::Backend`] rather than pretending. A caller that needs to
//! write wants the credentialed store and should say so.

use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::StatusCode;

use crate::{Error, ObjectStore};

/// Read-only [`ObjectStore`] backed by a public HTTPS origin.
///
/// Keys are appended to the origin as path segments: origin
/// `https://cdn.yah.dev` + key `blobs/abc…` → `https://cdn.yah.dev/blobs/abc…`.
pub struct HttpReadOnlyObjectStore {
    /// Base URL with no trailing slash.
    origin: String,
    client: Client,
}

impl HttpReadOnlyObjectStore {
    /// Build a store against `origin` (e.g. `https://cdn.yah.dev`).
    ///
    /// A trailing slash on `origin` is trimmed so key joining stays
    /// single-slashed.
    pub fn new(origin: impl Into<String>) -> Result<Self, Error> {
        let origin = origin.into().trim_end_matches('/').to_string();
        if origin.is_empty() {
            return Err(Error::Backend("bundle origin must not be empty".into()));
        }
        let client = Client::builder()
            // A cold bundle fetch pulls many small blobs; keep-alive matters
            // more than any single request's ceiling.
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| Error::Backend(format!("building http client: {e}")))?;
        Ok(Self { origin, client })
    }

    /// The origin this store reads from.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    fn url(&self, key: &str) -> String {
        format!("{}/{}", self.origin, key.trim_start_matches('/'))
    }

    /// Shared error text for the write half. Emulating a write over a read-only
    /// origin would silently diverge from the store a publisher actually wrote
    /// to, so every mutating method routes here instead.
    fn read_only(op: &str) -> Error {
        Error::Backend(format!(
            "{op} is not supported by the read-only bundle origin — publishing \
             goes through the credentialed R2 store on the publisher, never a node"
        ))
    }
}

impl ObjectStore for HttpReadOnlyObjectStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let url = self.url(key);
        let resp = self
            .client
            .get(&url)
            .send()
            .map_err(|e| Error::Io(format!("GET {url}: {e}")))?;

        match resp.status() {
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => {
                // R2/S3 origins answer a missing key with 403 when listing is
                // denied, which is the common public-bucket configuration.
                // Treat both as a clean miss — the caller (materialize) turns
                // that into MissingBlob with the key in hand.
                Ok(None)
            }
            s if s.is_success() => {
                let bytes = resp
                    .bytes()
                    .map_err(|e| Error::Io(format!("reading body of {url}: {e}")))?;
                Ok(Some(bytes.to_vec()))
            }
            s => Err(Error::Backend(format!("GET {url}: unexpected status {s}"))),
        }
    }

    fn head(&self, key: &str) -> Result<bool, Error> {
        let url = self.url(key);
        let resp = self
            .client
            .head(&url)
            .send()
            .map_err(|e| Error::Io(format!("HEAD {url}: {e}")))?;
        match resp.status() {
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => Ok(false),
            s if s.is_success() => Ok(true),
            s => Err(Error::Backend(format!("HEAD {url}: unexpected status {s}"))),
        }
    }

    fn put(&self, _key: &str, _data: Vec<u8>) -> Result<(), Error> {
        Err(Self::read_only("put"))
    }

    fn delete(&self, _key: &str) -> Result<(), Error> {
        Err(Self::read_only("delete"))
    }

    fn list_prefix(&self, _prefix: &str) -> Result<Vec<String>, Error> {
        // A plain HTTPS origin exposes no listing protocol. Materialize is
        // manifest-driven (it knows every key it needs), so nothing on the node
        // path calls this.
        Err(Self::read_only("list_prefix"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_trailing_slash_is_trimmed() {
        let s = HttpReadOnlyObjectStore::new("https://cdn.yah.dev/").unwrap();
        assert_eq!(s.origin(), "https://cdn.yah.dev");
        assert_eq!(s.url("blobs/abc"), "https://cdn.yah.dev/blobs/abc");
    }

    #[test]
    fn key_leading_slash_does_not_double_up() {
        let s = HttpReadOnlyObjectStore::new("https://cdn.yah.dev").unwrap();
        assert_eq!(s.url("/blobs/abc"), "https://cdn.yah.dev/blobs/abc");
    }

    #[test]
    fn empty_origin_is_rejected() {
        assert!(HttpReadOnlyObjectStore::new("").is_err());
        assert!(HttpReadOnlyObjectStore::new("///").is_err());
    }

    /// The write half must fail loudly rather than emulate. A node that could
    /// "succeed" at a put would diverge from the real store silently.
    #[test]
    fn mutating_ops_are_refused() {
        let s = HttpReadOnlyObjectStore::new("https://cdn.yah.dev").unwrap();
        assert!(s.put("blobs/x", vec![1]).is_err());
        assert!(s.delete("blobs/x").is_err());
        assert!(s.list_prefix("blobs/").is_err());
        // put_if / etag inherit the trait defaults, which also refuse.
        assert!(s.etag("blobs/x").is_err());
    }
}
