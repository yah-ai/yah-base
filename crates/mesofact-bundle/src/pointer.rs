//! `bundles/current/<name>.toml` — a by-name pointer to the digest most
//! recently published for one workload (R746-F5).
//!
//! The manifest object at `manifests/<digest>` is content-addressed and
//! immutable, so nothing about it tells a fresh assembly *which* digest was
//! last published for this service — there is no other way to find a reuse
//! candidate than to ask something mutable. This is that something: the one
//! deliberately-overwritable key in the scheme, the same role
//! `runtimes/…/<triple>.toml` plays for a stock runtime asset (see
//! `runtime.rs`).
//!
//! Written after a successful [`publish_bundle`](crate::publish_bundle) (not
//! after a deploy) so it only ever names bytes that are provably in the
//! store — a reader that resolves it and then fetches `manifests/<digest>`
//! cannot land on a digest the store never received.

use serde::{Deserialize, Serialize};
use yah_object_store::ObjectStore;

use crate::store::store_err;
use crate::{BundleError, BundleHash};

/// Wire version of the pointer object. Independent of [`SCHEMA_VERSION`](crate::SCHEMA_VERSION)
/// and [`RUNTIME_ASSET_SCHEMA_VERSION`](crate::RUNTIME_ASSET_SCHEMA_VERSION) — it versions a
/// third, much smaller object.
pub const CURRENT_POINTER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CurrentPointer {
    schema_version: u32,
    digest: BundleHash,
}

/// Object-store key for the current-digest pointer of workload `name`.
pub fn current_pointer_key(name: &str) -> String {
    format!("bundles/current/{name}.toml")
}

/// Record `digest` as the most recently published bundle for `name`,
/// overwriting whatever was there. Idempotent — publishing the same digest
/// twice writes the same bytes.
pub fn write_current_digest(
    store: &dyn ObjectStore,
    name: &str,
    digest: &BundleHash,
) -> Result<(), BundleError> {
    let pointer = CurrentPointer {
        schema_version: CURRENT_POINTER_SCHEMA_VERSION,
        digest: digest.clone(),
    };
    let toml = toml::to_string_pretty(&pointer).map_err(|e| BundleError::Manifest(e.to_string()))?;
    store
        .put(&current_pointer_key(name), toml.into_bytes())
        .map_err(store_err)
}

/// Read the current digest pointer for `name`, or `None` when nothing has
/// ever been published under that name.
pub fn read_current_digest(
    store: &dyn ObjectStore,
    name: &str,
) -> Result<Option<BundleHash>, BundleError> {
    let Some(bytes) = store.get(&current_pointer_key(name)).map_err(store_err)? else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes)
        .map_err(|e| BundleError::Manifest(format!("current-bundle pointer not utf-8: {e}")))?;
    let pointer: CurrentPointer =
        toml::from_str(&text).map_err(|e| BundleError::Manifest(e.to_string()))?;
    if pointer.schema_version != CURRENT_POINTER_SCHEMA_VERSION {
        return Err(BundleError::SchemaVersion {
            found: pointer.schema_version,
        });
    }
    Ok(Some(pointer.digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yah_object_store::InMemoryObjectStore;

    fn hash(s: &str) -> BundleHash {
        BundleHash::of(s.as_bytes())
    }

    #[test]
    fn absent_pointer_reads_as_none() {
        let store = InMemoryObjectStore::new();
        assert_eq!(read_current_digest(&store, "yah-marketing").unwrap(), None);
    }

    #[test]
    fn write_then_read_round_trips() {
        let store = InMemoryObjectStore::new();
        let d = hash("bundle-one");
        write_current_digest(&store, "yah-marketing", &d).unwrap();
        assert_eq!(
            read_current_digest(&store, "yah-marketing").unwrap(),
            Some(d)
        );
    }

    #[test]
    fn a_second_write_repoints_rather_than_appends() {
        let store = InMemoryObjectStore::new();
        let d1 = hash("bundle-one");
        let d2 = hash("bundle-two");
        write_current_digest(&store, "yah-marketing", &d1).unwrap();
        write_current_digest(&store, "yah-marketing", &d2).unwrap();
        assert_eq!(
            read_current_digest(&store, "yah-marketing").unwrap(),
            Some(d2)
        );
    }

    #[test]
    fn two_workload_names_do_not_alias() {
        let store = InMemoryObjectStore::new();
        let a = hash("a");
        let b = hash("b");
        write_current_digest(&store, "yah-marketing", &a).unwrap();
        write_current_digest(&store, "yah-chat", &b).unwrap();
        assert_eq!(read_current_digest(&store, "yah-marketing").unwrap(), Some(a));
        assert_eq!(read_current_digest(&store, "yah-chat").unwrap(), Some(b));
    }

    #[test]
    fn key_layout_is_stable() {
        assert_eq!(current_pointer_key("yah-marketing"), "bundles/current/yah-marketing.toml");
    }
}
