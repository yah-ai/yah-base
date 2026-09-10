//! Read-through chain over two stores (R870-B6): ask the workload's own store
//! first, fall back to the node's.
//!
//! This exists because a bundle's store is a **per-workload** fact while the
//! node also has one of its own, and both are legitimately in play at once. A
//! tenant publishes its site to its own bucket (`cdn.tenant.example`), so its
//! manifest and blobs are only there — but it does *not* republish the ~70MB
//! stock `mesofact/<ver>` serve runtime, which the fleet publishes once to the
//! node's origin. One store answers the first question, the other answers the
//! second, and which is which is not knowable per key: it is exactly "whoever
//! has it".
//!
//! Chaining is safe here for the same reason the whole read leg is
//! unauthenticated (see [`crate::http_ro`]): every key on this path is
//! content-addressed and verified against its blake3 after the fetch. A
//! fallback can therefore return the *wrong store's* bytes only if those bytes
//! hash to what was asked for, which is to say only if they are the right
//! bytes. There is no interleaving a chain permits that a single store would
//! have caught.
//!
//! Reads chain; **writes do not**. A chain has no principled answer to which
//! member a `put` lands in, and guessing would put a workload's bytes in
//! another tenant's store — the exact boundary R870-B6 exists to draw. The
//! mutating half returns [`Error::Backend`], as it does on the read-only origin
//! this usually wraps.

use std::sync::Arc;

use crate::{Error, ObjectStore};

/// Two stores read in order: `primary`, then `fallback` on a miss.
///
/// Errors from `primary` are **not** swallowed. A tenant origin that is
/// unreachable (DNS not yet bound, 5xx) is a misconfiguration an operator has
/// to see; quietly serving yah's copy instead would turn "your origin is
/// wrong" into "your deploy mysteriously works until the day it doesn't". Only
/// a clean miss — `Ok(None)` / `Ok(false)` — advances to the fallback.
pub struct FallbackObjectStore {
    primary: Arc<dyn ObjectStore>,
    fallback: Arc<dyn ObjectStore>,
}

impl FallbackObjectStore {
    /// Chain `primary` in front of `fallback`.
    pub fn new(primary: Arc<dyn ObjectStore>, fallback: Arc<dyn ObjectStore>) -> Self {
        Self { primary, fallback }
    }

    /// Shared error text for the write half — see the module docs.
    fn read_only(op: &str) -> Error {
        Error::Backend(format!(
            "{op} is not supported by a read-through store chain — a chain cannot say which \
             member a write belongs in; publish through the credentialed store for one bucket"
        ))
    }
}

impl ObjectStore for FallbackObjectStore {
    fn locate(&self, key: &str) -> String {
        // Both, because a miss means both were asked. An error naming only the
        // first sends an operator to curl a URL that was never the whole story.
        format!(
            "{} (falling back to {})",
            self.primary.locate(key),
            self.fallback.locate(key)
        )
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        match self.primary.get(key)? {
            Some(bytes) => Ok(Some(bytes)),
            None => self.fallback.get(key),
        }
    }

    fn head(&self, key: &str) -> Result<bool, Error> {
        if self.primary.head(key)? {
            return Ok(true);
        }
        self.fallback.head(key)
    }

    fn put(&self, _key: &str, _data: Vec<u8>) -> Result<(), Error> {
        Err(Self::read_only("put"))
    }

    fn delete(&self, _key: &str) -> Result<(), Error> {
        Err(Self::read_only("delete"))
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, Error> {
        // Union, deduped: a listing that dropped the fallback's keys would
        // describe neither store. Sorted so the result is stable regardless of
        // which member held what.
        let mut keys = self.primary.list_prefix(prefix)?;
        keys.extend(self.fallback.list_prefix(prefix)?);
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryObjectStore;

    fn store_with(entries: &[(&str, &[u8])]) -> Arc<dyn ObjectStore> {
        let s = InMemoryObjectStore::new();
        for (k, v) in entries {
            s.put(k, v.to_vec()).unwrap();
        }
        Arc::new(s)
    }

    #[test]
    fn the_primary_answers_when_it_has_the_key() {
        let chain = FallbackObjectStore::new(
            store_with(&[("blobs/a", b"tenant")]),
            store_with(&[("blobs/a", b"node")]),
        );
        assert_eq!(chain.get("blobs/a").unwrap().unwrap(), b"tenant".to_vec());
    }

    #[test]
    fn a_clean_miss_falls_through() {
        let chain = FallbackObjectStore::new(
            store_with(&[("blobs/a", b"tenant")]),
            store_with(&[("runtimes/mesofact/1/x.toml", b"node")]),
        );
        assert_eq!(
            chain.get("runtimes/mesofact/1/x.toml").unwrap().unwrap(),
            b"node".to_vec()
        );
        assert!(chain.get("blobs/absent").unwrap().is_none());
    }

    #[test]
    fn head_chains_the_same_way_get_does() {
        let chain = FallbackObjectStore::new(
            store_with(&[("blobs/a", b"tenant")]),
            store_with(&[("blobs/b", b"node")]),
        );
        assert!(chain.head("blobs/a").unwrap());
        assert!(chain.head("blobs/b").unwrap());
        assert!(!chain.head("blobs/c").unwrap());
    }

    /// The primary's failure must not be laundered into the fallback's answer —
    /// see the struct docs.
    #[test]
    fn a_primary_error_is_not_a_miss() {
        struct Broken;
        impl ObjectStore for Broken {
            fn put(&self, _: &str, _: Vec<u8>) -> Result<(), Error> {
                unreachable!()
            }
            fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
                Err(Error::Io(format!("GET {key}: dns failure")))
            }
            fn delete(&self, _: &str) -> Result<(), Error> {
                unreachable!()
            }
            fn list_prefix(&self, _: &str) -> Result<Vec<String>, Error> {
                unreachable!()
            }
        }
        let chain =
            FallbackObjectStore::new(Arc::new(Broken), store_with(&[("blobs/a", b"node")]));
        let err = chain.get("blobs/a").unwrap_err();
        assert!(format!("{err}").contains("dns failure"), "{err}");
    }

    #[test]
    fn locate_names_both_members() {
        let chain = FallbackObjectStore::new(store_with(&[]), store_with(&[]));
        let where_it_looked = chain.locate("blobs/a");
        assert!(
            where_it_looked.contains("blobs/a") && where_it_looked.contains("falling back"),
            "{where_it_looked}"
        );
    }

    #[test]
    fn writes_are_refused_rather_than_guessed_at() {
        let chain = FallbackObjectStore::new(store_with(&[]), store_with(&[]));
        assert!(chain.put("blobs/a", b"x".to_vec()).is_err());
        assert!(chain.delete("blobs/a").is_err());
    }

    #[test]
    fn list_prefix_unions_both_members() {
        let chain = FallbackObjectStore::new(
            store_with(&[("blobs/a", b"1"), ("blobs/shared", b"1")]),
            store_with(&[("blobs/b", b"1"), ("blobs/shared", b"1")]),
        );
        assert_eq!(
            chain.list_prefix("blobs/").unwrap(),
            vec![
                "blobs/a".to_string(),
                "blobs/b".to_string(),
                "blobs/shared".to_string()
            ]
        );
    }
}
