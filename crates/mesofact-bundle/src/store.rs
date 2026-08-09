//! The `store` surface (feature `store`): move a bundle between an assembled
//! on-disk tree and an object store, and cache materialized trees on a node.
//!
//! Two directions plus a cache:
//!
//! - [`publish_bundle`] — read an assembled `<bundle>/` tree and PUT every file
//!   as a content-addressed blob (`blobs/<blake3>`), append-only and deduped
//!   (an already-present blob is skipped), plus the manifest object keyed by the
//!   bundle digest. This is R2's floor: the release store.
//! - [`materialize_bundle`] — given a bundle digest, fetch the manifest, then
//!   every referenced blob, verify each against its recorded hash, and write the
//!   tree into a node cache dir. Idempotent and crash-safe (staging + atomic
//!   rename). This is the node-side cold path.
//! - [`BundleCache`] — an LRU-by-digest wrapper over a cache dir: materialize on
//!   miss, bump recency on hit, evict oldest bundles past a bytes budget.
//!
//! All three are synchronous over the sync [`ObjectStore`] trait, matching how
//! `R2ObjectStore` (reqwest blocking) is consumed — async callers wrap them in
//! `spawn_blocking`.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use yah_object_store::ObjectStore;

use crate::{blob_key, manifest_key, BundleError, BundleHash, BundleManifest};

/// The manifest file at a bundle root, and the completion marker for a
/// materialized tree.
const MANIFEST_FILENAME: &str = "manifest.toml";

/// Recency marker touched on every [`BundleCache::ensure`] — its mtime is the
/// LRU key. A plain file keeps the whole thing std-only (no filetime crate).
const ACCESS_MARKER: &str = ".accessed";

/// Outcome of a [`publish_bundle`] run.
#[derive(Debug, Clone)]
pub struct PublishReport {
    /// The bundle's content-address digest (manifest object key stem).
    pub digest: BundleHash,
    /// Blob keys freshly PUT this run.
    pub uploaded: Vec<String>,
    /// Blob keys skipped because the store already held them (append-only
    /// dedupe — the whole reason files are content-addressed).
    pub skipped: Vec<String>,
    /// Whether the manifest object was written (false when an identical bundle
    /// digest was already published — manifests are immutable by digest).
    pub manifest_uploaded: bool,
}

/// Publish an assembled bundle tree at `bundle_dir` to `store`.
///
/// Reads `<bundle_dir>/manifest.toml`, verifies each listed file hashes to its
/// recorded blake3, and PUTs the ones the store doesn't already hold. Finally
/// writes the manifest object under `manifests/<digest>` unless that digest is
/// already published. Append-only throughout: nothing is ever overwritten or
/// deleted.
pub fn publish_bundle(
    store: &dyn ObjectStore,
    bundle_dir: &Path,
) -> Result<PublishReport, BundleError> {
    let manifest_path = bundle_dir.join(MANIFEST_FILENAME);
    let manifest_text = fs::read_to_string(&manifest_path).map_err(io_ctx(&manifest_path))?;
    let manifest = BundleManifest::from_toml_str(&manifest_text)?;
    let digest = manifest.digest();

    let mut uploaded = Vec::new();
    let mut skipped = Vec::new();

    for (path, hash) in &manifest.content {
        let key = blob_key(hash);
        if store.head(&key).map_err(store_err)? {
            skipped.push(key);
            continue;
        }
        let rel = checked_rel(path)?;
        let file_path = bundle_dir.join(rel);
        let bytes = fs::read(&file_path).map_err(io_ctx(&file_path))?;
        let actual = BundleHash::of(&bytes);
        if &actual != hash {
            return Err(BundleError::HashMismatch {
                what: path.clone(),
                expected: hash.to_string(),
                actual: actual.to_string(),
            });
        }
        store.put(&key, bytes).map_err(store_err)?;
        uploaded.push(key);
    }

    // Manifest object, keyed by digest and immutable. Upload the canonically
    // re-serialized form (not the on-disk text) so what materialize parses is
    // exactly what produced the digest — comments/whitespace can't drift it.
    let mkey = manifest_key(&digest);
    let manifest_uploaded = if store.head(&mkey).map_err(store_err)? {
        false
    } else {
        let canonical = manifest.to_toml_string()?;
        store.put(&mkey, canonical.into_bytes()).map_err(store_err)?;
        true
    };

    Ok(PublishReport {
        digest,
        uploaded,
        skipped,
        manifest_uploaded,
    })
}

/// Materialize the bundle named by `digest` from `store` into
/// `<cache_dir>/bundles/<digest>/`, returning that path.
///
/// Idempotent: an already-materialized tree (its `manifest.toml` present) is
/// returned untouched. Otherwise the fetch runs into a `.staging-<digest>`
/// sibling and is atomically `rename`d into place, so a crash mid-fetch never
/// leaves a partial tree that the presence check would trust. Every blob and
/// the manifest itself are verified against their recorded hashes.
pub fn materialize_bundle(
    store: &dyn ObjectStore,
    cache_dir: &Path,
    digest: &BundleHash,
) -> Result<PathBuf, BundleError> {
    let bundles_dir = cache_dir.join("bundles");
    let dest = bundles_dir.join(digest.as_str());
    let dest_manifest = dest.join(MANIFEST_FILENAME);
    if dest_manifest.exists() {
        return Ok(dest);
    }

    // Fetch + verify the manifest.
    let mkey = manifest_key(digest);
    let manifest_bytes = store
        .get(&mkey)
        .map_err(store_err)?
        .ok_or_else(|| BundleError::MissingBlob {
            key: mkey.clone(),
            path: MANIFEST_FILENAME.to_string(),
        })?;
    let manifest_text = String::from_utf8(manifest_bytes)
        .map_err(|e| BundleError::Manifest(format!("manifest object not utf-8: {e}")))?;
    let manifest = BundleManifest::from_toml_str(&manifest_text)?;
    let actual_digest = manifest.digest();
    if &actual_digest != digest {
        // The store handed back a manifest that doesn't hash to the digest we
        // asked for — corruption or a key collision. Refuse it.
        return Err(BundleError::HashMismatch {
            what: mkey,
            expected: digest.to_string(),
            actual: actual_digest.to_string(),
        });
    }

    let staging = bundles_dir.join(format!(".staging-{}", digest.as_str()));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(io_ctx(&staging))?;
    }
    fs::create_dir_all(&staging).map_err(io_ctx(&staging))?;

    for (path, hash) in &manifest.content {
        let key = blob_key(hash);
        let bytes = store
            .get(&key)
            .map_err(store_err)?
            .ok_or_else(|| BundleError::MissingBlob {
                key: key.clone(),
                path: path.clone(),
            })?;
        let actual = BundleHash::of(&bytes);
        if &actual != hash {
            let _ = fs::remove_dir_all(&staging);
            return Err(BundleError::HashMismatch {
                what: path.clone(),
                expected: hash.to_string(),
                actual: actual.to_string(),
            });
        }
        let rel = checked_rel(path)?;
        let out = staging.join(rel);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(io_ctx(parent))?;
        }
        fs::write(&out, bytes).map_err(io_ctx(&out))?;
    }

    // Manifest written last — its presence is the "tree is complete" marker.
    let staged_manifest = staging.join(MANIFEST_FILENAME);
    fs::write(&staged_manifest, manifest_text.as_bytes()).map_err(io_ctx(&staged_manifest))?;

    fs::create_dir_all(&bundles_dir).map_err(io_ctx(&bundles_dir))?;
    // A concurrent materialize may have won the race while we staged. If dest
    // now exists, keep it and discard our staging copy.
    if dest_manifest.exists() {
        let _ = fs::remove_dir_all(&staging);
        return Ok(dest);
    }
    fs::rename(&staging, &dest).map_err(io_ctx(&dest))?;
    Ok(dest)
}

/// LRU-by-digest cache of materialized bundle trees under a bytes budget.
///
/// Bundles live at `<root>/bundles/<digest>/`. [`ensure`](BundleCache::ensure)
/// materializes on a miss, bumps recency on a hit, then evicts the
/// least-recently-ensured bundles until the cache is within `budget_bytes`
/// (never evicting the bundle it just ensured). A `budget_bytes` of 0 disables
/// eviction (unbounded cache).
pub struct BundleCache {
    root: PathBuf,
    budget_bytes: u64,
}

impl BundleCache {
    /// A cache rooted at `root` with the given byte budget (0 = unbounded).
    pub fn new(root: impl Into<PathBuf>, budget_bytes: u64) -> Self {
        Self {
            root: root.into(),
            budget_bytes,
        }
    }

    /// Ensure `digest` is materialized, return its path, and enforce the budget.
    pub fn ensure(
        &self,
        store: &dyn ObjectStore,
        digest: &BundleHash,
    ) -> Result<PathBuf, BundleError> {
        let path = materialize_bundle(store, &self.root, digest)?;
        touch_access(&path)?;
        if self.budget_bytes > 0 {
            self.evict_to_budget(digest)?;
        }
        Ok(path)
    }

    fn bundles_dir(&self) -> PathBuf {
        self.root.join("bundles")
    }

    /// Evict least-recently-ensured bundles until total size ≤ budget, never
    /// touching `keep` or in-flight `.staging-*` dirs.
    fn evict_to_budget(&self, keep: &BundleHash) -> Result<(), BundleError> {
        let dir = self.bundles_dir();
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io_ctx(&dir)(e)),
        };

        struct Entry {
            path: PathBuf,
            recency: u64,
            size: u64,
        }
        let mut entries = Vec::new();
        let mut total: u64 = 0;
        for de in rd {
            let de = de.map_err(io_ctx(&dir))?;
            let name = de.file_name();
            let name = name.to_string_lossy();
            // Skip in-flight staging trees and the just-ensured digest.
            if name.starts_with(".staging-") || name == keep.as_str() {
                // The kept bundle still counts toward the total (its bytes are
                // resident) — but is never itself a candidate.
                if name == keep.as_str() {
                    total += dir_size(&de.path());
                }
                continue;
            }
            if !de.path().is_dir() {
                continue;
            }
            let size = dir_size(&de.path());
            total += size;
            entries.push(Entry {
                recency: access_recency(&de.path()),
                path: de.path(),
                size,
            });
        }

        if total <= self.budget_bytes {
            return Ok(());
        }

        // Oldest first.
        entries.sort_by_key(|e| e.recency);
        for e in entries {
            if total <= self.budget_bytes {
                break;
            }
            fs::remove_dir_all(&e.path).map_err(io_ctx(&e.path))?;
            total = total.saturating_sub(e.size);
        }
        Ok(())
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Validate a bundle-internal path and return it as a relative `Path`.
///
/// Bundles may carry less-trusted content, so a path must not escape the bundle
/// root: reject absolute paths, `.`/`..` components, Windows drive prefixes, and
/// empty strings. Everything the manifest lists is written under (or read from)
/// the bundle dir and nowhere else.
fn checked_rel(path: &str) -> Result<PathBuf, BundleError> {
    if path.is_empty() {
        return Err(BundleError::Manifest("empty content path".to_string()));
    }
    let p = Path::new(path);
    for comp in p.components() {
        match comp {
            Component::Normal(_) => {}
            _ => {
                return Err(BundleError::Manifest(format!(
                    "unsafe content path {path:?} (must be relative, no '..' or absolute components)"
                )));
            }
        }
    }
    Ok(p.to_path_buf())
}

fn store_err(e: yah_object_store::Error) -> BundleError {
    BundleError::Io(e.to_string())
}

fn io_ctx(p: &Path) -> impl Fn(std::io::Error) -> BundleError + '_ {
    move |e| BundleError::Io(format!("{}: {e}", p.display()))
}

/// Touch the access marker inside a materialized bundle dir so its mtime tracks
/// last use. Best-effort: a failure here only degrades LRU accuracy.
fn touch_access(bundle_dir: &Path) -> Result<(), BundleError> {
    let marker = bundle_dir.join(ACCESS_MARKER);
    // Writing truncates + updates mtime; the byte is irrelevant.
    fs::write(&marker, b"1").map_err(io_ctx(&marker))
}

/// LRU recency key for a bundle dir: the access-marker mtime as epoch millis,
/// falling back to the dir's own mtime, then 0.
fn access_recency(bundle_dir: &Path) -> u64 {
    let marker = bundle_dir.join(ACCESS_MARKER);
    let mtime = fs::metadata(&marker)
        .or_else(|_| fs::metadata(bundle_dir))
        .and_then(|m| m.modified())
        .ok();
    mtime
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Total bytes of regular files under `dir` (recursive). Directories, symlinks,
/// and unreadable entries contribute 0 — a size estimate for eviction, not an
/// exact `du`.
fn dir_size(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for de in rd.flatten() {
            let Ok(ft) = de.file_type() else { continue };
            if ft.is_dir() {
                stack.push(de.path());
            } else if ft.is_file() {
                if let Ok(m) = de.metadata() {
                    total += m.len();
                }
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;
    use yah_object_store::InMemoryObjectStore;

    use crate::{BundleRuntime, SCHEMA_VERSION};

    /// Write an assembled bundle tree (manifest + files) into `dir` and return
    /// the manifest that describes it.
    fn write_bundle(dir: &Path, files: &[(&str, &[u8])], runtime: BundleRuntime) -> BundleManifest {
        let mut content = BTreeMap::new();
        for (path, bytes) in files {
            let full = dir.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, bytes).unwrap();
            content.insert(path.to_string(), BundleHash::of(bytes));
        }
        let manifest = BundleManifest {
            schema_version: SCHEMA_VERSION,
            name: "yah-marketing".to_string(),
            runtime,
            content,
        };
        fs::write(dir.join(MANIFEST_FILENAME), manifest.to_toml_string().unwrap()).unwrap();
        manifest
    }

    #[test]
    fn publish_then_materialize_round_trips() {
        let store = InMemoryObjectStore::new();
        let src = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();

        let manifest = write_bundle(
            src.path(),
            &[
                ("app/index.html", b"<html>home</html>"),
                ("app/dist/main.js", b"console.log(1)"),
            ],
            BundleRuntime::Mesofact { version: "0.8.18".into() },
        );
        let report = publish_bundle(&store, src.path()).unwrap();
        assert_eq!(report.digest, manifest.digest());
        assert_eq!(report.uploaded.len(), 2);
        assert!(report.skipped.is_empty());
        assert!(report.manifest_uploaded);

        let dest = materialize_bundle(&store, cache.path(), &manifest.digest()).unwrap();
        assert_eq!(
            fs::read(dest.join("app/index.html")).unwrap(),
            b"<html>home</html>"
        );
        assert_eq!(
            fs::read(dest.join("app/dist/main.js")).unwrap(),
            b"console.log(1)"
        );
        assert!(dest.join(MANIFEST_FILENAME).exists());
    }

    /// R703-T7 puts the first dot-directory entry into a bundle:
    /// `app/dist/html/.well-known/yah-publish.json`, the publish beacon the
    /// apex is checked against. `checked_rel` guards against `.` and `..`
    /// *components*, and a leading-dot filename is neither — but if that were
    /// ever tightened to a naive "no segment starts with a dot", publish would
    /// reject the bundle and, worse, a node would refuse to materialize one it
    /// had already accepted. Pin the round trip rather than the guard.
    #[test]
    fn a_dot_directory_entry_publishes_and_materializes() {
        let store = InMemoryObjectStore::new();
        let src = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let beacon = "app/dist/html/.well-known/yah-publish.json";

        let manifest = write_bundle(
            src.path(),
            &[
                ("app/dist/html/index.html", b"<html>home</html>"),
                (beacon, br#"{"prefix":"bundle/yah-marketing","files":1}"#),
            ],
            BundleRuntime::SelfContained,
        );
        let report = publish_bundle(&store, src.path()).unwrap();
        assert_eq!(report.uploaded.len(), 2);

        let dest = materialize_bundle(&store, cache.path(), &manifest.digest()).unwrap();
        assert_eq!(
            fs::read(dest.join(beacon)).unwrap(),
            br#"{"prefix":"bundle/yah-marketing","files":1}"#
        );
    }

    #[test]
    fn republish_dedupes_blobs_and_skips_manifest() {
        let store = InMemoryObjectStore::new();
        let src = TempDir::new().unwrap();
        write_bundle(
            src.path(),
            &[("app/index.html", b"same")],
            BundleRuntime::SelfContained,
        );

        let first = publish_bundle(&store, src.path()).unwrap();
        assert_eq!(first.uploaded.len(), 1);
        assert!(first.manifest_uploaded);

        // Second publish of the identical tree: blob + manifest already present.
        let second = publish_bundle(&store, src.path()).unwrap();
        assert!(second.uploaded.is_empty());
        assert_eq!(second.skipped.len(), 1);
        assert!(!second.manifest_uploaded);
        assert_eq!(first.digest, second.digest);
    }

    #[test]
    fn materialize_is_idempotent() {
        let store = InMemoryObjectStore::new();
        let src = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let m = write_bundle(src.path(), &[("app/x", b"y")], BundleRuntime::SelfContained);
        publish_bundle(&store, src.path()).unwrap();

        let a = materialize_bundle(&store, cache.path(), &m.digest()).unwrap();
        let b = materialize_bundle(&store, cache.path(), &m.digest()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn publish_rejects_hash_mismatch() {
        let store = InMemoryObjectStore::new();
        let src = TempDir::new().unwrap();
        let mut m = write_bundle(src.path(), &[("app/x", b"real")], BundleRuntime::SelfContained);
        // Corrupt the on-disk file so it no longer matches the manifest hash.
        fs::write(src.path().join("app/x"), b"tampered").unwrap();
        // Rewrite manifest.toml keeping the OLD (now-wrong) hash.
        m.content.insert("app/x".to_string(), BundleHash::of(b"real"));
        fs::write(src.path().join(MANIFEST_FILENAME), m.to_toml_string().unwrap()).unwrap();

        let err = publish_bundle(&store, src.path()).unwrap_err();
        assert!(matches!(err, BundleError::HashMismatch { .. }), "got {err:?}");
    }

    #[test]
    fn materialize_reports_missing_blob() {
        let store = InMemoryObjectStore::new();
        let src = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let m = write_bundle(src.path(), &[("app/x", b"y")], BundleRuntime::SelfContained);
        publish_bundle(&store, src.path()).unwrap();
        // Evict the blob from the store so materialize can't find it.
        store.delete(&blob_key(m.content.get("app/x").unwrap())).unwrap();

        let err = materialize_bundle(&store, cache.path(), &m.digest()).unwrap_err();
        assert!(matches!(err, BundleError::MissingBlob { .. }), "got {err:?}");
    }

    #[test]
    fn unsafe_paths_are_rejected() {
        assert!(checked_rel("../escape").is_err());
        assert!(checked_rel("/abs").is_err());
        assert!(checked_rel("a/../../b").is_err());
        assert!(checked_rel("").is_err());
        assert!(checked_rel("app/dist/main.js").is_ok());
    }

    #[test]
    fn cache_evicts_lru_past_budget() {
        let store = InMemoryObjectStore::new();
        let cache_dir = TempDir::new().unwrap();

        // Three ~1KB bundles; budget holds ~2 of them.
        let mut digests = Vec::new();
        for i in 0..3 {
            let src = TempDir::new().unwrap();
            let m = write_bundle(
                src.path(),
                &[("app/blob", vec![b'a' + i as u8; 1000].as_slice())],
                BundleRuntime::SelfContained,
            );
            publish_bundle(&store, src.path()).unwrap();
            digests.push(m.digest());
        }

        let cache = BundleCache::new(cache_dir.path(), 2500);
        // Ensure in order 0,1,2 with a recency gap so mtimes are distinct.
        for d in &digests {
            cache.ensure(&store, d).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let base = cache_dir.path().join("bundles");
        // Bundle 0 (oldest) evicted; 1 and 2 retained.
        assert!(!base.join(digests[0].as_str()).exists(), "oldest should be evicted");
        assert!(base.join(digests[1].as_str()).exists());
        assert!(base.join(digests[2].as_str()).exists());
    }

    #[test]
    fn cache_hit_bumps_recency_and_protects_from_eviction() {
        let store = InMemoryObjectStore::new();
        let cache_dir = TempDir::new().unwrap();
        let mut digests = Vec::new();
        for i in 0..3 {
            let src = TempDir::new().unwrap();
            let m = write_bundle(
                src.path(),
                &[("app/blob", vec![b'a' + i as u8; 1000].as_slice())],
                BundleRuntime::SelfContained,
            );
            publish_bundle(&store, src.path()).unwrap();
            digests.push(m.digest());
        }

        let cache = BundleCache::new(cache_dir.path(), 2500);
        cache.ensure(&store, &digests[0]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.ensure(&store, &digests[1]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Re-touch bundle 0 so it's now more recent than bundle 1.
        cache.ensure(&store, &digests[0]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Ensuring bundle 2 forces an eviction — bundle 1 (now LRU) should go.
        cache.ensure(&store, &digests[2]).unwrap();

        let base = cache_dir.path().join("bundles");
        assert!(base.join(digests[0].as_str()).exists(), "re-touched bundle survives");
        assert!(!base.join(digests[1].as_str()).exists(), "LRU bundle evicted");
        assert!(base.join(digests[2].as_str()).exists());
    }
}
