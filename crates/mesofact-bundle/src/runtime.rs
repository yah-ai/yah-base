//! The **node runtime-asset tier** (R746-F1, W272 §2/§7): the serve binary a
//! *vanilla* bundle does not carry.
//!
//! A self-contained bundle (`runtime = "self"`) closes over its own
//! `bins/<triple>/serve`, so its binary's bytes are covered by the bundle
//! digest and resolution is a path join. A vanilla bundle
//! (`runtime = "mesofact/<ver>"`) deliberately carries nothing — the whole
//! point is that one ~70MB V8-carrying binary is a **node-level** asset shared
//! by every site at that version, not a per-site blob re-uploaded and
//! re-downloaded per deploy. That trade only works if the node can *get* the
//! binary, which is what this module does. Until it existed, a vanilla bundle
//! assembled fine and then had nothing to exec.
//!
//! ```text
//! <cache>/bundles/<digest>/…                       # materialized bundle trees
//! <cache>/runtimes/mesofact/0.8.20/<triple>/serve   # stock runtime asset
//! <cache>/runtimes/acme/site/1.2.3/<triple>/serve   # namespaced CUSTOM runtime
//! <cache>/runtimes/almanac-feed/0.8.22/<triple>/almanac-feed   # a SIDECAR asset
//! ```
//!
//! **The tier is not serve-only** (R746-T3). One runtime ref names one binary,
//! whose filename the published manifest records — `serve` for a mesofact
//! runtime, `almanac-feed` for the feed-fetch sidecar. Before this, the feed
//! fetcher could only reach a node inside a self-contained bundle's `bins/`,
//! which meant a *vanilla* bundle with a feed tier still needed a cross-built
//! musl binary on the syncing machine. That single path was the last thing
//! standing between yah.dev and "a templates-only edit deploys from a laptop
//! with no Rust toolchain".
//!
//! **The path is namespaced from day one**, though nothing publishes a custom
//! runtime yet (W272 §7): custom runtimes cache exactly like stock ones, and
//! generalizing the key costs nothing while no node has written one to disk and
//! costs a fleet-wide migration afterwards. Stock is the unnamespaced case —
//! `mesofact/<ver>` is `<name>/<ver>`, `acme/site/1.2.3` is
//! `<namespace>/<name>/<ver>`. See [`RuntimeRef`].
//!
//! **Trust comes from the content address, not the transport.** The by-name key
//! (`runtimes/…/<triple>.toml`) resolves to a small published manifest naming
//! the binary's blake3; the bytes themselves come from the same
//! `blobs/<blake3>` namespace bundles use, and are verified against that hash
//! before anything is written where a fork could reach it. This is the property
//! the self-contained shape got for free from the bundle digest, and losing it
//! would make vanilla a strictly worse trust posture than the shape it
//! replaces. It also means the runtime asset dedupes against a self-contained
//! bundle carrying the identical binary — same bytes, same blob.
//!
//! Sharing the bundle store rather than inventing a second one is deliberate:
//! the node already reads it unauthenticated over plain HTTPS
//! ([`yah_object_store::HttpReadOnlyObjectStore`]), so a runtime asset needs no
//! new origin, no new credential, and no new cache-invalidation story.

use std::fmt;
use std::path::PathBuf;

use crate::BundleError;

/// A runtime the node resolves by *name*, as opposed to `runtime = "self"`
/// which resolves inside the bundle.
///
/// Wire form is slash-separated, either `<name>/<version>` (stock, e.g.
/// `mesofact/0.8.20`) or `<namespace>/<name>/<version>` (a custom runtime
/// published under an org/project, e.g. `acme/site/1.2.3`). The namespace is
/// what keeps two orgs' `site` runtimes from colliding in one node cache.
///
/// This parses the *general* form even though [`BundleRuntime::parse`] accepts
/// only `mesofact/<ver>` today: the node cache layout is the thing that is
/// expensive to change later (bytes on disk across a fleet), the manifest field
/// is not. Accepting a namespaced ref here early is forward-compatible and
/// unreachable in practice until a manifest can express one — R746-F6 versioned
/// the contract such an expression would range over, but left the field itself
/// a single runtime name (W272 §7).
///
/// [`BundleRuntime::parse`]: crate::BundleRuntime::parse
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuntimeRef {
    namespace: Option<String>,
    name: String,
    version: String,
}

impl RuntimeRef {
    /// Parse the wire form (`<name>/<ver>` or `<ns>/<name>/<ver>`).
    ///
    /// Every segment is validated to `[A-Za-z0-9._+-]+` and rejected if it is
    /// `.` or `..`. That is not decoration: these segments are joined onto a
    /// node's cache directory, so a permissive parse would let a published
    /// manifest name a write target outside the cache. Same reasoning as
    /// `store::checked_rel` for bundle content paths.
    pub fn parse(s: &str) -> Result<Self, BundleError> {
        let segments: Vec<&str> = s.split('/').collect();
        let (namespace, name, version) = match segments.as_slice() {
            [name, version] => (None, *name, *version),
            [ns, name, version] => (Some(*ns), *name, *version),
            _ => {
                return Err(BundleError::Runtime(format!(
                    "{s:?} is not a resolvable runtime reference (expected \
                     \"<name>/<version>\" or \"<namespace>/<name>/<version>\"; \
                     \"self\" is resolved inside the bundle, not here)"
                )))
            }
        };
        for seg in namespace.into_iter().chain([name, version]) {
            check_segment(seg, s)?;
        }
        Ok(Self {
            namespace: namespace.map(str::to_string),
            name: name.to_string(),
            version: version.to_string(),
        })
    }

    /// Publishing namespace (`None` for a stock runtime).
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Runtime name, e.g. `mesofact`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Exact runtime version, e.g. `0.8.20`.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The wire string this was parsed from.
    pub fn as_wire(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{ns}/{}/{}", self.name, self.version),
            None => format!("{}/{}", self.name, self.version),
        }
    }

    /// Cache-relative path to the binary named `bin`:
    /// `runtimes/[<ns>/]<name>/<ver>/<triple>/<bin>`.
    ///
    /// `bin` is a bare filename, never a path — it comes from a published
    /// manifest, and joining an unchecked one onto the cache dir would be the
    /// same write-outside-the-cache primitive [`RuntimeRef::parse`] exists to
    /// deny. Callers pass a compile-time constant ([`SERVE_BIN`],
    /// kamaji's `FEED_BIN_NAME`); [`check_bin_name`] enforces it for the
    /// manifest-supplied side.
    pub fn cache_rel_bin(&self, triple: &str, bin: &str) -> PathBuf {
        self.cache_rel_dir(triple).join(bin)
    }

    /// Cache-relative directory holding this runtime's binaries for `triple`:
    /// `runtimes/[<ns>/]<name>/<ver>/<triple>`.
    pub fn cache_rel_dir(&self, triple: &str) -> PathBuf {
        let mut p = PathBuf::from("runtimes");
        if let Some(ns) = &self.namespace {
            p.push(ns);
        }
        p.push(&self.name);
        p.push(&self.version);
        p.push(triple);
        p
    }

    /// Cache-relative path to the serve binary:
    /// `runtimes/[<ns>/]<name>/<ver>/<triple>/serve`. The [`SERVE_BIN`] case of
    /// [`cache_rel_bin`](Self::cache_rel_bin).
    pub fn cache_rel_serve(&self, triple: &str) -> PathBuf {
        self.cache_rel_bin(triple, SERVE_BIN)
    }

    /// Object-store key *prefix* every published asset manifest for this
    /// runtime sits directly under: `runtimes/[<ns>/]<name>/<ver>/`.
    ///
    /// The trailing slash is load-bearing — without it `mesofact/0.8.2` would
    /// list `mesofact/0.8.20`'s assets too. Entries below it are
    /// `<triple>.toml` and nothing else, so a listed key with a further `/` in
    /// it belongs to some other ref and is not this runtime's.
    pub fn asset_manifest_prefix(&self) -> String {
        let mut key = String::from("runtimes/");
        if let Some(ns) = &self.namespace {
            key.push_str(ns);
            key.push('/');
        }
        key.push_str(&self.name);
        key.push('/');
        key.push_str(&self.version);
        key.push('/');
        key
    }

    /// Object-store key of the published asset manifest for `triple`:
    /// `runtimes/[<ns>/]<name>/<ver>/<triple>.toml`.
    ///
    /// By *name*, not by content — this is the one mutable-shaped key in the
    /// scheme, and it is what turns "mesofact/0.8.20 on x86_64 musl" into a
    /// blake3 the node can then verify bytes against.
    pub fn asset_manifest_key(&self, triple: &str) -> String {
        let mut key = String::from("runtimes/");
        if let Some(ns) = &self.namespace {
            key.push_str(ns);
            key.push('/');
        }
        key.push_str(&self.name);
        key.push('/');
        key.push_str(&self.version);
        key.push('/');
        key.push_str(triple);
        key.push_str(".toml");
        key
    }
}

impl fmt::Display for RuntimeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_wire())
    }
}

/// Filename of a mesofact runtime's binary inside a resolved runtime-asset
/// directory. Mirrors `bins/<triple>/serve` in a self-contained bundle so the
/// two arms of resolution hand the same shape to the fork.
pub const SERVE_BIN: &str = "serve";

/// Reject a binary name that is anything other than a plain filename.
///
/// Applied to the *manifest-supplied* name in [`ensure_runtime_asset`]: a
/// published manifest is remote input, and its `bin` field is joined onto the
/// node's cache dir. Same reasoning — and the same character class — as
/// [`RuntimeRef::parse`]'s segment check.
pub fn check_bin_name(bin: &str) -> Result<(), BundleError> {
    check_segment(bin, bin).map_err(|_| {
        BundleError::Runtime(format!(
            "runtime asset binary name {bin:?} is not a plain filename \
             (must be non-empty [A-Za-z0-9._+-] and never \".\" or \"..\")"
        ))
    })
}

/// Reject anything that isn't a plain, path-safe identifier segment.
fn check_segment(seg: &str, whole: &str) -> Result<(), BundleError> {
    let ok = !seg.is_empty()
        && seg != "."
        && seg != ".."
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'));
    if ok {
        return Ok(());
    }
    Err(BundleError::Runtime(format!(
        "runtime reference {whole:?} has an unusable segment {seg:?} \
         (segments must be non-empty [A-Za-z0-9._+-] and never \".\" or \"..\")"
    )))
}

#[cfg(feature = "store")]
pub use asset::{
    ensure_runtime_asset, publish_runtime_asset, published_runtime_assets, require_runtime_contract,
    PublishedRuntime, RuntimeAsset, RuntimeAssetManifest, RUNTIME_ASSET_SCHEMA_VERSION,
};

/// Runtime ref + binary name for the almanac feed-fetch sidecar (R746-T3).
///
/// The fetcher is versioned with yubaba, so it gets its own unnamespaced
/// runtime ref (`almanac-feed/<ver>`) rather than riding the mesofact runtime's.
pub const FEED_BIN: &str = "almanac-feed";

#[cfg(feature = "store")]
mod asset {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde::{Deserialize, Serialize};
    use yah_object_store::ObjectStore;

    use super::{check_bin_name, RuntimeRef};
    use crate::contract::{describe_contracts, ContractRequirement, ContractVersion};
    use crate::store::{io_ctx, store_err, touch_access};
    use crate::{blob_key, BundleError, BundleHash};

    /// Wire version of the runtime-asset manifest. Separate from the bundle
    /// manifest's [`SCHEMA_VERSION`](crate::SCHEMA_VERSION): they version
    /// independent objects and a node speaking one may not speak the other.
    pub const RUNTIME_ASSET_SCHEMA_VERSION: u32 = 1;

    /// The small published object at `runtimes/…/<triple>.toml` — the by-name
    /// pointer into the content-addressed blob space.
    ///
    /// ```toml
    /// schema_version = 1
    /// runtime  = "mesofact/0.8.20"
    /// triple   = "x86_64-unknown-linux-musl"
    /// bin      = "serve"   # filename the bytes land under in the node cache
    /// contract = [1]       # bundle↔runtime contract versions this binary implements
    /// serve    = "9f3c…"   # blake3 of that binary, in blobs/<blake3>
    /// ```
    ///
    /// It carries `runtime` and `triple` redundantly with its own key on
    /// purpose: a node checks them against what it asked for, so an asset
    /// misfiled under the wrong version (a publish-script bug, a copy-paste in
    /// a pipeline) is caught by the fetcher instead of becoming a site served
    /// by the wrong binary. `bin` is checked the same way, which is what makes
    /// a sidecar asset (`almanac-feed`) safe to resolve through the same tier.
    ///
    /// **One ref, one binary.** The key is per (runtime × triple), so a runtime
    /// that shipped two executables would need two refs — which is the right
    /// shape anyway: `almanac-feed` is versioned with yubaba, not with
    /// mesofact, and pretending otherwise would tie their release cadences
    /// together for no reason.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RuntimeAssetManifest {
        /// Wire-format version. Always [`RUNTIME_ASSET_SCHEMA_VERSION`] today.
        pub schema_version: u32,
        /// The runtime this asset is for, in [`RuntimeRef`] wire form.
        pub runtime: String,
        /// Target triple these bytes were built for.
        pub triple: String,
        /// Filename these bytes are written under in the node's runtime cache,
        /// and the name a resolver asks for. `serve` for a mesofact runtime.
        ///
        /// Defaulted rather than required so a manifest published before the
        /// field existed still parses as the serve-only case it was.
        #[serde(default = "default_bin")]
        pub bin: String,
        /// Bundle↔runtime contract versions this binary implements (R746-F6).
        /// The **advertisement** half of the contract: a bundle requiring a
        /// version absent from this list is refused rather than served.
        ///
        /// Defaulted to `[1]` for a manifest published before the field
        /// existed — every such binary predates the second contract version by
        /// construction, so claiming 1 is a statement of fact, not an
        /// optimistic guess.
        #[serde(default = "default_contract")]
        pub contract: Vec<ContractVersion>,
        /// BLAKE3 of the binary; its blob lives at `blobs/<serve>`.
        pub serve: BundleHash,
    }

    fn default_bin() -> String {
        super::SERVE_BIN.to_string()
    }

    fn default_contract() -> Vec<ContractVersion> {
        vec![1]
    }

    impl RuntimeAssetManifest {
        /// Parse a published asset manifest, rejecting an unknown schema version.
        pub fn from_toml_str(s: &str) -> Result<Self, BundleError> {
            let m: RuntimeAssetManifest =
                toml::from_str(s).map_err(|e| BundleError::Manifest(e.to_string()))?;
            if m.schema_version != RUNTIME_ASSET_SCHEMA_VERSION {
                return Err(BundleError::SchemaVersion {
                    found: m.schema_version,
                });
            }
            Ok(m)
        }

        /// Serialize to the published TOML form.
        pub fn to_toml_string(&self) -> Result<String, BundleError> {
            toml::to_string_pretty(self).map_err(|e| BundleError::Manifest(e.to_string()))
        }
    }

    /// Outcome of [`publish_runtime_asset`].
    #[derive(Debug, Clone)]
    pub struct RuntimeAsset {
        /// The published manifest.
        pub manifest: RuntimeAssetManifest,
        /// Key of the manifest object.
        pub manifest_key: String,
        /// Key of the binary blob.
        pub blob_key: String,
        /// False when the store already held the binary's bytes — the whole
        /// point of sharing `blobs/` with bundles. A patch release that did not
        /// change the serve binary uploads nothing.
        pub blob_uploaded: bool,
    }

    /// Publish `serve_bin` as the runtime asset for `runtime` × `triple`,
    /// landing on the node under the filename `bin`
    /// ([`SERVE_BIN`](crate::SERVE_BIN) for a mesofact runtime;
    /// `almanac-feed` for the feed-fetch sidecar).
    ///
    /// PUTs the binary at `blobs/<blake3>` (skipped when already present, the
    /// same append-only dedupe `publish_bundle` uses) and the naming manifest at
    /// `runtimes/…/<triple>.toml`. The manifest key is by-name and therefore
    /// overwritable: re-publishing the same version with different bytes is a
    /// *repoint*, which is exactly what a re-cut release is. Nodes that already
    /// cached the old bytes keep them — the cache is keyed by name, so a repoint
    /// only reaches nodes that had not fetched it yet. Publish under a new
    /// version rather than repointing one that is live.
    ///
    /// `contract` is the set of bundle↔runtime contract versions **these bytes**
    /// implement (R746-F6). It is a required parameter and not derived from
    /// [`IMPLEMENTED_CONTRACTS`](crate::IMPLEMENTED_CONTRACTS) here on purpose:
    /// this function publishes a binary that was almost always cross-built
    /// somewhere else, so the publishing process's own constant is a statement
    /// about the wrong tree. The CLI defaults the flag to that constant — which
    /// is right when the binary came from this tree, and wrong silently
    /// otherwise, so the honest place for the assumption is one layer up where
    /// an operator can override it.
    pub fn publish_runtime_asset(
        store: &dyn ObjectStore,
        runtime: &RuntimeRef,
        triple: &str,
        bin: &str,
        contract: &[ContractVersion],
        serve_bin: &Path,
    ) -> Result<RuntimeAsset, BundleError> {
        check_bin_name(bin)?;
        if contract.is_empty() {
            return Err(BundleError::Manifest(format!(
                "refusing to publish {} as {runtime}/{triple} advertising no contract version at \
                 all — nothing could ever resolve it",
                serve_bin.display()
            )));
        }
        let bytes = fs::read(serve_bin).map_err(io_ctx(serve_bin))?;
        let hash = BundleHash::of(&bytes);
        let bkey = blob_key(&hash);
        let blob_uploaded = if store.head(&bkey).map_err(store_err)? {
            false
        } else {
            store.put(&bkey, bytes).map_err(store_err)?;
            true
        };

        let manifest = RuntimeAssetManifest {
            schema_version: RUNTIME_ASSET_SCHEMA_VERSION,
            runtime: runtime.as_wire(),
            triple: triple.to_string(),
            bin: bin.to_string(),
            contract: contract.to_vec(),
            serve: hash,
        };
        let mkey = runtime.asset_manifest_key(triple);
        store
            .put(&mkey, manifest.to_toml_string()?.into_bytes())
            .map_err(store_err)?;

        Ok(RuntimeAsset {
            manifest,
            manifest_key: mkey,
            blob_key: bkey,
            blob_uploaded,
        })
    }

    /// Resolve the binary named `bin` for `runtime` × `triple` under
    /// `cache_dir`, fetching and verifying it from `store` on a miss. Returns
    /// the executable path.
    ///
    /// `bin` is the caller's *expectation* — a compile-time constant at every
    /// call site — and the published manifest's own `bin` is checked against
    /// it, exactly as `runtime` and `triple` are. That is what keeps the
    /// cache-hit fast path possible: the resolver knows the filename before it
    /// has fetched anything, so a warm resolve touches the network zero times.
    ///
    /// Resolution is **purely** `<cache_dir>/runtimes/…/<bin>`: no `PATH`
    /// lookup, no scan for a plausible binary elsewhere on the box, no reuse of
    /// another bundle's `bins/`. A node that cannot fetch the named version
    /// fails the deploy — serving a site with a binary nobody named is a worse
    /// outcome than not serving it, because it succeeds silently.
    ///
    /// A cache hit returns immediately without re-hashing: the fetch verifies
    /// before an atomic rename, so a file visible at the final path was already
    /// checked, and re-blake3-ing ~70MB on every deploy buys nothing against a
    /// threat model where an attacker who can write the cache dir can also
    /// write the process that reads it.
    ///
    /// **Not evicted by [`BundleCache`](crate::BundleCache).** Runtime assets
    /// live outside `bundles/`, so the bundle LRU neither counts nor reclaims
    /// them — deliberately: one asset backs every resident serve process at that
    /// version, and evicting it under a bundle-shaped budget would break the
    /// next restart of sites that had nothing to do with the deploy that
    /// tripped the budget. An access marker is touched on every resolve so a
    /// future runtime-tier reclaim has recency to work from.
    pub fn ensure_runtime_asset(
        store: &dyn ObjectStore,
        cache_dir: &Path,
        runtime: &RuntimeRef,
        triple: &str,
        bin: &str,
        requires: ContractRequirement,
    ) -> Result<PathBuf, BundleError> {
        check_bin_name(bin)?;
        let dir = cache_dir.join(runtime.cache_rel_dir(triple));
        let dest = dir.join(bin);
        if dest.is_file() {
            // A cache hit skips the contract check along with the re-hash.
            // Checking it would cost a manifest GET on every warm resolve,
            // which is precisely the network round-trip the shared runtime
            // tier exists to avoid (see `a_second_resolve_at_the_same_version_
            // is_a_cache_hit`), and it would buy nothing: the advertised set is
            // a property of the ref, and the ref is the cache path.
            //
            // The one case it would catch is a live version REPOINTED to bytes
            // advertising a different set — already documented as the thing not
            // to do (`publish_runtime_asset`: publish a new version instead),
            // and already able to serve stale bytes for reasons that have
            // nothing to do with contracts.
            let _ = touch_access(&dir);
            return Ok(dest);
        }

        // By-name pointer → blake3.
        let mkey = runtime.asset_manifest_key(triple);
        let manifest_bytes = store
            .get(&mkey)
            .map_err(store_err)?
            .ok_or_else(|| BundleError::RuntimeAssetMissing {
                runtime: runtime.as_wire(),
                triple: triple.to_string(),
                location: store.locate(&mkey),
            })?;
        let manifest_text = String::from_utf8(manifest_bytes).map_err(|e| {
            BundleError::Manifest(format!("runtime asset manifest {mkey} not utf-8: {e}"))
        })?;
        let manifest = RuntimeAssetManifest::from_toml_str(&manifest_text)?;
        if manifest.runtime != runtime.as_wire() || manifest.triple != triple {
            return Err(BundleError::Manifest(format!(
                "runtime asset at {mkey} declares {}/{} but was published under {}/{triple} \
                 — refusing to serve a bundle with a binary built for something else",
                manifest.runtime,
                manifest.triple,
                runtime.as_wire(),
            )));
        }
        if manifest.bin != bin {
            return Err(BundleError::Manifest(format!(
                "runtime asset at {mkey} publishes the binary {:?} but {} was asked for \
                 {bin:?} — refusing to fork a binary under a name it was not published as",
                manifest.bin,
                runtime.as_wire(),
            )));
        }
        // R746-F6: the contract check, and the last one before bytes are
        // fetched. An apply-time gate is the primary enforcement point — this
        // is the backstop for the paths that don't go through one (a node
        // restarting a workload deployed before the gate existed, a hand-rolled
        // deploy), and it fails before a ~70MB download rather than after.
        if !requires.satisfied_by(&manifest.contract) {
            let ContractRequirement::Version(required) = requires else {
                unreachable!("Unchecked is satisfied by every advertised set")
            };
            return Err(BundleError::ContractUnsatisfied {
                runtime: runtime.as_wire(),
                triple: triple.to_string(),
                required,
                advertised: describe_contracts(&manifest.contract),
            });
        }

        // Content address → bytes, verified before they land anywhere forkable.
        let bkey = blob_key(&manifest.serve);
        let bytes = store
            .get(&bkey)
            .map_err(store_err)?
            .ok_or_else(|| BundleError::MissingBlob {
                key: store.locate(&bkey),
                path: format!("{}/{triple}/{bin}", runtime.as_wire()),
            })?;
        let actual = BundleHash::of(&bytes);
        if actual != manifest.serve {
            return Err(BundleError::HashMismatch {
                what: format!("runtime asset {}/{triple}", runtime.as_wire()),
                expected: manifest.serve.to_string(),
                actual: actual.to_string(),
            });
        }

        // Stage beside the destination and rename: the final path is never
        // visible holding a partial or unverified binary, and two concurrent
        // deploys of the same version race harmlessly (both wrote identical,
        // verified bytes).
        fs::create_dir_all(&dir).map_err(io_ctx(&dir))?;
        let staging = dir.join(format!(".staging-{}", manifest.serve.as_str()));
        fs::write(&staging, &bytes).map_err(io_ctx(&staging))?;
        set_executable(&staging)?;
        fs::rename(&staging, &dest).map_err(io_ctx(&dest))?;
        let _ = touch_access(&dir);
        Ok(dest)
    }

    /// One published runtime asset, as [`published_runtime_assets`] found it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PublishedRuntime {
        /// Target triple the asset was published for.
        pub triple: String,
        /// Bundle↔runtime contract versions it advertises.
        pub contract: Vec<ContractVersion>,
    }

    /// Every asset published for `runtime`, one per triple, sorted by triple.
    ///
    /// A manifest under the prefix that fails to parse is an error rather than
    /// a skipped row: this backs an apply-time gate, and a gate that quietly
    /// ignores the manifests it cannot read reports "all clear" for a store it
    /// never actually surveyed.
    pub fn published_runtime_assets(
        store: &dyn ObjectStore,
        runtime: &RuntimeRef,
    ) -> Result<Vec<PublishedRuntime>, BundleError> {
        let prefix = runtime.asset_manifest_prefix();
        let mut out = Vec::new();
        for key in store.list_prefix(&prefix).map_err(store_err)? {
            let Some(rest) = key.strip_prefix(&prefix) else {
                continue;
            };
            // Only this ref's own `<triple>.toml` rows — see asset_manifest_prefix.
            let Some(triple) = rest.strip_suffix(".toml") else {
                continue;
            };
            if triple.contains('/') || triple.is_empty() {
                continue;
            }
            let bytes = store.get(&key).map_err(store_err)?.ok_or_else(|| {
                // Listed and then gone: a concurrent delete, or a store whose
                // listing lies. Either way this is not a runtime we can vouch for.
                BundleError::Manifest(format!("runtime asset {key} was listed but could not be read"))
            })?;
            let text = String::from_utf8(bytes).map_err(|e| {
                BundleError::Manifest(format!("runtime asset manifest {key} not utf-8: {e}"))
            })?;
            let manifest = RuntimeAssetManifest::from_toml_str(&text)?;
            out.push(PublishedRuntime {
                triple: triple.to_string(),
                contract: manifest.contract,
            });
        }
        out.sort_by(|a, b| a.triple.cmp(&b.triple));
        Ok(out)
    }

    /// **The apply-time contract gate** (R746-F6). Refuse to deploy a bundle
    /// requiring contract `required` when a published asset for `runtime`
    /// cannot serve it, naming both versions.
    ///
    /// Returns the triples that *can*, so the caller can report what the deploy
    /// is actually resolvable on.
    ///
    /// Two deliberate choices:
    ///
    /// * **An unsatisfied triple fails the whole apply**, even if the machines
    ///   this deploy targets run a different one. One runtime ref is one
    ///   release; a version published with mixed contract sets across triples
    ///   is a publishing bug, and letting it through means the next site
    ///   placed on the odd node out fails on that node instead — at serve
    ///   time, on a machine nobody is watching, which is the exact failure this
    ///   gate exists to move earlier.
    /// * **Nothing published at all is `Ok(vec![])`, not an error.** That case
    ///   is [`BundleError::RuntimeAssetMissing`]'s (R746-F1) and it already
    ///   names the version and the location it looked; re-reporting it here as
    ///   a contract failure would send an operator hunting for a mismatch that
    ///   doesn't exist. The caller decides how loud an empty survey is.
    pub fn require_runtime_contract(
        store: &dyn ObjectStore,
        runtime: &RuntimeRef,
        required: ContractVersion,
    ) -> Result<Vec<String>, BundleError> {
        let published = published_runtime_assets(store, runtime)?;
        let requirement = ContractRequirement::Version(required);
        for asset in &published {
            if !requirement.satisfied_by(&asset.contract) {
                return Err(BundleError::ContractUnsatisfied {
                    runtime: runtime.as_wire(),
                    triple: asset.triple.clone(),
                    required,
                    advertised: describe_contracts(&asset.contract),
                });
            }
        }
        Ok(published.into_iter().map(|a| a.triple).collect())
    }

    /// Mark a staged runtime binary executable before it becomes visible.
    #[cfg(unix)]
    fn set_executable(path: &Path) -> Result<(), BundleError> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).map_err(io_ctx(path))?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).map_err(io_ctx(path))
    }

    #[cfg(not(unix))]
    fn set_executable(_path: &Path) -> Result<(), BundleError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stock_is_the_unnamespaced_case_and_custom_is_namespaced() {
        let stock = RuntimeRef::parse("mesofact/0.8.20").unwrap();
        assert_eq!(stock.namespace(), None);
        assert_eq!(stock.name(), "mesofact");
        assert_eq!(stock.version(), "0.8.20");
        assert_eq!(stock.as_wire(), "mesofact/0.8.20");

        let custom = RuntimeRef::parse("acme/site/1.2.3").unwrap();
        assert_eq!(custom.namespace(), Some("acme"));
        assert_eq!(custom.name(), "site");
        assert_eq!(custom.version(), "1.2.3");
        assert_eq!(custom.as_wire(), "acme/site/1.2.3");
    }

    /// The layout this ticket commits a fleet to. Changing it after nodes have
    /// written to disk is a migration, so pin both arms.
    #[test]
    fn cache_layout_is_namespace_name_version_triple() {
        let triple = "x86_64-unknown-linux-musl";
        assert_eq!(
            RuntimeRef::parse("mesofact/0.8.20")
                .unwrap()
                .cache_rel_serve(triple),
            PathBuf::from("runtimes/mesofact/0.8.20/x86_64-unknown-linux-musl/serve")
        );
        assert_eq!(
            RuntimeRef::parse("acme/site/1.2.3")
                .unwrap()
                .cache_rel_serve(triple),
            PathBuf::from("runtimes/acme/site/1.2.3/x86_64-unknown-linux-musl/serve")
        );
        assert_eq!(
            RuntimeRef::parse("mesofact/0.8.20")
                .unwrap()
                .asset_manifest_key(triple),
            "runtimes/mesofact/0.8.20/x86_64-unknown-linux-musl.toml"
        );
    }

    /// These segments are joined onto a node's cache dir, so a permissive parse
    /// is a write-outside-the-cache primitive handed to whoever publishes a
    /// manifest.
    #[test]
    fn traversal_and_junk_segments_are_rejected() {
        assert!(RuntimeRef::parse("mesofact/../../etc").is_err());
        assert!(RuntimeRef::parse("../mesofact/0.1.0").is_err());
        assert!(RuntimeRef::parse("mesofact/.").is_err());
        assert!(RuntimeRef::parse("mesofact/").is_err());
        assert!(RuntimeRef::parse("/0.1.0").is_err());
        assert!(RuntimeRef::parse("a/b/c/d").is_err());
        assert!(RuntimeRef::parse("mesofact").is_err());
        // `self` is resolved inside the bundle and must never reach this path.
        assert!(RuntimeRef::parse("self").is_err());
        // A whitespace or shell-metacharacter segment can't become a path.
        assert!(RuntimeRef::parse("mesofact/0.8 20").is_err());
        assert!(RuntimeRef::parse("mesofact/$(id)").is_err());
    }

    #[cfg(feature = "store")]
    mod asset {
        use super::*;
        use crate::runtime::{
            ensure_runtime_asset, publish_runtime_asset, published_runtime_assets,
            require_runtime_contract, PublishedRuntime, RuntimeAssetManifest,
        };
        use crate::{
            blob_key, BundleError, BundleHash, ContractRequirement, ContractVersion,
            BUNDLE_CONTRACT_VERSION, IMPLEMENTED_CONTRACTS,
        };
        use tempfile::TempDir;
        use yah_object_store::{InMemoryObjectStore, ObjectStore};

        const TRIPLE: &str = "x86_64-unknown-linux-musl";
        /// What a stock runtime built from this tree advertises.
        const V1: &[ContractVersion] = IMPLEMENTED_CONTRACTS;
        /// What a bundle assembled by this tree requires.
        const REQ1: ContractRequirement = ContractRequirement::Version(BUNDLE_CONTRACT_VERSION);

        fn write_bin(dir: &TempDir, bytes: &[u8]) -> std::path::PathBuf {
            let p = dir.path().join("mesofact-serve");
            std::fs::write(&p, bytes).unwrap();
            p
        }

        #[test]
        fn publish_then_resolve_round_trips_and_lands_executable() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.20").unwrap();

            let published =
                publish_runtime_asset(&store, &rref, TRIPLE, SERVE_BIN, V1, &write_bin(&src, b"ELF serve")).unwrap();
            assert!(published.blob_uploaded);

            let resolved = ensure_runtime_asset(&store, cache.path(), &rref, TRIPLE, SERVE_BIN, REQ1).unwrap();
            assert_eq!(
                resolved,
                cache.path().join("runtimes/mesofact/0.8.20").join(TRIPLE).join("serve")
            );
            assert_eq!(std::fs::read(&resolved).unwrap(), b"ELF serve");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&resolved).unwrap().permissions().mode();
                assert!(mode & 0o111 != 0, "a runtime asset must land forkable, mode={mode:o}");
            }
        }

        /// The sharing property the vanilla shape exists for: a second site at
        /// the same runtime version fetches nothing. A per-bundle copy would be
        /// the self-contained shape wearing a different manifest.
        #[test]
        fn a_second_resolve_at_the_same_version_is_a_cache_hit() {
            struct CountingStore {
                inner: InMemoryObjectStore,
                gets: std::sync::atomic::AtomicUsize,
            }
            impl ObjectStore for CountingStore {
                fn put(&self, key: &str, data: Vec<u8>) -> Result<(), yah_object_store::Error> {
                    self.inner.put(key, data)
                }
                fn get(&self, key: &str) -> Result<Option<Vec<u8>>, yah_object_store::Error> {
                    self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    self.inner.get(key)
                }
                fn delete(&self, key: &str) -> Result<(), yah_object_store::Error> {
                    self.inner.delete(key)
                }
                fn list_prefix(&self, p: &str) -> Result<Vec<String>, yah_object_store::Error> {
                    self.inner.list_prefix(p)
                }
            }

            let store = CountingStore {
                inner: InMemoryObjectStore::new(),
                gets: std::sync::atomic::AtomicUsize::new(0),
            };
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.20").unwrap();
            publish_runtime_asset(&store, &rref, TRIPLE, SERVE_BIN, V1, &write_bin(&src, b"ELF serve")).unwrap();

            ensure_runtime_asset(&store, cache.path(), &rref, TRIPLE, SERVE_BIN, REQ1).unwrap();
            let after_cold = store.gets.load(std::sync::atomic::Ordering::SeqCst);
            assert!(after_cold >= 2, "cold resolve fetches manifest + blob");

            // Second site, same node, same runtime version.
            ensure_runtime_asset(&store, cache.path(), &rref, TRIPLE, SERVE_BIN, REQ1).unwrap();
            assert_eq!(
                store.gets.load(std::sync::atomic::Ordering::SeqCst),
                after_cold,
                "a second bundle at the same runtime version must fetch nothing"
            );
        }

        /// Two versions are two assets; resolving one must not satisfy the other.
        #[test]
        fn versions_do_not_alias() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let old = RuntimeRef::parse("mesofact/0.8.19").unwrap();
            let new = RuntimeRef::parse("mesofact/0.8.20").unwrap();
            publish_runtime_asset(&store, &old, TRIPLE, SERVE_BIN, V1, &write_bin(&src, b"old serve")).unwrap();
            ensure_runtime_asset(&store, cache.path(), &old, TRIPLE, SERVE_BIN, REQ1).unwrap();

            // 0.8.20 was never published — the cached 0.8.19 must not stand in.
            let err = ensure_runtime_asset(&store, cache.path(), &new, TRIPLE, SERVE_BIN, REQ1).unwrap_err();
            assert!(
                matches!(err, BundleError::RuntimeAssetMissing { .. }),
                "got {err:?}"
            );
        }

        /// Verify #2: an unfetchable version fails loudly, naming the version
        /// and where it looked, and falls back to nothing.
        #[test]
        fn an_unpublished_version_fails_naming_version_and_location() {
            let store = InMemoryObjectStore::new();
            let cache = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/9.9.9").unwrap();

            let err = ensure_runtime_asset(&store, cache.path(), &rref, TRIPLE, SERVE_BIN, REQ1).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("mesofact/9.9.9"), "got {msg}");
            assert!(msg.contains(TRIPLE), "got {msg}");
            assert!(
                msg.contains("runtimes/mesofact/9.9.9/x86_64-unknown-linux-musl.toml"),
                "the message must name what it looked for, got {msg}"
            );
            assert!(
                !cache.path().join("runtimes").exists(),
                "a failed resolve must not leave a partial runtime dir"
            );
        }

        /// The trust property vanilla must not lose relative to a self-contained
        /// bundle, whose binary is covered by the bundle digest.
        #[test]
        fn tampered_bytes_are_refused_and_never_written() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.20").unwrap();
            let published =
                publish_runtime_asset(&store, &rref, TRIPLE, SERVE_BIN, V1, &write_bin(&src, b"ELF serve")).unwrap();

            // A hostile origin swaps the blob's bytes under its content address.
            store.put(&published.blob_key, b"malware".to_vec()).unwrap();

            let err = ensure_runtime_asset(&store, cache.path(), &rref, TRIPLE, SERVE_BIN, REQ1).unwrap_err();
            assert!(matches!(err, BundleError::HashMismatch { .. }), "got {err:?}");
            assert!(
                !cache.path().join(rref.cache_rel_serve(TRIPLE)).exists(),
                "unverified bytes must never reach the resolved path"
            );
        }

        /// An asset misfiled under the wrong version is caught by the fetcher
        /// rather than becoming a site served by the wrong binary.
        #[test]
        fn a_misfiled_asset_manifest_is_refused() {
            let store = InMemoryObjectStore::new();
            let cache = TempDir::new().unwrap();
            let asked = RuntimeRef::parse("mesofact/0.8.20").unwrap();

            // Published at 0.8.20's key but declaring 0.8.19 inside.
            let bytes = b"ELF serve".to_vec();
            let hash = BundleHash::of(&bytes);
            store.put(&blob_key(&hash), bytes).unwrap();
            let manifest = RuntimeAssetManifest {
                schema_version: 1,
                runtime: "mesofact/0.8.19".to_string(),
                triple: TRIPLE.to_string(),
                bin: SERVE_BIN.to_string(),
                contract: V1.to_vec(),
                serve: hash,
            };
            store
                .put(
                    &asked.asset_manifest_key(TRIPLE),
                    manifest.to_toml_string().unwrap().into_bytes(),
                )
                .unwrap();

            let err = ensure_runtime_asset(&store, cache.path(), &asked, TRIPLE, SERVE_BIN, REQ1).unwrap_err();
            assert!(err.to_string().contains("0.8.19"), "got {err}");
        }

        /// A runtime asset and a self-contained bundle carrying the identical
        /// binary share one blob — the dedupe that makes sharing the bundle
        /// store rather than inventing a second one worth it.
        #[test]
        fn identical_binaries_dedupe_against_the_bundle_blob_space() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.20").unwrap();
            let bin = write_bin(&src, b"ELF serve");

            let first = publish_runtime_asset(&store, &rref, TRIPLE, SERVE_BIN, V1, &bin).unwrap();
            assert!(first.blob_uploaded);
            let other = RuntimeRef::parse("acme/site/1.0.0").unwrap();
            let second = publish_runtime_asset(&store, &other, TRIPLE, SERVE_BIN, V1, &bin).unwrap();
            assert!(!second.blob_uploaded, "identical bytes must not re-upload");
            assert_eq!(first.blob_key, second.blob_key);
        }

        /// R746-T3: the tier is not serve-only. The feed fetcher resolves
        /// through it under its own name, which is what lets a *vanilla*
        /// bundle carry a feed tier without carrying a binary.
        #[test]
        fn a_sidecar_asset_resolves_under_its_own_binary_name() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let feed = RuntimeRef::parse("almanac-feed/0.8.22").unwrap();

            publish_runtime_asset(&store, &feed, TRIPLE, FEED_BIN, V1, &write_bin(&src, b"ELF feed"))
                .unwrap();
            let resolved = ensure_runtime_asset(&store, cache.path(), &feed, TRIPLE, FEED_BIN, REQ1)
                .unwrap();

            assert_eq!(
                resolved,
                cache
                    .path()
                    .join("runtimes/almanac-feed/0.8.22")
                    .join(TRIPLE)
                    .join(FEED_BIN)
            );
            assert_eq!(std::fs::read(&resolved).unwrap(), b"ELF feed");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&resolved).unwrap().permissions().mode();
                assert!(mode & 0o111 != 0, "a sidecar asset must land forkable");
            }
        }

        /// The binary name is checked like `runtime` and `triple` are: asking
        /// for `serve` and being handed the feed fetcher is exactly the
        /// misfiling the by-name key makes possible, and it would fork a
        /// binary that exits on `serve --bundle`.
        #[test]
        fn an_asset_published_under_another_binary_name_is_refused() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.22").unwrap();

            publish_runtime_asset(&store, &rref, TRIPLE, FEED_BIN, V1, &write_bin(&src, b"ELF feed"))
                .unwrap();

            let err =
                ensure_runtime_asset(&store, cache.path(), &rref, TRIPLE, SERVE_BIN, REQ1).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(FEED_BIN) && msg.contains(SERVE_BIN), "got {msg}");
            assert!(
                !cache.path().join(rref.cache_rel_serve(TRIPLE)).exists(),
                "a refused resolve must leave nothing forkable behind"
            );
        }

        /// Two assets at one version × triple do not collide, because they are
        /// two refs — and the cache dirs are disjoint, so the mesofact runtime
        /// never shadows the fetcher.
        #[test]
        fn serve_and_feed_assets_do_not_share_a_cache_slot() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let serve_ref = RuntimeRef::parse("mesofact/0.8.22").unwrap();
            let feed_ref = RuntimeRef::parse("almanac-feed/0.8.22").unwrap();

            publish_runtime_asset(&store, &serve_ref, TRIPLE, SERVE_BIN, V1, &write_bin(&src, b"S"))
                .unwrap();
            let feed_src = TempDir::new().unwrap();
            publish_runtime_asset(&store, &feed_ref, TRIPLE, FEED_BIN, V1, &write_bin(&feed_src, b"F"))
                .unwrap();

            let s = ensure_runtime_asset(&store, cache.path(), &serve_ref, TRIPLE, SERVE_BIN, REQ1)
                .unwrap();
            let f =
                ensure_runtime_asset(&store, cache.path(), &feed_ref, TRIPLE, FEED_BIN, REQ1).unwrap();
            assert_ne!(s, f);
            assert_eq!(std::fs::read(&s).unwrap(), b"S");
            assert_eq!(std::fs::read(&f).unwrap(), b"F");
        }

        /// A published manifest is remote input; its `bin` is joined onto the
        /// node's cache dir. Same traversal posture as the ref's segments.
        #[test]
        fn a_traversing_binary_name_is_refused() {
            for bad in ["../serve", "a/b", "..", ".", "", "serve bin"] {
                assert!(
                    crate::runtime::check_bin_name(bad).is_err(),
                    "{bad:?} must not become a cache path"
                );
            }
            assert!(crate::runtime::check_bin_name(FEED_BIN).is_ok());
            assert!(crate::runtime::check_bin_name(SERVE_BIN).is_ok());
        }

        // ---- R746-F6: the bundle↔runtime contract ----

        /// The node-side backstop. A runtime that does not advertise the
        /// contract a bundle requires is refused *before* its bytes are
        /// fetched, and the message names both versions — the fix is a choice
        /// between them and an operator cannot make it holding only one.
        #[test]
        fn a_runtime_that_does_not_implement_the_required_contract_is_refused() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.20").unwrap();

            // Published advertising contract 1 only.
            publish_runtime_asset(&store, &rref, TRIPLE, SERVE_BIN, &[1], &write_bin(&src, b"ELF"))
                .unwrap();

            let err = ensure_runtime_asset(
                &store,
                cache.path(),
                &rref,
                TRIPLE,
                SERVE_BIN,
                ContractRequirement::Version(2),
            )
            .unwrap_err();

            let msg = err.to_string();
            assert!(matches!(err, BundleError::ContractUnsatisfied { .. }), "got {err:?}");
            assert!(msg.contains("mesofact/0.8.20") && msg.contains(TRIPLE), "got {msg}");
            assert!(msg.contains('1') && msg.contains('2'), "both versions, got {msg}");
            assert!(
                !cache.path().join(rref.cache_rel_serve(TRIPLE)).exists(),
                "a refused resolve must leave nothing forkable behind"
            );
        }

        /// A runtime serving several contracts satisfies a bundle requiring any
        /// of them — the property that makes a published bundle keep working
        /// across a contract bump instead of being stranded by it.
        #[test]
        fn a_runtime_advertising_a_set_serves_every_version_in_it() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.9.0").unwrap();
            publish_runtime_asset(&store, &rref, TRIPLE, SERVE_BIN, &[1, 2], &write_bin(&src, b"ELF"))
                .unwrap();

            for required in [1, 2] {
                let cache = TempDir::new().unwrap();
                assert!(
                    ensure_runtime_asset(
                        &store,
                        cache.path(),
                        &rref,
                        TRIPLE,
                        SERVE_BIN,
                        ContractRequirement::Version(required),
                    )
                    .is_ok(),
                    "contract {required} is advertised and must resolve"
                );
            }
        }

        /// The sidecar exemption is real and narrow: `almanac-feed`'s interface
        /// is its own CLI, not the bundle↔runtime contract, so it resolves
        /// `Unchecked` against whatever its publisher recorded.
        #[test]
        fn an_unchecked_requirement_resolves_a_sidecar_whatever_it_advertises() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let cache = TempDir::new().unwrap();
            let feed = RuntimeRef::parse("almanac-feed/0.8.22").unwrap();
            publish_runtime_asset(&store, &feed, TRIPLE, FEED_BIN, &[99], &write_bin(&src, b"F"))
                .unwrap();

            assert!(ensure_runtime_asset(
                &store,
                cache.path(),
                &feed,
                TRIPLE,
                FEED_BIN,
                ContractRequirement::Unchecked,
            )
            .is_ok());
        }

        /// A manifest published before the field existed advertises contract 1
        /// — a statement of fact about every binary that predates version 2,
        /// not an optimistic default. Without it, every asset already in R2
        /// would stop resolving the moment this shipped.
        #[test]
        fn an_asset_manifest_without_a_contract_field_advertises_contract_1() {
            let store = InMemoryObjectStore::new();
            let cache = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.18").unwrap();

            // Hand-written in the pre-F6 shape.
            let bytes = b"ELF serve".to_vec();
            let hash = BundleHash::of(&bytes);
            store.put(&blob_key(&hash), bytes).unwrap();
            store
                .put(
                    &rref.asset_manifest_key(TRIPLE),
                    format!(
                        "schema_version = 1\nruntime = \"mesofact/0.8.18\"\n\
                         triple = \"{TRIPLE}\"\nbin = \"serve\"\nserve = \"{hash}\"\n"
                    )
                    .into_bytes(),
                )
                .unwrap();

            let parsed = RuntimeAssetManifest::from_toml_str(
                &String::from_utf8(store.get(&rref.asset_manifest_key(TRIPLE)).unwrap().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(parsed.contract, vec![1]);

            assert!(
                ensure_runtime_asset(&store, cache.path(), &rref, TRIPLE, SERVE_BIN, REQ1).is_ok(),
                "a pre-F6 asset must keep serving a contract-1 bundle"
            );
        }

        /// An asset advertising nothing could never be resolved by any bundle,
        /// so it is refused at publish rather than becoming a runtime that
        /// silently satisfies no one.
        #[test]
        fn publishing_an_asset_that_advertises_no_contract_is_refused() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.20").unwrap();
            let err =
                publish_runtime_asset(&store, &rref, TRIPLE, SERVE_BIN, &[], &write_bin(&src, b"E"))
                    .unwrap_err();
            assert!(err.to_string().contains("no contract version"), "got {err}");
            assert!(
                store.list_prefix(&rref.asset_manifest_prefix()).unwrap().is_empty(),
                "a refused publish must write no manifest"
            );
        }

        /// The apply-time gate's survey: one row per published triple, sorted,
        /// carrying what each advertises.
        #[test]
        fn the_survey_reports_every_published_triple_for_a_runtime() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.20").unwrap();
            publish_runtime_asset(&store, &rref, "x86_64-unknown-linux-musl", SERVE_BIN, &[1], &write_bin(&src, b"x")).unwrap();
            let src2 = TempDir::new().unwrap();
            publish_runtime_asset(&store, &rref, "aarch64-unknown-linux-musl", SERVE_BIN, &[1, 2], &write_bin(&src2, b"a")).unwrap();
            // A neighbouring version must not leak into this one's survey.
            let other = RuntimeRef::parse("mesofact/0.8.2").unwrap();
            let src3 = TempDir::new().unwrap();
            publish_runtime_asset(&store, &other, "x86_64-unknown-linux-musl", SERVE_BIN, &[9], &write_bin(&src3, b"o")).unwrap();

            assert_eq!(
                published_runtime_assets(&store, &rref).unwrap(),
                vec![
                    PublishedRuntime {
                        triple: "aarch64-unknown-linux-musl".to_string(),
                        contract: vec![1, 2],
                    },
                    PublishedRuntime {
                        triple: "x86_64-unknown-linux-musl".to_string(),
                        contract: vec![1],
                    },
                ]
            );
        }

        /// **Verify #1.** The apply-time gate refuses before anything reaches a
        /// node, naming the runtime, the triple, and both contract versions.
        #[test]
        fn the_apply_gate_refuses_a_runtime_that_cannot_serve_the_bundle() {
            let store = InMemoryObjectStore::new();
            let src = TempDir::new().unwrap();
            let rref = RuntimeRef::parse("mesofact/0.8.20").unwrap();
            publish_runtime_asset(&store, &rref, TRIPLE, SERVE_BIN, &[1], &write_bin(&src, b"x"))
                .unwrap();

            assert_eq!(
                require_runtime_contract(&store, &rref, 1).unwrap(),
                vec![TRIPLE.to_string()]
            );

            let err = require_runtime_contract(&store, &rref, 2).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("mesofact/0.8.20"), "got {msg}");
            assert!(msg.contains(TRIPLE), "got {msg}");
            assert!(msg.contains('1') && msg.contains('2'), "both versions, got {msg}");
        }

        /// One unsatisfied triple fails the whole apply even when others are
        /// fine — a version published with mixed contract sets is a publishing
        /// bug, and letting it through relocates the failure onto whichever
        /// node happens to be the odd one out, at serve time.
        #[test]
        fn one_stale_triple_fails_the_apply_for_all_of_them() {
            let store = InMemoryObjectStore::new();
            let rref = RuntimeRef::parse("mesofact/0.9.0").unwrap();
            let a = TempDir::new().unwrap();
            let b = TempDir::new().unwrap();
            publish_runtime_asset(&store, &rref, "x86_64-unknown-linux-musl", SERVE_BIN, &[1, 2], &write_bin(&a, b"new")).unwrap();
            publish_runtime_asset(&store, &rref, "aarch64-unknown-linux-musl", SERVE_BIN, &[1], &write_bin(&b, b"old")).unwrap();

            let err = require_runtime_contract(&store, &rref, 2).unwrap_err();
            assert!(
                err.to_string().contains("aarch64-unknown-linux-musl"),
                "the refusal must name the triple that is behind, got {err}"
            );
        }

        /// Nothing published is not a contract failure — that is
        /// `RuntimeAssetMissing`'s case (R746-F1), which already names the
        /// version and where it looked. Reporting it as a mismatch would send
        /// an operator hunting for a version conflict that does not exist.
        #[test]
        fn an_unpublished_runtime_surveys_empty_rather_than_failing_the_gate() {
            let store = InMemoryObjectStore::new();
            let rref = RuntimeRef::parse("mesofact/9.9.9").unwrap();
            assert!(require_runtime_contract(&store, &rref, 1).unwrap().is_empty());
        }
    }
}
