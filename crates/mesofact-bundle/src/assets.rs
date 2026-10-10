//! Per-file serving metadata for a served static tree (MFT-R825-F1): the
//! **asset index**, the declared **immutable** globs it is built from, and the
//! publish-time **precompression** that fills in its encodings.
//!
//! One rule, three readers. Before this module, "may this file be cached
//! forever?" was answered three different ways — `mesofact serve` never said
//! (no `Cache-Control`, no `ETag`, identity bytes only), yubaba's R2 publish
//! sniffed hash-shaped filenames under `hydrate/`, and `mesofact-build` wrote
//! `immutable: false` into every manifest `static_assets` entry. Now:
//!
//! - **Immutability is declared, never sniffed.** A component lists the output
//!   files it knows to be content-addressed in its `mesofact.config.toml`
//!   (`[build] immutable = ["app-*.js", "*_bg.wasm"]`, read by
//!   [`declared_immutable`], matched by [`ImmutableGlobs`]). The only thing
//!   still recognised by shape is
//!   mesofact's own bundler output under `hydrate/`
//!   ([`is_content_hashed_hydrate_output`]), because there mesofact is the
//!   author of the naming and the declaration would be redundant.
//! - **Encodings are produced at publish time, never per request.**
//!   [`finalize_component_output`] writes `<file>.br` / `<file>.gz` siblings
//!   for compressible files and records which ones exist. Compressing a 35 MB
//!   wasm costs ~10 s of CPU at brotli 9 and ~80 s at brotli 11 (measured on
//!   noisetable's `_bg.wasm`, 2026-10-09) — a cost a deploy can pay once and a
//!   request path cannot pay at all.
//! - **The index is the carrier.** Both facts land in
//!   [`ASSET_INDEX_FILE`] at the root of the served tree, keyed by path
//!   relative to that root, alongside each file's sha256 (its `ETag`). Because
//!   it lives *inside* the tree, it travels with the files through every
//!   deploy shape unchanged: a mounted component's index stages at
//!   `app/dist/html/<mount>/` along with the component, so a server resolving
//!   the nearest index above a file needs no knowledge of mounts at all.
//!
//! Adding these files to a bundle is not a bundle-contract change
//! ([`crate::BUNDLE_CONTRACT_VERSION`]): a runtime that predates the index
//! serves the same identity bytes it always did, and a runtime that reads it
//! falls back to hashing on demand for a bundle that has none.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::BundleError;

/// File name of the asset index at the root of a served tree.
///
/// Dot-prefixed so it sorts out of the way in a listing; it is not secret —
/// every value in it is also sent as an `ETag` header.
pub const ASSET_INDEX_FILE: &str = ".mesofact-assets.json";

/// Current [`AssetIndex::version`]. A reader seeing a different value ignores
/// the index (and serves without it) rather than guessing at its shape.
pub const ASSET_INDEX_VERSION: u32 = 1;

/// `Cache-Control` for a declared-immutable file. Byte-equal to
/// `yah_object_store::CACHE_CONTROL_IMMUTABLE` and to mesofact serve's SSR
/// instance-pointer value — one directive, everywhere it is emitted.
pub const CACHE_CONTROL_IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// `Cache-Control` for everything not declared immutable: cache it, but
/// revalidate before every use. With an `ETag` that revalidation is a 304 with
/// no body, so "not immutable" no longer means "re-download everything".
pub const CACHE_CONTROL_REVALIDATE: &str = "no-cache";

/// Below this size a file is never precompressed: the header overhead and the
/// extra round of negotiation are worth more than the bytes saved.
const MIN_COMPRESS_BYTES: u64 = 1024;

/// A variant is kept only when it is at most this fraction (in percent) of the
/// identity size; anything closer is not worth a second representation.
const MAX_KEPT_PERCENT: u64 = 95;

/// Files at or above this size get brotli quality 9 instead of 11. Measured on
/// noisetable's 35,306,127 B `_bg.wasm`: q11 → 7,845,662 B in 79 s CPU, q9 →
/// 9,161,591 B in 12.5 s. Below the threshold (every JS/CSS/HTML file a site
/// realistically ships) q11 costs well under a second and is what's used.
const BROTLI_MAX_QUALITY_BELOW: u64 = 4 * 1024 * 1024;

/// A content encoding a precompressed variant can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// brotli — `<file>.br`, `Content-Encoding: br`.
    Br,
    /// gzip — `<file>.gz`, `Content-Encoding: gzip`.
    Gzip,
}

impl Encoding {
    /// Every encoding, in server preference order (smallest output first).
    pub const ALL: [Encoding; 2] = [Encoding::Br, Encoding::Gzip];

    /// The `Content-Encoding` / `Accept-Encoding` token.
    pub fn token(self) -> &'static str {
        match self {
            Encoding::Br => "br",
            Encoding::Gzip => "gzip",
        }
    }

    /// Suffix appended to the identity file's name for this variant.
    pub fn suffix(self) -> &'static str {
        match self {
            Encoding::Br => ".br",
            Encoding::Gzip => ".gz",
        }
    }
}

/// What the index records about one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEntry {
    /// Lowercase hex sha256 of the identity bytes — the file's strong `ETag`,
    /// and the same digest a mesofact manifest records as `content_hash`.
    pub sha256: String,
    /// Identity size in bytes. A reader compares it with the file on disk and
    /// ignores an entry that no longer describes the file.
    pub size: u64,
    /// Declared content-addressed: safe to cache for a year without
    /// revalidating.
    #[serde(default)]
    pub immutable: bool,
    /// Precompressed variants present beside the file, in preference order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub encodings: Vec<Encoding>,
}

impl AssetEntry {
    /// The strong `ETag` (quotes included) of the representation in
    /// `encoding`. Each encoding is a distinct representation and must carry a
    /// distinct tag, or a cache could answer a gzip-only client with brotli
    /// bytes it validated against the identity tag.
    pub fn etag(&self, encoding: Option<Encoding>) -> String {
        etag_for(&self.sha256, encoding)
    }

    /// `Cache-Control` value for this file.
    pub fn cache_control(&self) -> &'static str {
        if self.immutable {
            CACHE_CONTROL_IMMUTABLE
        } else {
            CACHE_CONTROL_REVALIDATE
        }
    }
}

/// Lowercase hex sha256 — the digest an [`AssetEntry`] records, exposed so a
/// server hashing an unindexed file on demand produces the identical `ETag`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Strong `ETag` for content `sha256` in `encoding`; see [`AssetEntry::etag`].
pub fn etag_for(sha256: &str, encoding: Option<Encoding>) -> String {
    match encoding {
        None => format!("\"{sha256}\""),
        Some(e) => format!("\"{sha256}.{}\"", e.token()),
    }
}

/// The index written at the root of a served tree as [`ASSET_INDEX_FILE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetIndex {
    pub version: u32,
    /// Keyed by forward-slashed path relative to the directory holding the
    /// index.
    pub assets: BTreeMap<String, AssetEntry>,
}

impl AssetIndex {
    /// Parse an index, returning `None` for anything this build cannot trust —
    /// malformed JSON or a version it does not speak. Callers treat `None`
    /// exactly like a missing index.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let index: AssetIndex = serde_json::from_slice(raw).ok()?;
        (index.version == ASSET_INDEX_VERSION).then_some(index)
    }
}

/// Declared-immutable path patterns, matched against a file's path relative to
/// the served root of the component that produced it.
///
/// Syntax, deliberately small: `/` separates segments; `*` matches any run of
/// characters within one segment; `?` matches one character; a whole `**`
/// segment matches zero or more segments. Matching is against the WHOLE path,
/// so `*_bg.wasm` matches `app_bg.wasm` but not `snippets/x/app_bg.wasm` —
/// write `**/*_bg.wasm` to reach into directories. That is on purpose: Trunk's
/// `snippets/<crate>-<hash>/` directories look hashed but are keyed on the
/// crate, not on the bytes, and a pattern that reached them by accident would
/// pin stale JS in browsers for a year.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImmutableGlobs {
    patterns: Vec<Vec<String>>,
}

impl ImmutableGlobs {
    /// Validate and compile `patterns`. Rejects what could only be a mistake:
    /// an empty pattern, an absolute one, a `..` or empty segment, and `[` —
    /// character classes are not supported and silently matching `[` literally
    /// would turn a typo into a year-long cache entry.
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Result<Self, BundleError> {
        let mut compiled = Vec::with_capacity(patterns.len());
        for p in patterns {
            let p = p.as_ref();
            let bad = |why: &str| {
                BundleError::AssetPolicy(format!("immutable pattern {p:?}: {why}"))
            };
            if p.is_empty() {
                return Err(bad("empty pattern"));
            }
            if p.starts_with('/') {
                return Err(bad("must be relative to the build output, not absolute"));
            }
            if p.contains('[') || p.contains(']') {
                return Err(bad("character classes are not supported"));
            }
            let segs: Vec<String> = p.split('/').map(str::to_string).collect();
            if segs.iter().any(|s| s.is_empty() || s == "." || s == "..") {
                return Err(bad("empty, `.` and `..` segments are not allowed"));
            }
            compiled.push(segs);
        }
        Ok(Self { patterns: compiled })
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// True when `rel` (forward-slashed, relative to the served root) matches
    /// any declared pattern.
    pub fn matches(&self, rel: &str) -> bool {
        let path: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        self.patterns.iter().any(|p| match_segments(p, &path))
    }
}

fn match_segments(pat: &[String], path: &[&str]) -> bool {
    match pat.split_first() {
        None => path.is_empty(),
        Some((head, rest)) if head == "**" => {
            (0..=path.len()).any(|skip| match_segments(rest, &path[skip..]))
        }
        Some((head, rest)) => match path.split_first() {
            Some((seg, path_rest)) => match_segment(head, seg) && match_segments(rest, path_rest),
            None => false,
        },
    }
}

/// Wildcard match of one segment (`*`, `?`), iterative with single-star
/// backtracking — linear in practice, no recursion on adversarial input.
fn match_segment(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// mesofact's own bundler names every hydrate output `<key>.<hash>.js` or
/// `<key>.chunk-<hash>.js` (`mesofact-build` `bundle.rs`), so under `hydrate/`
/// a hash-shaped name IS a declaration — mesofact wrote it. `rel` is relative
/// to the hydrate directory.
///
/// The shape check is still strict, not "has two dots": a hand-dropped
/// `app.min.js` or a plain `app.js` (someone bypassing the bundler) is not
/// content-addressed, and a year-long immutable cache on it would be
/// unrecoverable. Unknown ⇒ not immutable, always; guessing "cacheable" wrong
/// costs far more than guessing "not". Moved here from yubaba's
/// `r2_publish::cache_control_for` (R703-T10) so the R2 path and the bundle
/// path apply one rule.
pub fn is_content_hashed_hydrate_output(rel: &str) -> bool {
    rel.rsplit_once('.')
        // `<name>.<hash>.js` → after dropping `.js`, the trailing dot-segment
        // is the hash. Bun/rolldown emit 8+ chars of base62/hex; require that.
        .and_then(|(stem, ext)| (ext == "js").then_some(stem))
        .and_then(|stem| stem.rsplit_once('.'))
        .is_some_and(|(_, tok)| {
            let tok = tok.strip_prefix("chunk-").unwrap_or(tok);
            tok.len() >= 8 && tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// File, relative to a component's project root, that carries its declared
/// immutable patterns as `[build] immutable = [...]`.
pub const DECLARATION_FILE: &str = "mesofact.config.toml";

/// Read a component's declared immutable patterns from
/// `<project_root>/mesofact.config.toml`, `[build] immutable` — beside
/// `[build] public_dir`, in mesofact's own project config.
///
/// **Why not `workload.toml`**, which is where R825 first suggested it:
/// `workload_spec::BuildConfig` is `deny_unknown_fields` AND rides the kamaji
/// postcard wire (positional, non-self-describing), so a new `[build]` key
/// there is a fleet wire change touching yah, yubaba and kamaji to state a
/// fact no node ever reads. This one is consumed only at build and assembly
/// time, by mesofact-build and by this crate. A component that is not a
/// mesofact project (a Trunk app) gets a two-line `mesofact.config.toml`
/// carrying just this table.
///
/// The single reader of the key: mesofact-build calls it for the manifest's
/// `static_assets[].immutable`, assembly calls it via
/// [`finalize_component_output`]. No file ⇒ nothing declared. A malformed
/// file, or a pattern [`ImmutableGlobs::new`] rejects, IS an error — a deploy
/// that quietly drops a declaration is the failure this module exists to
/// remove.
pub fn declared_immutable(project_root: &Path) -> Result<ImmutableGlobs, BundleError> {
    let path = project_root.join(DECLARATION_FILE);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ImmutableGlobs::default()),
        Err(e) => return Err(BundleError::Io(format!("reading {}: {e}", path.display()))),
    };
    #[derive(Deserialize)]
    struct Sliver {
        #[serde(default)]
        build: Option<BuildSliver>,
    }
    #[derive(Deserialize)]
    struct BuildSliver {
        #[serde(default)]
        immutable: Vec<String>,
    }
    let sliver: Sliver = toml::from_str(&raw)
        .map_err(|e| BundleError::AssetPolicy(format!("parsing {}: {e}", path.display())))?;
    ImmutableGlobs::new(&sliver.build.map(|b| b.immutable).unwrap_or_default())
}

/// True for a file [`finalize_served_dir`] wrote rather than one the build
/// produced: the index itself, or a `<file>.br` / `<file>.gz` whose `<file>`
/// exists beside it. `rel` is relative to `dir`. A publisher that walks a
/// finalized tree for a CDN that negotiates encodings on its own uses this to
/// skip them.
pub fn is_finalize_artifact(dir: &Path, rel: &str) -> bool {
    if rel.rsplit('/').next() == Some(ASSET_INDEX_FILE) {
        return true;
    }
    Encoding::ALL.iter().any(|e| {
        rel.strip_suffix(e.suffix())
            .is_some_and(|base| !base.is_empty() && dir.join(base).is_file())
    })
}

/// Finalize one component's build output for serving, in place: index every
/// file, mark the declared-immutable ones, and write precompressed variants.
///
/// `project_root` holds the component's [`DECLARATION_FILE`]; `out_dir` is
/// its `[build] out_dir`. Two shapes, told apart by what the build emitted:
///
/// - **A mesofact build** (`out_dir/html/` exists): the served root is
///   `out_dir/html`, finalized with the declared patterns; `out_dir/hydrate`
///   is its own served root (`/<build_id>/hydrate/…`), finalized with
///   [`is_content_hashed_hydrate_output`].
/// - **Anything else** (Trunk, a hand-rolled static tree): `out_dir` IS the
///   served root, finalized with the declared patterns.
///
/// Called from every bundle-assembly entry point before the tree is
/// collected, so the variants and index ride into the bundle like any other
/// output file. Idempotent and cheap on a second run: a file whose sha256
/// matches the existing index keeps its variants without recompressing, so
/// re-deploying an unchanged 35 MB wasm costs one hash, not 80 s of brotli.
pub fn finalize_component_output(project_root: &Path, out_dir: &Path) -> Result<(), BundleError> {
    let policy = OutputPolicy::load(project_root, out_dir)?;
    if policy.mesofact_build {
        let html = out_dir.join("html");
        finalize_served_dir(&html, &|rel| policy.is_immutable(&format!("html/{rel}")))?;
        let hydrate = out_dir.join("hydrate");
        if hydrate.is_dir() {
            finalize_served_dir(&hydrate, &|rel| policy.is_immutable(&format!("hydrate/{rel}")))?;
        }
    } else if out_dir.is_dir() {
        finalize_served_dir(out_dir, &|rel| policy.is_immutable(rel))?;
    }
    Ok(())
}

/// Which files of one component's build output are immutable, keyed by path
/// relative to its `out_dir` — the single statement of the shape → rule
/// mapping that [`finalize_component_output`] (bundle path) and yubaba's
/// `r2_publish` (R2 path) both apply, so the two cannot drift.
///
/// For a mesofact build (`out_dir/html/` exists) `html/<rel>` is matched
/// against the declared patterns, `hydrate/<rel>` by
/// [`is_content_hashed_hydrate_output`], and everything else (`manifest.json`,
/// `tag-index.json`, `server/`) is never immutable — each is rewritten in
/// place by the next build. For any other output, `<rel>` is matched against
/// the declared patterns directly.
#[derive(Debug, Clone, Default)]
pub struct OutputPolicy {
    declared: ImmutableGlobs,
    mesofact_build: bool,
}

impl OutputPolicy {
    /// The policy for the component whose project root is `project_root` and
    /// whose build output is `out_dir` (see [`declared_immutable`]).
    pub fn load(project_root: &Path, out_dir: &Path) -> Result<Self, BundleError> {
        Ok(Self {
            declared: declared_immutable(project_root)?,
            mesofact_build: out_dir.join("html").is_dir(),
        })
    }

    /// `out_rel` is forward-slashed and relative to the component's `out_dir`.
    pub fn is_immutable(&self, out_rel: &str) -> bool {
        if !self.mesofact_build {
            return self.declared.matches(out_rel);
        }
        if let Some(rel) = out_rel.strip_prefix("html/") {
            self.declared.matches(rel)
        } else if let Some(rel) = out_rel.strip_prefix("hydrate/") {
            is_content_hashed_hydrate_output(rel)
        } else {
            false
        }
    }
}

/// Index and precompress every file under `dir`, writing
/// `<dir>/`[`ASSET_INDEX_FILE`]. `immutable` decides each file's flag from its
/// `dir`-relative path. Returns the index it wrote.
pub fn finalize_served_dir(
    dir: &Path,
    immutable: &dyn Fn(&str) -> bool,
) -> Result<AssetIndex, BundleError> {
    let io = |what: &str, p: &Path, e: std::io::Error| {
        BundleError::Io(format!("{what} {}: {e}", p.display()))
    };

    let mut files = BTreeSet::new();
    walk_rel(dir, "", &mut files)?;

    let prior = fs::read(dir.join(ASSET_INDEX_FILE))
        .ok()
        .and_then(|raw| AssetIndex::parse(&raw))
        .map(|i| i.assets)
        .unwrap_or_default();

    // A file the previous pass indexed is gone (a rebuild that does not wipe
    // its output dir): its variants are ours and now orphaned. Left in place,
    // `x.js.br` with no `x.js` would be indexed as an asset of its own.
    for (rel, entry) in &prior {
        if files.contains(rel) {
            continue;
        }
        for enc in &entry.encodings {
            let variant = format!("{rel}{}", enc.suffix());
            if files.remove(&variant) {
                let path = dir.join(&variant);
                fs::remove_file(&path).map_err(|e| io("removing orphaned", &path, e))?;
            }
        }
    }

    let mut assets = BTreeMap::new();
    for rel in &files {
        if is_variant_of_listed(rel, &files) || rel.rsplit('/').next() == Some(ASSET_INDEX_FILE) {
            continue;
        }
        let path = dir.join(rel);
        let bytes = fs::read(&path).map_err(|e| io("reading", &path, e))?;
        let sha256 = sha256_hex(&bytes);
        let size = bytes.len() as u64;
        let previous = prior.get(rel).filter(|p| p.sha256 == sha256);

        let mut encodings = Vec::new();
        let worth_compressing = size >= MIN_COMPRESS_BYTES && is_compressible(rel);
        for enc in Encoding::ALL {
            let variant = dir.join(format!("{rel}{}", enc.suffix()));
            if !worth_compressing {
                // Only ever remove a variant this function created — the prior
                // index lists it. A build that shipped its own `x.gz` keeps it.
                if prior.get(rel).is_some_and(|p| p.encodings.contains(&enc)) && variant.is_file() {
                    fs::remove_file(&variant).map_err(|e| io("removing stale", &variant, e))?;
                }
                continue;
            }
            if previous.is_some_and(|p| p.encodings.contains(&enc)) && variant.is_file() {
                encodings.push(enc);
                continue;
            }
            let compressed = compress(enc, &bytes)
                .map_err(|e| io(&format!("{} compressing", enc.token()), &path, e))?;
            if (compressed.len() as u64) * 100 <= size * MAX_KEPT_PERCENT {
                fs::write(&variant, &compressed).map_err(|e| io("writing", &variant, e))?;
                encodings.push(enc);
            } else if variant.is_file() && prior.get(rel).is_some_and(|p| p.encodings.contains(&enc)) {
                fs::remove_file(&variant).map_err(|e| io("removing stale", &variant, e))?;
            }
        }

        assets.insert(
            rel.clone(),
            AssetEntry { sha256, size, immutable: immutable(rel), encodings },
        );
    }

    let index = AssetIndex { version: ASSET_INDEX_VERSION, assets };
    let json = serde_json::to_vec_pretty(&index)
        .map_err(|e| BundleError::Io(format!("serializing asset index: {e}")))?;
    let index_path = dir.join(ASSET_INDEX_FILE);
    fs::write(&index_path, json).map_err(|e| io("writing", &index_path, e))?;
    Ok(index)
}

/// `rel` is `<other>.br` / `<other>.gz` for some `<other>` in `files` — i.e. a
/// variant of a file this pass indexes, not an asset in its own right.
fn is_variant_of_listed(rel: &str, files: &BTreeSet<String>) -> bool {
    Encoding::ALL
        .iter()
        .any(|e| rel.strip_suffix(e.suffix()).is_some_and(|base| files.contains(base)))
}

/// Text-like and wasm types that compress well. Images, fonts in woff/woff2
/// and archives are already compressed; a variant of them is wasted bytes.
fn is_compressible(rel: &str) -> bool {
    let ext = rel.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    matches!(
        ext.as_str(),
        "html" | "htm" | "css" | "js" | "mjs" | "cjs" | "json" | "map" | "xml" | "svg" | "txt"
            | "md" | "csv" | "sh" | "wasm" | "webmanifest" | "ico" | "ttf" | "otf"
    )
}

fn compress(enc: Encoding, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    match enc {
        Encoding::Br => {
            let large = bytes.len() as u64 >= BROTLI_MAX_QUALITY_BELOW;
            let params = brotli::enc::BrotliEncoderParams {
                quality: if large { 9 } else { 11 },
                lgwin: 24,
                ..Default::default()
            };
            let mut out = Vec::with_capacity(bytes.len() / 3);
            brotli::BrotliCompress(&mut &bytes[..], &mut out, &params)?;
            Ok(out)
        }
        Encoding::Gzip => {
            let mut enc = flate2::write::GzEncoder::new(
                Vec::with_capacity(bytes.len() / 2),
                flate2::Compression::best(),
            );
            enc.write_all(bytes)?;
            enc.finish()
        }
    }
}

fn walk_rel(abs: &Path, rel: &str, out: &mut BTreeSet<String>) -> Result<(), BundleError> {
    let entries =
        fs::read_dir(abs).map_err(|e| BundleError::Io(format!("reading {}: {e}", abs.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| BundleError::Io(format!("reading {}: {e}", abs.display())))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let child = if rel.is_empty() { name } else { format!("{rel}/{name}") };
        let ty = entry
            .file_type()
            .map_err(|e| BundleError::Io(format!("stat {}: {e}", entry.path().display())))?;
        if ty.is_dir() {
            walk_rel(&entry.path(), &child, out)?;
        } else if ty.is_file() {
            out.insert(child);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn globs(p: &[&str]) -> ImmutableGlobs {
        ImmutableGlobs::new(p).unwrap()
    }

    #[test]
    fn globs_match_whole_paths_and_never_reach_into_snippets_by_accident() {
        let g = globs(&["noise_table_browser-*.js", "*_bg.wasm"]);
        assert!(g.matches("noise_table_browser-ccb80901df6f7edc.js"));
        assert!(g.matches("noise_table_browser-ccb80901df6f7edc_bg.wasm"));
        // Trunk's snippets dir looks hashed but is keyed on the crate, not the
        // bytes — a bare pattern must not reach it (the R825-F1 gotcha).
        assert!(!g.matches("snippets/noise_table_browser-0f1e2d3c/inline0.js"));
        assert!(!g.matches("index.html"));
        assert!(!g.matches("audio_worklet_processor.js"));
    }

    #[test]
    fn double_star_spans_zero_or_more_directories() {
        let g = globs(&["**/*_bg.wasm", "assets/**"]);
        assert!(g.matches("app_bg.wasm"));
        assert!(g.matches("a/b/app_bg.wasm"));
        assert!(g.matches("assets/x.png"));
        assert!(g.matches("assets/deep/x.png"));
        assert!(!g.matches("other/x.png"));
    }

    #[test]
    fn star_and_question_mark_stay_within_a_segment() {
        let g = globs(&["a*z", "v?.js"]);
        assert!(g.matches("az"));
        assert!(g.matches("abcz"));
        assert!(!g.matches("ab/cz"));
        assert!(g.matches("v1.js"));
        assert!(!g.matches("v12.js"));
    }

    #[test]
    fn patterns_that_can_only_be_mistakes_are_refused() {
        for bad in ["", "/abs.js", "a/../b", "a//b", "[ab].js", "./x"] {
            assert!(ImmutableGlobs::new(&[bad]).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn only_bundler_shaped_hydrate_names_are_content_hashed() {
        for k in ["home.a1b2c3d4.js", "home.chunk-a1b2c3d4.js", "x.AbCd1234_-.js"] {
            assert!(is_content_hashed_hydrate_output(k), "{k}");
        }
        for k in ["app.js", "app.min.js", "home.abc.js", "home.a1b2c3d4.css"] {
            assert!(!is_content_hashed_hydrate_output(k), "{k}");
        }
    }

    #[test]
    fn declared_immutable_reads_the_build_table_and_refuses_bad_patterns() {
        let dir = tempfile::tempdir().unwrap();
        assert!(declared_immutable(dir.path()).unwrap().is_empty(), "no config file");

        fs::write(
            dir.path().join(DECLARATION_FILE),
            "[build]\npublic_dir = \"public\"\nimmutable = [\"*_bg.wasm\"]\n[sources.x]\nscope = \"global\"\n",
        )
        .unwrap();
        assert!(declared_immutable(dir.path()).unwrap().matches("x_bg.wasm"));

        fs::write(dir.path().join(DECLARATION_FILE), "[build]\nimmutable = [\"/abs\"]\n").unwrap();
        assert!(declared_immutable(dir.path()).is_err());

        fs::write(dir.path().join(DECLARATION_FILE), "[build]\nimmutable = \"*.js\"\n").unwrap();
        assert!(declared_immutable(dir.path()).is_err(), "a bare string is not a list");
    }

    fn js_body(n: usize) -> Vec<u8> {
        "export const value = 'repetitive text compresses well';\n".repeat(n).into_bytes()
    }

    #[test]
    fn finalize_indexes_marks_declared_files_and_writes_smaller_variants() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("app-0123abcd.js"), js_body(200)).unwrap();
        fs::write(root.join("index.html"), b"<html>tiny</html>").unwrap();
        fs::write(root.join("logo.png"), vec![7u8; 4096]).unwrap();

        let index = finalize_served_dir(root, &|rel| rel.starts_with("app-")).unwrap();

        let js = &index.assets["app-0123abcd.js"];
        assert!(js.immutable);
        assert_eq!(js.encodings, vec![Encoding::Br, Encoding::Gzip]);
        assert_eq!(js.sha256, format!("{:x}", Sha256::digest(js_body(200))));
        let br = fs::read(root.join("app-0123abcd.js.br")).unwrap();
        let mut decoded = Vec::new();
        brotli::BrotliDecompress(&mut &br[..], &mut decoded).unwrap();
        assert_eq!(decoded, js_body(200), "the variant must decode to the identity bytes");

        // Under MIN_COMPRESS_BYTES, and an incompressible type: no variants.
        assert!(index.assets["index.html"].encodings.is_empty());
        assert!(!index.assets["index.html"].immutable);
        assert!(index.assets["logo.png"].encodings.is_empty());
        assert!(!root.join("logo.png.br").exists());

        // The index itself and the variants are not assets.
        assert_eq!(index.assets.len(), 3);
        let on_disk = AssetIndex::parse(&fs::read(root.join(ASSET_INDEX_FILE)).unwrap()).unwrap();
        assert_eq!(on_disk, index);
        assert!(is_finalize_artifact(root, "app-0123abcd.js.gz"));
        assert!(is_finalize_artifact(root, ASSET_INDEX_FILE));
        assert!(!is_finalize_artifact(root, "app-0123abcd.js"));
    }

    #[test]
    fn refinalizing_reuses_variants_for_unchanged_bytes_and_replaces_them_for_changed_ones() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.js"), js_body(100)).unwrap();
        finalize_served_dir(root, &|_| false).unwrap();

        // Plant a sentinel in the variant: an unchanged source must keep it
        // (proof nothing was recompressed).
        fs::write(root.join("a.js.br"), b"sentinel").unwrap();
        finalize_served_dir(root, &|_| false).unwrap();
        assert_eq!(fs::read(root.join("a.js.br")).unwrap(), b"sentinel");

        // Changed bytes ⇒ fresh variant.
        fs::write(root.join("a.js"), js_body(150)).unwrap();
        finalize_served_dir(root, &|_| false).unwrap();
        let mut decoded = Vec::new();
        brotli::BrotliDecompress(&mut &fs::read(root.join("a.js.br")).unwrap()[..], &mut decoded)
            .unwrap();
        assert_eq!(decoded, js_body(150));

        // Shrunk below the threshold ⇒ the variants this function made are removed.
        fs::write(root.join("a.js"), b"x").unwrap();
        let index = finalize_served_dir(root, &|_| false).unwrap();
        assert!(index.assets["a.js"].encodings.is_empty());
        assert!(!root.join("a.js.br").exists());
        assert!(!root.join("a.js.gz").exists());
    }

    #[test]
    fn a_deleted_source_takes_its_variants_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("gone.js"), js_body(100)).unwrap();
        fs::write(root.join("kept.js"), js_body(100)).unwrap();
        finalize_served_dir(root, &|_| false).unwrap();
        assert!(root.join("gone.js.br").exists());

        fs::remove_file(root.join("gone.js")).unwrap();
        let index = finalize_served_dir(root, &|_| false).unwrap();

        assert!(!root.join("gone.js.br").exists());
        assert!(!root.join("gone.js.gz").exists());
        assert_eq!(index.assets.keys().collect::<Vec<_>>(), vec!["kept.js"]);
    }

    #[test]
    fn a_shipped_archive_with_no_identity_sibling_is_an_asset_not_a_variant() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.tar.gz"), vec![1u8; 2048]).unwrap();
        let index = finalize_served_dir(dir.path(), &|_| false).unwrap();
        assert!(index.assets.contains_key("data.tar.gz"));
    }

    #[test]
    fn component_output_finalizes_html_and_hydrate_roots_of_a_mesofact_build() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join(DECLARATION_FILE), "[build]\nimmutable = [\"img/*\"]\n").unwrap();
        let out = project.path().join("dist");
        fs::create_dir_all(out.join("html/img")).unwrap();
        fs::create_dir_all(out.join("hydrate")).unwrap();
        fs::write(out.join("html/index.html"), js_body(50)).unwrap();
        fs::write(out.join("html/img/a.png"), b"png").unwrap();
        fs::write(out.join("hydrate/home.a1b2c3d4.js"), js_body(50)).unwrap();
        fs::write(out.join("hydrate/polyfill.js"), js_body(50)).unwrap();

        finalize_component_output(project.path(), &out).unwrap();

        let html = AssetIndex::parse(&fs::read(out.join("html").join(ASSET_INDEX_FILE)).unwrap()).unwrap();
        assert!(html.assets["img/a.png"].immutable);
        assert!(!html.assets["index.html"].immutable);
        let hydrate =
            AssetIndex::parse(&fs::read(out.join("hydrate").join(ASSET_INDEX_FILE)).unwrap()).unwrap();
        assert!(hydrate.assets["home.a1b2c3d4.js"].immutable);
        assert!(!hydrate.assets["polyfill.js"].immutable);
        assert!(!out.join(ASSET_INDEX_FILE).exists(), "a mesofact build's dist/ root is not served");
    }

    #[test]
    fn etags_differ_per_representation() {
        let e = AssetEntry { sha256: "ab".into(), size: 1, immutable: false, encodings: vec![] };
        assert_eq!(e.etag(None), "\"ab\"");
        assert_eq!(e.etag(Some(Encoding::Br)), "\"ab.br\"");
        assert_eq!(e.etag(Some(Encoding::Gzip)), "\"ab.gzip\"");
    }
}
