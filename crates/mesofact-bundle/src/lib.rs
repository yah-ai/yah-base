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
//! schema_version    = 1
//! name              = "yah-marketing"
//! runtime           = "mesofact/0.8.18"   # vanilla: resolve stock runtime from node cache
//! # runtime         = "self"              # custom: bins/<triple>/serve ships in the bundle
//! requires_contract = 1                   # bundle↔runtime interface version (R746-F6)
//!
//! [content]
//! "app/mesofact.routes.ts" = "b3f1…"   # path → blake3, one row per file
//! ```
//!
//! `schema_version` and `requires_contract` version different things and move
//! independently: the first is the wire shape of *this file*, the second is the
//! whole interface a serving binary must implement (see [`contract`]).
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
//!
//! @yah:ticket(R746-F5, "Bundle-only release for CUSTOM mesofact: reuse the serve binary by digest, gated on a recorded runtime contract")
//! @yah:status(review)
//! @yah:at(2026-08-16T04:36:16Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R746)
//! @yah:next("OPERATOR INTENT, and the relay's title under-describes it: bundle-only release must work for CUSTOM mesofact too, not just vanilla. A consumer who changed only templates should re-release without recompiling. A Rust rebuild happens when the Rust side changed — and only then.")
//! @yah:next("GAP 1, the mechanism. assemble_self_bundle / assemble_self_bundle_with take serve_bins as (triple, PathBuf) — always a local file — so a template-only re-release needs the binary present on the assembling machine even when it is byte-identical to the one already in the store. Add a digest form: pin the bin by blake3 and have the assembler reference the blob the previous publish already uploaded, with no local file and no build. The store is append-only and blob-deduped, so the bytes are provably still there and the re-publish uploads only the changed app blobs.")
//! @yah:next("GAP 2, and this is the one that makes GAP 1 safe. BundleRuntime::SelfContained (oss/yah-base/crates/mesofact-bundle/src/lib.rs:164) is a UNIT variant — it records nothing about what the carried binary was built against. That is sound today only because bins and app are assembled in one moment from one tree; reuse across assemblies destroys the guarantee. SelfContained must carry the contract: at minimum the mesofact library version the binary was built against, plus the bundle manifest schema version it can read.")
//! @yah:next("THE RULE that falls out: reuse is permitted when the app's DECLARED mesofact dependency equals the version recorded on the reused binary. Different -> refuse the reuse and dispatch the build (R746-F2's arm). Declared, never diffed — same discipline as the vanilla/self split itself. This is precisely the operator's framing: bundle-only works as long as the consumer has not messed up the mesofact library dependency, and the recorded contract is what makes messing it up detectable instead of silent.")
//! @yah:next("SHIP BOTH HALVES TOGETHER. Landing the digest-reuse without the recorded contract is strictly worse than today: it makes a silent binary/bundle mismatch reachable for the first time, and the symptom would be a served site failing at runtime on a node, not a failed apply.")
//! @yah:next("REFINEMENT WORTH DECIDING IN-TICKET, not before: crate version is a conservative PROXY for the real contract, which is the bundle manifest schema plus the app-tree layout (mesofact.routes.ts + dist/) plus the SSR entrypoint calling convention. Exact-match refuses reuse across a patch bump that changed nothing relevant. Start exact — wrong-and-rebuilds is cheap, wrong-and-reuses is a broken site — and consider a declared compat range once the surface is actually versioned.")
//! @yah:verify("Change only a template in a custom service, sync, and the release completes with NO cargo invocation and NO local serve binary present — the new bundle references the previous binary blob by digest. This is the ticket's whole point; prove it on a machine that has never built that binary.")
//! @yah:verify("The re-publish uploads only the changed app blobs. Read it off the publish output rather than inferring it from dedupe existing.")
//! @yah:verify("Bump the service's mesofact dependency, change nothing else, and sync: the reuse is REFUSED and a build is dispatched. A reuse that silently succeeds here is the defect this ticket exists to prevent.")
//! @yah:verify("A bundle published before this change (SelfContained with no recorded contract) still materializes and serves — it just cannot be a reuse SOURCE, since nothing recorded what it was built against.")
//! @yah:assumes("Tier: Wizard — it puts a compatibility contract into a content-addressed format that is already published and immutable, and the failure mode of getting it wrong is a live site serving from a mismatched runtime rather than a red build.")
//! @yah:next("SUPERSEDES the exact-version-match framing above (operator direction 2026-08-11, written up as W272 section 7). A bundle names a compatible SET of runtimes rather than one, tight to loose: an exact blake3 pin, a semver range over a stock build, a semver range over an org/project-namespaced CUSTOM build, or a capability constraint. Vanilla and self stop being two shapes and become two narrowings of one expression, with self as the degenerate tightest case.")
//! @yah:next("CONSEQUENCE for this ticket: the reuse gate is no longer equality on a recorded crate version, it is SATISFACTION of the bundle's declared constraint by the candidate runtime. Reuse when the previously built binary still satisfies what the app now declares; rebuild when it does not. Same discipline — declared, never diffed — but it stops refusing reuse across a patch bump that changed nothing relevant.")
//! @yah:next("ORDERING, and it is not optional: a range is only as good as the contract it ranges over. Land R746-F6 (versioned bundle-runtime contract) FIRST, or ship this ticket pinned to exact digests only. A semver range with nothing enforcing compatibility is unenforced optimism whose failure surfaces on a node at serve time — after the apply that caused it reported success.")
//! @yah:handoff("SHIPPED PINNED-TO-EXACT-DIGESTS ONLY, per the ticket's own ordering escape hatch (F6's semver-range contract is NOT landed or required by this). GAP1+GAP2 both closed.")
//! @yah:handoff("GAP2 (the contract): BundleRuntime::SelfContained is now a struct variant carrying built_against: Option<String> — the yah_qed::build_context::source_context_fingerprint of the source tree every bins/<triple>/serve in the bundle was compiled from. Wire form self / self/<fp>, old bundles with no fp still parse+serve, they just can't be a reuse SOURCE. oss/yah-base/crates/mesofact-bundle/src/lib.rs.")
//! @yah:handoff("GAP1 (the mechanism): new ServeBinSource enum {Local(PathBuf), Pinned(BundleHash)} — assemble_self_bundle_with takes serve_bins as (triple, ServeBinSource) + a built_against param. A Pinned entry costs no local read/copy; publish_bundle already skipped-on-head for any hash the store holds (verified with a new store.rs test proving publish never touches a local path that was never written). oss/yah-base/crates/mesofact-bundle/src/assemble.rs.")
//! @yah:handoff("New by-name pointer bundles/current/<workload-name>.toml (pointer.rs, write_current_digest/read_current_digest) + fetch_manifest (manifest-object-only read, no blob download) — what a reuse decision on a machine with zero local state reads to find a candidate.")
//! @yah:handoff("CLI wiring: serve_build::resolve_serve_build_with_reuse computes each declared triple's fingerprint (reusing F2's plan_triple), checks it against the previously-published bundle's recorded built_against + per-triple bins hash; on a full match every triple is Pinned with ZERO dispatch and no local-cache lookup — proves the 'never built here' case unit-testably. Any mismatch/miss falls through to F2's existing Cached/Built tiers untouched. deploy_mesofact_bundle opens the bucket once, reads the pointer before assembly, writes it after a successful publish (never before — a reader must only ever see a digest that's provably in the store).")
//! @yah:handoff("The serve_bins hand-path escape hatch and yah cloud bundle build (CLI one-shot) stay Local-only / built_against=None by design — no fingerprint to reuse against.")
//! @yah:handoff("Extra: refactored materialize_bundle to share fetch_manifest's fetch+verify — no behavior change, one fewer copy of the verification logic.")
//! @yah:verify("cargo test -p yah-mesofact-bundle --all-features (run from oss/yah-base): 54 pass, 0 fail — includes the pinned-entry publish/assemble/round-trip tests and the pointer tests.")
//! @yah:verify("cargo test -p yah --lib serve_build:: : 15 pass, 0 fail — 5 new: matching-contract reuse dispatches nothing AND needs no local cache dir at all (the literal 'machine that never built it' case), stale contract forces a build, missing-triple forces a build, first-ever-sync builds and records a fingerprint, PreviousBundle::from_manifest round-trips a real manifest.")
//! @yah:verify("cargo test -p yah --lib cloud:: -- bundle: 126 pass, 0 fail (bundle_assembly_tests + serve_build:: together) — confirms assemble_component_bundle*'s new ServeBinSource-typed signature didn't break any existing call site.")
//! @yah:verify("cargo check -p yah --lib: clean, 0 errors (18 pre-existing warnings elsewhere, none touched by this change).")
//! @yah:gotcha("NOT LIVE-VERIFIED end to end — same gap R746-F2 was accepted at review with (its own gotcha: 'VERIFY #2 HAS NOT RUN LIVE, and cannot yet... blocked on relocating containerd to /data on the arm workers'). yah-marketing is going vanilla (R746-T3), so there is still no live custom (runtime=self) bundle-tier service to sync from a real machine — R746-S4 tracks finding one. This ticket's reuse arm rides the exact same serve_build declaration F2's live gap already blocks on; nothing here narrows or widens that gap.")
//! @yah:gotcha("R746-F6 (versioned bundle-runtime contract / compat ranges) is NOT required by this and was deliberately NOT started — the ordering note in the ticket explicitly allows shipping exact-digest-only first. If F6 lands later, the natural extension point is BundleRuntime::SelfContained::built_against and the exact-equality check in resolve_serve_build_with_reuse — both isolated to one file/one function.")
//!
//! @yah:ticket(R746-F6, "Version the bundle-runtime contract so a compatibility range means something a runtime is held to")
//! @yah:status(review)
//! @yah:at(2026-08-16T23:35:10Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R746)
//! @yah:next("PREREQUISITE for R746-F5's constraint expression. The interface between a bundle and the binary that serves it is currently undeclared: the manifest carries schema_version = 1 and nothing states what a runtime must implement. So mesofact ^0.8 is a claim nobody is held to.")
//! @yah:next("The interface, enumerated (W272 section 7): (1) the bundle manifest schema; (2) the app/ tree layout the runtime reads — mesofact.routes.ts plus dist/; (3) the SSR entrypoint calling convention; (4) the sidecar and bins/ contract from assemble_self_bundle_with. Give that set a version. A runtime ADVERTISES which contract versions it implements; a bundle REQUIRES one; mesofact semver stays a human-facing hint layered on top rather than the thing resolution trusts.")
//! @yah:next("Test shape that makes it real rather than declarative: a compatibility matrix that materializes and SERVES a fixture bundle at contract version N against every runtime claiming N. A contract version nothing exercises is a comment. This is also what makes it safe to widen a range later — the matrix is the evidence.")
//! @yah:verify("A runtime that does not implement the contract version a bundle requires is REFUSED at apply time, naming both versions. It must not reach a node and fail at serve time — that is the failure mode the whole ticket exists to move earlier.")
//! @yah:verify("The matrix runs in CI and a new contract version cannot land without a row.")
//! @yah:assumes("Tier: Wizard — defining a compatibility interface for an already-published immutable format; the cost of drawing the boundary wrong is paid by every future runtime and bundle.")
//! @yah:handoff("LANDED at contract version 1. New pub mod oss/yah-base/crates/mesofact-bundle/src/contract.rs is the NORMATIVE text: ContractVersion, BUNDLE_CONTRACT_VERSION (what this build emits), IMPLEMENTED_CONTRACTS (what a runtime built here implements), ContractRequirement (Version | Unchecked), describe_contracts. Its doc enumerates the four clauses of v1 and the bump procedure. W272 section 7 now points at it rather than restating it.")
//! @yah:handoff("THE THREE WIRE CHANGES. (1) BundleManifest.requires_contract, stamped by assemble_bundle - the single site every shape funnels through, so no caller can under-declare it. (2) RuntimeAssetManifest.contract (a Vec) - the advertisement, defaulted to [1] for assets published before the field, which is a fact about every binary predating v2 rather than an optimistic guess. (3) publish_runtime_asset takes the advertised set as a REQUIRED param and refuses an empty one; the yah cloud bundle publish-runtime --contract flag defaults it to IMPLEMENTED_CONTRACTS, which is right when the binary came from this tree and silently wrong for a cross-built binary from an older checkout - so the assumption sits one layer up where an operator can override it.")
//! @yah:handoff("DIGEST STABILITY, the one subtle thing a reviewer must check. requires_contract is fed into BundleManifest::digest ONLY when it is not 1. Feeding it unconditionally would re-hash every manifest already in R2, and fetch_manifest verifies a fetched manifest against the digest it was stored under - so every live bundle would stop resolving at once. The skip is permanent, not a placeholder. Pinned by the test adding_requires_contract_did_not_move_any_published_digest, which spells the pre-F6 field sequence out long-hand rather than pinning a hex literal nobody can audit.")
//! @yah:handoff("ENFORCEMENT, two points. PRIMARY is apply time: require_runtime_contract surveys every published triple for the runtime a vanilla bundle names and fails the apply naming both versions. Wired into deploy_mesofact_bundle (app/yah/cli/src/cloud.rs) between assembly and publish, so a refusal uploads nothing. One unsatisfied triple fails the whole apply even for machines that would not have used it - one runtime ref is one release, and a mixed-contract publish otherwise relocates the failure onto whichever node is the odd one out, at serve time. Nothing published at all is NOT a contract failure (that is RuntimeAssetMissing, R746-F1) - it prints a note. BACKSTOP is kamaji: materialize_and_resolve_serve reads requires_contract off the materialized manifest.toml (covered by the digest, so it cannot disagree with the bundle, and no new wire field to keep in sync) and passes it to ensure_runtime_asset.")
//! @yah:handoff("THE MATRIX (the half that makes this real rather than declarative). NEW oss/yah-base/crates/mesofact-bundle/tests/contract_matrix.rs: one row per known contract version, each taken through assemble -> publish -> materialize -> resolve -> FORK against a stand-in runtime advertising it, asserting the page comes out. The stand-in is a shell script, not a real mesofact serve, because this crate is the V8-less assembly half and linking the runtime would invert the dependency it exists to avoid - it exercises exactly the clauses that are this crate's to keep (manifest parse, app/ tree layout, argv shape) and does not pretend to cover the runtime's rendering.")
//! @yah:handoff("DISCOVERED WORK, done in this pass and wider than the title. (1) NOTHING in oss/yah-base has ever run in CI - it is its own cargo workspace, consumed by the root only as a [patch.crates-io] path source, and cargo builds a patched path dep but never runs its tests. So R746-F1/F5's 54+ tests were invisible to the bar. New bundle-contract-matrix step in .yah/qed/check.toml closes that for this one package (scoped deliberately: making the matrix a gate, not quietly adopting the whole workspace). Verified live via yah qed pipelines. (2) Fixed an unresolved [`SERVE_BIN`] intra-doc link in runtime.rs (mod asset has no such name in scope). (3) Made mod contract public - W272 points at its doc as normative, so a runtime author outside this repo has to be able to read it.")
//! @yah:handoff("THE SIDECAR EXEMPTION is narrow and has to be chosen. almanac-feed is versioned with yubaba and its interface is its own CLI, not the bundle-runtime contract, so kamaji resolves it with ContractRequirement::Unchecked. Spelled as an enum variant rather than Option::None precisely so it cannot be copy-pasted into a serve-runtime call site without someone noticing. Only a serve runtime is contract-checked.")
//! @yah:gotcha("A WARM CACHE HIT SKIPS THE CONTRACT CHECK, deliberately. ensure_runtime_asset returns early when the binary is already at the cache path, before any manifest GET. Checking there would cost a network round-trip per deploy - exactly the round-trip the shared runtime tier exists to avoid, pinned by a_second_resolve_at_the_same_version_is_a_cache_hit - and would buy only the case of a LIVE version repointed to bytes advertising a different set, which publish_runtime_asset already documents as the thing not to do (publish a new version instead). Documented at the early-return site.")
//! @yah:gotcha("STILL OPEN, and it is F5's to consume: the manifest field is ONE required version, not the compatible SET the W272 section 7 grammar describes (blake3 pin / semver over stock / semver over a namespaced custom build / capability constraint). That is fine today because F5 shipped pinned to exact digests under its own ordering escape hatch, so nothing depends on a range yet. What this ticket delivers is the thing such a range would range over - which was the stated prerequisite. Widening the field is a separate ticket and now has a matrix to be safe against.")
//! @yah:verify("cargo test -p yah-mesofact-bundle --all-features --locked (run from the repo root, the exact argv the new CI step uses): 73 pass, 0 fail. 70 lib + 3 matrix. New lib tests cover the refusal naming both versions, a runtime advertising a set serving every version in it, the Unchecked sidecar path, a pre-F6 asset manifest defaulting to [1] and still serving, an empty advertised set refused at publish, the apply-gate survey, one-stale-triple-fails-all, unpublished-surveys-empty, and the digest-stability proof.")
//! @yah:verify("cargo test -p kamaji-bin --features bundle-serving (from oss/kamaji): 240 pass, 0 fail, including the new end-to-end a_runtime_that_does_not_implement_the_bundles_contract_fails_the_deploy - the deploy reaches WorkloadState::Failed, the detail names both contract versions, and no runtime binary is left in the cache. cargo check -p kamaji-bin --features bundle-serving --all-targets: clean.")
//! @yah:verify("cargo check -p yah --lib: exit 0, clean - covers the apply-time gate in deploy_mesofact_bundle and the new --contract flag on yah cloud bundle publish-runtime. The 14 warnings in that run are all pre-existing and in peers in-flight files (cli.rs, mesh.rs, mcp/tools.rs, rollout/apply.rs), none from this change. cargo doc -p yah-mesofact-bundle --all-features --no-deps: no warnings from any new doc; the four remaining unclosed-HTML-tag warnings are inside R746-F5s own annotation block and are not mine to edit.")
//! @yah:verify("Verify #2 of the ticket, both halves: the matrix runs in CI as the bundle-contract-matrix step of .yah/qed/check.toml, which .github/workflows/ci.yml runs via `yah qed run check` on every dispatch (confirmed the step parses and is live with `yah qed pipelines --verbose`); and a new contract version cannot land without a row, enforced by every_known_contract_version_has_a_row, which fails in both directions - a version in IMPLEMENTED_CONTRACTS with no row, and a row naming a version nothing implements.")
//! @yah:gotcha("oss/yubaba CANNOT be test-compiled right now, for a reason unrelated to this ticket: a peers uncommitted TransformRecipe.admission field (untracked oss/yah-base/crates/workload-spec/src/admission.rs + oss/qed/crates/velveteen-exec/src/admission.rs, the R555-F4 signed-transform-admission work) leaves crates/cloud/src/reconciler/lowering_golden.rs:48 at E0063. The two one-line requires_contract additions this ticket made to that workspace (reconciler/publish_beacon.rs, reconciler/bundle_store.rs test fixtures) DO compile - they would have surfaced in the same rustc pass and did not. Left alone per shared-tree: not my ticket, not my files.")
//! @yah:verify("cargo test -p yah --lib -- serve_build:: cloud::bundle : 28 pass, 0 fail. Confirms the apply-gate insertion and the new ServeBinSource/manifest field did not disturb assemble_component_bundle*'s call sites (bundle_assembly_tests) or R746-F5's reuse resolution (serve_build::).")
//! @yah:gotcha("NOT INSTALLED, deliberately. The CLI leg (the --contract flag and the apply gate in yah cloud apply) does not reach the operator shell until cargo xtask install runs, per app/yah/cli/CLAUDE.md. I did not run it: on this camp the working tree currently carries four other sessions uncommitted edits (app/yah/cli/src/mcp/tools.rs, cli.rs, crates/yah/policy-dsl, oss/qed velveteen-exec, the R555-F4 admission work), so an install right now would snapshot all of that into ~/.local/bin/yah and into the app bundle. R746-F1s own install already hit exactly this (its verify records a W298 SUSPECT RESULT from two peer edits landing mid-build). One line for the operator: install when the tree is quieter, or accept the peer WIP knowingly.")
//! @yah:handoff("COMPLETE at contract version 1. Both ticket verify criteria met: a runtime that does not implement the contract a bundle requires is refused at apply time naming both versions, and the matrix runs in CI with a gate that blocks a new contract version landing without a row. Full detail in the handoff/verify/gotcha entries above.")

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Emitting side: walk a built app into a bundle tree + manifest. Pure
/// `std::fs` + blake3 + toml, so it stays in the default (types-only) feature
/// set — `mesofact-build` re-exports it, and the V8-less yah CLI can assemble a
/// bundle without linking the build toolchain (R599-T5).
mod assemble;
pub use assemble::{
    assemble_bundle, assemble_self_bundle, assemble_self_bundle_with, assemble_vanilla_bundle,
    collect_dir, BundleFile, ServeBinSource,
};

#[cfg(feature = "store")]
mod store;
#[cfg(feature = "store")]
pub use store::{fetch_manifest, materialize_bundle, publish_bundle, BundleCache, PublishReport};

/// Node runtime-asset tier (R746-F1): binaries a vanilla bundle resolves by
/// name instead of carrying — the shared `serve` runtime, and (R746-T3) the
/// `almanac-feed` sidecar. [`RuntimeRef`] (the cache-key shape) is types-only;
/// the fetch/publish half needs `store`.
mod runtime;
pub use runtime::{check_bin_name, FEED_BIN, RuntimeRef, SERVE_BIN};
#[cfg(feature = "store")]
pub use runtime::{
    ensure_runtime_asset, publish_runtime_asset, published_runtime_assets, require_runtime_contract,
    PublishedRuntime, RuntimeAsset, RuntimeAssetManifest, RUNTIME_ASSET_SCHEMA_VERSION,
};

/// By-name pointer to the most recently published bundle per workload
/// (R746-F5) — what a reuse-aware assembly reads to find a candidate to pin
/// by digest instead of building.
#[cfg(feature = "store")]
mod pointer;
#[cfg(feature = "store")]
pub use pointer::{current_pointer_key, read_current_digest, write_current_digest};

/// The versioned bundle↔runtime contract (R746-F6): what a runtime must
/// implement to serve a bundle, and the enforcement points that hold it to it.
///
/// Public because its doc comment is the *normative* statement of the contract
/// — W272 §7 points here rather than restating it, and a runtime author outside
/// this repo needs to be able to read it.
pub mod contract;
pub use contract::{
    describe_contracts, ContractRequirement, ContractVersion, BUNDLE_CONTRACT_VERSION,
    IMPLEMENTED_CONTRACTS,
};

/// Bundle-manifest schema version. Bumping this is a wire-format change: the
/// materialize side rejects a manifest whose `schema_version` it does not know.
///
/// Narrower than [`BUNDLE_CONTRACT_VERSION`]: this versions the shape of
/// `manifest.toml` only, which is clause 1 of four in the contract.
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

    /// Filesystem or object-store failure. Constructed by the assemble path
    /// (always available) and by the `store` feature's publish/materialize.
    #[error("bundle io: {0}")]
    Io(String),

    /// A blob referenced by the manifest was absent from the store during
    /// materialize (only constructed under `store`).
    #[error("missing blob {key} for path {path:?} while materializing bundle")]
    MissingBlob { key: String, path: String },

    /// No runtime asset is published for the runtime × triple a vanilla bundle
    /// named (R746-F1). Deliberately verbose: this is the one failure an
    /// operator hits by declaring a `runtime_version` nothing has built yet, and
    /// the fix is entirely in the version and the location, so both are in the
    /// message rather than in a log line somewhere upstream.
    #[error(
        "no serve runtime asset published for {runtime} on {triple} \
         (looked for {location}); a vanilla bundle resolves its runtime by name \
         and will not fall back to any other binary on this node"
    )]
    RuntimeAssetMissing {
        runtime: String,
        triple: String,
        location: String,
    },

    /// A runtime does not implement the contract version a bundle requires
    /// (R746-F6). Both versions are in the message because the fix is a choice
    /// between them — publish a newer runtime, or rebuild the bundle against an
    /// older contract — and an operator cannot make it holding only one.
    #[error(
        "runtime {runtime} on {triple} implements bundle contract version(s) {advertised} \
         but this bundle requires contract version {required} — refusing to serve it \
         with a runtime that does not implement the interface it was built against"
    )]
    ContractUnsatisfied {
        runtime: String,
        triple: String,
        required: ContractVersion,
        advertised: String,
    },
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
/// Serialized as a single string: `"self"` / `"self/<built_against>"` for a
/// bundle that ships its own `bins/<triple>/serve`, or `"mesofact/<version>"`
/// for a vanilla bundle that resolves the stock `mesofact serve` runtime from
/// the node's runtime cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleRuntime {
    /// Vanilla: resolve the stock `mesofact serve` runtime asset of this
    /// version from the node cache. No binaries in the bundle.
    Mesofact { version: String },

    /// Custom: the bundle carries `bins/<triple>/serve` and is served by its
    /// own binary. No node runtime asset is resolved.
    SelfContained {
        /// R746-F5: the reuse contract. A content fingerprint
        /// (`yah_qed::build_context::source_context_fingerprint`) of the
        /// source tree every `bins/<triple>/serve` in this bundle was
        /// compiled from — `None` when the assembly didn't (or couldn't)
        /// record one, or when the triples in this bundle came from more than
        /// one fingerprint.
        ///
        /// A later assembly may reuse a *previous* bundle's serve binary by
        /// digest (skipping the build) only when its own fingerprint equals
        /// the one recorded here — exact match, not a semver range (R746-F6
        /// supersedes this with a versioned compatibility expression; until
        /// that lands, a bundle with no recorded fingerprint can still be
        /// materialized and served, it just cannot be a reuse SOURCE).
        built_against: Option<String>,
    },
}

impl BundleRuntime {
    /// The wire string form (`"self"`, `"self/<built_against>"`, or
    /// `"mesofact/<version>"`).
    pub fn as_wire(&self) -> String {
        match self {
            BundleRuntime::SelfContained {
                built_against: None,
            } => "self".to_string(),
            BundleRuntime::SelfContained {
                built_against: Some(fp),
            } => format!("self/{fp}"),
            BundleRuntime::Mesofact { version } => format!("mesofact/{version}"),
        }
    }

    /// Parse the wire string form.
    pub fn parse(s: &str) -> Result<Self, BundleError> {
        if s == "self" {
            return Ok(BundleRuntime::SelfContained {
                built_against: None,
            });
        }
        if let Some(fp) = s.strip_prefix("self/") {
            if !fp.is_empty() {
                return Ok(BundleRuntime::SelfContained {
                    built_against: Some(fp.to_string()),
                });
            }
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

    /// Whether the bundle ships its own serve binaries (`runtime = "self"` /
    /// `"self/<built_against>"`).
    pub fn is_self_contained(&self) -> bool {
        matches!(self, BundleRuntime::SelfContained { .. })
    }

    /// A self-contained runtime with no recorded contract — the shape every
    /// call site used before R746-F5, and still the right one for a one-shot
    /// local assembly (`yah cloud bundle build`) that isn't going through the
    /// fingerprint-tracked sync path.
    pub fn self_contained() -> Self {
        BundleRuntime::SelfContained {
            built_against: None,
        }
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

    /// The bundle↔runtime contract version this bundle was built against
    /// (R746-F6). Whatever serves it must advertise this version; see
    /// [`contract`] for what the four clauses of version 1 are.
    ///
    /// Defaulted rather than required so a bundle published before the field
    /// existed still parses — and parses as exactly what it is, since every
    /// such bundle was assembled against contract 1. That default is also what
    /// keeps their digests intact; see [`BundleManifest::digest`].
    ///
    /// Declared before `content` because TOML puts a table's keys after it —
    /// a scalar field serialized after `[content]` would land inside the table.
    #[serde(default = "default_requires_contract")]
    pub requires_contract: ContractVersion,

    /// Every file the bundle carries, keyed by its path *within the bundle*
    /// (e.g. `"app/dist/index.html"`, `"bins/x86_64-unknown-linux-musl/serve"`)
    /// mapped to its BLAKE3 content hash. Sorted (BTreeMap) so the manifest
    /// serialization — and therefore the digest — is deterministic.
    #[serde(default)]
    pub content: BTreeMap<String, BundleHash>,
}

/// Contract version assumed for a manifest that predates the field. Every
/// bundle published before R746-F6 was assembled against contract 1.
fn default_requires_contract() -> ContractVersion {
    1
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
    ///
    /// **`requires_contract` is fed only when it is not 1** (R746-F6). It is
    /// identity-affecting — two bundles differing only in the interface they
    /// demand are different bundles — but feeding it unconditionally would
    /// re-hash every *already published* manifest to a new value, and
    /// [`fetch_manifest`] verifies a fetched manifest against the digest it was
    /// stored under. Every such manifest defaults to 1, so skipping the default
    /// leaves their encoding byte-identical while any bundle requiring contract
    /// ≥ 2 still gets a distinct digest. The skip is not a place-holder to tidy
    /// up later: the manifests it protects are immutable and permanent.
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
        if self.requires_contract != 1 {
            feed(b"requires_contract");
            feed(&self.requires_contract.to_le_bytes());
        }
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
            requires_contract: BUNDLE_CONTRACT_VERSION,
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
        assert_eq!(BundleRuntime::parse("self").unwrap(), BundleRuntime::self_contained());
        assert_eq!(
            BundleRuntime::parse("mesofact/0.8.18").unwrap(),
            BundleRuntime::Mesofact { version: "0.8.18".into() }
        );
        assert_eq!(BundleRuntime::self_contained().as_wire(), "self");
        assert_eq!(
            BundleRuntime::Mesofact { version: "1.2.3".into() }.as_wire(),
            "mesofact/1.2.3"
        );
        // Malformed runtimes reject.
        assert!(BundleRuntime::parse("mesofact/").is_err());
        assert!(BundleRuntime::parse("caddy").is_err());
    }

    /// R746-F5: a recorded fingerprint round-trips through `"self/<fp>"`, and
    /// a bundle carrying one is still self-contained.
    #[test]
    fn runtime_round_trips_the_recorded_contract() {
        let fp = "a".repeat(64);
        let rt = BundleRuntime::SelfContained {
            built_against: Some(fp.clone()),
        };
        assert_eq!(rt.as_wire(), format!("self/{fp}"));
        assert_eq!(BundleRuntime::parse(&rt.as_wire()).unwrap(), rt);
        assert!(rt.is_self_contained());
        assert!(BundleRuntime::parse("self/").is_err());
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
        // No `requires_contract` in the doc shape above — a manifest published
        // before R746-F6 parses as the contract-1 bundle it is.
        assert_eq!(m.requires_contract, 1);
    }

    /// R746-F6, and the reason `digest` skips the default: a manifest already
    /// in the store must keep hashing to the key it was stored under, or
    /// `fetch_manifest`'s digest check rejects it and the site stops serving —
    /// for every bundle published before this field existed, all at once.
    ///
    /// The expected encoding is spelled out here rather than pinned as a hex
    /// literal on purpose. A literal would catch the regression but tell a
    /// reader nothing about *what* the bytes are supposed to be, and nobody can
    /// audit a blake3 by eye; this is the pre-F6 field sequence written out
    /// long-hand, so a diff that starts feeding `requires_contract`
    /// unconditionally fails against something legible.
    #[test]
    fn adding_requires_contract_did_not_move_any_published_digest() {
        let h = "a".repeat(64);
        let pre_f6 = format!(
            r#"
schema_version = 1
name = "yah-marketing"
runtime = "mesofact/0.8.18"

[content]
"app/mesofact.routes.ts" = "{h}"
"#
        );
        let parsed = BundleManifest::from_toml_str(&pre_f6).unwrap();
        assert_eq!(parsed.requires_contract, 1);

        // The exact encoding pre-F6 `digest()` produced: domain tag,
        // schema_version, name, runtime wire string, content count, then each
        // (path, hash) pair — every field length-prefixed, and NO contract
        // field anywhere in it.
        let mut hasher = blake3::Hasher::new();
        let mut feed = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        feed(b"yah-mesofact-bundle/v1");
        feed(&1u32.to_le_bytes());
        feed(b"yah-marketing");
        feed(b"mesofact/0.8.18");
        feed(&1u64.to_le_bytes());
        feed(b"app/mesofact.routes.ts");
        feed(h.as_bytes());
        let pre_f6_digest = hasher.finalize().to_hex().to_string();

        assert_eq!(parsed.digest().as_str(), pre_f6_digest);
    }

    /// Requiring a *different* contract is a different bundle: two otherwise
    /// identical trees that demand different runtime interfaces must not
    /// collide on one digest.
    #[test]
    fn a_higher_contract_requirement_flips_the_digest() {
        let base = sample();
        assert_ne!(
            BundleManifest {
                requires_contract: 2,
                ..sample()
            }
            .digest(),
            base.digest()
        );
    }

    /// The field survives the TOML round trip, and lands *before* `[content]` —
    /// serialized after the table, TOML would read it as a content entry.
    #[test]
    fn requires_contract_round_trips_ahead_of_the_content_table() {
        let m = BundleManifest {
            requires_contract: 7,
            ..sample()
        };
        let text = m.to_toml_string().unwrap();
        assert_eq!(BundleManifest::from_toml_str(&text).unwrap(), m);
        let contract_at = text.find("requires_contract").expect("field is emitted");
        let content_at = text.find("[content]").expect("content table is emitted");
        assert!(
            contract_at < content_at,
            "requires_contract must precede [content], got:\n{text}"
        );
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
            BundleManifest { runtime: BundleRuntime::self_contained(), ..sample() }.digest(),
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
