//! The **bundle↔runtime contract** (R746-F6, W272 §7): a version for the
//! interface between a bundle and whatever binary serves it.
//!
//! Before this, the only version in the format was
//! [`SCHEMA_VERSION`](crate::SCHEMA_VERSION) — the wire shape of
//! `manifest.toml`. That is a fraction of the real interface. A runtime also
//! has to know where in the tree to find routes and assets, how it will be
//! forked, and what `bins/` means. None of that was stated anywhere, which is
//! why `runtime = "mesofact/0.8.18"` could only ever be an exact pin: a range
//! like `mesofact ^0.8` asserts that every 0.8.x can serve this bundle, and
//! nothing existed for that assertion to be *about*.
//!
//! So: a runtime **advertises** the contract versions it implements (recorded
//! as `contract` on its published `RuntimeAssetManifest`, under the `store`
//! feature), a bundle **requires** one
//! ([`BundleManifest::requires_contract`](crate::BundleManifest::requires_contract)), and
//! resolution refuses the pair when the advertised set doesn't contain the
//! required version. Product semver (`mesofact 0.8.20`) stays a human-facing
//! hint layered on top rather than the thing resolution trusts.
//!
//! # Contract version 1
//!
//! Four clauses. A change to **any** of them that an existing runtime would
//! get wrong is a new contract version; a change no existing runtime can
//! observe is not.
//!
//! 1. **Manifest schema.** `manifest.toml` at the bundle root, parsing as
//!    [`BundleManifest`](crate::BundleManifest) at
//!    [`SCHEMA_VERSION`](crate::SCHEMA_VERSION) `= 1`: `schema_version`,
//!    `name`, `runtime`, `requires_contract`, and a `[content]` table of
//!    bundle-relative path → BLAKE3.
//! 2. **App tree layout.** Everything the runtime reads lives under `app/`:
//!    `app/mesofact.routes.ts` (routes + config), `app/mesofact.config.toml`
//!    (optional `[publish]` block for a `--revalidate` receiver),
//!    `app/dist/**` (built TS + rendered assets), and each route's declared
//!    `data_inputs` staged at `app/<rel>` — resolved against `<bundle>/app`
//!    as the workload root, not against the machine that built it.
//! 3. **Entrypoint calling convention.** The resolved binary is forked as
//!    `<bin> serve --bundle <bundle-dir> --listen <addr>`. `serve` is a
//!    *subcommand*: the published asset is the whole mesofact binary, and one
//!    that takes `--bundle` as `argv[1]` exits on an unknown argument before
//!    it ever binds.
//! 4. **`bins/` and sidecars.** In a self-contained bundle the runtime is
//!    `bins/<triple>/serve`; sidecars are `bins/<triple>/<name>` and `serve`
//!    is reserved. A vanilla bundle carries no `bins/` at all and resolves
//!    both from the node runtime-asset tier instead.
//!
//! # Bumping it
//!
//! Add the new version to [`IMPLEMENTED_CONTRACTS`], move
//! [`BUNDLE_CONTRACT_VERSION`] to it, and add a row to the compatibility
//! matrix (`tests/contract_matrix.rs`). The matrix has a gate test that fails
//! when a known version has no row — a contract version nothing exercises is
//! a comment, and the matrix is also what makes it safe to *widen* a bundle's
//! accepted set later, because it is the evidence.
//!
//! Dropping a version from [`IMPLEMENTED_CONTRACTS`] is the breaking move: it
//! strands every published bundle requiring it, and those are immutable.

/// A contract version. Small dense integers, not semver — the whole point is
/// that this is the thing semver ranges would have had to range over.
pub type ContractVersion = u32;

/// The contract version this build **emits** on every bundle it assembles.
pub const BUNDLE_CONTRACT_VERSION: ContractVersion = 1;

/// Every contract version a runtime built from this tree **implements**, and
/// therefore what [`publish_runtime_asset`](crate::publish_runtime_asset)
/// advertises by default.
///
/// A superset of `[BUNDLE_CONTRACT_VERSION]` in general: a runtime keeps
/// serving older bundles long after the assembler stops emitting them, because
/// published bundles are immutable and a node may still be asked to materialize
/// one from years ago.
pub const IMPLEMENTED_CONTRACTS: &[ContractVersion] = &[BUNDLE_CONTRACT_VERSION];

/// What a resolution site demands of the runtime it is about to fork.
///
/// An enum rather than an `Option<ContractVersion>` on purpose: `None` at a
/// call site reads as "nothing to pass" and gets copy-pasted into places that
/// did have something to pass. [`Unchecked`](Self::Unchecked) has to be
/// spelled, and spelling it invites the question of why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractRequirement {
    /// The version the bundle's manifest requires. The resolved runtime must
    /// advertise it.
    Version(ContractVersion),

    /// Resolve without a contract check. The sidecar case: `almanac-feed` is
    /// versioned with yubaba and its interface is its own CLI, not the
    /// bundle↔runtime contract, so holding it to *this* contract's versions
    /// would be a category error. Nothing that resolves a **serve** runtime
    /// may use this.
    Unchecked,
}

impl ContractRequirement {
    /// Whether `advertised` satisfies this requirement.
    pub fn satisfied_by(&self, advertised: &[ContractVersion]) -> bool {
        match self {
            ContractRequirement::Unchecked => true,
            ContractRequirement::Version(v) => advertised.contains(v),
        }
    }
}

/// Render an advertised set for an error message: `1` / `1, 2` / `(none)`.
///
/// `(none)` is reachable — a publisher can record an empty set — and reads
/// far better in a refusal than `[]`.
pub fn describe_contracts(advertised: &[ContractVersion]) -> String {
    if advertised.is_empty() {
        return "(none)".to_string();
    }
    advertised
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The emitted version must be one this tree's runtimes can actually
    /// serve, or every bundle assembled here is born unservable.
    #[test]
    fn this_build_implements_what_it_emits() {
        assert!(IMPLEMENTED_CONTRACTS.contains(&BUNDLE_CONTRACT_VERSION));
    }

    #[test]
    fn satisfaction_is_set_membership() {
        assert!(ContractRequirement::Version(1).satisfied_by(&[1]));
        assert!(ContractRequirement::Version(1).satisfied_by(&[1, 2]));
        assert!(!ContractRequirement::Version(2).satisfied_by(&[1]));
        assert!(!ContractRequirement::Version(1).satisfied_by(&[]));
        // Unchecked resolves against anything, including nothing.
        assert!(ContractRequirement::Unchecked.satisfied_by(&[]));
    }

    #[test]
    fn describe_reads_as_a_list() {
        assert_eq!(describe_contracts(&[]), "(none)");
        assert_eq!(describe_contracts(&[1]), "1");
        assert_eq!(describe_contracts(&[1, 2, 3]), "1, 2, 3");
    }
}
