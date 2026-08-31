//! **The bundle↔runtime compatibility matrix** (R746-F6, W272 §7).
//!
//! One row per contract version this tree knows. Each row takes a fixture
//! bundle *requiring* that version all the way through the real path — assemble
//! → publish → materialize → resolve the runtime asset → fork it — against a
//! stand-in runtime that *advertises* that version, and asserts the page comes
//! out. Then it points the same bundle at a runtime advertising every other
//! known version and asserts the pair is refused.
//!
//! Why a matrix and not a unit test on the predicate: a contract version whose
//! only evidence is a `contains()` check is a comment. The claim being made is
//! "a runtime advertising N can serve a bundle requiring N", and the only thing
//! that establishes it is *serving one*. It is also what makes it safe to widen
//! a bundle's accepted set later — a widened range is a claim about rows, so
//! the rows have to exist first.
//!
//! The stand-in runtime is a shell script rather than a real `mesofact serve`
//! for a deliberate reason: this crate is the V8-less assembly half (see
//! `assemble.rs`), so linking the real runtime here would invert the dependency
//! the whole crate exists to avoid. What the script exercises is exactly the
//! part of the contract that is *this* crate's to keep — the manifest it must
//! parse (clause 1), the `app/` tree it must read (clause 2), and the argv it
//! is forked with (clause 3). It cannot exercise the runtime's own rendering,
//! and does not pretend to.
//!
//! Bumping the contract: add a row here in the same change that adds the
//! version to `IMPLEMENTED_CONTRACTS`. `every_known_contract_version_has_a_row`
//! fails otherwise — that gate is the "a new contract version cannot land
//! without a row" half of this ticket.

#![cfg(all(feature = "store", unix))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;
use yah_mesofact_bundle::{
    assemble_vanilla_bundle, ensure_runtime_asset, materialize_bundle, publish_bundle,
    publish_runtime_asset, BundleManifest, ContractRequirement, ContractVersion, RuntimeRef,
    BUNDLE_CONTRACT_VERSION, IMPLEMENTED_CONTRACTS, SERVE_BIN,
};
use yah_object_store::InMemoryObjectStore;

const TRIPLE: &str = "x86_64-unknown-linux-musl";
const PAGE: &str = "<html><body>yah.dev</body></html>";

/// One row of the matrix: a contract version, plus a runtime that implements it.
struct Row {
    version: ContractVersion,
    /// A stand-in runtime honouring this version's calling convention and app
    /// tree layout. Given `argv` as the contract specifies it, it must print
    /// the bundle's rendered page to stdout.
    runtime_program: &'static str,
}

/// Contract v1's runtime, per `contract.rs`:
///
///   * clause 3 — forked as `<bin> serve --bundle <dir> --listen <addr>`, with
///     `serve` a *subcommand*. A binary taking `--bundle` as `argv[1]` exits on
///     an unknown argument before it ever binds, which is precisely the failure
///     the published-asset docs warn about, so the script asserts the shape.
///   * clause 2 — reads `app/mesofact.routes.ts` and `app/dist/` under the
///     materialized bundle root.
const RUNTIME_V1: &str = r#"#!/bin/sh
set -e
[ "$1" = "serve" ] || { echo "contract v1: expected the 'serve' subcommand, got '$1'" >&2; exit 64; }
[ "$2" = "--bundle" ] || { echo "contract v1: expected --bundle, got '$2'" >&2; exit 64; }
bundle="$3"
[ "$4" = "--listen" ] || { echo "contract v1: expected --listen, got '$4'" >&2; exit 64; }
[ -n "$5" ] || { echo "contract v1: --listen takes an address" >&2; exit 64; }
[ -f "$bundle/app/mesofact.routes.ts" ] || { echo "contract v1: no app/mesofact.routes.ts" >&2; exit 65; }
cat "$bundle/app/dist/index.html"
"#;

/// Every contract version this tree knows, and the runtime that implements it.
const MATRIX: &[Row] = &[Row {
    version: 1,
    runtime_program: RUNTIME_V1,
}];

/// **The gate.** A contract version with no row is a version nothing has ever
/// been served against — the exact "declarative, not real" failure this file
/// exists to prevent. Adding one to `IMPLEMENTED_CONTRACTS` without adding a
/// row fails here.
#[test]
fn every_known_contract_version_has_a_row() {
    let rows: Vec<ContractVersion> = MATRIX.iter().map(|r| r.version).collect();
    for known in IMPLEMENTED_CONTRACTS {
        assert!(
            rows.contains(known),
            "contract version {known} is in IMPLEMENTED_CONTRACTS but has no matrix row — \
             add one to MATRIX in this file so something actually serves against it"
        );
    }
    assert!(
        rows.contains(&BUNDLE_CONTRACT_VERSION),
        "the version this build EMITS ({BUNDLE_CONTRACT_VERSION}) has no matrix row"
    );
    // Rows for versions nothing implements would pass silently and prove
    // nothing about this build; catch them too.
    for row in MATRIX {
        assert!(
            IMPLEMENTED_CONTRACTS.contains(&row.version),
            "matrix row {} names a contract version no runtime in this tree implements",
            row.version
        );
    }
}

/// Every row: a bundle requiring version N is served by a runtime advertising
/// N, through the whole publish → materialize → resolve → fork path.
#[test]
fn each_contract_version_serves_against_a_runtime_that_advertises_it() {
    for row in MATRIX {
        let store = InMemoryObjectStore::new();
        let cache = TempDir::new().unwrap();
        let src = TempDir::new().unwrap();

        let digest = publish_fixture_bundle(&store, src.path(), row.version);
        let runtime = RuntimeRef::parse("mesofact/0.9.0").unwrap();
        publish_runtime_asset(
            &store,
            &runtime,
            TRIPLE,
            SERVE_BIN,
            &[row.version],
            &write_program(src.path(), row.runtime_program),
        )
        .unwrap();

        // What a node does on deploy, in order.
        let bundle_dir = materialize_bundle(&store, cache.path(), &digest).unwrap();
        let manifest = read_manifest(&bundle_dir);
        assert_eq!(manifest.requires_contract, row.version);

        let serve_bin = ensure_runtime_asset(
            &store,
            cache.path(),
            &runtime,
            TRIPLE,
            SERVE_BIN,
            ContractRequirement::Version(manifest.requires_contract),
        )
        .unwrap_or_else(|e| panic!("contract {} must resolve: {e}", row.version));

        let out = Command::new(&serve_bin)
            .args(["serve", "--bundle"])
            .arg(&bundle_dir)
            .args(["--listen", "127.0.0.1:0"])
            .output()
            .unwrap_or_else(|e| panic!("forking the contract-{} runtime: {e}", row.version));

        assert!(
            out.status.success(),
            "contract {} runtime rejected the calling convention: {}",
            row.version,
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            PAGE,
            "contract {} runtime did not serve the bundle's page",
            row.version
        );
    }
}

/// The other half of every row: a runtime that does not advertise this row's
/// version cannot serve it. Without this the matrix would pass just as well
/// against a resolver that never checked anything at all.
///
/// The counterparties are every *other* row plus two synthetic neighbours — a
/// runtime one version behind (the node that has not been upgraded) and one
/// version ahead that dropped support (the node upgraded past this bundle).
/// The synthetics matter: with a single row the cross-product is empty, and an
/// only-negative-test-is-vacuous matrix is how a check rots into decoration.
#[test]
fn a_bundle_is_refused_by_every_runtime_that_does_not_advertise_its_version() {
    for row in MATRIX {
        let mut counterparties: Vec<ContractVersion> = MATRIX
            .iter()
            .map(|o| o.version)
            .filter(|v| *v != row.version)
            .collect();
        counterparties.push(row.version + 1);
        if row.version > 1 {
            counterparties.push(row.version - 1);
        }

        for advertised in counterparties {
            let store = InMemoryObjectStore::new();
            let cache = TempDir::new().unwrap();
            let src = TempDir::new().unwrap();

            publish_fixture_bundle(&store, src.path(), row.version);
            let runtime = RuntimeRef::parse("mesofact/0.9.0").unwrap();
            publish_runtime_asset(
                &store,
                &runtime,
                TRIPLE,
                SERVE_BIN,
                &[advertised],
                &write_program(src.path(), row.runtime_program),
            )
            .unwrap();

            let err = match ensure_runtime_asset(
                &store,
                cache.path(),
                &runtime,
                TRIPLE,
                SERVE_BIN,
                ContractRequirement::Version(row.version),
            ) {
                Ok(path) => panic!(
                    "a runtime advertising only {advertised} must not resolve a bundle \
                     requiring {}, but it resolved to {}",
                    row.version,
                    path.display()
                ),
                Err(e) => e,
            };
            let msg = err.to_string();
            assert!(
                msg.contains(&row.version.to_string()) && msg.contains(&advertised.to_string()),
                "a refusal must name both versions, got: {msg}"
            );
            assert!(
                !cache
                    .path()
                    .join(runtime.cache_rel_serve(TRIPLE))
                    .exists(),
                "a refused resolve must leave nothing forkable in the cache"
            );
        }
    }
}

/// Assemble + publish a vanilla fixture bundle requiring `version`, returning
/// its digest.
///
/// `assemble_vanilla_bundle` stamps `BUNDLE_CONTRACT_VERSION`, which is the
/// only version this tree can emit; a row for any other version has to
/// overwrite it, which is exactly what a bundle built by a *different* tree
/// looks like on the wire.
fn publish_fixture_bundle(
    store: &InMemoryObjectStore,
    root: &Path,
    version: ContractVersion,
) -> yah_mesofact_bundle::BundleHash {
    let project = root.join("project");
    let out_dir = project.join("dist");
    let bundle = root.join("bundle");
    write(&project.join("mesofact.routes.ts"), b"export default {}");
    write(&out_dir.join("index.html"), PAGE.as_bytes());

    let mut manifest =
        assemble_vanilla_bundle(&bundle, "yah-marketing", "0.9.0", &project, &out_dir).unwrap();
    if manifest.requires_contract != version {
        manifest.requires_contract = version;
        fs::write(bundle.join("manifest.toml"), manifest.to_toml_string().unwrap()).unwrap();
    }

    let report = publish_bundle(store, &bundle).unwrap();
    assert_eq!(report.digest, manifest.digest());
    report.digest
}

fn read_manifest(bundle_dir: &Path) -> BundleManifest {
    BundleManifest::from_toml_str(&fs::read_to_string(bundle_dir.join("manifest.toml")).unwrap())
        .unwrap()
}

fn write_program(root: &Path, program: &str) -> PathBuf {
    let p = root.join("runtime-serve");
    fs::write(&p, program).unwrap();
    p
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
