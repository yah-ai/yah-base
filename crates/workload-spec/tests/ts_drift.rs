//! Drift test for `packages/yah/workload-spec/index.ts` (R605-B28).
//!
//! Mirrors `xtask/tests/schema_drift.rs`'s
//! `committed_schemas_match_current_rust_types`: render the TS binding
//! in-memory via [`workload_spec::export_ts::render`] and assert it's
//! byte-identical to the committed file. No git involved — this answers
//! "is the committed file what the Rust types imply right now", not "has a
//! human committed the regeneration yet", which is the question
//! `scripts/check-workload-spec-ts.sh`'s old `git diff` against HEAD could
//! not answer on a camp that defers commits to a human sweep.

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is oss/yah-base/crates/workload-spec/. Workspace
    // root is four parents up — same anchor bin/export-ts.rs uses, and for
    // the same reason (R546-B7: the crate move added a directory level).
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("CARGO_MANIFEST_DIR has at least four parents")
        .to_path_buf()
}

#[test]
fn committed_ts_bindings_match_current_rust_types() {
    let path = workspace_root().join("packages/yah/workload-spec/index.ts");
    let expected = workload_spec::export_ts::render();

    match std::fs::read_to_string(&path) {
        Ok(actual) if actual == expected => { /* match */ }
        Ok(_) => panic!(
            "schema drift in {} — run \
             `cargo run --manifest-path oss/yah-base/crates/workload-spec/Cargo.toml --bin export-ts`",
            path.display()
        ),
        Err(e) => panic!(
            "missing committed TS bindings {}: {e} — run \
             `cargo run --manifest-path oss/yah-base/crates/workload-spec/Cargo.toml --bin export-ts`",
            path.display()
        ),
    }
}
