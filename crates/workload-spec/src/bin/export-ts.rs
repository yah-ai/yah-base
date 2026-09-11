//! Codegen: emit a single-file TypeScript binding for `WorkloadSpec` and
//! every type it references.
//!
//! Run with `cargo run -p yah-workload-spec --bin export-ts`. Writes to
//! `packages/yah/workload-spec/index.ts` (relative to the workspace root).
//! The output is deterministic — `tests/ts_drift.rs` regenerates in-memory
//! via [`workload_spec::export_ts::render`] and compares against the
//! committed file directly, so divergence between Rust and TS shows up
//! without touching git (R605-B28).

use std::path::PathBuf;

fn main() {
    let out = workload_spec::export_ts::render();

    // Anchor the output path to the yah camp root via CARGO_MANIFEST_DIR so the
    // bin produces the same file regardless of the cwd cargo is invoked from.
    // The crate sits at oss/yah-base/crates/workload-spec — FOUR parents up is
    // the camp root (75d8df7e split yah-base out of yubaba and added the extra
    // `oss/yah-base` level; the count stayed at three, so since that commit
    // this bin silently wrote to oss/yah-base/packages/… and the committed
    // bindings stopped tracking the Rust types. Found while regenerating for
    // R546-B7).
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let camp_root = manifest_dir
        .ancestors()
        .nth(4)
        .expect("CARGO_MANIFEST_DIR has at least four parents");
    let path = camp_root.join("packages/yah/workload-spec/index.ts");

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(&path, &out).expect("write index.ts");

    println!("Wrote {} ({} bytes)", path.display(), out.len());
}
