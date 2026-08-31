//! R743-T4: single integration-test binary for workload-spec.
//!
//! `autotests = false` in Cargo.toml turns off cargo's default "one binary
//! per file under tests/" behavior; this file is the sole `[[test]]` target
//! (`name = "main"`) and pulls the 7 former top-level test files in as
//! modules. Each keeps its own namespace (helpers, fixtures) exactly as
//! before — only the number of linked/compiled test binaries changes, not
//! test identity or behavior. `tests/compose/` and `tests/fixtures/` are
//! data directories read via `CARGO_MANIFEST_DIR`-relative paths, untouched
//! by this move.

mod compose_import;
mod mesh_resolver;
mod restart_policy;
mod round_trip;
mod secrets_invariant;
mod semantic;
mod shape_fixtures;
