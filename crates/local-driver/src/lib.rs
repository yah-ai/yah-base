//! Local-tier infrastructure primitives shared by `cloud` (sim/pond reconciler)
//! and `yubaba` (pond MinIO slot lifecycle).
//!
//! Two concerns live here:
//!
//! 1. **`local_runtime`** — detect an orbstack/docker-desktop/colima/podman/
//!    docker socket and drive appliance containers via the docker CLI. The
//!    docker-CLI driver was previously `cloud::local_runtime`; yubaba grew a
//!    dep on it in R374-F3 when MinIO lifecycle moved into the pond
//!    workload-status surface.
//!
//! 2. **`s3_sign`** — AWS Signature Version 4 helpers for S3-compatible object
//!    storage. Used by cloud's Hetzner driver, the R2 publisher, and yubaba's
//!    MinIO bucket-public bring-up.
//!
//! The crate is intentionally backend-agnostic: no cloud-config types, no
//! yubaba-config types. Callers wire it in via small adapters in their own
//! crates (see `cloud::local_container_spec_from_provider`).
//!
//! @yah:ticket(R374-F3, "Extracted from cloud crate so yubaba owns MinIO lifecycle without a yubaba→cloud dep")
//! @yah:at(2026-06-28T20:35:37Z)
//! @yah:status(review)
//! @yah:parent(R374)
//! @arch:see(.yah/docs/working/W142-pond.md)
//! @yah:gotcha("yubaba's MinioReconciler probe runs every 5s; after 3 consecutive restart failures it marks the workload Failed and exits the loop. PondPhase Failed is terminal — operator restarts the camp daemon.")
//! @yah:gotcha("Camp passes Arc<LocalRuntime> to yubaba once at startup. If orbstack/colima/docker isn't running when camp starts, pond mirrors are skipped with a clear warning; restart yah-camp once the runtime is up.")
//! @yah:gotcha("local-driver moved into the untracked oss/yah-base workspace (crate extraction reorg, not yet committed). cargo test -p local-driver must run from oss/yah-base, not oss/yubaba.")
//! @yah:verify("cargo test -p yubaba --lib  # 106 pass (grew past handoff's 85 as later work landed); F3's PondRegistry + MinioReconciler tests intact")
//! @yah:verify("cargo test -p cloud --lib  # 467 pass (grew past handoff's 212); F3 adopt-path + shared pond_minio primitives green")
//! @yah:verify("cargo test -p local-driver --lib  # 64/64 (run from oss/yah-base)")
//! @yah:verify("YAH_LOCAL_SIM_E2E=1 cargo test -p yubaba --test pond_reconciler_smoke  # LIVE re-verified 2026-06-28: docker kill MinIO → recover 11.2s; docker kill miniflare → recover 11.2s. Both reconcilers restart their slot; half-alive structurally impossible.")
//! @yah:verify("Cold-start within S1 budget (cold ~1.2s / warm ~500ms) via YAH_LOCAL_SIM_E2E=1 cargo test -p cloud --release --test pond_smoke. Bundled in .yah/qed/pond-smoke.toml.")

pub mod cloudflared_ingress;
pub mod local_runtime;
pub mod passway_ingress;
pub mod pond_miniflare;
pub mod pond_minio;
pub mod pond_ssr_runtime;
pub mod pond_warden;
pub mod s3_sign;

pub use local_runtime::{
    canonical_label, canonical_name, pond_network_name, ContainerLauncher, ContainerRunSpec,
    ContainerState,
    CustomDockerHostProvider, DetectedRuntime, LocalContainerSpec, LocalDockerRuntime,
    LocalRuntime, OwnedContainer, RuntimePref, RuntimeProvider, SocketRuntimeProvider, LABEL_KEY,
    NAME_PREFIX,
};

/// Env var overriding the host used to probe pond containers' published
/// host ports. Unset (the host-side default) means `127.0.0.1`.
///
/// The containerized pond yubaba (R454-F1) sets this to
/// `host.docker.internal`: inside that container, loopback is the yubaba
/// container itself, so liveness probes and S3 admin calls against
/// host-published MinIO/miniflare ports must route through the host
/// gateway instead. `pond_warden::build_warden_run_spec` injects the env
/// var + the `--add-host host.docker.internal:host-gateway` mapping.
pub const POND_PROBE_HOST_ENV: &str = "YAH_POND_PROBE_HOST";

/// Host used for probing pond containers' published host ports — see
/// [`POND_PROBE_HOST_ENV`]. `127.0.0.1` unless the env var overrides it.
pub fn pond_probe_host() -> String {
    std::env::var(POND_PROBE_HOST_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}
