//! Pond yubaba-container `ContainerRunSpec` builder + permission model (R408-T2).
//!
//! Companion to the `yah-yubaba` image (R408-T1). Encodes the docker socket
//! mount, cgroup-namespace, capability, and bind-mount contract the
//! yubaba-container expects when it's run on a pond host (OrbStack on macOS,
//! plain docker on Linux dev boxes).
//!
//! ## Why a dedicated builder
//!
//! The yah-yubaba image inside pond is shaped differently from every other
//! container [`LocalRuntime::run`] orchestrates today: it needs the host
//! docker socket mounted in, the cgroup namespace privatised, and `SYS_ADMIN`
//! capabilities so Kamaji can write child cgroups. Encoding that as a
//! per-call set of args in a future pond reconciler would scatter the
//! knowledge across files; centralising it here means the contract is one
//! place and the next agent picking up T-future-integration (containerise
//! yubaba in pond bring-up) consumes a struct, not a tribal-knowledge
//! checklist.
//!
//! ## Permission model
//!
//! Pond runs the yah-yubaba container with sibling-container workloads
//! orchestrated through the **host's docker socket** rather than
//! docker-in-docker. The model is intentionally narrow:
//!
//! - **Inside the container**: process runs as root (uid 0). The Dockerfile
//!   does not declare a non-root `USER`. tini (PID 1) and the yubaba +
//!   kamaji siblings expect to write `/run/kamaji/`, `/var/lib/yah-yubaba/`,
//!   and `/sys/fs/cgroup/*` — all of which require root on the standard image.
//!
//! - **Outside (host)**: the docker socket at `/var/run/docker.sock` is the
//!   trust boundary. Anyone who can write to that socket has root-equivalent
//!   on the host. Pond accepts that trade-off because it's dev-tier on a
//!   single operator's machine; cloud-tier uses containerd RPC + MeshIdent
//!   instead.
//!
//! - **OrbStack (macOS, default pond runtime)**: the docker socket lives on
//!   the host (mac) filesystem as a unix socket that OrbStack proxies into
//!   the linux VM. Bind-mounting `/var/run/docker.sock` from the host into
//!   the container gives the container's root process access to the same
//!   socket OrbStack already proxies — no gid juggling required.
//!
//! - **Linux dev box**: the host socket is typically `root:docker 0660`.
//!   The container runs as root (uid 0), so the gid on the socket is
//!   immaterial — root bypasses group checks on socket connect. If a future
//!   pond shape ever runs the container as a non-root user, the
//!   `docker_socket_gid` field would need to be wired through and applied
//!   via `--group-add`. Not done today; documented as the extension point.
//!
//! - **Cgroup writes**: `--cgroupns=private` plus `--cap-add=SYS_ADMIN` are
//!   the minimum for Kamaji to write child cgroups under the container's
//!   own `/sys/fs/cgroup`. We do not grant `--privileged` — that's broader
//!   than needed and would dilute the principle-of-least-privilege story for
//!   the operator-trust review of pond.
//!
//! - **What's NOT mounted**: no host `/proc`, no `/sys` beyond the cgroup
//!   subtree the kernel provides per-container under `--cgroupns=private`,
//!   no SSH agent socket. Container-backend workloads spawned through the
//!   docker socket get their own bind-mounts declared in their `WorkloadSpec`.
//!
//! ## What this builder does NOT do
//!
//! - It does not actually `docker run` the container — callers feed the
//!   returned [`ContainerRunSpec`] to [`crate::LocalRuntime::run`]. The pond
//!   reconciler integration (the "replace embedded-yubaba with
//!   yubaba-container" lift) is the next ticket after T2/T3.
//! - It does not probe readiness — that lives next to the future lifecycle
//!   wrapper, mirroring [`crate::pond_minio::ensure_minio_running`] shape.
//! - It does not pull the image — callers use
//!   [`crate::LocalRuntime::ensure_image`] before running.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::{canonical_label, canonical_name, ContainerRunSpec};

/// Default tag of the `yah-yubaba` image. Per W148, the release pipeline
/// injects a digest-pinned tag at build time; pond falls back to `:latest`
/// for local-built images. T2 doesn't bake the published image ref because
/// the release-pipeline wiring for `image-yah-yubaba` is still queued
/// (T1's handoff calls this out).
pub const DEFAULT_WARDEN_IMAGE: &str = "ghcr.io/yah-ai/yah-yubaba:latest";

/// Canonical host path of the docker daemon's unix socket. Bind-mounted
/// 1:1 into the container so container-backend workloads spawn as host
/// siblings rather than docker-in-docker.
pub const DEFAULT_DOCKER_SOCKET_PATH: &str = "/var/run/docker.sock";

/// Container-side mount target for the docker socket. Matches the host path
/// so the docker CLI inside the container needs no `DOCKER_HOST` override.
pub const DOCKER_SOCKET_CONTAINER_PATH: &str = "/var/run/docker.sock";

/// Container-side mount target for yubaba's persistent state (raft log,
/// identity, registry). The Dockerfile pre-creates this directory.
pub const WARDEN_STATE_CONTAINER_PATH: &str = "/var/lib/yah-yubaba";

/// Default operator-visible HTTP port for yubaba's pond status surface.
/// Mirrors today's embedded-yubaba binding (R374-F2 wrote the port to
/// `<camp_root>/.yah/jit/yubaba-pond-port.json`); the container path will
/// expose the same file on the same shape.
pub const DEFAULT_WARDEN_HTTP_PORT: u16 = 8800;

/// Slot role used to scope `canonical_name` / `canonical_label` for the
/// yubaba container. The full container name is `yah-pond-camp-<env>-yubaba`
/// (see [`WARDEN_CAMP_SCOPE`]), grep-friendly alongside the per-service
/// `yah-pond-<service>-<env>-object_store` MinIO containers.
pub const WARDEN_SLOT: &str = "yubaba";

/// The pond yubaba container is a **camp singleton**: one yubaba supervises
/// every pond cell's sibling workloads, so its name must NOT embed a service
/// (R602-B2 — before this, the name derived from the *first* pond mirror, so
/// per-service probes for every non-first cell resolved nothing). It's scoped
/// to this fixed sentinel + env instead, so every pond cell's probe resolves
/// the same container. The per-cell appliance containers
/// (`yah-pond-<svc>-<env>-{object_store,miniflare}`) stay service-scoped —
/// only the yubaba is shared.
pub const WARDEN_CAMP_SCOPE: &str = "camp";

/// Canonical name of the camp's pond yubaba container for `env`:
/// `yah-pond-camp-<env>-yubaba`. The camp (which starts it) and the desktop
/// probes (which inspect it) MUST agree on this — always go through here.
pub fn warden_container_name(env: &str) -> String {
    canonical_name(WARDEN_CAMP_SCOPE, env, WARDEN_SLOT)
}

/// Canonical label of the camp's pond yubaba container: `camp:<env>:yubaba`.
pub fn warden_container_label(env: &str) -> String {
    canonical_label(WARDEN_CAMP_SCOPE, env, WARDEN_SLOT)
}

/// Bring-up parameters for the pond yubaba-container. Mirrors
/// [`crate::pond_minio::MinioSpec`] in shape: callers (camp, cloud
/// reconciler) build this from their own source of truth.
#[derive(Debug, Clone)]
pub struct WardenContainerSpec {
    /// Container image ref (digest-pinned in production; defaults to
    /// [`DEFAULT_WARDEN_IMAGE`] for local builds).
    pub image: String,
    /// Environment identifier ("pond", "local", etc). The container name +
    /// label are camp-scoped ([`warden_container_name`]) — the yubaba is a
    /// per-camp singleton, so `env` is the only identity axis it carries.
    pub env: String,
    /// Host port mapped to [`DEFAULT_WARDEN_HTTP_PORT`] inside the container.
    /// `0` picks a random port (caller resolves via `docker port` afterward).
    pub http_port: u16,
    /// Host path of the docker socket to bind-mount into the container.
    /// Defaults to [`DEFAULT_DOCKER_SOCKET_PATH`]; OrbStack callers may
    /// override when the operator points at a non-default runtime.
    pub docker_socket_path: PathBuf,
    /// Host directory that holds yubaba's persistent state across container
    /// life cycles. Bind-mounted to [`WARDEN_STATE_CONTAINER_PATH`].
    pub state_dir: PathBuf,
    /// Camp's pond state root (`<camp_root>/.yah/infra/pond`), bind-mounted
    /// **1:1 at the same absolute path** inside the container. The pond
    /// deploy handler materialises files (miniflare's `worker.js`, MinIO
    /// data dirs) under per-cell state dirs and then bind-mounts those same
    /// paths into sibling containers via the host docker socket — the mount
    /// sources resolve on the *host*, so writes made inside the yubaba
    /// container must land on the host at the identical path or siblings
    /// mount stale/absent files. `None` skips the mount (embedded/host-side
    /// yubaba, tests).
    pub pond_state_root: Option<PathBuf>,
    /// Extra env vars layered on top of the image defaults (e.g.
    /// `RUST_LOG=yubaba=debug`).
    pub extra_env: BTreeMap<String, String>,
}

impl WardenContainerSpec {
    /// Build a spec with default image + socket path. Caller still must set
    /// `state_dir` to a real host directory.
    pub fn new(env: impl Into<String>, state_dir: PathBuf) -> Self {
        Self {
            image: DEFAULT_WARDEN_IMAGE.into(),
            env: env.into(),
            http_port: 0,
            docker_socket_path: PathBuf::from(DEFAULT_DOCKER_SOCKET_PATH),
            state_dir,
            pond_state_root: None,
            extra_env: BTreeMap::new(),
        }
    }
}

/// `YAH_WARDEN_ARGS` injected into every pond yubaba container so yubaba binds
/// to the expected pond HTTP port. These are the *flags* appended after the
/// `serve` subcommand — `pond-supervise.sh` owns the `serve` token itself
/// (`yah-yubaba serve $YAH_WARDEN_ARGS`), so this string must NOT repeat it or
/// clap sees a doubled subcommand and the container crash-loops (R471 redux).
/// Callers that need a different bind address or extra flags can override via
/// [`WardenContainerSpec::extra_env`].
pub const DEFAULT_WARDEN_ARGS: &str =
    "--bind 0.0.0.0:8800 --state /var/lib/yah-yubaba/identity.json";

/// Translate a [`WardenContainerSpec`] into the [`ContainerRunSpec`] that
/// [`crate::LocalRuntime::run`] will emit as `docker run …`. Pure: builds
/// no directories and probes nothing.
///
/// Encodes the W154 + R408-T1 acceptance contract:
/// - `--cgroupns=private`
/// - `--cap-add=SYS_ADMIN`
/// - `-v <docker_socket_path>:/var/run/docker.sock`
/// - `-v <state_dir>:/var/lib/yah-yubaba`
/// - `-p <http_port>:8800`
/// - camp-scoped label/name (`yah-pond-camp-<env>-yubaba`)
/// - `YAH_WARDEN_ARGS=--bind 0.0.0.0:8800 --state …` (flags only — the
///   `serve` subcommand is supplied by `pond-supervise.sh`; unless overridden
///   via [`WardenContainerSpec::extra_env`])
pub fn build_warden_run_spec(spec: &WardenContainerSpec) -> ContainerRunSpec {
    let mut env = spec.extra_env.clone();
    env.entry("YAH_WARDEN_ARGS".into())
        .or_insert_with(|| DEFAULT_WARDEN_ARGS.into());
    // Inside this container, loopback is the container itself — pond
    // liveness probes + S3 admin calls against host-published MinIO/
    // miniflare ports must route through the host gateway instead
    // (`crate::pond_probe_host`). OrbStack/Docker Desktop resolve
    // host.docker.internal natively; the --add-host host-gateway mapping
    // below covers plain Linux docker.
    env.entry(crate::POND_PROBE_HOST_ENV.into())
        .or_insert_with(|| "host.docker.internal".into());

    let mut volumes = vec![
        (
            spec.docker_socket_path.clone(),
            DOCKER_SOCKET_CONTAINER_PATH.into(),
        ),
        (spec.state_dir.clone(), WARDEN_STATE_CONTAINER_PATH.into()),
    ];
    // Pond state root mounts 1:1 (same path inside) so files the deploy
    // handler writes for sibling bind-mounts land on the host — see the
    // field doc on [`WardenContainerSpec::pond_state_root`].
    if let Some(root) = &spec.pond_state_root {
        volumes.push((root.clone(), root.display().to_string()));
    }

    ContainerRunSpec {
        name: warden_container_name(&spec.env),
        image: spec.image.clone(),
        label: warden_container_label(&spec.env),
        ports: vec![(spec.http_port, DEFAULT_WARDEN_HTTP_PORT)],
        env,
        volumes,
        cmd: vec![],
        cap_add: vec!["SYS_ADMIN".into()],
        cgroupns: Some("private".into()),
        network: None,
        network_aliases: vec![],
        extra_hosts: vec!["host.docker.internal:host-gateway".into()],
    }
}

/// True if `host_socket_path` looks like a unix socket the operator can
/// expect docker to listen on. Cheap structural check — does not stat the
/// path. Used by callers that want to surface a clear early-failure error
/// instead of waiting for the container's first docker-CLI invocation to
/// blow up. Two patterns accepted: `/var/run/docker.sock` (Linux + OrbStack)
/// and any path ending in `.sock` (Colima, custom DOCKER_HOST unix:// shape).
pub fn looks_like_docker_socket(host_socket_path: &Path) -> bool {
    let s = host_socket_path.to_string_lossy();
    s == "/var/run/docker.sock"
        || s.ends_with("/docker.sock")
        || s.ends_with(".sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_for_test() -> WardenContainerSpec {
        let mut s = WardenContainerSpec::new("pond", PathBuf::from("/tmp/state"));
        s.http_port = 8800;
        s
    }

    #[test]
    fn run_spec_has_camp_scoped_name_and_label() {
        // R602-B2: name is camp-scoped, not derived from any service — every
        // pond cell's probe resolves this same container.
        let crs = build_warden_run_spec(&spec_for_test());
        assert_eq!(crs.name, "yah-pond-camp-pond-yubaba");
        assert_eq!(crs.name, warden_container_name("pond"));
        assert!(crs.label.contains("camp:pond:yubaba"));
        assert_eq!(crs.label, warden_container_label("pond"));
    }

    #[test]
    fn run_spec_mounts_docker_socket() {
        let crs = build_warden_run_spec(&spec_for_test());
        let has_socket = crs.volumes.iter().any(|(h, c)| {
            h == &PathBuf::from(DEFAULT_DOCKER_SOCKET_PATH) && c == DOCKER_SOCKET_CONTAINER_PATH
        });
        assert!(has_socket, "expected docker socket mount, got {:?}", crs.volumes);
    }

    #[test]
    fn run_spec_mounts_state_dir() {
        let crs = build_warden_run_spec(&spec_for_test());
        let has_state = crs.volumes.iter().any(|(h, c)| {
            h == &PathBuf::from("/tmp/state") && c == WARDEN_STATE_CONTAINER_PATH
        });
        assert!(has_state, "expected state-dir mount, got {:?}", crs.volumes);
    }

    #[test]
    fn run_spec_requests_private_cgroupns_and_sys_admin() {
        let crs = build_warden_run_spec(&spec_for_test());
        assert_eq!(crs.cgroupns.as_deref(), Some("private"));
        assert!(crs.cap_add.iter().any(|c| c == "SYS_ADMIN"));
    }

    #[test]
    fn run_spec_exposes_http_port() {
        let mut spec = spec_for_test();
        spec.http_port = 14321;
        let crs = build_warden_run_spec(&spec);
        assert_eq!(crs.ports, vec![(14321, DEFAULT_WARDEN_HTTP_PORT)]);
    }

    #[test]
    fn run_spec_injects_default_warden_args() {
        let crs = build_warden_run_spec(&spec_for_test());
        assert_eq!(
            crs.env.get("YAH_WARDEN_ARGS").map(String::as_str),
            Some(DEFAULT_WARDEN_ARGS),
            "build_warden_run_spec must inject YAH_WARDEN_ARGS so pond-supervise.sh \
             starts `yah-yubaba serve` on the expected port"
        );
    }

    /// Regression guard for the R471-redux crash-loop: `pond-supervise.sh`
    /// invokes `yah-yubaba serve $YAH_WARDEN_ARGS`, so the injected args must
    /// carry flags ONLY. If this string ever leads with `serve` again the
    /// container expands to `yah-yubaba serve serve …`, clap rejects the
    /// doubled subcommand, and the pond yubaba restart-loops.
    #[test]
    fn default_warden_args_must_not_repeat_serve_subcommand() {
        let crs = build_warden_run_spec(&spec_for_test());
        let args = crs.env.get("YAH_WARDEN_ARGS").map(String::as_str).unwrap();
        let first = args.split_whitespace().next();
        assert_ne!(
            first,
            Some("serve"),
            "YAH_WARDEN_ARGS must be flags-only; pond-supervise.sh owns the `serve` \
             token. Leading `serve` here doubles the subcommand and crash-loops \
             the container (R471 redux). Got: {args:?}"
        );
    }

    #[test]
    fn run_spec_extra_env_overrides_warden_args() {
        // Callers that need a non-standard bind can override via extra_env.
        let mut spec = spec_for_test();
        spec.extra_env.insert("YAH_WARDEN_ARGS".into(), "--bind 0.0.0.0:9900".into());
        let crs = build_warden_run_spec(&spec);
        assert_eq!(
            crs.env.get("YAH_WARDEN_ARGS").map(String::as_str),
            Some("--bind 0.0.0.0:9900"),
        );
    }

    #[test]
    fn run_spec_forwards_extra_env() {
        let mut spec = spec_for_test();
        spec.extra_env.insert("RUST_LOG".into(), "yubaba=debug".into());
        let crs = build_warden_run_spec(&spec);
        assert_eq!(crs.env.get("RUST_LOG").map(String::as_str), Some("yubaba=debug"));
    }

    #[test]
    fn docker_run_argv_carries_cgroupns_and_cap_add() {
        // Exercise ContainerRunSpec::docker_run_args via the yubaba spec so
        // T2's contract is end-to-end visible in the argv that docker sees.
        let crs = build_warden_run_spec(&spec_for_test());
        let argv = crs.docker_run_args();
        assert!(
            argv.iter().any(|a| a == "--cgroupns=private"),
            "missing --cgroupns=private in {argv:?}",
        );
        let cap_idx = argv.iter().position(|a| a == "--cap-add");
        assert!(cap_idx.is_some(), "missing --cap-add in {argv:?}");
        assert_eq!(argv.get(cap_idx.unwrap() + 1).map(String::as_str), Some("SYS_ADMIN"));
    }

    #[test]
    fn looks_like_docker_socket_classifies_common_paths() {
        assert!(looks_like_docker_socket(Path::new("/var/run/docker.sock")));
        assert!(looks_like_docker_socket(Path::new(
            "/Users/user/.orbstack/run/docker.sock"
        )));
        assert!(looks_like_docker_socket(Path::new(
            "/run/user/501/docker.sock"
        )));
        assert!(looks_like_docker_socket(Path::new("/tmp/colima.sock")));
        assert!(!looks_like_docker_socket(Path::new("/var/run/foo")));
    }
}
