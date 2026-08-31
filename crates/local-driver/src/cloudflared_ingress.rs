//! Rented public-ingress appliance — `cloudflared` under kamaji (R594-F11 / W267).
//!
//! The sovereign twin of [`super::passway_ingress`]. Both answer exactly one
//! question — *given these local workload ports, make them publicly reachable
//! at these hostnames* — and W267 §"Ingress is a provider" says they must
//! therefore have the **same lifecycle**. They did not:
//!
//! | | before | after |
//! |---|---|---|
//! | passway | kamaji-supervised workload on a `public-ip` taint | unchanged |
//! | cloudflared | `cloudflared service install <TOKEN>` + systemd, written once by cloud-init and never reconciled | this module: a kamaji-supervised workload |
//!
//! That asymmetry was W267 §"Gap 2". A provisioned-once systemd unit cannot be
//! swapped by flipping a mirror field, cannot be restarted by the same
//! supervisor as everything else on the node, and — as the R591-F1 headscale
//! incident showed for the raw-systemctl shape — can sit dead for days because
//! a `Restart=` policy did not cover the way the process actually exited.
//! Declaring [`RestartPolicy::Always`] on a kamaji [`LifecycleArchetype::Appliance`]
//! is the same guarantee the passway appliance already carries.
//!
//! **cloudflared is supervised, never reimplemented.** It is a large Go binary
//! speaking a proprietary, vendor-controlled protocol; there is no viable Rust
//! client and writing one is a permanent race against a vendor who can change
//! the protocol at will (W267). This module produces a *container spec*, not a
//! tunnel implementation.
//!
//! ## Token handling
//!
//! The tunnel token never appears in the spec JSON. cloudflared reads it from
//! a file when `--token-file` / `TUNNEL_TOKEN_FILE` is set
//! (`cmd/cloudflared/tunnel/subcommands.go`, `tunnelTokenFileFlag`), so the
//! token rides a [`SecretRef`] → [`SecretTarget::File`] mount exactly like
//! passway's cert and key. This is a strict improvement on the cloud-init
//! path, which renders the token into `runcmd` as a literal argv word.
//!
//! ## Ingress rules are NOT here
//!
//! A token-form tunnel is **remotely managed**: its hostname→service rules live
//! in Cloudflare's API, not in a file on the box (W267 §Granularity). Publishing
//! them is an API call, and it lives in
//! `cloud::reconciler::ingress::ensure_tunnel_ingress`. This module only stands
//! the connector up. The split is the same one passway has — the appliance
//! runs, and its backend set is derived from placement elsewhere.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use workload_spec::{
    EnvValue, EnvVar, ExposeSpec, HealthProbe, Healthcheck, ImageRef, LifecycleArchetype,
    MeshExpose, MeshIdent, Millis, NamespaceId, ResourceLimits, RestartPolicy, SchemaVersion,
    SecretMount, SecretRef, SecretTarget, StopPolicy, TenantId, TierTag, VolumeMount, Workload,
    WorkloadSpec, HOST_NETWORK_ANNOTATION, HOST_NETWORK_VALUE, PUBLIC_IP_TAINT,
    REQUIRES_TAINT_ANNOTATION,
};

/// DNS name + mesh identity of the cloudflared ingress workload.
///
/// Distinct from [`passway_ingress::INGRESS_WORKLOAD_NAME`](super::passway_ingress::INGRESS_WORKLOAD_NAME)
/// so a node mid-migration can run both and the operator can tell them apart in
/// `GET /workloads`.
pub const INGRESS_WORKLOAD_NAME: &str = "cloudflared-ingress";

/// Container path the tunnel token is mounted at (mode `0o400`).
const TOKEN_MOUNT_PATH: &str = "/run/secrets/tunnel-token";

/// Loopback metrics/readiness listener. cloudflared registers `/ready` on its
/// metrics server (`metrics/metrics.go`), which reports healthy only once a
/// connector edge connection is up — the distinction that matters, because a
/// running-but-disconnected cloudflared serves no traffic while looking alive
/// to a bare process check.
const METRICS_LISTEN: &str = "127.0.0.1:20241";
/// Port half of [`METRICS_LISTEN`], for the health probe.
const METRICS_PORT: u16 = 20241;
/// cloudflared's readiness path on the metrics listener.
const READY_PATH: &str = "/ready";

/// Default cloudflared binary path inside the official image (`build_oci_spec`
/// ignores the image ENTRYPOINT and runs `command` directly, so it must be
/// spelled out — same constraint as the passway appliance).
const DEFAULT_BIN: &str = "/usr/local/bin/cloudflared";

/// Keys-vault / cluster-secret slot holding the tunnel connector token. Matches
/// the slot `yah cloud machine provision` already reads for the cloud-init path
/// (`fob::get_or_env("cloudflare-tunnel-token", …)`), so re-homing the
/// connector does not mint a second place to store the same credential.
pub const DEFAULT_TOKEN_SECRET: &str = "cloudflare-tunnel-token";

/// Caller-supplied cloudflared bring-up parameters. `yah cloud ingress deploy
/// --provider cloudflare-tunnel` builds this, then lowers it to the yubaba
/// workload payload via [`Self::into_container_workload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflaredIngressSpec {
    /// Tunnel ID this connector joins — the same value
    /// `MachineConfig.cloudflared` carries. Recorded as a label so the node's
    /// workload list says *which* tunnel is up, and so the reconciler that
    /// publishes ingress rules can be pointed at the same one.
    pub tunnel_id: String,

    /// Cluster-secret key holding the connector token. Defaults to
    /// [`DEFAULT_TOKEN_SECRET`].
    #[serde(default = "default_token_secret")]
    pub token_secret: String,

    /// Override the cloudflared invocation. Defaults to
    /// `["/usr/local/bin/cloudflared", "tunnel", "--no-autoupdate",
    /// "--metrics", "127.0.0.1:20241", "run"]` — no `--token` word, because the
    /// token arrives via `TUNNEL_TOKEN_FILE`.
    ///
    /// Overriding this is an escape hatch: a command that drops `--metrics`
    /// leaves the health probe pointing at a closed port, and the appliance
    /// will restart-loop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

fn default_token_secret() -> String {
    DEFAULT_TOKEN_SECRET.to_string()
}

impl CloudflaredIngressSpec {
    /// Lower this connector spec into a containerd [`Workload`] yubaba deploys.
    ///
    /// Host-networked infra-tier on a `public-ip` taint, `Appliance` archetype,
    /// `RestartPolicy::Always`, one Cluster→File token mount, and an HTTP
    /// readiness probe against cloudflared's own `/ready`.
    ///
    /// Host networking is required for the same reason passway needs it: the
    /// connector dials the workloads it fronts on node loopback (R599-F12 —
    /// bundles bind `127.0.0.1`). Unlike passway it binds **no** inbound port;
    /// a tunnel connector's whole point is that the box needs zero public
    /// ingress ports.
    ///
    /// `image` is the content-addressed cloudflared image (operator-supplied,
    /// digest-pinned, same as the passway appliance).
    pub fn into_container_workload(&self, image: ImageRef) -> Workload {
        let env = vec![
            // cloudflared reads the token from this path rather than argv, so
            // it never lands in the spec JSON or in `ps` output.
            literal_env("TUNNEL_TOKEN_FILE", TOKEN_MOUNT_PATH.into()),
        ];

        let secrets = vec![SecretMount {
            source: SecretRef::Cluster {
                name: self.token_secret.clone(),
            },
            target: SecretTarget::File {
                path: TOKEN_MOUNT_PATH.into(),
                mode: 0o400,
            },
        }];

        let mut annotations = HashMap::new();
        // Reach node-local upstreams over loopback — guarded escape hatch,
        // infra-only.
        annotations.insert(
            HOST_NETWORK_ANNOTATION.to_string(),
            HOST_NETWORK_VALUE.to_string(),
        );
        // A tunnel connector only makes sense on a node meant to carry public
        // traffic. Same marker passway uses (enforced once R572-F5 lands).
        annotations.insert(
            REQUIRES_TAINT_ANNOTATION.to_string(),
            PUBLIC_IP_TAINT.to_string(),
        );

        let mut labels = HashMap::new();
        labels.insert("yah.ingress.tunnel-id".to_string(), self.tunnel_id.clone());

        let spec = WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: INGRESS_WORKLOAD_NAME.into(),
            image,
            tier: TierTag("infra".into()),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            replicas: 1,
            command: Some(self.command.clone().unwrap_or_else(default_command)),
            entrypoint: None,
            workdir: None,
            user: None,
            env,
            secrets,
            volumes: Vec::<VolumeMount>::new(),
            resources: ResourceLimits {
                memory_mb: 256,
                cpu_millis: 512,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            healthcheck: Some(Healthcheck {
                probe: HealthProbe::HttpGet {
                    path: READY_PATH.into(),
                    port: METRICS_PORT,
                    expect_status: None,
                },
                interval: Millis::from_secs(10),
                timeout: Millis::from_secs(2),
                initial_delay: Millis::from_secs(10),
                failure_threshold: 3,
            }),
            // The R591-F1 lesson: a front door must come back from EVERY exit,
            // graceful ones included. `Always`, never `OnFailure`.
            restart_policy: RestartPolicy::Always,
            archetype: Some(LifecycleArchetype::Appliance),
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(INGRESS_WORKLOAD_NAME.into()),
                    // Metrics stay on loopback; nothing is mesh-reachable.
                    ports: vec![],
                    allow_from: vec![],
                },
                // The connector dials OUT. There is no inbound listener for
                // yubaba to publish, and `expose.public` would send yubaba's
                // deploy handler off to register a tunnel route for the tunnel
                // itself.
                public: None,
                operator: None,
            },
            labels,
            annotations,
        };

        Workload::container(spec)
    }
}

/// Default argv: run the named tunnel with the metrics/readiness listener up.
fn default_command() -> Vec<String> {
    vec![
        DEFAULT_BIN.into(),
        "tunnel".into(),
        // Never let the connector swap its own binary under kamaji — image
        // updates are a deploy, not a self-mutation.
        "--no-autoupdate".into(),
        "--metrics".into(),
        METRICS_LISTEN.into(),
        "run".into(),
    ]
}

fn literal_env(name: &str, value: String) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: EnvValue::Literal { value },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image() -> ImageRef {
        ImageRef {
            registry: "docker.io".into(),
            repository: "cloudflare/cloudflared".into(),
            tag: "2026.1.0".into(),
            digest: workload_spec::testing::test_digest(),
        }
    }

    fn sample_spec() -> CloudflaredIngressSpec {
        CloudflaredIngressSpec {
            tunnel_id: "abc123".into(),
            token_secret: DEFAULT_TOKEN_SECRET.into(),
            command: None,
        }
    }

    fn lower(spec: &CloudflaredIngressSpec) -> WorkloadSpec {
        let w = spec.into_container_workload(sample_image());
        w.container_spec()
            .unwrap_or_else(|| panic!("expected Container, got {w:?}"))
            .clone()
    }

    #[test]
    fn appliance_is_pinned_and_always_restarted() {
        let w = lower(&sample_spec());
        assert_eq!(w.archetype, Some(LifecycleArchetype::Appliance));
        // R591-F1: a graceful exit-0 must still bring the front door back.
        assert_eq!(w.restart_policy, RestartPolicy::Always);
    }

    #[test]
    fn placement_and_networking_match_the_passway_appliance() {
        let w = lower(&sample_spec());
        assert_eq!(w.requires_taint(), Some(PUBLIC_IP_TAINT));
        assert!(w.wants_host_network());
        assert_eq!(w.tier.0, "infra");
    }

    #[test]
    fn token_rides_a_file_mount_and_never_appears_in_the_spec() {
        let spec = sample_spec();
        let w = lower(&spec);
        assert_eq!(w.secrets.len(), 1);
        assert_eq!(
            w.secrets[0].source,
            SecretRef::Cluster {
                name: DEFAULT_TOKEN_SECRET.into()
            }
        );
        assert!(matches!(
            &w.secrets[0].target,
            SecretTarget::File { path, mode } if path.as_os_str() == TOKEN_MOUNT_PATH && *mode == 0o400
        ));
        // cloudflared is pointed at the mount, not handed a literal token.
        let token_env = w
            .env
            .iter()
            .find(|e| e.name == "TUNNEL_TOKEN_FILE")
            .expect("TUNNEL_TOKEN_FILE env");
        assert_eq!(
            token_env.value,
            EnvValue::Literal {
                value: TOKEN_MOUNT_PATH.into()
            }
        );
        // The whole serialized spec must be token-free.
        let json = serde_json::to_string(&w).unwrap();
        assert!(!json.contains("--token"), "token flag leaked into argv");
        assert!(
            !json.contains("TUNNEL_TOKEN\""),
            "bare TUNNEL_TOKEN env leaked: {json}"
        );
    }

    #[test]
    fn command_runs_the_tunnel_with_the_metrics_listener() {
        let w = lower(&sample_spec());
        let cmd = w.command.expect("command is spelled out, not inherited");
        assert_eq!(
            cmd,
            vec![
                "/usr/local/bin/cloudflared",
                "tunnel",
                "--no-autoupdate",
                "--metrics",
                "127.0.0.1:20241",
                "run",
            ]
        );
    }

    #[test]
    fn readiness_probe_targets_cloudflared_ready_not_a_bare_port() {
        let w = lower(&sample_spec());
        let hc = w.healthcheck.expect("healthcheck");
        // A TcpConnect on the metrics port would pass while the connector is
        // disconnected from the edge; /ready is the connection-aware signal.
        assert_eq!(
            hc.probe,
            HealthProbe::HttpGet {
                path: "/ready".into(),
                port: 20241,
                expect_status: None,
            }
        );
    }

    #[test]
    fn declares_no_inbound_listener() {
        let w = lower(&sample_spec());
        assert!(w.expose.public.is_none(), "a connector dials out");
        assert!(w.expose.mesh.ports.is_empty());
    }

    #[test]
    fn tunnel_id_is_labelled_for_the_rule_publisher() {
        let w = lower(&sample_spec());
        assert_eq!(
            w.labels.get("yah.ingress.tunnel-id").map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn does_not_collide_with_the_passway_appliance_name() {
        assert_ne!(
            INGRESS_WORKLOAD_NAME,
            super::super::passway_ingress::INGRESS_WORKLOAD_NAME
        );
    }

    #[test]
    fn passes_shape_validation() {
        let w = lower(&sample_spec());
        workload_spec::validate::shape(&w).expect("cloudflared appliance is a valid spec");
    }

    #[test]
    fn token_secret_defaults_when_absent_from_json() {
        let spec: CloudflaredIngressSpec =
            serde_json::from_str(r#"{"tunnel_id":"t1"}"#).expect("minimal JSON parses");
        assert_eq!(spec.token_secret, DEFAULT_TOKEN_SECRET);
        assert!(spec.command.is_none());
    }
}
