//! Passway public-ingress appliance bring-up primitives (R600-F5 / W273).
//!
//! The passway L7 ingress (W267/R594) terminates TLS for the fleet's public
//! `*.yah.dev` traffic. This module lowers the operator-facing knobs (domain,
//! listener, upstreams) into the containerd [`Workload`] yubaba deploys — the
//! **cert-consuming** shape R600 exists to produce:
//!
//! - It declares two [`SecretRef::Cluster`] → [`SecretTarget::File`] mounts for
//!   the fleet-shared cert + key (raft-replicated by the single ACME issuer,
//!   R600-F3; materialized to a host tmpfs bind at admission, R600-F6;
//!   re-rendered + graceful-upgraded on rotation, R600-F4/F7/F9).
//! - It runs passway in `PASSWAY_TLS_MODE=manual`, pointing `PASSWAY_TLS_CERT`
//!   / `PASSWAY_TLS_KEY` at those mounts. **No `PASSWAY_ACME_*` env is set** —
//!   per-node self-issuance is dropped by construction, so the Let's Encrypt
//!   duplicate-certificate rate limit disappears (the W273 payoff). ACME
//!   collapses to the elected issuer's job alone.
//!
//! Placement: the appliance marks itself `archetype = Appliance` (pinned /
//! non-drainable) and `requires_taint() == PUBLIC_IP_TAINT`, so a future
//! scheduler (R572-F5) can place it only on machines carrying the `public-ip`
//! taint. Until that scheduler + the machine-TOML `taints` field (R572-F3)
//! land, the deploy verb targets the public-IP node explicitly; the annotation
//! is the agreed-upon contract both sides read once enforcement exists.
//!
//! Networking: host-networked infra-tier, exactly like the cloud
//! mesofact-runner — passway binds the node's public `:443` directly, so it
//! needs the host netns (the guarded `yah.network=host` escape hatch, honoured
//! only for `tier="infra"`). The upstreams it forwards to are reached over the
//! WireGuard mesh.
//!
//! Upstreams come from two sources, selected by
//! [`PasswayIngressSpec::discover_from`] (R594-F8): a fixed list
//! ([`PasswayIngressSpec::upstreams`] → `PASSWAY_UPSTREAMS`), and/or yubaba's
//! service-record surface (`PASSWAY_UPSTREAM_SOURCE=yubaba`), which is what
//! makes this appliance an ingress *provider* — the backend set follows
//! placement instead of being typed in, the same way the rented
//! `cloudflare-tunnel` arm's ingress rules are generated from deployed
//! workloads rather than hand-written.
//!
//! Discovery mode also needs [`PasswayIngressSpec::discover_ident`]
//! (R844-B6): the record surface answers for the whole node, so the ident is
//! what keeps this appliance fronting *its* workload rather than every Ready
//! container on the box.
//!
//! R858-T1 made the two sources **coexist on one door** rather than exclude
//! each other. A yubaba's service records are strictly per-node (R844-B11: a
//! record's `mesh_ip` must equal the answering node's own mesh address), so a
//! door polling its local yubaba can never discover a workload placed on a
//! *different* node. The headscale coordinator behind the front doors is
//! exactly that shape, so its address is a **static pin resolved at the
//! control plane** ([`front_door_upstream_rule`]) while every other hostname
//! on the same door keeps following placement. passway merges the two per
//! hostname, static winning a collision.
//!
//! That coordinator upstream also wants a different *scheme* from the rest of
//! the door — headscale terminates its own TLS — so [`HostScoped`] lets
//! `PASSWAY_UPSTREAM_TLS` / `PASSWAY_UPSTREAM_SNI` be stated either once for
//! the whole door (today's meaning, unchanged) or per fronted hostname.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use workload_spec::{
    EnvValue, EnvVar, ExposeSpec, HealthProbe, Healthcheck, ImageRef, LifecycleArchetype,
    MeshExpose, MeshIdent, Millis, NamespaceId, ResourceLimits, RestartPolicy, SchemaVersion,
    SecretMount, SecretRef, SecretTarget, StopPolicy, TenantId, TierTag, VolumeMount, Workload,
    WorkloadSpec, HOST_NETWORK_ANNOTATION, HOST_NETWORK_VALUE, PUBLIC_IP_TAINT,
    REQUIRES_TAINT_ANNOTATION,
};

/// DNS name + mesh identity of the passway ingress workload. Contains
/// `"passway"` so `cloud.ha_diagnose`'s ingress probe (which matches idents
/// by that substring) recognises it.
pub const INGRESS_WORKLOAD_NAME: &str = "passway-ingress";

/// Container-side TLS listener address when the caller doesn't override it.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:443";

/// Container-side TLS port. Mesh-exposed and TCP-probed for liveness.
const TLS_PORT: u16 = 443;

/// Container path the shared cert chain is mounted at (mode `0o400`).
const CERT_MOUNT_PATH: &str = "/run/secrets/tls.crt";
/// Container path the shared private key is mounted at (mode `0o400`).
const KEY_MOUNT_PATH: &str = "/run/secrets/tls.key";

/// Container path the cheers issuer's Ed25519 **verify** key is mounted at
/// (mode `0o400`), when [`PasswayIngressSpec::auth`] is set.
///
/// ⚠ RAW BYTES, EXACTLY 32, AND BOTH FAILURES ARE BOOT PANICS. passway's
/// `build_auth` reads this file and does two things to it in a row, either of
/// which kills the process before it serves a request:
///
/// 1. `bytes.as_slice().try_into()` into `[u8; 32]`, panicking with
///    `"expected exactly 32 bytes, got {n}"` — so a hex/base64/PEM-encoded
///    mount, or one with a trailing newline, dies here.
/// 2. `PasetoV4PublicVerifier::from_public_key(&key).expect("valid Ed25519
///    public key bytes")` — so 32 bytes of the *wrong* thing dies on the very
///    next line.
///
/// Written down because it is exactly the constraint a later reader
/// "simplifies" by storing the key as text: the cost is not a config error at
/// deploy time, it is a door that never comes up, on the host whose whole
/// reason for existing is that it is confidential. Both panics are at
/// `oss/passway/crates/passway/src/main.rs:1139-1146`.
const AUTH_KEY_MOUNT_PATH: &str = "/run/secrets/cheers-verify.key";

/// pingora's per-instance pid file — the target for kamaji's graceful-upgrade
/// `SIGQUIT`. Lives under a writable tmpfs the image provides.
const PID_FILE: &str = "/run/passway/pingora.pid";
/// pingora's per-instance graceful-upgrade fd-handoff socket.
const UPGRADE_SOCK: &str = "/run/passway/upgrade.sock";

/// Default passway binary path inside the image (no `ENTRYPOINT` reliance:
/// `build_oci_spec` ignores the image CMD/ENTRYPOINT and runs `command`
/// directly, so it must be spelled out).
const DEFAULT_COMMAND: &str = "/usr/local/bin/passway";

/// The `<hostname>=` key passway reads as "the catch-all set", as opposed to a
/// bare entry with no prefix at all. Same spelling on both sides of the wire.
pub const CATCH_ALL_LABEL: &str = "*";

/// A per-upstream setting stated either once for the whole door or per fronted
/// hostname (R858-T1) — the spec-side mirror of passway's `HostScoped<T>`.
///
/// A sum type rather than "a global field plus a per-host map" because passway
/// **rejects** a variable that mixes a bare value with `<hostname>=` prefixed
/// ones: an unprefixed value is the process-wide default for every set, so
/// writing both leaves two readings and no way to pick. Modelling it as an
/// either/or makes that unrenderable state unrepresentable here instead of
/// discovering it as a boot panic on the node.
///
/// Two rules follow from the same asymmetry passway documents. A bare value is
/// the *process-wide default*, not the catch-all set's value — that is what
/// the bare form has always meant, and every already-deployed door writes it.
/// [`CATCH_ALL_LABEL`] (`*=<value>`) is how you name the catch-all set
/// specifically. A repeated hostname cannot arise: the map's keys are unique,
/// which is the same error passway raises, enforced one layer earlier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostScoped<T> {
    /// The bare `VAR=value` form — the default for every set that names no
    /// scheme of its own.
    Global(T),
    /// The `<hostname>=<value>,<hostname>=<value>` fan-in form.
    PerHost(BTreeMap<String, T>),
}

impl<T: Default> Default for HostScoped<T> {
    fn default() -> Self {
        Self::Global(T::default())
    }
}

impl<T> HostScoped<T> {
    /// Render to passway's wire grammar — the bare value, or `<hostname>=`
    /// entries joined by `,`. `value_str` spells one `T` the way passway's
    /// matching `parse_value` reads it back.
    ///
    /// Iteration order is the [`BTreeMap`]'s, so the rendered string is a pure
    /// function of the spec: a redeploy that changed nothing produces a
    /// byte-identical env and does not look like a diff to whoever is
    /// comparing two nodes.
    pub fn render(&self, value_str: impl Fn(&T) -> String) -> String {
        match self {
            Self::Global(v) => value_str(v),
            Self::PerHost(map) => map
                .iter()
                .map(|(host, v)| format!("{host}={}", value_str(v)))
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    /// Reject the keys passway refuses at boot, naming `var` so the operator
    /// reads the same variable name here and in the panic they were spared.
    ///
    /// Structural checks only — mixing and repetition are already impossible
    /// by construction (see the type doc), which leaves the two a `BTreeMap`
    /// key cannot rule out: an empty hostname, and one carrying a separator
    /// the grammar would re-split on.
    pub fn validate_keys(&self, var: &str) -> Result<(), String> {
        let Self::PerHost(map) = self else {
            return Ok(());
        };
        for host in map.keys() {
            if host.trim().is_empty() {
                return Err(format!(
                    "{var} has an entry with an empty hostname; write \
                     {CATCH_ALL_LABEL:?} if you meant the catch-all set"
                ));
            }
            if host.contains(',') || host.contains('=') {
                return Err(format!(
                    "{var} hostname {host:?} contains ',' or '=', which the wire grammar uses \
                     as separators — it would be re-split into entries that parse as something \
                     else"
                ));
            }
        }
        Ok(())
    }

    /// Set one hostname's value, promoting a [`Self::Global`] default into the
    /// fan-in form by carrying it over as the explicit catch-all.
    ///
    /// The promotion is what keeps the door's *other* hostnames behaving
    /// exactly as before: dropping the global instead would silently re-default
    /// every set that was relying on it.
    pub fn with_host(self, hostname: impl Into<String>, value: T) -> Self
    where
        T: Clone,
    {
        let mut map = match self {
            Self::PerHost(map) => map,
            Self::Global(global) => {
                BTreeMap::from([(CATCH_ALL_LABEL.to_string(), global)])
            }
        };
        map.insert(hostname.into(), value);
        Self::PerHost(map)
    }
}

/// Render one front door's `PASSWAY_UPSTREAMS` entry for a hostname whose
/// upstream is pinned at the control plane rather than discovered (R591-T2,
/// wired by R858-T1) — the sovereign form of "the external identity follows
/// placement".
///
/// `placed_at` is the mesh address of the node the fronted appliance sits on
/// (for headscale, yubaba publishes it as the `headscale` service record).
/// `this_door` is the mesh address of the node *this* front door runs on.
/// Every front door in the fleet gets a rule for the same hostname, so DNS
/// never moves — a failover repoints upstreams, not records.
///
/// # The co-located door routes to loopback, and that is a constraint, not an
/// optimisation
///
/// Fronting the coordinator over the mesh creates a cycle: a node dials
/// `cloud.mesh.yah.dev` → DNS → a front door → headscale's *mesh* address, so
/// the proxying node needs a working mesh to reach the thing that grants
/// meshes. Steady state is fine (a rebooting node borrows a healthy peer's
/// mesh). A **total-fleet cold start has no path** — nobody has a mesh, so no
/// front door can reach the coordinator, so nobody can get a mesh.
///
/// The operator's answer to the general case is that a camp bootstraps a mesh
/// **out of band** — over ssh, from a list of IPs — rather than over the mesh
/// it is creating; that holds for any new mesh, not just this one. The
/// in-design mitigation is this function: the front door sitting on the same
/// node as the appliance dials `127.0.0.1`, so **one** path to the coordinator
/// never traverses the mesh at all. Whichever node raft placed it on can
/// bootstrap itself, and the rest follow from there.
///
/// (The deadlock is inference from the 2026-08-12 config + topology, not a
/// tested failure. The dev cluster — us-west-011/013/014 — is the sanctioned
/// place to prove it.)
///
/// # Why it lives here
///
/// R858-T1 moved it from `yubaba::headscale_appliance`, which still re-exports
/// it so that module's four tests and its public API are unchanged. It renders
/// `PASSWAY_UPSTREAMS` grammar, which is this module's subject, and the
/// deploy path that had to call it (`yah cloud ingress`) links `local-driver`
/// but deliberately **not** the full `yubaba` lib — that would pull openraft,
/// axum and russh into the CLI for one pure six-line function (R483-T5).
pub fn front_door_upstream_rule(
    hostname: &str,
    placed_at: Ipv4Addr,
    this_door: Ipv4Addr,
    port: u16,
) -> String {
    let upstream = if placed_at == this_door {
        Ipv4Addr::LOCALHOST
    } else {
        placed_at
    };
    format!("{hostname}={upstream}:{port}")
}

/// Cluster-secret key holding the AES-256-GCM-sealed cert chain for `domain`.
/// Mirrors what the R600-F3 issuer writes (`tls/<domain>/cert`).
fn cert_secret_name(domain: &str) -> String {
    format!("tls/{domain}/cert")
}

/// Cluster-secret key holding the sealed private key for `domain`
/// (`tls/<domain>/key`, written key-first/cert-last by the issuer).
fn key_secret_name(domain: &str) -> String {
    format!("tls/{domain}/key")
}

/// Cheers bearer-auth configuration for a door (R556-F6).
///
/// **ONE `Option`, NOT FIVE, AND THAT IS THE POINT.** passway's `build_auth`
/// keys the entire feature off a single variable: it returns `None` — *"every
/// route stays anonymous in that case"* — the moment
/// `PASSWAY_AUTH_PUBLIC_KEY_FILE` is unset, and only `.expect()`s KID / ISS /
/// AUD once the key file **is** set. So the two half-configured spellings fail
/// in opposite directions:
///
/// - key file set, kid missing → a loud boot panic naming the variable. Fine.
/// - key file **unset**, kid/iss/aud set → a **silently anonymous door**, with
///   nothing anywhere complaining, on a host whose whole purpose is that it is
///   operator-confidential.
///
/// The second is the worst outcome in this feature, so it is made
/// unrepresentable rather than merely refused: there is no way to spell four of
/// these five and not the fifth. (Same move R870-F23 made with `DeployTier`.)
///
/// **Auth belongs on the OUTER door.** If a service ever runs an inner door
/// too, it does not get one of these: the outer door is the trust boundary and
/// terminates TLS, while the inner one is cleartext on loopback *behind* it, so
/// a per-process `CheersAuth` there would re-verify a token on a hop that has
/// already passed the boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswayAuth {
    /// Cluster-secret key holding the issuer's **32 raw bytes** of Ed25519
    /// public key — e.g. `"cheers/yah-camp/verify"`. Delivered as a
    /// Cluster→File `SecretMount` at [`AUTH_KEY_MOUNT_PATH`], the same channel
    /// and the same mode the cert/key pair already ride.
    ///
    /// A `SecretMount` rather than `WorkloadSpec::files` because this is key
    /// material and `files` stores its content **in the clear in the spec** —
    /// its own doc says so. The reverse split holds too: a generated, non-
    /// secret routing table has no business in the secret store.
    pub key_secret: String,

    /// `PASSWAY_AUTH_KID` — the issuer key id. `yah cloud cheers show`.
    pub kid: String,

    /// `PASSWAY_AUTH_ISS` — the expected token issuer. `yah cloud cheers show`.
    pub iss: String,

    /// `PASSWAY_AUTH_AUD` — the expected audience. Must match what
    /// `yah cloud cheers token` mints for the service this door fronts.
    pub aud: String,

    /// Path prefixes that REQUIRE a bearer, rendered **comma-joined** into the
    /// single `PASSWAY_AUTH_REQUIRED_PREFIXES` variable — passway splits that
    /// one value on `,` (main.rs:1152), so repeated flags join here rather
    /// than emitting the variable twice.
    ///
    /// It is an allowlist of prefixes that require auth, with no exclusion
    /// form, so `"/"` is the only value that covers a whole surface. Empty is
    /// rejected by [`PasswayIngressSpec::validate`]: a door carrying a verify
    /// key that protects no prefix is auth-configured and anonymous at once,
    /// which is the same failure class this type exists to make unspellable.
    pub require_prefixes: Vec<String>,
}

/// Caller-supplied passway ingress bring-up parameters. The `yah cloud ingress`
/// deploy verb builds this from flags/component config, then lowers it to the
/// yubaba workload payload via [`Self::into_container_workload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswayIngressSpec {
    /// Base/wildcard domain whose fleet-shared cert this ingress consumes, e.g.
    /// `"yah.dev"`. The cluster-secret keys are `tls/<domain>/cert` and
    /// `tls/<domain>/key` (R600-F3).
    pub domain: String,

    /// TLS listener address. Defaults to [`DEFAULT_LISTEN`] (`0.0.0.0:443`).
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Upstream mesh endpoints (`host:port`) passway round-robins across.
    /// Reached over the WireGuard mesh; empty is valid (passway fail-ready-503s
    /// until records populate).
    ///
    /// R594-F10: entries are rendered into `PASSWAY_UPSTREAMS` verbatim, so an
    /// appliance fronting several services writes them host-prefixed —
    /// `"marketing.yah.dev=100.64.0.5:8080"` — and passway gives each hostname
    /// its own health-checked set. No extra field is needed here for that;
    /// mixing prefixed and unprefixed entries is what passway rejects at boot.
    ///
    /// R858-T1: **also rendered alongside [`Self::discover_from`]**, where it
    /// stops being "the backend list" and becomes a set of *pins* — the
    /// hostnames local discovery structurally cannot answer for, because a
    /// yubaba's service records only ever describe its own node (R844-B11).
    /// [`front_door_upstream_rule`] is what produces such an entry. On a
    /// hostname both sources name, passway takes the pin and warns by name.
    #[serde(default)]
    pub upstreams: Vec<String>,

    /// R594-F8: base URL of a yubaba to *discover* upstreams from, e.g.
    /// `http://100.64.0.2:7443`. When set, passway polls that node's
    /// `GET /service-records?ready=true` for every hostname that has no static
    /// pin in [`Self::upstreams`] (R858-T1 — before that the two were
    /// exclusive and the list was dropped entirely).
    ///
    /// This is what makes the appliance an ingress **provider** rather than a
    /// hand-configured proxy: the backend set follows placement, exactly as
    /// the rented arm's tunnel ingress rules do. Leave it `None` for a
    /// standalone edge fronting something yubaba doesn't place.
    ///
    /// Pairs with [`Self::discover_ident`] — set one and you must set the
    /// other, or passway refuses to boot (R844-B6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover_from: Option<String>,

    /// R844-B6: the workload ident whose service records this passway adopts
    /// as backends, rendered as `PASSWAY_YUBABA_IDENT`. Only meaningful
    /// alongside [`Self::discover_from`], and **required** whenever that is
    /// set: the discovery endpoint answers for the whole node, so a passway
    /// polling without an ident routes its one hostname's traffic to every
    /// Ready workload on that node.
    ///
    /// It is `Option` for wire compatibility only — this type is persisted,
    /// and `into_container_workload` returns a `Workload` rather than a
    /// `Result`, so an unpaired spec cannot be rejected at lowering time. It
    /// lowers to a discovery-mode workload with no ident, and passway panics
    /// at boot with the missing variable named. Loud there beats silently
    /// fronting the wrong containers here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover_ident: Option<String>,

    /// Speak TLS to upstreams. Default `false` — the mesh is already
    /// encrypted, so this is the plain-HTTP-over-WireGuard case.
    ///
    /// R858-T1 widened `bool` to [`HostScoped`]: `Global(false)` renders the
    /// bare `PASSWAY_UPSTREAM_TLS=false` every deployed door already carries,
    /// while the fan-in form gives one fronted hostname its own scheme. The
    /// headscale coordinator needs exactly that — it terminates its own Let's
    /// Encrypt TLS on `:443`, so its door must re-encrypt to it while the rest
    /// of the same door stays plaintext.
    #[serde(default)]
    pub upstream_tls: HostScoped<bool>,

    /// SNI to present when upstream TLS is on, rendered as
    /// `PASSWAY_UPSTREAM_SNI` (R858-T1). `None` omits the variable, which is
    /// passway's own default and what every pre-R858 door carries.
    ///
    /// Needed because a TLS upstream reached by *mesh address* presents a
    /// certificate for its public hostname: without an SNI naming that
    /// hostname the handshake fails verification, and the operator would be
    /// debugging the backend's certificate rather than the door's config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_sni: Option<HostScoped<String>>,

    /// R556-F6: require a cheers bearer on this door. `None` — the shape every
    /// door in the tree carried until now — is a fully anonymous door.
    ///
    /// WHY A DOOR-LEVEL FIELD AND NOT A PER-HOSTNAME ONE, which is the first
    /// thing a reader will want: passway's `build_auth` constructs ONE
    /// `CheersAuth` and ONE `RouteAuthPolicy` per **process** and applies them
    /// to every hostname that process fronts. There is no host dimension;
    /// `RouteAuthPolicy::allow_anonymous` carves out sub-*paths*, not hosts.
    /// So "authenticated" is a property of a door, and a confidential service
    /// sharing a door with a public one cannot be protected — it needs a door
    /// of its own. That is not an implementation gap to route around here: it
    /// is why analytics.yah.dev gets a per-tenant door rather than riding
    /// us-east-001's `*.yah.dev` one, whose REQUIRED_PREFIXES="/" would have
    /// demanded a bearer for yah.dev itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<PasswayAuth>,

    /// Override the passway binary invocation. Defaults to
    /// `["/usr/local/bin/passway"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

impl PasswayIngressSpec {
    /// Reject host-scoped settings passway would refuse at boot (R858-T1).
    ///
    /// Separate from [`Self::into_container_workload`] rather than folded into
    /// it because that returns a `Workload`, not a `Result` — this type is
    /// persisted, so lowering has to stay total. Callers that *build* a spec
    /// from operator input (the `yah cloud ingress` deploy verb) call this
    /// first, which turns a boot panic on a remote node into a message in the
    /// terminal of whoever typed the flag.
    pub fn validate(&self) -> Result<(), String> {
        self.upstream_tls.validate_keys("PASSWAY_UPSTREAM_TLS")?;
        if let Some(sni) = &self.upstream_sni {
            sni.validate_keys("PASSWAY_UPSTREAM_SNI")?;
            // passway accepts an empty SNI only in the bare form, where it is
            // the default. Writing `<hostname>=` and stopping says a specific
            // SNI was intended and then names none.
            if let HostScoped::PerHost(map) = sni {
                for (host, value) in map {
                    if value.trim().is_empty() {
                        return Err(format!(
                            "PASSWAY_UPSTREAM_SNI entry for {host:?} names no SNI; omit the \
                             entry to inherit the process-wide default"
                        ));
                    }
                }
            }
        }
        if let Some(auth) = &self.auth {
            // Each of these reaches passway as a variable it `.expect()`s, so an
            // empty one is a boot panic on a remote node. Same argument the
            // function header makes for the host-scoped keys: turn it into a
            // message in the terminal of whoever typed the flag.
            for (field, value) in [
                ("--auth-key-secret", &auth.key_secret),
                ("--auth-kid", &auth.kid),
                ("--auth-iss", &auth.iss),
                ("--auth-aud", &auth.aud),
            ] {
                if value.trim().is_empty() {
                    return Err(format!("{field} is empty; passway panics at boot without it"));
                }
            }
            // A verify key that protects no prefix is auth-configured and
            // anonymous at the same time — the failure class `PasswayAuth`
            // exists to make unspellable, arriving through the one field that
            // can still express it.
            if auth.require_prefixes.iter().all(|p| p.trim().is_empty()) {
                return Err(
                    "--require-auth names no prefix; a door with a verify key that protects \
                     nothing is authenticated and anonymous at once (pass `/` for the whole \
                     surface — the policy is an allowlist of prefixes REQUIRING auth, with no \
                     exclusion form)"
                        .to_string(),
                );
            }
            // PASSWAY_AUTH_REQUIRED_PREFIXES is ONE variable split on `,`, so a
            // comma inside a prefix silently becomes two prefixes — one of them
            // a path nobody meant to protect and, worse, the other a path
            // nobody meant to leave open.
            if let Some(bad) = auth.require_prefixes.iter().find(|p| p.contains(',')) {
                return Err(format!(
                    "--require-auth prefix {bad:?} contains a comma; \
                     PASSWAY_AUTH_REQUIRED_PREFIXES is comma-separated, so this would silently \
                     split into two different prefixes"
                ));
            }
        }
        Ok(())
    }

    /// Lower this ingress spec into a containerd [`Workload`] yubaba can deploy.
    ///
    /// The result is the W273 cert-consuming shape: host-networked infra-tier,
    /// `Appliance` archetype, `public-ip` taint requirement, two Cluster→File
    /// cert/key secret mounts, and `PASSWAY_TLS_MODE=manual` with **no**
    /// `PASSWAY_ACME_*` env.
    ///
    /// `image` is the content-addressed passway image (operator-supplied, same
    /// as the mesofact-runner digest).
    pub fn into_container_workload(&self, image: ImageRef) -> Workload {
        let mut env = vec![
            literal_env("PASSWAY_LISTEN", self.listen.clone()),
            // Consume the shared mount instead of self-issuing — the whole point.
            literal_env("PASSWAY_TLS_MODE", "manual".into()),
            literal_env("PASSWAY_TLS_CERT", CERT_MOUNT_PATH.into()),
            literal_env("PASSWAY_TLS_KEY", KEY_MOUNT_PATH.into()),
            literal_env(
                "PASSWAY_UPSTREAM_TLS",
                self.upstream_tls.render(bool::to_string),
            ),
            // Per-instance paths so kamaji's graceful-upgrade fd-handoff
            // (R600-F4/F7/F9) targets the right pingora process on rotation.
            literal_env("PASSWAY_PID_FILE", PID_FILE.into()),
            literal_env("PASSWAY_UPGRADE_SOCK", UPGRADE_SOCK.into()),
        ];

        // Optional SNI: absent means "inherit passway's default of none",
        // which is what every pre-R858 door renders. Emitting an empty string
        // instead would read as a configured-and-broken value to an operator
        // inspecting the container's env.
        if let Some(sni) = &self.upstream_sni {
            env.push(literal_env("PASSWAY_UPSTREAM_SNI", sni.render(String::clone)));
        }

        // R858-T1 relaxed this from "exactly one source, never both". The
        // invariant is now narrower but still real: PASSWAY_UPSTREAMS is a
        // *pin list* whenever a discovery URL is present, never a fallback.
        // passway's yubaba arm merges the two per hostname and takes the pin
        // on a collision (warning by name), so both being live is a decided
        // outcome rather than the which-arm-did-main.rs-take ambiguity the
        // old comment was written against. What must not happen is the
        // reverse: static mode never emits a discovery URL, because there the
        // proxy genuinely ignores it and the operator would be reading a
        // variable that is not in play.
        match &self.discover_from {
            Some(base_url) => {
                env.push(literal_env("PASSWAY_UPSTREAM_SOURCE", "yubaba".into()));
                env.push(literal_env("PASSWAY_YUBABA_URL", base_url.clone()));
                // Omitted only when the spec is unpaired, which passway then
                // rejects at boot by name — see `discover_ident`.
                if let Some(ident) = &self.discover_ident {
                    env.push(literal_env("PASSWAY_YUBABA_IDENT", ident.clone()));
                }
                // Only when there is something to pin. An empty
                // PASSWAY_UPSTREAMS parses to no sets and would change
                // nothing, but it reads as a list that failed to populate.
                if !self.upstreams.is_empty() {
                    env.push(literal_env("PASSWAY_UPSTREAMS", self.upstreams.join(",")));
                }
            }
            None => {
                env.push(literal_env("PASSWAY_UPSTREAM_SOURCE", "static".into()));
                env.push(literal_env("PASSWAY_UPSTREAMS", self.upstreams.join(",")));
            }
        }

        // R556-F6. Emitted as a block, never piecemeal: the key-file variable
        // is what switches the whole feature on inside passway, so a partial
        // render is the silently-anonymous door `PasswayAuth` exists to
        // prevent. `Option<PasswayAuth>` is what makes that structural — there
        // is no partial value to render.
        if let Some(auth) = &self.auth {
            env.push(literal_env(
                "PASSWAY_AUTH_PUBLIC_KEY_FILE",
                AUTH_KEY_MOUNT_PATH.into(),
            ));
            env.push(literal_env("PASSWAY_AUTH_KID", auth.kid.clone()));
            env.push(literal_env("PASSWAY_AUTH_ISS", auth.iss.clone()));
            env.push(literal_env("PASSWAY_AUTH_AUD", auth.aud.clone()));
            // ONE variable, comma-joined — passway splits this value on `,`
            // rather than reading a repeated variable.
            env.push(literal_env(
                "PASSWAY_AUTH_REQUIRED_PREFIXES",
                auth.require_prefixes.join(","),
            ));
        }

        let mut secrets = vec![
            cluster_file_secret(cert_secret_name(&self.domain), CERT_MOUNT_PATH),
            cluster_file_secret(key_secret_name(&self.domain), KEY_MOUNT_PATH),
        ];
        if let Some(auth) = &self.auth {
            secrets.push(cluster_file_secret(
                auth.key_secret.clone(),
                AUTH_KEY_MOUNT_PATH,
            ));
        }

        let mut annotations = HashMap::new();
        // Bind the public :443 on the host — guarded escape hatch, infra-only.
        annotations.insert(
            HOST_NETWORK_ANNOTATION.to_string(),
            HOST_NETWORK_VALUE.to_string(),
        );
        // Place only on a publicly-routable node (enforced once R572-F5 lands).
        annotations.insert(
            REQUIRES_TAINT_ANNOTATION.to_string(),
            PUBLIC_IP_TAINT.to_string(),
        );

        let grace = Millis::from_secs(5);

        let spec = WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: INGRESS_WORKLOAD_NAME.into(),
            image,
            tier: TierTag("infra".into()),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            replicas: 1,
            command: Some(
                self.command
                    .clone()
                    .unwrap_or_else(|| vec![DEFAULT_COMMAND.into()]),
            ),
            entrypoint: None,
            workdir: None,
            user: None,
            env,
            secrets,
            volumes: Vec::<VolumeMount>::new(),
            resources: ResourceLimits {
                memory_mb: 256,
                cpu_millis: 512,
                ephemeral_storage_mb: 256,
            },
            depends_on: vec![],
            requires: vec![],
            healthcheck: Some(Healthcheck {
                // :443 speaks TLS, so a plaintext HttpGet probe would fail the
                // handshake — a bare TCP connect is the right liveness signal.
                probe: HealthProbe::TcpConnect { port: TLS_PORT },
                interval: Millis::from_secs(10),
                timeout: Millis::from_secs(2),
                initial_delay: Millis::from_secs(10),
                failure_threshold: 3,
            }),
            // Appliance = pinned/non-drainable; always restart the ingress.
            restart_policy: RestartPolicy::Always,
            archetype: Some(LifecycleArchetype::Appliance),
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: grace,
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(INGRESS_WORKLOAD_NAME.into()),
                    ports: MeshExpose::anonymous_ports([TLS_PORT]),
                    allow_from: vec![],
                },
                // passway terminates TLS itself on the public :443 — this is NOT
                // a yubaba CF-managed route, so leave `public` unset.
                public: None,
                operator: None,
            },
            labels: HashMap::new(),
            annotations,
            files: Vec::new(),
        };

        Workload::container(spec)
    }
}

fn literal_env(name: &str, value: String) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: EnvValue::Literal { value },
    }
}

fn cluster_file_secret(name: String, mount_path: &str) -> SecretMount {
    SecretMount {
        source: SecretRef::Cluster { name },
        target: SecretTarget::File {
            path: mount_path.into(),
            mode: 0o400,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image() -> ImageRef {
        ImageRef {
            registry: "localhost".into(),
            repository: "passway".into(),
            tag: "r600f5".into(),
            digest: workload_spec::testing::test_digest(),
        }
    }

    fn sample_spec() -> PasswayIngressSpec {
        PasswayIngressSpec {
            domain: "yah.dev".into(),
            listen: DEFAULT_LISTEN.into(),
            upstreams: vec!["yah-marketing.pdx:8080".into(), "yah-dashboard.pdx:8080".into()],
            upstream_tls: HostScoped::Global(false),
            upstream_sni: None,
            discover_from: None,
            discover_ident: None,
            auth: None,
            command: None,
        }
    }

    /// The R556-F6 shape: a per-tenant door fronting one confidential service,
    /// with cheers auth over its whole surface.
    fn authed_spec() -> PasswayIngressSpec {
        let mut s = sample_spec();
        s.auth = Some(PasswayAuth {
            key_secret: "cheers/yah-camp/verify".into(),
            kid: "YOHV4Riq-g8fX4uYl8rTjQ".into(),
            iss: "yah-camp".into(),
            aud: "yah-analytics".into(),
            require_prefixes: vec!["/".into()],
        });
        s
    }

    /// A discovery-mode spec with the coordinator pinned the way the deploy
    /// path builds it — the R858-T1 shape under test.
    fn discovery_spec_with_pin() -> PasswayIngressSpec {
        let mut s = sample_spec();
        s.discover_from = Some("http://100.64.0.2:7443".into());
        s.discover_ident = Some("yah.dev=yah-marketing".into());
        s.upstreams = vec![front_door_upstream_rule(
            "cloud.mesh.yah.dev",
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            443,
        )];
        s.upstream_tls = HostScoped::Global(false).with_host("cloud.mesh.yah.dev", true);
        s.upstream_sni = Some(HostScoped::PerHost(BTreeMap::from([(
            "cloud.mesh.yah.dev".to_string(),
            "cloud.mesh.yah.dev".to_string(),
        )])));
        s
    }

    fn lower(spec: &PasswayIngressSpec) -> WorkloadSpec {
        spec.into_container_workload(sample_image())
            .container_spec()
            .expect("expected a container reference workload")
            .clone()
    }

    fn env_val<'a>(spec: &'a WorkloadSpec, name: &str) -> Option<&'a str> {
        spec.env.iter().find(|e| e.name == name).and_then(|e| match &e.value {
            EnvValue::Literal { value } => Some(value.as_str()),
            _ => None,
        })
    }

    #[test]
    fn consumes_shared_cert_via_two_cluster_file_mounts() {
        let spec = lower(&sample_spec());
        assert_eq!(spec.secrets.len(), 2, "cert + key");

        let cert = &spec.secrets[0];
        assert_eq!(
            cert.source,
            SecretRef::Cluster {
                name: "tls/yah.dev/cert".into()
            }
        );
        assert_eq!(
            cert.target,
            SecretTarget::File {
                path: CERT_MOUNT_PATH.into(),
                mode: 0o400
            }
        );

        let key = &spec.secrets[1];
        assert_eq!(
            key.source,
            SecretRef::Cluster {
                name: "tls/yah.dev/key".into()
            }
        );
        assert_eq!(
            key.target,
            SecretTarget::File {
                path: KEY_MOUNT_PATH.into(),
                mode: 0o400
            }
        );
    }

    #[test]
    fn runs_manual_tls_pointing_at_the_mounts() {
        let spec = lower(&sample_spec());
        assert_eq!(env_val(&spec, "PASSWAY_TLS_MODE"), Some("manual"));
        assert_eq!(env_val(&spec, "PASSWAY_TLS_CERT"), Some(CERT_MOUNT_PATH));
        assert_eq!(env_val(&spec, "PASSWAY_TLS_KEY"), Some(KEY_MOUNT_PATH));
    }

    #[test]
    fn drops_self_issuance_no_acme_env() {
        let spec = lower(&sample_spec());
        // The W273 payoff: not a single ACME knob, so a stale var can't
        // re-enable per-node issuance.
        assert!(
            !spec.env.iter().any(|e| e.name.starts_with("PASSWAY_ACME")),
            "ingress must carry no PASSWAY_ACME_* env"
        );
        assert_ne!(env_val(&spec, "PASSWAY_TLS_MODE"), Some("acme"));
    }

    #[test]
    fn upstreams_join_into_one_env() {
        let spec = lower(&sample_spec());
        assert_eq!(env_val(&spec, "PASSWAY_UPSTREAM_SOURCE"), Some("static"));
        assert_eq!(
            env_val(&spec, "PASSWAY_UPSTREAMS"),
            Some("yah-marketing.pdx:8080,yah-dashboard.pdx:8080")
        );
        assert_eq!(env_val(&spec, "PASSWAY_UPSTREAM_TLS"), Some("false"));
    }

    #[test]
    fn discover_from_selects_the_yubaba_upstream_source() {
        let mut s = sample_spec();
        s.discover_from = Some("http://100.64.0.2:7443".into());
        s.discover_ident = Some("yah-marketing".into());
        let spec = lower(&s);

        assert_eq!(env_val(&spec, "PASSWAY_UPSTREAM_SOURCE"), Some("yubaba"));
        assert_eq!(
            env_val(&spec, "PASSWAY_YUBABA_URL"),
            Some("http://100.64.0.2:7443")
        );
    }

    #[test]
    fn discovery_mode_renders_the_workload_ident() {
        // R844-B6: without this the deployed passway adopts every Ready
        // record on the polled node, whatever workload it describes.
        let mut s = sample_spec();
        s.discover_from = Some("http://100.64.0.2:7443".into());
        s.discover_ident = Some("yah-marketing".into());
        let spec = lower(&s);

        assert_eq!(
            env_val(&spec, "PASSWAY_YUBABA_IDENT"),
            Some("yah-marketing")
        );
    }

    #[test]
    fn static_mode_renders_no_workload_ident() {
        let spec = lower(&sample_spec());
        assert_eq!(env_val(&spec, "PASSWAY_YUBABA_IDENT"), None);
    }

    #[test]
    fn discovery_mode_renders_static_pins_only_when_they_are_given() {
        // R858-T1 replaced "discovery renders no static list" with "discovery
        // renders the pins it was given, and nothing when it was given none".
        // An empty PASSWAY_UPSTREAMS parses to no sets either way, so omitting
        // it is about what the operator reads off the container, not passway.
        let mut s = sample_spec();
        s.discover_from = Some("http://100.64.0.2:7443".into());
        s.upstreams = vec![];
        let spec = lower(&s);
        assert_eq!(
            env_val(&spec, "PASSWAY_UPSTREAMS"),
            None,
            "a discovery-mode ingress with nothing pinned must not carry an empty list"
        );

        let spec = lower(&discovery_spec_with_pin());
        assert_eq!(env_val(&spec, "PASSWAY_UPSTREAM_SOURCE"), Some("yubaba"));
        assert_eq!(
            env_val(&spec, "PASSWAY_UPSTREAMS"),
            Some("cloud.mesh.yah.dev=100.64.0.1:443"),
            "the pin rides alongside discovery — it names a node this door's \
             local yubaba cannot see (R844-B11)"
        );
        assert_eq!(
            env_val(&spec, "PASSWAY_YUBABA_URL"),
            Some("http://100.64.0.2:7443"),
            "and discovery stays live for every other hostname"
        );
        assert_eq!(
            env_val(&spec, "PASSWAY_YUBABA_IDENT"),
            Some("yah.dev=yah-marketing")
        );
    }

    #[test]
    fn per_host_upstream_scheme_renders_passways_fan_in_grammar() {
        // The coordinator terminates its own TLS on :443 while the rest of the
        // same door stays plaintext over the mesh.
        let spec = lower(&discovery_spec_with_pin());
        assert_eq!(
            env_val(&spec, "PASSWAY_UPSTREAM_TLS"),
            Some("*=false,cloud.mesh.yah.dev=true"),
            "the prior global is carried over as the explicit catch-all, so no \
             other hostname's scheme changes"
        );
        assert_eq!(
            env_val(&spec, "PASSWAY_UPSTREAM_SNI"),
            Some("cloud.mesh.yah.dev=cloud.mesh.yah.dev")
        );
    }

    #[test]
    fn bare_upstream_scheme_still_renders_the_pre_r858_shape() {
        // Every already-deployed door writes the bare form; widening the field
        // to a sum type must not have moved that byte.
        let mut s = sample_spec();
        s.upstream_tls = HostScoped::Global(true);
        s.upstream_sni = Some(HostScoped::Global("edge.example.com".into()));
        let spec = lower(&s);
        assert_eq!(env_val(&spec, "PASSWAY_UPSTREAM_TLS"), Some("true"));
        assert_eq!(
            env_val(&spec, "PASSWAY_UPSTREAM_SNI"),
            Some("edge.example.com")
        );
    }

    #[test]
    fn omitted_sni_renders_no_variable_at_all() {
        let spec = lower(&sample_spec());
        assert_eq!(env_val(&spec, "PASSWAY_UPSTREAM_SNI"), None);
    }

    #[test]
    fn front_door_rule_sends_the_co_located_door_to_loopback() {
        const WEST: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
        const EAST: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

        assert_eq!(
            front_door_upstream_rule("cloud.mesh.yah.dev", WEST, EAST, 443),
            "cloud.mesh.yah.dev=100.64.0.1:443"
        );
        // The bootstrap-cycle mitigation: one path to the coordinator that
        // never traverses the mesh the coordinator itself grants.
        assert_eq!(
            front_door_upstream_rule("cloud.mesh.yah.dev", WEST, WEST, 443),
            "cloud.mesh.yah.dev=127.0.0.1:443"
        );
    }

    #[test]
    fn validate_rejects_the_keys_passway_would_panic_on() {
        let mut s = sample_spec();
        s.upstream_tls = HostScoped::PerHost(BTreeMap::from([("".to_string(), true)]));
        let err = s.validate().expect_err("empty hostname");
        assert!(err.contains("PASSWAY_UPSTREAM_TLS"), "names the var: {err}");

        let mut s = sample_spec();
        s.upstream_sni = Some(HostScoped::PerHost(BTreeMap::from([(
            "cloud.mesh.yah.dev".to_string(),
            String::new(),
        )])));
        let err = s.validate().expect_err("empty SNI value");
        assert!(err.contains("names no SNI"), "explains why: {err}");

        assert!(discovery_spec_with_pin().validate().is_ok());
        assert!(sample_spec().validate().is_ok());
    }

    #[test]
    fn static_mode_renders_no_discovery_url() {
        let spec = lower(&sample_spec());
        assert_eq!(env_val(&spec, "PASSWAY_YUBABA_URL"), None);
    }

    #[test]
    fn upgrade_wiring_present_for_graceful_reload() {
        let spec = lower(&sample_spec());
        assert_eq!(env_val(&spec, "PASSWAY_PID_FILE"), Some(PID_FILE));
        assert_eq!(env_val(&spec, "PASSWAY_UPGRADE_SOCK"), Some(UPGRADE_SOCK));
        // PASSWAY_UPGRADE is set by kamaji ONLY on the replacement process, never
        // baked into the steady-state spec.
        assert!(!spec.env.iter().any(|e| e.name == "PASSWAY_UPGRADE"));
    }

    #[test]
    fn is_public_ip_appliance_on_host_network() {
        let spec = lower(&sample_spec());
        assert_eq!(spec.archetype, Some(LifecycleArchetype::Appliance));
        assert_eq!(spec.requires_taint(), Some(PUBLIC_IP_TAINT));
        assert!(spec.wants_host_network());
        assert_eq!(spec.tier.0, "infra");
    }

    #[test]
    fn ha_diagnose_can_find_it_by_ident() {
        let spec = lower(&sample_spec());
        assert!(spec.expose.mesh.identity.0.to_lowercase().contains("passway"));
        assert_eq!(spec.expose.mesh.numbers(), vec![443]);
    }

    #[test]
    fn command_defaults_and_overrides() {
        let spec = lower(&sample_spec());
        assert_eq!(spec.command.as_deref().unwrap(), [DEFAULT_COMMAND]);

        let mut custom = sample_spec();
        custom.command = Some(vec!["/usr/bin/tini".into(), "--".into(), "/bin/passway".into()]);
        let spec = lower(&custom);
        assert_eq!(
            spec.command.as_deref().unwrap(),
            ["/usr/bin/tini", "--", "/bin/passway"]
        );
    }

    #[test]
    fn lowered_spec_passes_shape_validation() {
        let spec = lower(&sample_spec());
        workload_spec::validate::shape(&spec).expect("ingress spec passes shape validation");
    }

    #[test]
    fn spec_round_trips_through_serde_with_defaults() {
        let json = r#"{ "domain": "yah.dev", "upstreams": ["a.pdx:8080"] }"#;
        let spec: PasswayIngressSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.listen, DEFAULT_LISTEN);
        // R858-T1 widened this from `bool`; the default it defaults TO is
        // unchanged, which is the part the wire cares about.
        assert_eq!(spec.upstream_tls, HostScoped::Global(false));
        assert!(spec.upstream_sni.is_none(), "no SNI is passway's default");
        assert!(spec.command.is_none());
        assert!(spec.discover_from.is_none(), "static is the default source");
        assert_eq!(spec.upstreams, vec!["a.pdx:8080".to_string()]);
    }

    #[test]
    fn host_scoped_settings_round_trip_in_both_forms() {
        // Untagged, so the bare JSON scalar every persisted spec already
        // carries keeps deserializing — widening the field must not have
        // invalidated a stored document.
        let bare: PasswayIngressSpec =
            serde_json::from_str(r#"{ "domain": "yah.dev", "upstream_tls": true }"#).unwrap();
        assert_eq!(bare.upstream_tls, HostScoped::Global(true));
        assert_eq!(serde_json::to_value(&bare.upstream_tls).unwrap(), true);

        let fanned: PasswayIngressSpec = serde_json::from_str(
            r#"{ "domain": "yah.dev",
                 "upstream_tls": { "cloud.mesh.yah.dev": true, "*": false },
                 "upstream_sni": { "cloud.mesh.yah.dev": "cloud.mesh.yah.dev" } }"#,
        )
        .unwrap();
        assert_eq!(
            fanned.upstream_tls.render(bool::to_string),
            "*=false,cloud.mesh.yah.dev=true"
        );
        assert_eq!(
            fanned.upstream_sni.as_ref().unwrap().render(String::clone),
            "cloud.mesh.yah.dev=cloud.mesh.yah.dev"
        );
    }

    // ── R556-F6: cheers auth on a door ──────────────────────────────────────

    #[test]
    fn a_door_is_anonymous_unless_auth_is_declared() {
        // The shape every door in the tree carried before R556-F6, asserted so
        // that adding auth cannot silently arm it on the public apex.
        let spec = lower(&sample_spec());
        for name in [
            "PASSWAY_AUTH_PUBLIC_KEY_FILE",
            "PASSWAY_AUTH_KID",
            "PASSWAY_AUTH_ISS",
            "PASSWAY_AUTH_AUD",
            "PASSWAY_AUTH_REQUIRED_PREFIXES",
        ] {
            assert_eq!(env_val(&spec, name), None, "{name} leaked onto an unauthed door");
        }
        assert!(
            !spec.secrets.iter().any(|s| matches!(
                &s.target,
                SecretTarget::File { path, .. } if path.as_os_str() == AUTH_KEY_MOUNT_PATH
            )),
            "an unauthed door mounted a verify key"
        );
    }

    #[test]
    fn auth_renders_all_five_variables_and_mounts_the_key() {
        let spec = lower(&authed_spec());
        // The key file variable names the MOUNT PATH, never the secret key —
        // passway reads a file, and the cluster-secret name is resolved
        // node-side by the SecretMount below.
        assert_eq!(
            env_val(&spec, "PASSWAY_AUTH_PUBLIC_KEY_FILE"),
            Some(AUTH_KEY_MOUNT_PATH)
        );
        assert_eq!(env_val(&spec, "PASSWAY_AUTH_KID"), Some("YOHV4Riq-g8fX4uYl8rTjQ"));
        assert_eq!(env_val(&spec, "PASSWAY_AUTH_ISS"), Some("yah-camp"));
        assert_eq!(env_val(&spec, "PASSWAY_AUTH_AUD"), Some("yah-analytics"));
        assert_eq!(env_val(&spec, "PASSWAY_AUTH_REQUIRED_PREFIXES"), Some("/"));

        // Cluster→File at 0o400, the same channel and mode the cert/key pair
        // ride — key material never goes through `WorkloadSpec::files`, which
        // stores content in the clear in the spec.
        let mount = spec
            .secrets
            .iter()
            .find(|s| matches!(
                &s.target,
                SecretTarget::File { path, .. } if path.as_os_str() == AUTH_KEY_MOUNT_PATH
            ))
            .expect("verify key was not mounted");
        assert!(
            matches!(&mount.source, SecretRef::Cluster { name } if name == "cheers/yah-camp/verify"),
            "verify key must come from the cluster store, got {:?}",
            mount.source
        );
        assert!(
            matches!(&mount.target, SecretTarget::File { mode, .. } if *mode == 0o400),
            "verify key mount must be 0o400 like the cert/key pair"
        );
        // The cert/key pair is still there — auth adds a mount, never replaces.
        assert_eq!(spec.secrets.len(), 3);
    }

    #[test]
    fn required_prefixes_is_one_comma_joined_variable() {
        // passway splits PASSWAY_AUTH_REQUIRED_PREFIXES on `,` (main.rs:1152)
        // rather than reading a repeated variable, so several `--require-auth`
        // flags must join here. Emitting the variable twice would leave passway
        // seeing whichever the runtime kept.
        let mut s = authed_spec();
        s.auth.as_mut().unwrap().require_prefixes =
            vec!["/api".into(), "/admin".into()];
        let spec = lower(&s);
        assert_eq!(
            env_val(&spec, "PASSWAY_AUTH_REQUIRED_PREFIXES"),
            Some("/api,/admin")
        );
        assert_eq!(
            spec.env
                .iter()
                .filter(|e| e.name == "PASSWAY_AUTH_REQUIRED_PREFIXES")
                .count(),
            1
        );
    }

    #[test]
    fn half_configured_auth_has_no_spelling() {
        // The whole reason `auth` is ONE Option rather than five. passway's
        // build_auth keys the feature off PASSWAY_AUTH_PUBLIC_KEY_FILE alone
        // and returns None — every route anonymous — when it is unset, while
        // .expect()-ing kid/iss/aud only once it IS set. Five independent
        // fields would let a caller spell kid+iss+aud with no key and get a
        // silently anonymous door on a confidential host; this asserts the
        // rendering is all-or-nothing, which `Option<PasswayAuth>` makes
        // structural rather than merely tested.
        let anon = lower(&sample_spec());
        let authed = lower(&authed_spec());
        let count = |s: &WorkloadSpec| {
            s.env.iter().filter(|e| e.name.starts_with("PASSWAY_AUTH_")).count()
        };
        assert_eq!(count(&anon), 0);
        assert_eq!(count(&authed), 5);
    }

    #[test]
    fn validate_refuses_the_shapes_that_would_panic_or_go_quiet() {
        assert!(authed_spec().validate().is_ok());

        // Each of these reaches passway as a variable it .expect()s.
        for blank in ["key_secret", "kid", "iss", "aud"] {
            let mut s = authed_spec();
            let a = s.auth.as_mut().unwrap();
            match blank {
                "key_secret" => a.key_secret = "  ".into(),
                "kid" => a.kid = String::new(),
                "iss" => a.iss = String::new(),
                _ => a.aud = String::new(),
            }
            assert!(s.validate().is_err(), "{blank} blank was accepted");
        }

        // Auth-configured and anonymous at once — the failure class the type
        // exists to prevent, arriving through the one field that can still
        // express it.
        let mut none = authed_spec();
        none.auth.as_mut().unwrap().require_prefixes = vec![];
        assert!(none.validate().is_err());
        let mut blank = authed_spec();
        blank.auth.as_mut().unwrap().require_prefixes = vec!["  ".into()];
        assert!(blank.validate().is_err());

        // A comma inside a prefix silently becomes two prefixes — one nobody
        // meant to protect, one nobody meant to leave open.
        let mut comma = authed_spec();
        comma.auth.as_mut().unwrap().require_prefixes = vec!["/a,/b".into()];
        let err = comma.validate().unwrap_err();
        assert!(err.contains("comma-separated"), "{err}");
    }

    #[test]
    fn auth_survives_a_serde_round_trip_and_defaults_to_absent() {
        // The spec is persisted, so an older record with no `auth` key must
        // deserialize as an anonymous door rather than failing.
        let legacy: PasswayIngressSpec =
            serde_json::from_str(r#"{ "domain": "yah.dev" }"#).unwrap();
        assert!(legacy.auth.is_none());

        let round: PasswayIngressSpec =
            serde_json::from_str(&serde_json::to_string(&authed_spec()).unwrap()).unwrap();
        assert_eq!(round.auth, authed_spec().auth);

        // ...and an anonymous door does not persist a null `auth` key.
        let json = serde_json::to_string(&sample_spec()).unwrap();
        assert!(!json.contains("auth"), "{json}");
    }
}
