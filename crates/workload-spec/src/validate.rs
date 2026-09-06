//! Shape validators for [`WorkloadSpec`].
//!
//! Called by clients (desktop, agent, CLI) before sending a spec over RPC.
//! Sync, no I/O. Returns `Ok(warnings)` on pass or `Err(ShapeError)` on the
//! first hard constraint violation.
//!
//! Layers: shape (this file, no I/O) → semantic (yubaba-side, R090-F3) →
//! environment (deploy-time, R090-F4).

use std::fmt;
use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;

use crate::{
    EnvValue, EnvVar, ImageRef, LifecycleArchetype, MachineId, MeshIdent, MeshLookup,
    RestartPolicy, SecretRef, SecretTarget, StaticAssetWorkload, Supply, VolumeSource,
    WorkloadSpec, DURABILITY_SUBJECTS_ANNOTATION, DURABILITY_TIER_ANNOTATION,
};

// ── Field paths ───────────────────────────────────────────────────────────────

/// Identifies the field that caused a shape error or warning.
///
/// Structured as an enum so promoting to all-errors mode (collecting into
/// `Vec<FieldError>` instead of returning on the first hit) is mechanical.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldPath {
    Name,
    MeshIdentity,
    TailscaleTag,
    Replicas,
    ImageTag,
    Tier,
    /// `volumes[index].<sub>` — e.g. `Volume(0, "source")`.
    Volume(usize, &'static str),
    /// Public port not found in `expose.mesh.ports`.
    ExposeMeshPort(u16),
    /// `expose.mesh.ports[index]` — a malformed port declaration (R844-F17):
    /// an empty entry, a bad name, or a name/number repeated within the list.
    MeshPort(usize),
    /// `secrets[index].<sub>` — e.g. `Secret(0, "target.path")`.
    Secret(usize, &'static str),
    /// `healthcheck.<sub>`.
    Healthcheck(&'static str),
    RestartPolicy,
    /// `image` — registry says the image/tag is unknown.
    Image,
    /// `depends_on[index]` — mesh ident is not a known deployed workload.
    DependsOn(usize),
    /// `requires[index]` — a malformed requirement (R860-T1): a `supply` /
    /// `provides` mismatch, a provider whose spec names a different identity,
    /// a nested `self` supply, or a repeated / self-naming ident.
    Requires(usize),
    /// `expose.public.hostname` — hostname is not in an owned CF zone.
    Hostname,
    /// `resources` — machine lacks sufficient capacity.
    Resources,
    /// `aliases[key]` — alias target filename is not in the `[[asset]]` catalog.
    AssetAlias(String),
    /// `asset[index].<sub>` — e.g. `Asset(0, "source")` for the XOR rule.
    Asset(usize, &'static str),
    /// `annotations["<key>"]` — a declaration carried as an annotation rather
    /// than a field, because `WorkloadSpec` crosses a positional postcard wire
    /// (R590-B3). `yah.durability.tier` is the first.
    Annotation(&'static str),
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldPath::Name => write!(f, "name"),
            FieldPath::MeshIdentity => write!(f, "expose.mesh.identity"),
            FieldPath::TailscaleTag => write!(f, "expose.operator.tailscale_tag"),
            FieldPath::Replicas => write!(f, "replicas"),
            FieldPath::ImageTag => write!(f, "image.tag"),
            FieldPath::Tier => write!(f, "tier"),
            FieldPath::Volume(i, sub) => write!(f, "volumes[{i}].{sub}"),
            FieldPath::ExposeMeshPort(port) => write!(f, "expose.public.port ({port})"),
            FieldPath::MeshPort(i) => write!(f, "expose.mesh.ports[{i}]"),
            FieldPath::Secret(i, sub) => write!(f, "secrets[{i}].{sub}"),
            FieldPath::Healthcheck(sub) => write!(f, "healthcheck.{sub}"),
            FieldPath::RestartPolicy => write!(f, "restart_policy"),
            FieldPath::Image => write!(f, "image"),
            FieldPath::DependsOn(i) => write!(f, "depends_on[{i}]"),
            FieldPath::Requires(i) => write!(f, "requires[{i}]"),
            FieldPath::Hostname => write!(f, "expose.public.hostname"),
            FieldPath::Resources => write!(f, "resources"),
            FieldPath::AssetAlias(key) => write!(f, "aliases[{key}]"),
            FieldPath::Asset(i, sub) => write!(f, "asset[{i}].{sub}"),
            FieldPath::Annotation(key) => write!(f, "annotations[\"{key}\"]"),
        }
    }
}

// ── Hard errors ───────────────────────────────────────────────────────────────

/// A hard constraint violation that makes a spec impossible to deploy.
///
/// V1 surfaces the first error found. When the UI needs per-field
/// highlighting, wrap in `Vec<ShapeError>` and collect instead of returning
/// early — the `FieldPath` enum is already the common currency.
#[derive(Debug, Error, PartialEq)]
pub enum ShapeError {
    #[error("field {path}: {reason}")]
    Field { path: FieldPath, reason: String },
}

// ── Soft warnings ─────────────────────────────────────────────────────────────

/// A soft check that passed but may indicate misconfiguration.
#[derive(Debug, Clone, PartialEq)]
pub struct ShapeWarning {
    pub path: FieldPath,
    pub message: String,
}

impl fmt::Display for ShapeWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "warning at {}: {}", self.path, self.message)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// V1 known tier values. Unknown tiers produce a warning, not an error
/// (cluster config may add custom tiers).
const KNOWN_TIERS: &[&str] = &["public", "tenant", "private", "infra"];

fn dns_label_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$").unwrap())
}

fn env_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Z_][A-Z0-9_]*$").unwrap())
}

/// Validates a single DNS label: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, ≤ 63 chars.
fn check_dns_label(value: &str, path: FieldPath) -> Result<(), ShapeError> {
    if value.len() > 63 {
        return Err(ShapeError::Field {
            path,
            reason: format!("length {} exceeds maximum 63", value.len()),
        });
    }
    if !dns_label_re().is_match(value) {
        return Err(ShapeError::Field {
            path,
            reason: format!(
                "{:?} must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
                value
            ),
        });
    }
    Ok(())
}

/// Validates a dot-separated mesh identity where each segment is a DNS label.
/// Total length ≤ 63. Example valid value: `"noisetable-api.pdx"`.
fn check_mesh_ident(value: &str, path: FieldPath) -> Result<(), ShapeError> {
    if value.len() > 63 {
        return Err(ShapeError::Field {
            path,
            reason: format!("length {} exceeds maximum 63", value.len()),
        });
    }
    for segment in value.split('.') {
        if !dns_label_re().is_match(segment) {
            return Err(ShapeError::Field {
                path,
                reason: format!(
                    "segment {:?} in {:?} must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
                    segment, value
                ),
            });
        }
    }
    Ok(())
}

/// The longest a port name may be. Matches IANA's service-name limit, which is
/// what Kubernetes uses for the same field and what any tool that has to render
/// a port name in a fixed column already assumes.
const MESH_PORT_NAME_MAX: usize = 15;

/// Validates `expose.mesh.ports` (R844-F17): every entry states something, every
/// name is a DNS label short enough to be a service name, and nothing is
/// declared twice.
///
/// The uniqueness rules are the load-bearing half. A repeated *name* would make
/// `name -> port` ambiguous at exactly the moment a consumer asks for it —
/// `ServiceRecord::port("http")` and the `PORT_HTTP` variable both resolve
/// through that map — and a repeated *number* is a workload asking to bind one
/// socket twice. Both are caught here rather than at bring-up because the
/// author can still see the manifest.
fn check_mesh_ports(
    mesh: &crate::MeshExpose,
    warnings: &mut Vec<ShapeWarning>,
) -> Result<(), ShapeError> {
    let mut seen_names: Vec<&str> = Vec::new();
    let mut seen_numbers: Vec<u16> = Vec::new();

    for (i, port) in mesh.ports.iter().enumerate() {
        let path = FieldPath::MeshPort(i);

        if port.name.is_none() && port.number.is_none() {
            return Err(ShapeError::Field {
                path,
                reason: "declares neither a name nor a number — write a number \
                         (8080), a name (\"http\"), or both \
                         ({ name = \"http\", port = 8080 })"
                    .to_string(),
            });
        }

        if let Some(name) = port.name.as_deref() {
            if name.len() > MESH_PORT_NAME_MAX {
                return Err(ShapeError::Field {
                    path,
                    reason: format!(
                        "port name {name:?} is {} characters; the maximum is \
                         {MESH_PORT_NAME_MAX}",
                        name.len()
                    ),
                });
            }
            if !dns_label_re().is_match(name) {
                return Err(ShapeError::Field {
                    path,
                    reason: format!(
                        "port name {name:?} must match \
                         ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
                    ),
                });
            }
            if seen_names.contains(&name) {
                return Err(ShapeError::Field {
                    path,
                    reason: format!(
                        "port name {name:?} is declared twice; a name is how a \
                         consumer selects one port, so it has to pick out \
                         exactly one"
                    ),
                });
            }
            seen_names.push(name);
        }

        match port.number {
            Some(number) => {
                if seen_numbers.contains(&number) {
                    return Err(ShapeError::Field {
                        path,
                        reason: format!(
                            "port {number} is declared twice; a workload cannot \
                             bind the same port on two listeners"
                        ),
                    });
                }
                seen_numbers.push(number);
            }
            // Still a warning rather than an error, but R844-F21 changed what
            // it has to say. A name-only port IS allocated now — on the native
            // backend, which owns the workload's network namespace: kamaji
            // picks the number, remembers it per `(ident, name)` across a
            // restart, and hands it to the process as `PORT_<NAME>`.
            //
            // It is still unbindable on a container backend, where the ports
            // are the image's and both backends refuse the spelling outright
            // (`kamaji::reject_unresolved_ports`). Shape validation cannot tell
            // which backend a spec will land on — placement decides that later
            // — so naming the split is the most this layer can honestly say,
            // and it is why an error here would be wrong.
            None => warnings.push(ShapeWarning {
                path,
                message: format!(
                    "port {:?} declares no number: the native backend allocates \
                     one and tells the process via PORT_{}, but a container \
                     backend refuses it — a container's ports are its image's. \
                     State the number ({{ name = {:?}, port = <n> }}) if this \
                     workload runs as a container.",
                    port.name.as_deref().unwrap_or_default(),
                    port.name
                        .as_deref()
                        .unwrap_or_default()
                        .to_uppercase()
                        .replace(|c: char| !c.is_ascii_alphanumeric(), "_"),
                    port.name.as_deref().unwrap_or_default(),
                ),
            }),
        }
    }

    Ok(())
}

/// Validates `requires` (R860-T1 / W338): the `supply` / `provides` pairing,
/// the identity a self-provisioned provider claims, the depth bound on the
/// recursion, and ident uniqueness.
///
/// The depth bound is the load-bearing rule. `Requirement::provides` makes
/// `WorkloadSpec` recursive, and a provider that may itself self-provision
/// turns "a workload plus its sidecars" into an unbounded tree that placement
/// would have to flatten before it could schedule anything. One level is what
/// the design asks for, so one level is what is representable.
fn check_requires(spec: &WorkloadSpec) -> Result<(), ShapeError> {
    let mut seen: Vec<&str> = Vec::new();

    for (i, req) in spec.requires.iter().enumerate() {
        let path = || FieldPath::Requires(i);
        let ident = req.ident.0.as_str();

        if ident == spec.expose.mesh.identity.0 {
            return Err(ShapeError::Field {
                path: path(),
                reason: format!(
                    "requires its own identity {ident:?}; a workload cannot be \
                     its own provider"
                ),
            });
        }
        if seen.contains(&ident) {
            return Err(ShapeError::Field {
                path: path(),
                reason: format!(
                    "ident {ident:?} is declared twice; one requirement per \
                     provider, since a second entry could only contradict the \
                     first's locality or supply"
                ),
            });
        }
        seen.push(ident);

        match (req.supply, &req.provides) {
            (Supply::SelfProvision, None) => {
                return Err(ShapeError::Field {
                    path: path(),
                    reason: format!(
                        "supply = \"self\" on {ident:?} but no `provides` spec; \
                         a self-provisioned requirement is the one that carries \
                         its provider, so there is nothing to stand up"
                    ),
                });
            }
            (Supply::Wait, Some(_)) => {
                return Err(ShapeError::Field {
                    path: path(),
                    reason: format!(
                        "supply = \"wait\" on {ident:?} but a `provides` spec is \
                         present; a waiting requirement names a provider someone \
                         else declares, so this spec would have no owner — set \
                         supply = \"self\" to deploy it here"
                    ),
                });
            }
            (Supply::Wait, None) => {}
            (Supply::SelfProvision, Some(provided)) => {
                if provided.expose.mesh.identity.0 != ident {
                    return Err(ShapeError::Field {
                        path: path(),
                        reason: format!(
                            "`provides` declares expose.mesh.identity {:?} but the \
                             requirement names {ident:?}; the provider keeps its \
                             own mesh identity and it has to be the one this \
                             requirement asks for (its `name` is {:?})",
                            provided.expose.mesh.identity.0, provided.name
                        ),
                    });
                }
                if let Some(nested) = provided
                    .requires
                    .iter()
                    .find(|r| matches!(r.supply, Supply::SelfProvision))
                {
                    return Err(ShapeError::Field {
                        path: path(),
                        reason: format!(
                            "`provides` spec {ident:?} itself requires {:?} with \
                             supply = \"self\"; composition is bounded at one \
                             level, so a provider may only wait on things it \
                             does not deploy — hoist that requirement up to this \
                             spec's own `requires`",
                            nested.ident.0
                        ),
                    });
                }
            }
        }
    }

    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Run shape validation — sync, no I/O.
///
/// Returns `Ok(warnings)` when all hard constraints pass; the `Vec` is empty
/// for a clean spec. Returns `Err` on the first hard constraint violation.
/// Callers that only need hard errors can discard the Ok value with
/// `.map(|_| ())`.
///
/// Hard constraints checked:
/// - `name`, `expose.mesh.identity`: DNS-label format, ≤ 63 chars.
/// - `expose.operator.tailscale_tag`: `"tag:<dns-label>"`, ≤ 63 chars.
/// - `replicas`: 0–100.
/// - `image.tag`: non-empty when `digest` is `None`.
/// - `volumes[*].source = Bind`: only allowed when `tier = "infra"`.
/// - `expose.mesh.ports[*]`: each entry states a name and/or a number; names are
///   DNS labels ≤ 15 chars; no name and no number is declared twice (R844-F17).
/// - `expose.public.port`: must appear in `expose.mesh.ports`.
/// - `secrets[*].target`: file paths must be absolute; env-var names must
///   match `^[A-Z_][A-Z0-9_]*$`.
/// - `requires[*]`: `supply = "self"` carries a `provides` spec and
///   `supply = "wait"` does not; a `provides` spec declares the identity its
///   requirement names; a `provides` spec carries no `self` supply of its own
///   (depth 1); idents are unique and none is the spec's own (R860-T1).
///
/// Soft checks (produce warnings, not errors):
/// - `expose.mesh.ports[*]`: a name with no number — nothing allocates from the
///   manifest yet, so nothing binds it (R844-F17).
/// - Unknown tier value.
/// - `RestartPolicy::Never` without `annotations["yah.forge"] = "true"`.
/// - `healthcheck.initial_delay < stop_policy.grace_period * 2`.
pub fn shape(spec: &WorkloadSpec) -> Result<Vec<ShapeWarning>, ShapeError> {
    let mut warnings: Vec<ShapeWarning> = Vec::new();

    // name: single DNS label, ≤ 63 chars
    check_dns_label(&spec.name, FieldPath::Name)?;

    // expose.mesh.identity: dot-separated DNS name, ≤ 63 total
    check_mesh_ident(&spec.expose.mesh.identity.0, FieldPath::MeshIdentity)?;

    // expose.operator.tailscale_tag: "tag:<dns-label>", ≤ 63 chars (optional)
    if let Some(op) = &spec.expose.operator {
        let tag = &op.tailscale_tag;
        if tag.len() > 63 {
            return Err(ShapeError::Field {
                path: FieldPath::TailscaleTag,
                reason: format!("length {} exceeds maximum 63", tag.len()),
            });
        }
        let rest = tag.strip_prefix("tag:").ok_or_else(|| ShapeError::Field {
            path: FieldPath::TailscaleTag,
            reason: format!("{:?} must start with \"tag:\"", tag),
        })?;
        if !dns_label_re().is_match(rest) {
            return Err(ShapeError::Field {
                path: FieldPath::TailscaleTag,
                reason: format!(
                    "the part after \"tag:\" in {:?} must match \
                     ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
                    tag
                ),
            });
        }
    }

    // replicas: 0..=100
    if spec.replicas > 100 {
        return Err(ShapeError::Field {
            path: FieldPath::Replicas,
            reason: format!("{} exceeds maximum 100", spec.replicas),
        });
    }

    // image.tag: non-empty (informational identifier; digest is the source of
    // truth and is structurally required at the type level).
    if spec.image.tag.is_empty() {
        return Err(ShapeError::Field {
            path: FieldPath::ImageTag,
            reason: "tag is empty; provide a human-readable tag alongside the digest".into(),
        });
    }

    // tier: warn on unknown (cluster config may add custom tiers)
    if !KNOWN_TIERS.contains(&spec.tier.0.as_str()) {
        warnings.push(ShapeWarning {
            path: FieldPath::Tier,
            message: format!(
                "\"{}\" is not in the known tier set (public/tenant/private/infra); \
                 yubaba may reject it if the cluster config does not include this tier",
                spec.tier.0
            ),
        });
    }

    // volumes[*]: Bind rejected unless tier = "infra"
    for (i, vol) in spec.volumes.iter().enumerate() {
        if matches!(&vol.source, VolumeSource::Bind { .. }) && spec.tier.0 != "infra" {
            return Err(ShapeError::Field {
                path: FieldPath::Volume(i, "source"),
                reason: format!(
                    "Bind mounts are only allowed when tier = \"infra\" \
                     (current tier: {:?})",
                    spec.tier.0
                ),
            });
        }
    }

    // expose.mesh.ports[*]: names well-formed, nothing declared twice (R844-F17)
    check_mesh_ports(&spec.expose.mesh, &mut warnings)?;

    // requires[*]: supply/provides pairing, provider identity, depth bound,
    // ident uniqueness (R860-T1)
    check_requires(spec)?;

    // expose.public.port must appear in expose.mesh.ports
    if let Some(public) = &spec.expose.public {
        if !spec.expose.mesh.declares_number(public.port) {
            return Err(ShapeError::Field {
                path: FieldPath::ExposeMeshPort(public.port),
                reason: format!(
                    "port {} must appear in expose.mesh.ports {:?} \
                     before it can be exposed publicly",
                    public.port,
                    spec.expose.mesh.numbers()
                ),
            });
        }
    }

    // secrets[*]: target paths absolute; env-var names valid identifiers
    for (i, secret) in spec.secrets.iter().enumerate() {
        match &secret.target {
            SecretTarget::File { path, .. } => {
                if !path.is_absolute() {
                    return Err(ShapeError::Field {
                        path: FieldPath::Secret(i, "target.path"),
                        reason: format!("{:?} is not an absolute path", path),
                    });
                }
            }
            SecretTarget::EnvVar { name } => {
                if !env_name_re().is_match(name) {
                    return Err(ShapeError::Field {
                        path: FieldPath::Secret(i, "target.name"),
                        reason: format!(
                            "{:?} is not a valid env-var identifier (^[A-Z_][A-Z0-9_]*$)",
                            name
                        ),
                    });
                }
            }
        }
    }

    // soft: RestartPolicy::Never without yah.forge=true annotation
    if matches!(spec.restart_policy, RestartPolicy::Never) {
        let is_forge = spec
            .annotations
            .get("yah.forge")
            .map(|v| v == "true")
            .unwrap_or(false);
        if !is_forge {
            warnings.push(ShapeWarning {
                path: FieldPath::RestartPolicy,
                message: "restart_policy=Never is intended for forge runs; \
                          add annotation yah.forge=true to suppress this warning"
                    .into(),
            });
        }
    }

    // yah.durability.*: a malformed declaration is hard, and a stateful
    // workload with no declaration at all is soft (R850-P4).
    //
    // The asymmetry is deliberate. Refusing every undeclared appliance would
    // fail every spec in the tree on the day the annotation shipped; reading a
    // *malformed* one as "undeclared" would let `tier = "streem"` mean "no
    // backups" silently, which is the failure this whole surface exists to
    // stop. See `WorkloadSpec::durability`.
    let durability = spec
        .durability()
        .map_err(|e| ShapeError::Field {
            path: FieldPath::Annotation(DURABILITY_TIER_ANNOTATION),
            reason: e.to_string(),
        })?;
    // R850-F1: a bytes-shipping tier's subjects are volume-relative, so there
    // has to be exactly one volume for them to be relative *to*. Zero means the
    // declaration names files that will never exist; two or more means the
    // hydrate helper would have to guess which host directory to restore into,
    // and a wrong guess writes somebody's database over somebody else's.
    if let Some(d) = durability.as_ref().filter(|d| d.tier.ships_bytes()) {
        let named: Vec<&str> = spec
            .volumes
            .iter()
            .filter_map(|v| match &v.source {
                VolumeSource::Named { name } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        if named.len() != 1 {
            return Err(ShapeError::Field {
                path: FieldPath::Annotation(DURABILITY_SUBJECTS_ANNOTATION),
                reason: format!(
                    "{DURABILITY_TIER_ANNOTATION} = \"{}\" declares subjects {:?}, which are \
                     relative to a named volume, but this spec declares {} named volumes{}; \
                     a tier that ships bytes needs exactly one",
                    d.tier,
                    d.subjects,
                    named.len(),
                    if named.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", named.join(", "))
                    }
                ),
            });
        }
    }

    if durability.is_none()
        && spec.effective_archetype() == LifecycleArchetype::Appliance
        && spec
            .volumes
            .iter()
            .any(|v| matches!(v.source, VolumeSource::Named { .. }))
    {
        warnings.push(ShapeWarning {
            path: FieldPath::Annotation(DURABILITY_TIER_ANNOTATION),
            message: format!(
                "appliance with a yubaba-managed named volume declares no durability \
                 tier, so that volume is the only copy of its state and losing the node \
                 loses it; declare {DURABILITY_TIER_ANNOTATION} = \"none\" if that is \
                 intended, or a real tier if it is not"
            ),
        });
    }

    // soft: healthcheck.initial_delay >= stop_policy.grace_period * 2
    if let Some(hc) = &spec.healthcheck {
        let min_recommended = spec.stop_policy.grace_period.as_ms().saturating_mul(2);
        if hc.initial_delay.as_ms() < min_recommended {
            warnings.push(ShapeWarning {
                path: FieldPath::Healthcheck("initial_delay"),
                message: format!(
                    "initial_delay ({}ms) is less than stop_policy.grace_period * 2 ({}ms); \
                     a SIGTERM during startup may catch a still-initialising container",
                    hc.initial_delay.as_ms(),
                    min_recommended
                ),
            });
        }
    }

    Ok(warnings)
}

// ── StaticAsset validator ─────────────────────────────────────────────────────

/// Shape-validate a `kind = "static-asset"` workload.
///
/// Enforces the closed-catalog invariant: every value in `[aliases]` must be a
/// `filename` present in `[[asset]]`. A mirror's `[asset_aliases]` overrides
/// are bound by the same rule and are validated separately at sync time when
/// both the workload and mirror are loaded together.
pub fn shape_static_asset(workload: &StaticAssetWorkload) -> Result<(), ShapeError> {
    // XOR rule (W164 / R438-T2): every [[asset]] row must set exactly one of
    // `source` (legacy local bytes) or `derive` (fetch + optional transform).
    // Both-set is ambiguous (which one wins?); neither-set leaves the
    // reconciler with no bytes to upload.
    for (i, entry) in workload.assets.iter().enumerate() {
        match (entry.source.is_some(), entry.derive.is_some()) {
            (true, true) => {
                return Err(ShapeError::Field {
                    path: FieldPath::Asset(i, "source"),
                    reason: format!(
                        "asset {:?}: both `source` and `derive` are set; pick exactly one",
                        entry.filename
                    ),
                });
            }
            (false, false) => {
                return Err(ShapeError::Field {
                    path: FieldPath::Asset(i, "source"),
                    reason: format!(
                        "asset {:?}: neither `source` nor `derive` is set; pick exactly one",
                        entry.filename
                    ),
                });
            }
            _ => {}
        }
    }

    let filenames: std::collections::HashSet<&str> =
        workload.assets.iter().map(|a| a.filename.as_str()).collect();

    for (alias_key, alias_target) in &workload.aliases {
        if !filenames.contains(alias_target.as_str()) {
            return Err(ShapeError::Field {
                path: FieldPath::AssetAlias(alias_key.clone()),
                reason: format!(
                    "alias target {:?} is not present in the [[asset]] catalog; \
                     add a matching [[asset]] row or correct the filename",
                    alias_target
                ),
            });
        }
    }

    Ok(())
}

// ── Semantic layer ────────────────────────────────────────────────────────────

/// Transient error from a [`ValidationContext`] lookup.
///
/// Distinct from a semantic "resource not found" failure. `ContextError` means
/// the lookup itself could not complete (network timeout, auth failure, etc.),
/// not that the resource is definitively absent.
#[derive(Debug, Error, Clone, PartialEq)]
#[error("context lookup failed: {0}")]
pub struct ContextError(pub String);

/// A semantic constraint violation: the spec references a resource that is not
/// known to the cluster at validation time.
#[derive(Debug, Error, PartialEq)]
pub enum SemanticError {
    #[error("field {path}: {reason}")]
    Unknown { path: FieldPath, reason: String },
}

/// Top-level validation error spanning both shape and semantic layers.
///
/// `Shape` always wins: if the spec is structurally invalid, semantic checks
/// never run.
#[derive(Debug, Error, PartialEq)]
pub enum WorkloadValidationError {
    /// Hard shape constraint failed — spec is structurally invalid.
    #[error("shape: {0}")]
    Shape(ShapeError),

    /// Semantic check failed — spec references an unknown cluster resource.
    #[error("semantic: {0}")]
    Semantic(SemanticError),

    /// Transient ValidationContext lookup failure — the check itself failed.
    #[error("context: {0}")]
    Context(ContextError),
}

impl From<ShapeError> for WorkloadValidationError {
    fn from(e: ShapeError) -> Self { WorkloadValidationError::Shape(e) }
}

impl From<ContextError> for WorkloadValidationError {
    fn from(e: ContextError) -> Self { WorkloadValidationError::Context(e) }
}

/// Read-only view of yubaba state used for semantic validation.
///
/// Defined here so clients (desktop, CLI, agents) can run semantic checks
/// without depending on the yubaba crate. Yubaba implements this trait.
///
/// Each method returns `Result<bool, ContextError>` so transient failures are
/// distinguishable from definitive "not found" answers.
pub trait ValidationContext {
    /// True when the registry confirms the image exists.
    fn image_exists(&self, image: &ImageRef) -> Result<bool, ContextError>;

    /// True when the named secret exists in the yubaba secret store.
    fn secret_exists(&self, secret: &SecretRef) -> Result<bool, ContextError>;

    /// True when `ident` is a known deployed workload OR appears in `batch`
    /// (the set of specs co-deployed in the same request — allows forward
    /// references within a single deployment batch).
    fn mesh_ident_known(&self, ident: &MeshIdent, batch: &[MeshIdent]) -> Result<bool, ContextError>;

    /// True when `hostname` falls under a Cloudflare zone owned by this cluster.
    fn cf_zone_owned(&self, hostname: &str) -> Result<bool, ContextError>;

    /// True when `tag` (e.g. `"tag:noisetable-ops"`) is in the cluster's
    /// Tailscale ACL tag list.
    fn tailscale_tag_known(&self, tag: &str) -> Result<bool, ContextError>;

    /// True when `machine_id` has sufficient remaining capacity to host the
    /// given spec's resource requirements.
    ///
    /// Implementors: read memory via [`WorkloadSpec::memory_request_mb`], not
    /// `spec.resources.memory_mb`. The latter is a cgroup ceiling, and using
    /// it as a capacity floor is what made every build-worker smaller than
    /// `for_forge`'s 32 GiB ceiling unschedulable in `admit_workload`. Only a
    /// test implementation of this trait exists today, so the bug is not live
    /// here — this note is to keep it from arriving with the first real one.
    fn capacity_for(&self, spec: &WorkloadSpec, machine_id: &MachineId) -> Result<bool, ContextError>;
}

/// Run semantic validation — requires yubaba state via [`ValidationContext`].
///
/// Shape validation is NOT run here. Callers MUST run [`shape`] first; use
/// [`all`] to enforce this automatically.
///
/// `machine_id` is the target machine for admission-control capacity checks.
/// `batch` is the set of mesh idents being co-deployed (pass `&[]` for
/// single-spec deployment); these count as "known" for `depends_on` resolution.
pub fn semantic(
    spec: &WorkloadSpec,
    ctx: &dyn ValidationContext,
    machine_id: &MachineId,
    batch: &[MeshIdent],
) -> Result<(), WorkloadValidationError> {
    if !ctx.image_exists(&spec.image)? {
        return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
            path: FieldPath::Image,
            reason: format!(
                "image {}/{}:{} not found in registry",
                spec.image.registry, spec.image.repository, spec.image.tag
            ),
        }));
    }

    for (i, secret) in spec.secrets.iter().enumerate() {
        if !ctx.secret_exists(&secret.source)? {
            return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
                path: FieldPath::Secret(i, "source"),
                reason: format!("secret source at index {i} not found in yubaba secret store"),
            }));
        }
    }

    for (i, dep) in spec.depends_on.iter().enumerate() {
        if !ctx.mesh_ident_known(dep, batch)? {
            return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
                path: FieldPath::DependsOn(i),
                reason: format!("mesh ident {:?} is not a known deployed workload", dep.0),
            }));
        }
    }

    if let Some(public) = &spec.expose.public {
        if !ctx.cf_zone_owned(&public.hostname)? {
            return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
                path: FieldPath::Hostname,
                reason: format!(
                    "hostname {:?} is not under a Cloudflare zone owned by this cluster",
                    public.hostname
                ),
            }));
        }
    }

    if let Some(op) = &spec.expose.operator {
        if !ctx.tailscale_tag_known(&op.tailscale_tag)? {
            return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
                path: FieldPath::TailscaleTag,
                reason: format!(
                    "tailscale tag {:?} is not in the cluster's ACL tag list",
                    op.tailscale_tag
                ),
            }));
        }
    }

    if !ctx.capacity_for(spec, machine_id)? {
        return Err(WorkloadValidationError::Semantic(SemanticError::Unknown {
            path: FieldPath::Resources,
            reason: format!(
                "machine {:?} lacks capacity (memory={}MB cpu_millis={} ephemeral={}MB)",
                machine_id.0,
                spec.resources.memory_mb,
                spec.resources.cpu_millis,
                spec.resources.ephemeral_storage_mb
            ),
        }));
    }

    Ok(())
}

// ── Mesh resolution layer ─────────────────────────────────────────────────────

/// Failure surface for [`MeshResolver`] lookups.
///
/// `NotDeployed` means the dependency hasn't been observed in mesh state yet
/// (yubaba's deploy step waits on this — see [`crate::EnvValue::FromMesh`]).
/// `NoPorts` means the dependency is deployed but its `MeshExpose.ports`
/// list is empty, so a port-based lookup can't render a value. `Lookup`
/// covers transient failures from the underlying state read.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum MeshError {
    #[error("mesh ident {ident:?} is not yet deployed")]
    NotDeployed { ident: String },

    #[error(
        "mesh ident {ident:?} exposes no ports; {lookup:?} requires at least one"
    )]
    NoPorts { ident: String, lookup: MeshLookup },

    /// The peer exposes several ports and the lookup did not say which
    /// (R844-B22). Deliberately an error rather than a pick — see
    /// [`MeshLookup`]'s docs.
    #[error(
        "mesh ident {ident:?} exposes {} ports ({}) and none is named \"http\", \
         so {lookup:?} cannot say which one to use. Name the port in the \
         lookup (kind = \"port_named\", name = \"…\"), or name one of the \
         peer's ports \"http\" in its expose.mesh.ports.",
        .names.len(),
        .names.join(", ")
    )]
    AmbiguousPort {
        ident: String,
        lookup: MeshLookup,
        names: Vec<String>,
    },

    /// The lookup named a port the peer does not expose (R844-B22).
    #[error(
        "mesh ident {ident:?} exposes no port named {name:?}; it has {}",
        if .available.is_empty() { "none".to_string() } else { .available.join(", ") }
    )]
    NoSuchPort {
        ident: String,
        name: String,
        available: Vec<String>,
    },

    #[error("mesh state lookup failed: {0}")]
    Lookup(String),
}

/// The port name a peer's sole/default listener carries. Agrees with
/// `kamaji::DEFAULT_PORT_NAME` by convention rather than by import: kamaji sits
/// *above* workload-spec in the publish DAG (`yah-base <- {qed,kamaji} <-
/// yubaba`), so depending on it here would invert the graph. The two are pinned
/// together by `default_port_name_agrees_with_the_supervisor` in this file's
/// tests.
pub const DEFAULT_PORT_NAME: &str = "http";

/// Pick the port a [`MeshLookup`] refers to out of a peer's `name -> port` map
/// (R844-B22) — the one place the rule lives, so every resolver answers the
/// same way.
///
/// - A **named** lookup takes that port, or errors naming what the peer does
///   have. No fallback: a lookup that asked for `wss` and silently got `http`
///   would be the positional guess wearing a name.
/// - An **unnamed** lookup takes the sole port when there is one, else the port
///   named [`DEFAULT_PORT_NAME`], else errors. It never takes "the first",
///   which is what this function exists to stop.
pub fn select_mesh_port(
    ident: &str,
    ports: &std::collections::BTreeMap<String, u16>,
    lookup: &MeshLookup,
) -> Result<u16, MeshError> {
    if let Some(name) = lookup.port_name() {
        return ports.get(name).copied().ok_or_else(|| MeshError::NoSuchPort {
            ident: ident.to_string(),
            name: name.to_string(),
            available: ports.keys().cloned().collect(),
        });
    }

    let mut entries = ports.iter();
    match (entries.next(), entries.next()) {
        (None, _) => Err(MeshError::NoPorts {
            ident: ident.to_string(),
            lookup: lookup.clone(),
        }),
        (Some((_, &only)), None) => Ok(only),
        _ => ports
            .get(DEFAULT_PORT_NAME)
            .copied()
            .ok_or_else(|| MeshError::AmbiguousPort {
                ident: ident.to_string(),
                lookup: lookup.clone(),
                names: ports.keys().cloned().collect(),
            }),
    }
}

/// Resolve [`crate::EnvValue::FromMesh`] references to literal env values.
///
/// Defined in workload-spec so clients (agents, desktop, CLI) can render
/// specs against fake mesh state without depending on the yubaba crate.
/// Yubaba's production implementation (in `yubaba::deploy::mesh_resolve`)
/// reads from raft state.
///
/// **Resolution rules** (R844-B22 replaced the positional ones):
/// - [`MeshLookup::Host`] — the bare DNS-ish identifier as authored (e.g.
///   `"noisetable-db.pdx"`). Needs no port and resolves for a portless peer.
/// - [`MeshLookup::Url`] — `"http://<ident>:<port>"`.
/// - [`MeshLookup::Port`] — that port stringified, e.g. `"5432"`.
/// - [`MeshLookup::UrlNamed`] / [`MeshLookup::PortNamed`] — the same, at the
///   peer's port of that name.
///
/// **Which port** is [`select_mesh_port`]'s decision, and implementations must
/// route through it rather than re-deriving: a sole port, else the one named
/// [`DEFAULT_PORT_NAME`], else an error. It is emphatically *not* "the first
/// entry", which is what this trait's doc used to promise — declaration order
/// is not a statement about which listener a dependent should dial, and acting
/// as if it were is how a workload gets handed a metrics port as its API URL.
///
/// Because the rule is name-based rather than positional, a `Url` and a `Port`
/// resolved in the same deploy agree by construction; the old doc had to ask
/// implementations to make the lookup atomic to get that.
pub trait MeshResolver {
    fn resolve(&self, ident: &MeshIdent, kind: MeshLookup) -> Result<String, MeshError>;
}

/// Render every [`EnvValue::FromMesh`] entry in `env` to a [`EnvValue::Literal`]
/// using `resolver`; pass through `Literal` and `FromSecret` values unchanged.
///
/// Returns the first resolution error encountered. Callers should run this
/// after yubaba's stage-3 mesh peering completes (see
/// `yubaba::deploy::env_validate::run` doc), at containerd-spec assembly.
///
/// `FromSecret` values are deliberately untouched here — secret resolution
/// is the secrets layer's job (R090-F5), not the mesh resolver's.
///
/// @yah:ticket(R844-B22, "MeshLookup::Url and ::Port resolve &quot;the first entry in expose.mesh.ports&quot; — the positional guess this relay abolishes, in the env-injection path")
/// @yah:status(review)
/// @yah:at(2026-09-04T14:10:34Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R844)
/// @yah:severity(medium)
/// @yah:gotcha("THE CLAIM IS IN THE TRAIT'S OWN DOC, so this is confirmed rather than inferred. `MeshResolver` (oss/yah-base/crates/workload-spec/src/validate.rs, \\\"Resolution rules\\\") states: `MeshLookup::Url` resolves to `\\\"http://&lt;ident&gt;:&lt;port&gt;\\\"` where port is \\\"the first entry in the referenced workload's `MeshExpose.ports`\\\", and `MeshLookup::Port` is \\\"the first port stringified\\\". That is precisely the index-guess `kamaji::name_anonymous_ports` refuses to make and that R844-F15's `ServiceRecordFanout::port_for` was rewritten to stop making — an ingress rule resolved off declaration order can publish a hostname at a metrics listener, and this path can hand a DEPENDENT WORKLOAD the same wrong number in its environment. Nothing has hit it because no fronted or depended-on workload declares two ports yet; that is the same reason F15 gave for the passway gap it left, and it stops being true the moment someone uses R844-F17's new spelling.")
/// @yah:next("THIS IS NOW FIXABLE, WHICH IS WHY IT IS FILED — before R844-F17 a manifest could not name a port, so \\\"first\\\" was the only selector available and the doc was describing a limitation rather than a bug. `MeshExpose::named_numbers()` and `kamaji::declared_port_names()` now give a name-keyed answer.")
/// @yah:next("SHAPE: add a named variant to `MeshLookup` (e.g. `Port { name: String }` / `Url { name: String }`) and make the unnamed forms resolve through the `http` rule instead of index 0 — i.e. one port resolves as today, several resolve to `http` if one is named that, and NONE otherwise. Returning an error when several ports are unnamed is the whole point: it sends the author to the manifest rather than handing a dependent a plausible wrong number. MIND THE WIRE: `MeshLookup` rides `EnvValue::FromMesh` inside `WorkloadSpec`, which crosses the postcard kamaji UDS — see the V6/V7 stanza in oss/kamaji/crates/kamaji-proto/src/version.rs. Adding a field to an existing variant is a bump; appending a whole new variant is not.")
/// @yah:handoff("FIXED — the positional guess is gone from the env-injection path. `MeshLookup` gained `UrlNamed { name }` / `PortNamed { name }`, APPENDED rather than added as fields on `Url`/`Port` exactly as the ticket instructed, so every existing postcard encoding stays byte-identical (an enum is encoded by variant index) and NO ProtocolVersion bump was needed — verified by the kamaji-proto codec suite passing untouched. The unnamed forms no longer mean \"index 0\": they resolve through `workload_spec::validate::select_mesh_port`, which takes the sole port when there is one, else the port named `http`, else RETURNS AN ERROR. `MeshLookup` also lost `Copy` (it now owns a String); the one call site that relied on it is `resolve_env_from_mesh`, now cloning.")
/// @yah:handoff("THE RULE LIVES IN ONE PLACE, which is the actual repair — the bug was not that a rule was wrong, it was that the rule was RE-DERIVED at every site, so all of them agreed about something false. `select_mesh_port(ident, &BTreeMap<String,u16>, &MeshLookup)` in workload-spec is now the only implementation; yubaba `StateMeshResolver` calls it, the workload-spec test fake calls it (it had been carrying its OWN copy of \"the first entry\", which is why the test suite confirmed the bug rather than catching it), and the `MeshResolver` trait doc now REQUIRES implementations to route through it instead of describing the rule for them to copy. A named lookup deliberately does NOT fall back to `http`: that would be the positional guess wearing a name.")
/// @yah:handoff("REQUIRED A TYPE CHANGE THE TICKET DID NOT NAME, and it is where the names were actually being lost: `yubaba::deploy::mesh_resolve::MeshAddress.ports` was a `Vec<u16>`. A bare number list CANNOT answer \"which of these is the API port\", so positional resolution was not a shortcut in that file — it was the only thing the type permitted, and the trait doc had written that limitation down as a rule. It is now the same `BTreeMap<String,u16>` that `kamaji::WorkloadState::ports` and `ServiceRecord::resolved_ports` already carry, so a name survives from manifest to dependent environment. Cheap to change: `MeshAddress` is constructed in exactly one file and only by tests.")
/// @yah:handoff("ONE CROSS-CRATE CONSTANT, pinned rather than duplicated silently. `select_mesh_port` needs the default port name and CANNOT import `kamaji::DEFAULT_PORT_NAME` — kamaji sits above workload-spec in the publish DAG (`yah-base <- {qed,kamaji} <- yubaba`), so the dep would invert the graph. So `workload_spec::validate::DEFAULT_PORT_NAME` states it, and `kamaji::tests::default_port_name_agrees_with_the_mesh_resolver` asserts all three spellings (kamaji DEFAULT_PORT_NAME, ports::HTTP, the validate const) are one string. Without that pin a future rename would make a dependent `FromMesh` URL and its own `PORT` env disagree about which listener is the default, silently.")
/// @yah:verify("cargo test --manifest-path oss/yah-base/Cargo.toml -p yah-workload-spec = 146/0 + 94/0 (87 before, so +7). The behaviour change is pinned by name: `several_unnamed_ports_is_an_error_not_the_first_one` (the case that previously rendered 5432 out of [5432,9100] and had a test LOCKING THAT IN), `several_ports_resolve_through_http_when_one_is_named_that`, `a_named_lookup_selects_that_port_and_nothing_else`, `a_named_lookup_for_an_absent_port_errors_rather_than_falling_back`, `a_sole_port_resolves_whatever_it_is_called` (sole beats the http rule on purpose — no ambiguity exists with one listener), `an_empty_port_map_is_no_ports_not_ambiguous`, `host_resolves_for_a_portless_peer`.")
/// @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib = 634 passed / 0 failed (632 before). Two new cases run the PRODUCTION resolver, not the fake: `several_unnamed_ports_error_rather_than_resolving_to_the_first` and `a_named_lookup_selects_that_port_through_the_state_resolver`. THREE PRE-EXISTING TESTS ASSERTED THE BUG and were rewritten rather than worked around — `url_renders_first_port_with_http_prefix` / `port_renders_first_port_as_string` (both crates) took a two-port peer and asserted the first one came back; their fixtures are now single-port and the multi-port case is its own explicitly-named test.")
/// @yah:verify("WHOLE-TREE on a settled tree: cargo test --manifest-path oss/kamaji/Cargo.toml --workspace --all-features = every target ok (kamaji lib 185/0, kamaji-bin 278/0, kamaji-proto codec suite untouched and green — the no-wire-bump evidence); yah-cloud --lib 1019/0/4 ignored; yah-local-driver --lib 99/0; cargo test -p yah --lib 1364 passed / 0 failed / 1 ignored; cargo check --workspace --all-targets = ZERO errors. R844 PURITY CANARY HELD: cargo test -p xtask --test main mirror_ingress = 11 passed / 0 failed.")
/// @yah:gotcha("MEASURED SCOPE, so nobody over- or under-reads this fix: THE FromMesh ENV PATH HAS NO PRODUCTION CALLER TODAY. `resolve_env_from_mesh` is called only from workload-spec own tests; `StateMeshResolver` is constructed only in its own module tests; and kamaji-bin `resolve_env` (native.rs:208) REFUSES an unresolved `EnvValue::FromMesh` outright with \"Yubaba must resolve mesh refs before dispatching to Kamaji\" — but nothing in yubaba calls the resolver on the deploy path. So the wrong rule had not yet handed a real workload a wrong number; it was a loaded gun, not a fired one. That is also why the fix was cheap (no call sites to migrate) and why it was worth doing NOW rather than after the path is wired.")
/// @yah:gotcha("GENERATED ARTIFACTS REGENERATED, and they carry MORE than this ticket. `.yah/schema/workload.toml.schema.json` and `packages/yah/workload-spec/index.ts` are generated from these Rust types and the pre-commit regen was disabled 2026-08-15, so they had gone stale at R844-F17 — the TS binding still said `ports: Array<number>` weeks after `MeshExpose.ports` became `Vec<MeshPort>`. Running `cargo run -p xtask -- emit-schemas` and the workload-spec `export-ts` bin swept BOTH F17 drift and this ticket. Diff is confined to the two expected surfaces (`MeshExpose.ports`, `MeshLookup`) and nothing else. Flagging per the shared-tree rule that a derived file is nobody property: whoever owns R844-F17 should know their type change is now reflected in the bindings.")
pub fn resolve_env_from_mesh(
    env: &[EnvVar],
    resolver: &dyn MeshResolver,
) -> Result<Vec<EnvVar>, MeshError> {
    env.iter()
        .map(|var| match &var.value {
            EnvValue::FromMesh { ident, kind } => {
                let value = resolver.resolve(ident, kind.clone())?;
                Ok(EnvVar {
                    name: var.name.clone(),
                    value: EnvValue::Literal { value },
                })
            }
            _ => Ok(var.clone()),
        })
        .collect()
}

/// Run shape then semantic validation in the correct order.
///
/// Shape always runs first. If shape fails, `WorkloadValidationError::Shape`
/// is returned and semantic checks are skipped — callers never see a
/// `Semantic` error for a structurally invalid spec.
///
/// `machine_id` is forwarded to the capacity admission-control check.
/// `batch` is the set of co-deployed mesh idents for forward-reference
/// resolution; pass `&[]` for single-spec deployment.
pub fn all(
    spec: &WorkloadSpec,
    ctx: &dyn ValidationContext,
    machine_id: &MachineId,
    batch: &[MeshIdent],
) -> Result<(), WorkloadValidationError> {
    shape(spec)?;
    semantic(spec, ctx, machine_id, batch)
}
