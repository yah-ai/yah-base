//! Pluggable secret resolver for [`crate::SecretRef`] values, plus the access
//! rule that decides which workloads a cluster secret may be served to.
//!
//! The trait lives in `workload-spec` so consumers can construct specs and
//! invoke the resolver without linking yubaba's containerd client. Yubaba
//! provides the production impl in `crates/yah/yubaba/src/secrets.rs`.
//!
//! ## Access rules (R706 / W294)
//!
//! Before R706, `SecretRef::Cluster { name }` was a **bearer reference**:
//! naming the secret was the entire authorization. [`SecretAccess`] closes
//! that — it rides on the stored record, so the check happens on the node at
//! mount time, where it cannot be routed around by a hand-rolled deploy.
//!
//! The vocabulary is [`WorkloadSpec`](crate::WorkloadSpec) fields
//! ([`SecretConsumer`]) rather than, say, cheers principals, because those are
//! the only identity the enforcement point actually holds: at mount time yubaba
//! has a `WorkloadSpec` and nothing else.
//!
//! Fail-closed by construction: [`SecretAccess::default`] is an **empty**
//! allow-list, which admits nobody. A legacy record written before this field
//! existed deserializes to that default, so it is refused rather than granted.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{NamespaceId, SecretRef, TenantId, WorkloadSpec};

/// Errors returned by [`SecretResolver::resolve`].
#[derive(Debug, Error)]
pub enum SecretError {
    /// The referenced secret file does not exist in the yubaba secret store.
    #[error("secret not found at {path}")]
    NotFound { path: PathBuf },

    /// `SecretRef::Cluster` reached a resolver that has no cluster backing —
    /// e.g. the per-machine `LocalFileResolver`, which cannot decrypt cluster
    /// secrets. The fleet resolver (yubaba's `ClusterResolver`) handles the
    /// `Cluster` arm; this error means the wrong resolver was used.
    #[error("cluster secrets require a cluster-backed resolver")]
    ClusterNotImplemented,

    /// The referenced cluster secret is not present in the local raft replica
    /// (never written, or deleted). Fails closed — nothing is served.
    #[error("cluster secret {name} not found in the local raft replica")]
    ClusterNotFound { name: String },

    /// The cluster secret exists but its [`SecretAccess`] rule does not admit
    /// the requesting workload (R706 / W294).
    ///
    /// **The `#[error(...)]` text is a deliberate byte-for-byte duplicate of
    /// [`SecretError::ClusterNotFound`]'s.** Yubaba surfaces the `Display` form
    /// of this error in the deploy rejection body, so a distinguishable message
    /// would turn any workload spec into an oracle for the cluster's secret
    /// namespace: deploy a throwaway spec naming a guessed secret and read off
    /// "forbidden" (it exists) versus "not found" (it doesn't). The variants
    /// stay separate *internally* — the node logs which one it was, and
    /// `secrets_forbidden_is_externally_indistinguishable` pins the equality so
    /// a future edit to either message can't silently reopen the oracle.
    #[error("cluster secret {name} not found in the local raft replica")]
    Forbidden { name: String },

    /// Decryption or authentication of a cluster secret failed — a wrong
    /// node-local KEK, a truncated/tampered record, a malformed nonce, or
    /// (R911-F4) a record whose name or access rule is not the one it was
    /// sealed under ([`secret_aad`]): a widened rule or a ciphertext copied to
    /// another name. Fails closed; the message carries only the logical name,
    /// never key or ciphertext bytes.
    #[error("cluster secret {name} failed to decrypt")]
    ClusterDecrypt { name: String },

    /// The cluster secret store could not answer for `name` — the fleet object
    /// store is unreachable, returned a malformed record, refused the name as a
    /// key, or this node has no store configured at all (R911-F1).
    ///
    /// **Deliberately distinct from [`SecretError::ClusterNotFound`].** A
    /// caller that treats absence as a decision — headscale minting a fresh
    /// noise identity when the store holds none — must not reach that decision
    /// because a bucket blipped. The message carries only the logical name; the
    /// node logs the underlying store error. It is not a namespace oracle: an
    /// outage answers the same for every name.
    #[error("cluster secret {name} is unavailable: the cluster secret store could not be read")]
    ClusterUnavailable { name: String },

    /// The node-local cluster KEK could not be loaded (missing, unreadable, or
    /// not exactly 32 bytes). Fails closed; `reason` is a generic diagnostic
    /// and never contains key material.
    #[error("cluster KEK unavailable: {reason}")]
    Kek { reason: String },

    /// I/O error on a secret file. `op` is the operation that failed, as a
    /// present participle (`"reading"`, `"writing"`, `"creating"`, …).
    ///
    /// R848: the message used to hardcode "reading" while yubaba's *writer*
    /// (`deploy::secret_mount::write_secret_file`) reused the variant for its
    /// writes. Yubaba surfaces this `Display` form in the 422 deploy-rejection
    /// body, so an EACCES writing the tmpfs file read as a resolver failure and
    /// sent the operator to the cluster KEK instead of to the file being
    /// written two lines down. Naming the operation is the whole fix.
    #[error("I/O error {op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Resolves a [`SecretRef`] to its raw byte content.
///
/// The trait is defined here (in `workload-spec`) so callers don't need to
/// link yubaba. Yubaba's `LocalFileResolver` reads from the per-machine secret
/// store at `/var/lib/yah/yubaba/secrets/`. Tests use an inline `FakeResolver`.
pub trait SecretResolver {
    fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError>;
}

// ── Access rules (R706 / W294) ────────────────────────────────────────────────

/// The identity a cluster-secret access rule is evaluated against: the
/// requesting workload, as yubaba knows it at mount time.
///
/// Built from a [`WorkloadSpec`] via [`SecretConsumer::of`]. These three fields
/// are the whole vocabulary because they are the whole identity available at the
/// enforcement point — yubaba resolves secrets while holding a spec, with no
/// cheers principal and no spec→principal mapping in reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct SecretConsumer {
    /// [`WorkloadSpec::name`] — the DNS-friendly workload name.
    pub workload: String,
    /// [`WorkloadSpec::tenant`] — the isolation axis (W206).
    pub tenant: TenantId,
    /// [`WorkloadSpec::namespace`] — the routing/naming axis (W206).
    pub namespace: NamespaceId,
    /// The signed recipe this run was admitted as, when it carried a grant that
    /// **verified** (R555-F5). `None` for every ordinary service workload, and
    /// for any spec whose grant did not verify — see [`RecipeIdentity`].
    #[serde(default)]
    pub recipe: Option<RecipeIdentity>,
}

/// Who a remote run proved itself to be, cryptographically.
///
/// A forge workload's [`WorkloadSpec::name`] is a fresh `forge-<uuid>` per run,
/// so it can never appear in an allow-list written in advance — which left
/// [`SecretAccess::AllowAny`] as the only rule under which a dispatched recipe
/// could read a cluster secret at all. That is precisely the ambient grant W235
/// §(c) says must not be how a remote build gets the R2 and cosign keys.
///
/// This is the durable identity underneath the ephemeral one: the recipe name
/// out of a verified admission grant, plus the key that vouched for it. Both
/// halves matter — the name alone would let anyone holding *any* trusted key
/// mint a grant claiming to be `rusty-v8-musl`.
///
/// Construct only from
/// [`admission::admit_grant`](crate::admission::admit_grant)'s return value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct RecipeIdentity {
    /// `AdmissionGrant::recipe` from the verified grant.
    pub recipe: String,
    /// Hex Ed25519 public key that signed it, as pinned on the node.
    pub key: String,
}

impl SecretConsumer {
    /// The consumer identity of `spec`.
    ///
    /// Carries no recipe identity: this constructor sees only the spec, and a
    /// recipe identity is a claim about a signature. Add one with
    /// [`SecretConsumer::admitted_as`] after verifying.
    pub fn of(spec: &WorkloadSpec) -> Self {
        Self {
            workload: spec.name.clone(),
            tenant: spec.tenant.clone(),
            namespace: spec.namespace.clone(),
            recipe: None,
        }
    }

    /// Attach the recipe identity a verified admission grant established.
    pub fn admitted_as(mut self, recipe: RecipeIdentity) -> Self {
        self.recipe = Some(recipe);
        self
    }

    /// A consumer in the singleton tenant/namespace — the shape every spec on a
    /// single-tenant fleet has. Convenience for tests and for authoring rules.
    pub fn workload(name: impl Into<String>) -> Self {
        Self {
            workload: name.into(),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            recipe: None,
        }
    }
}

/// One entry in a [`SecretAccess::Workloads`] allow-list.
///
/// A match requires **all three** fields to be equal. `tenant` and `namespace`
/// default to their singletons rather than to a wildcard: on today's
/// single-tenant fleet that makes them free to omit, and it means a rule written
/// today cannot silently widen to admit a same-named workload in a tenant that
/// gets created tomorrow. Cross-tenant sharing is spelled as two entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct WorkloadMatch {
    /// The admitted [`WorkloadSpec::name`].
    pub workload: String,
    /// Tenant the workload must be in. Defaults to [`TenantId::singleton`].
    #[serde(default = "TenantId::singleton")]
    pub tenant: TenantId,
    /// Namespace the workload must be in. Defaults to [`NamespaceId::singleton`].
    #[serde(default = "NamespaceId::singleton")]
    pub namespace: NamespaceId,
}

impl WorkloadMatch {
    /// A match on `name` in the singleton tenant/namespace.
    pub fn workload(name: impl Into<String>) -> Self {
        Self {
            workload: name.into(),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
        }
    }

    /// Whether `consumer` satisfies this entry.
    pub fn admits(&self, consumer: &SecretConsumer) -> bool {
        self.workload == consumer.workload
            && self.tenant == consumer.tenant
            && self.namespace == consumer.namespace
    }
}

/// Who may be served a given cluster secret.
///
/// Stored alongside the ciphertext (yubaba's `SecretRecord`) so the check rides
/// on the record itself and is evaluated on the node at mount time — a rule
/// checked only by the tool that authors a deploy is a lint, not a rule.
///
/// [`Default`] is `Workloads(vec![])`, which admits nobody. That is what makes
/// the migration fail closed: a record serialized before this field existed
/// deserializes (via `#[serde(default)]`) to an empty allow-list and is refused,
/// rather than being implicitly granted to everyone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SecretAccess {
    /// Deliberately unrestricted: any workload that names this secret gets it.
    ///
    /// This is the *explicit* escape hatch, never an implicit one. It has to be
    /// written into the record by whoever put the secret there, and it shows up
    /// in `yah cloud secret ls` as `allow-any`, so an unrestricted secret is an
    /// auditable choice rather than the silent default.
    AllowAny,

    /// Only workloads matching one of these entries. An empty list admits
    /// nobody — see the type-level note on fail-closed defaulting.
    Workloads(Vec<WorkloadMatch>),

    /// Only runs of one of these **signed recipes** (R555-F5 / W235 §(c)).
    ///
    /// The rule a dispatched build needs: its workload name is a per-run
    /// `forge-<uuid>` that no allow-list can name in advance, so
    /// [`SecretAccess::Workloads`] cannot express "the rusty-v8-musl build may
    /// read the R2 write key" and [`SecretAccess::AllowAny`] over-answers it by
    /// handing that key to anything that can reach the node.
    ///
    /// Matching consumes a [`RecipeIdentity`] that only exists on the far side
    /// of a verified Ed25519 grant, so this is *narrower* than the workload
    /// rule, not a loophole in it: the requester has to be running argv the
    /// recipe author signed, on a node that pins the author's key.
    Recipes(Vec<RecipeMatch>),
}

/// One entry in a [`SecretAccess::Recipes`] allow-list.
///
/// Both fields are required and both are compared exactly. `key` is here
/// because the recipe *name* is chosen by whoever writes the recipe: without
/// it, any holder of any key the node trusts could sign a recipe called
/// `rusty-v8-musl` and inherit its credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct RecipeMatch {
    /// The admitted recipe name, as it appears in the signed grant.
    pub recipe: String,
    /// Hex Ed25519 public key that must have signed the grant.
    pub key: String,
}

impl RecipeMatch {
    /// Whether `consumer` presents a verified identity this entry admits.
    pub fn admits(&self, consumer: &SecretConsumer) -> bool {
        consumer
            .recipe
            .as_ref()
            .is_some_and(|id| id.recipe == self.recipe && id.key == self.key)
    }
}

impl Default for SecretAccess {
    fn default() -> Self {
        Self::Workloads(Vec::new())
    }
}

impl SecretAccess {
    /// Allow exactly the named workloads, in the singleton tenant/namespace.
    pub fn workloads<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Workloads(names.into_iter().map(WorkloadMatch::workload).collect())
    }

    /// Whether `consumer` may be served the secret this rule guards.
    /// Allow exactly the named recipes, each signed by the given hex key.
    pub fn recipes<I, N, K>(entries: I) -> Self
    where
        I: IntoIterator<Item = (N, K)>,
        N: Into<String>,
        K: Into<String>,
    {
        Self::Recipes(
            entries
                .into_iter()
                .map(|(recipe, key)| RecipeMatch {
                    recipe: recipe.into(),
                    key: key.into(),
                })
                .collect(),
        )
    }

    pub fn admits(&self, consumer: &SecretConsumer) -> bool {
        match self {
            Self::AllowAny => true,
            Self::Workloads(entries) => entries.iter().any(|e| e.admits(consumer)),
            Self::Recipes(entries) => entries.iter().any(|e| e.admits(consumer)),
        }
    }

    /// Short operator-facing rendering for `yah cloud secret ls`.
    pub fn summary(&self) -> String {
        match self {
            Self::AllowAny => "allow-any".to_string(),
            Self::Recipes(entries) if entries.is_empty() => "deny-all (no rule)".to_string(),
            Self::Recipes(entries) => entries
                .iter()
                // Keys are 64 hex chars; a truncated prefix is enough to tell
                // two signing identities apart in a table without wrapping it.
                .map(|e| format!("recipe {}@{}", e.recipe, &e.key[..e.key.len().min(8)]))
                .collect::<Vec<_>>()
                .join(", "),
            Self::Workloads(entries) if entries.is_empty() => "deny-all (no rule)".to_string(),
            Self::Workloads(entries) => entries
                .iter()
                .map(|e| {
                    if e.tenant.is_singleton() && e.namespace.is_singleton() {
                        e.workload.clone()
                    } else {
                        format!("{}/{}/{}", e.tenant.0, e.namespace.0, e.workload)
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}

// ── Associated data (R911-F4) ────────────────────────────────────────────────

/// The version tag every sealed-secret associated-data block starts with.
pub const SECRET_AAD_V1: &[u8] = b"yah/secret-aad/v1\0";

/// The AEAD associated data a cluster secret is sealed and opened under: its
/// logical `name` and its `access` rule (R911-F4). **The only builder** — the
/// camp's `yah cloud secret put`, the node's issuers, and the node's resolver
/// all call this, so the two sides cannot encode it differently.
///
/// Why it exists: in the fleet object store a record's rule is plaintext JSON
/// beside its ciphertext. Binding both here means a bucket writer who widens a
/// rule, or copies one name's ciphertext under another name, produces a record
/// whose GCM tag no longer verifies.
///
/// The layout is a contract, pinned byte-for-byte by `aad_bytes_are_pinned`:
///
/// 1. [`SECRET_AAD_V1`];
/// 2. the name: u32 big-endian byte length, then its UTF-8;
/// 3. the rule's variant tag (`allow_any` / `workloads` / `recipes`), length-
///    prefixed the same way;
/// 4. for a list variant, a u32 big-endian entry count, then each entry's
///    fields in declared order (`workload`, `tenant`, `namespace` /
///    `recipe`, `key`), each length-prefixed.
///
/// Entries are bound in their **stored** order, never sorted: reordering a
/// rule is an edit to it. Deliberately not `serde_json` — map order and
/// whitespace are not a contract anyone promised to keep.
pub fn secret_aad(name: &str, access: &SecretAccess) -> Vec<u8> {
    fn field(out: &mut Vec<u8>, bytes: &[u8]) {
        let len = u32::try_from(bytes.len()).expect("a secret name or rule field over 4 GiB");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    fn count(out: &mut Vec<u8>, n: usize) {
        let n = u32::try_from(n).expect("an access rule with over 4 billion entries");
        out.extend_from_slice(&n.to_be_bytes());
    }

    let mut out = SECRET_AAD_V1.to_vec();
    field(&mut out, name.as_bytes());
    // Exhaustive matches and destructures on purpose: a new rule variant or a
    // new entry field does not compile until it chooses its encoding here.
    match access {
        SecretAccess::AllowAny => field(&mut out, b"allow_any"),
        SecretAccess::Workloads(entries) => {
            field(&mut out, b"workloads");
            count(&mut out, entries.len());
            for WorkloadMatch {
                workload,
                tenant,
                namespace,
            } in entries
            {
                field(&mut out, workload.as_bytes());
                field(&mut out, tenant.0.as_bytes());
                field(&mut out, namespace.0.as_bytes());
            }
        }
        SecretAccess::Recipes(entries) => {
            field(&mut out, b"recipes");
            count(&mut out, entries.len());
            for RecipeMatch { recipe, key } in entries {
                field(&mut out, recipe.as_bytes());
                field(&mut out, key.as_bytes());
            }
        }
    }
    out
}

// ── Sealing (R706 / W294, `seal` feature) ────────────────────────────────────

/// A cluster secret's sealed bytes: AES-256-GCM ciphertext plus the 12-byte
/// nonce it was sealed under.
///
/// Deliberately *not* the storage record — yubaba's `SecretRecord` adds the
/// timestamp and the access rule and lives in the raft layer. This is only the
/// cryptographic output, which is the part both writers share.
#[cfg(feature = "seal")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// AES-256-GCM output: sealed bytes with the GCM tag appended.
    pub ciphertext: Vec<u8>,
    /// The 12-byte GCM nonce, freshly drawn for this call.
    pub nonce: Vec<u8>,
}

/// AES-256-GCM-seal `plaintext` under the 32-byte cluster `kek`, authenticating
/// `aad` alongside it (R911-F4). For a cluster secret `aad` is always
/// [`secret_aad`]`(name, access)`; [`open`] must be handed the same bytes.
///
/// A cryptographically-random 12-byte nonce is drawn **per call**, so re-sealing
/// identical plaintext (a rotation, a re-ship of an unchanged value) never
/// reuses a nonce. That is the whole reason this lives in one place: nonce reuse
/// under a fixed key is catastrophic for GCM, and it is exactly the invariant
/// that erodes when two call sites each roll their own seal.
///
/// Infallible by construction: the only error `aead` can return here is a
/// plaintext-length overflow far beyond any credential.
///
/// @yah:ticket(R911-F4, "Seal binds secret name + access rule as AEAD associated data, so a bucket writer cannot widen access or swap records")
/// @yah:status(review)
/// @yah:at(2026-09-15T05:11:28Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R911)
/// @yah:next("Tier: Warrior — crypto format change across camp and node; getting the AAD canonicalization wrong silently fails every open.")
/// @yah:next("WHY: in raft, a record's `access` rule could only be written through the node API. In R2 it is plaintext JSON beside the ciphertext, and seal(kek, plaintext) (:390) has no associated data. So anyone with bucket write can widen access to admit another workload, or copy one name's ciphertext under another name, and the node would open it.")
/// @yah:next("Change seal/open to take associated data = a canonical, versioned encoding of (secret name, SecretAccess). Use a fixed field order, not serde_json map order. A record that fails to open is a distinct fail-closed error. Update every seal() caller (grep `secrets::seal(` across app/, oss/yubaba, crates/) and ClusterResolver's open. The access check still runs BEFORE decrypt, and a tampered access rule then fails the AEAD tag.")
/// @yah:next("Existing records (the raft map and per-domain certs/<issuer>/ objects written by domain_issuer) will not open under the new format. R911-F5's node-side migration re-seals them; say in the handoff exactly which records need it.")
/// @yah:verify("cargo test -p yah-workload-spec (from oss/yah-base), cargo test -p yubaba --lib, cargo test -p yah --lib cloud_secret: green vs baseline.")
/// @yah:verify("Tests: an edited access rule fails to open; a ciphertext moved to another name fails to open; a round trip succeeds.")
/// @yah:depends_on(R911-F3)
/// @yah:files(oss/yah-base/crates/workload-spec/src/secrets.rs)
/// @yah:files(oss/yubaba/crates/yubaba/src/secrets.rs)
/// @yah:files(app/yah/cli/src/cloud_secret.rs)
/// @yah:files(oss/yubaba/crates/yubaba/src/acme_issuer.rs)
/// @yah:handoff("AAD (oss/yah-base/crates/workload-spec/src/secrets.rs): new `pub const SECRET_AAD_V1 = b\"yah/secret-aad/v1\\0\"` and `pub fn secret_aad(name: &str, access: &SecretAccess) -> Vec<u8>`, the ONLY builder. The layout is the version tag, then u32-BE length + UTF-8 name, then the rule: a length-prefixed variant tag (allow_any / workloads / recipes) and, for a list variant, a u32-BE entry count followed by each entry's fields in declared order (workload, tenant.0, namespace.0 / recipe, key), each length-prefixed. Entries are bound in stored order, never sorted, and serde_json is not involved. The match and the entry destructures are exhaustive, so a new rule variant or entry field does not compile until it chooses an encoding. `secret_aad` is not feature-gated (it does no crypto).")
/// @yah:handoff("SIGNATURES BROKEN (pre-1.0): `seal(kek, plaintext, aad) -> Sealed`; new `open(kek, nonce, ciphertext, aad) -> Result<Vec<u8>, OpenError>` (a nonce that is not 12 bytes returns OpenError, never a panic); new zero-information `pub struct OpenError`. All three are behind the `seal` feature. The one legacy door is `#[doc(hidden)] open_legacy_unbound(kek, nonce, ciphertext)` (= open with empty AAD), with a one-line comment saying it exists only for R911-F5's migration and R911-T7 deletes it. Code-only, its only callers are two workload-spec tests.")
/// @yah:handoff("CALLERS UPDATED, counts confirmed code-only with wc -l. `workload_spec::secrets::seal(` has 3 callers: yubaba `seal_cluster_secret` and cloud_secret.rs `put` (both now pass `secret_aad(name, &access)`), plus one yubaba test that builds a deliberately unbound legacy record. `workload_spec::secrets::open(` has 1 caller: yubaba `open_cluster_secret`, the only open path for ClusterResolver and tenant_passway. `.decrypt(` in cluster-secret code: 1, inside workload-spec `open`. yubaba's own Aes256Gcm/Nonce imports moved into its test module, where the fixed-nonce fixtures still encrypt directly. `seal_cluster_secret` gained `name` as its second argument, and all 23 callers pass the name the record is stored AND resolved under: acme_issuer (cert_key/key_key + 2 tests), domain_issuer (cert_name/key_name), tenant_passway tests (cert/key_secret_name of the domain), lib.rs, headscale_state, cert_materialize, secret_reload, secret_watch, fleet_secrets and secrets.rs tests. New test fixture `seal_named`, used by the recipe test that resolves r2/write.")
/// @yah:handoff("ORDER IN THE RESOLVER is unchanged: `open_cluster_secret` checks `rec.access.admits(consumer)` first (refusal = SecretError::Forbidden, KEK untouched), then opens with `secret_aad(name, &rec.access)`. Any open failure (widened rule, ciphertext moved from another name, wrong KEK, tampered bytes, malformed nonce, unbound pre-F4 record) maps to **SecretError::ClusterDecrypt { name }**. It is fail-closed and name-only, and it was already distinct from ClusterNotFound/Forbidden/ClusterUnavailable. Its doc now names the AAD case. The digest (HMAC over plaintext) is unchanged.")
/// @yah:handoff("FOR R911-F5 — LIVE RECORD CLASSES THAT NO LONGER OPEN under this build (every one was sealed with no associated data): (1) EVERY record in each group's RAFT secret map (YubabaState secrets, written by raft PutSecret). Per the R911 recon, prod has 7: cheers/cloud-admin/verify-key, headscale/noise-private-key, noisetable/account/{magic-link-key,session-key,smtp-password}, tls/yah.dev/{cert,key}. Dev has 3: cloudflare-tunnel-token, noisetable/account-staging/{magic-link-key,session-key}. (2) EVERY object under certs/<issuer>/<domain>/{cert,key}.sealed in the shared bucket: per-domain tenant certs written by domain_issuer, plus the tls/yah.dev pair the pre-F3 acme issuer mirrored there under R779. (3) Anything already under secrets/<group>/, which should be empty in production because the F3 PUT route has not rolled. F5 must open each with `open_legacy_unbound` under the node KEK and re-seal it with `seal_cluster_secret(kek, name, plaintext, updated_at, access)`, preserving updated_at, access, digest, sans and ari.")
/// @yah:verify("BASELINES recorded before editing: workload-spec (oss/yah-base, `cargo test -p yah-workload-spec`) = 205 + 107 passed / 0 failed; with `--features seal` = 207 + 107 / 0. Operator-stated: yubaba lib 980/0, cloud-client 52+1, yah cloud_secret 23/0.")
/// @yah:verify("AFTER: `cargo test -p yah-workload-spec` = 207 + 107 / 0 (+2: aad_bytes_are_pinned, aad_binds_the_rule_in_stored_order_and_separates_fields); `--features seal` = 214 + 107 / 0 (+7: those two plus a_sealed_secret_round_trips_under_its_own_name_and_rule, an_edited_access_rule_fails_to_open, a_ciphertext_moved_to_another_name_fails_to_open, a_malformed_nonce_is_an_open_error_not_a_panic, the_legacy_door_opens_only_unbound_records). From oss/yubaba: `cargo check -p yubaba --all-targets` EXIT=0 (log shows Checking yubaba, no yubaba warnings); `cargo test -p yubaba --lib` = 983 / 0 (+3: secrets::tests::a_widened_access_rule_passes_the_check_and_fails_the_tag, ::a_record_copied_under_another_name_fails_the_tag, ::a_pre_r911_f4_unbound_record_does_not_open); `cargo test -p yubaba --features testing --lib secret_reload` = 2 / 0. Root: `cargo test -p cloud-client` = 52 + 1 / 0 (unchanged); `cargo test -p yah --lib cloud_secret` = 23 / 0 (unchanged); `cargo run -p xtask -- cluster-epochs` EXIT=0 (no protocol surface moved).")
/// @yah:verify("aad_bytes_are_pinned pins exact bytes for a Workloads rule (name a/b, one entry w/t/n), a Recipes rule, and AllowAny. If it fails, the change would break every sealed record in the fleet: bump the version tag and migrate instead.")
/// @yah:gotcha("ROLL ORDER, HARD: this build opens NO pre-F4 record. Rolling it before R911-F5 has re-sealed both the raft map and certs/<issuer>/ would make every cluster-secret deploy fail ClusterDecrypt. start_headscale would REFUSE to start (NoiseKeyError::Unusable), secret rotation and cert_materialize would stop, and tenant_passway would count every per-domain cert as failed. The issuers do not re-order because of it: both renewal gates read record metadata (updated_at/sans/ari), never the plaintext, so there is no LE rate-limit exposure.")
/// @yah:gotcha("CAMP/NODE LOCKSTEP: a `yah cloud secret put` from a CLI built before this change seals with no AAD, and this node would store the record but never open it. Install the CLI (`cargo xtask install`) in the same roll.")
#[cfg(feature = "seal")]
pub fn seal(kek: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Sealed {
    use aes_gcm::aead::{Aead, AeadCore, OsRng, Payload};
    use aes_gcm::{Aes256Gcm, Key, KeyInit};

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("AES-256-GCM seal of a KB-scale secret cannot fail on length");
    Sealed {
        ciphertext,
        nonce: nonce.to_vec(),
    }
}

/// A sealed secret did not open. Deliberately carries nothing: which of wrong
/// key, tampered bytes, malformed nonce or mismatched associated data it was is
/// not something a caller may learn or log.
#[cfg(feature = "seal")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("sealed secret failed to open")]
pub struct OpenError;

/// Open what [`seal`] produced: `nonce` and `ciphertext` from the record, and
/// the same `aad` it was sealed under (for a cluster secret,
/// [`secret_aad`]`(name, &record.access)`). A nonce that is not 12 bytes is an
/// [`OpenError`], never a panic.
#[cfg(feature = "seal")]
pub fn open(
    kek: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, OpenError> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

    if nonce.len() != 12 {
        return Err(OpenError);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| OpenError)
}
/// Draw 32 cryptographically-secure random bytes for a fresh cluster KEK.
///
/// Same `OsRng` [`seal`] draws its nonces from, on purpose: a KEK minted from a
/// weaker source would silently undermine every secret sealed under it, and
/// pulling a second RNG dependency into the camp is how that happens.
#[cfg(feature = "seal")]
pub fn generate_kek() -> zeroize::Zeroizing<[u8; 32]> {
    use aes_gcm::aead::rand_core::RngCore;
    let mut kek = zeroize::Zeroizing::new([0u8; 32]);
    aes_gcm::aead::OsRng.fill_bytes(kek.as_mut());
    kek
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R911-F4: the associated-data layout is a wire contract between the camp
    /// and every node. If this fails, the change breaks every sealed record in
    /// the fleet — bump the version tag and migrate instead.
    #[test]
    fn aad_bytes_are_pinned() {
        let rule = SecretAccess::Workloads(vec![WorkloadMatch {
            workload: "w".into(),
            tenant: TenantId("t".into()),
            namespace: NamespaceId("n".into()),
        }]);
        let expected: Vec<u8> = [
            b"yah/secret-aad/v1\0".as_slice(),
            &[0, 0, 0, 3],
            b"a/b",
            &[0, 0, 0, 9],
            b"workloads",
            &[0, 0, 0, 1],
            &[0, 0, 0, 1],
            b"w",
            &[0, 0, 0, 1],
            b"t",
            &[0, 0, 0, 1],
            b"n",
        ]
        .concat();
        assert_eq!(secret_aad("a/b", &rule), expected);

        let recipes = SecretAccess::Recipes(vec![RecipeMatch {
            recipe: "r".into(),
            key: "k".into(),
        }]);
        let expected: Vec<u8> = [
            b"yah/secret-aad/v1\0".as_slice(),
            &[0, 0, 0, 1],
            b"x",
            &[0, 0, 0, 7],
            b"recipes",
            &[0, 0, 0, 1],
            &[0, 0, 0, 1],
            b"r",
            &[0, 0, 0, 1],
            b"k",
        ]
        .concat();
        assert_eq!(secret_aad("x", &recipes), expected);

        let expected: Vec<u8> = [
            b"yah/secret-aad/v1\0".as_slice(),
            &[0, 0, 0, 1],
            b"x",
            &[0, 0, 0, 9],
            b"allow_any",
        ]
        .concat();
        assert_eq!(secret_aad("x", &SecretAccess::AllowAny), expected);
    }

    #[test]
    fn aad_binds_the_rule_in_stored_order_and_separates_fields() {
        let ab = SecretAccess::workloads(["a", "b"]);
        let ba = SecretAccess::workloads(["b", "a"]);
        assert_ne!(secret_aad("s", &ab), secret_aad("s", &ba), "reordering is an edit");
        // Length prefixes keep field boundaries unambiguous.
        assert_ne!(
            secret_aad("s", &SecretAccess::workloads(["ab"])),
            secret_aad("s", &SecretAccess::workloads(["a", "b"]))
        );
        assert_ne!(secret_aad("a", &SecretAccess::AllowAny), secret_aad("b", &SecretAccess::AllowAny));
        assert_ne!(
            secret_aad("s", &SecretAccess::default()),
            secret_aad("s", &SecretAccess::AllowAny)
        );
    }

    #[cfg(feature = "seal")]
    #[test]
    fn a_sealed_secret_round_trips_under_its_own_name_and_rule() {
        let kek = [7u8; 32];
        let rule = SecretAccess::workloads(["ingress"]);
        let aad = secret_aad("tls/yah.dev/key", &rule);
        let sealed = seal(&kek, b"KEYPEM", &aad);
        assert_eq!(open(&kek, &sealed.nonce, &sealed.ciphertext, &aad).unwrap(), b"KEYPEM");
    }

    #[cfg(feature = "seal")]
    #[test]
    fn an_edited_access_rule_fails_to_open() {
        let kek = [7u8; 32];
        let sealed = seal(
            &kek,
            b"secret",
            &secret_aad("cf/dns-token", &SecretAccess::workloads(["passway"])),
        );
        for widened in [
            SecretAccess::AllowAny,
            SecretAccess::workloads(["passway", "attacker"]),
        ] {
            let aad = secret_aad("cf/dns-token", &widened);
            assert_eq!(open(&kek, &sealed.nonce, &sealed.ciphertext, &aad), Err(OpenError));
        }
    }

    #[cfg(feature = "seal")]
    #[test]
    fn a_ciphertext_moved_to_another_name_fails_to_open() {
        let kek = [7u8; 32];
        let rule = SecretAccess::AllowAny;
        let sealed = seal(&kek, b"secret", &secret_aad("noisetable/account/session-key", &rule));
        let aad = secret_aad("cheers/cloud-admin/verify-key", &rule);
        assert_eq!(open(&kek, &sealed.nonce, &sealed.ciphertext, &aad), Err(OpenError));
    }

    #[cfg(feature = "seal")]
    #[test]
    fn a_malformed_nonce_is_an_open_error_not_a_panic() {
        let kek = [7u8; 32];
        let aad = secret_aad("x", &SecretAccess::AllowAny);
        let sealed = seal(&kek, b"secret", &aad);
        assert_eq!(open(&kek, &sealed.nonce[..8], &sealed.ciphertext, &aad), Err(OpenError));
    }

    #[cfg(feature = "seal")]
    #[test]
    fn seal_draws_a_fresh_nonce_per_call() {
        let kek = [7u8; 32];
        let a = seal(&kek, b"same-plaintext", b"aad");
        let b = seal(&kek, b"same-plaintext", b"aad");
        assert_eq!(a.nonce.len(), 12);
        assert_ne!(a.nonce, b.nonce, "nonce must never repeat under one key");
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.ciphertext, b"same-plaintext".to_vec());
    }

    #[cfg(feature = "seal")]
    #[test]
    fn generated_keks_are_32_bytes_and_distinct() {
        let a = generate_kek();
        let b = generate_kek();
        assert_eq!(a.len(), 32);
        assert_ne!(*a, *b, "two mints must not collide");
        assert_ne!(*a, [0u8; 32], "must not be all-zero");
    }

    #[test]
    fn default_access_admits_nobody() {
        // The fail-closed migration hinges on exactly this.
        let rule = SecretAccess::default();
        assert!(!rule.admits(&SecretConsumer::workload("yah-cloud-admin")));
        assert_eq!(rule.summary(), "deny-all (no rule)");
    }

    #[test]
    fn legacy_record_shape_deserializes_to_deny_all() {
        // A record serialized before the field existed: serde(default) must land
        // on deny-all, not allow-all.
        #[derive(Deserialize)]
        struct Legacyish {
            #[serde(default)]
            access: SecretAccess,
        }
        let v: Legacyish = serde_json::from_str("{}").unwrap();
        assert!(!v.access.admits(&SecretConsumer::workload("anything")));
    }

    #[test]
    fn allow_list_matches_on_all_three_axes() {
        let rule = SecretAccess::workloads(["yah-cloud-admin"]);
        assert!(rule.admits(&SecretConsumer::workload("yah-cloud-admin")));
        assert!(!rule.admits(&SecretConsumer::workload("other-service")));

        // Same name, different tenant → refused (the entry defaulted to the
        // singleton tenant, and defaults are narrowing, not widening).
        let other_tenant = SecretConsumer {
            workload: "yah-cloud-admin".into(),
            tenant: TenantId("acme".into()),
            namespace: NamespaceId::singleton(),
            recipe: None,
        };
        assert!(!rule.admits(&other_tenant));
    }

    #[test]
    fn allow_any_is_explicit_and_visible() {
        let rule = SecretAccess::AllowAny;
        assert!(rule.admits(&SecretConsumer::workload("anything-at-all")));
        assert_eq!(rule.summary(), "allow-any");
        // And it must survive a round-trip as a distinct, greppable token.
        let json = serde_json::to_string(&rule).unwrap();
        assert_eq!(json, "\"allow_any\"");
    }

    #[test]
    fn omitted_tenant_and_namespace_default_to_singleton() {
        let m: WorkloadMatch = serde_json::from_str(r#"{"workload":"api"}"#).unwrap();
        assert_eq!(m.tenant, TenantId::singleton());
        assert_eq!(m.namespace, NamespaceId::singleton());
    }

    // ── recipe rules (R555-F5) ───────────────────────────────────────────────

    const KEY: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0537bb43f2a8d9c";

    fn forge_run(recipe: Option<&str>) -> SecretConsumer {
        // What a dispatched build actually looks like: a per-run workload name
        // no allow-list could have named in advance.
        let c = SecretConsumer::workload("forge-0193a7c2-9f11-7e3a-9c1e-2b0f4d8e6a55");
        match recipe {
            Some(r) => c.admitted_as(RecipeIdentity {
                recipe: r.into(),
                key: KEY.into(),
            }),
            None => c,
        }
    }

    #[test]
    fn a_recipe_rule_admits_the_signed_recipe_whatever_the_run_is_called() {
        let rule = SecretAccess::recipes([("rusty-v8-musl", KEY)]);
        assert!(rule.admits(&forge_run(Some("rusty-v8-musl"))));
        // A second run of the same recipe has a different workload name and is
        // still admitted — that is the whole point of keying on the recipe.
        let other_run = SecretConsumer::workload("forge-0193a7c2-ffff-7e3a-9c1e-2b0f4d8e6a55")
            .admitted_as(RecipeIdentity {
                recipe: "rusty-v8-musl".into(),
                key: KEY.into(),
            });
        assert!(rule.admits(&other_run));
    }

    #[test]
    fn a_recipe_rule_admits_nobody_without_a_verified_identity() {
        // The fail-closed direction: an unsigned dispatch, or one whose grant
        // did not verify, carries `recipe: None` and gets nothing.
        let rule = SecretAccess::recipes([("rusty-v8-musl", KEY)]);
        assert!(!rule.admits(&forge_run(None)));
        assert!(!rule.admits(&SecretConsumer::workload("rusty-v8-musl")));
    }

    #[test]
    fn a_recipe_rule_matches_on_the_signing_key_too() {
        // Otherwise anyone holding any key the node pins could sign a recipe
        // named `rusty-v8-musl` and inherit its credentials.
        let rule = SecretAccess::recipes([("rusty-v8-musl", KEY)]);
        let impostor = SecretConsumer::workload("forge-1").admitted_as(RecipeIdentity {
            recipe: "rusty-v8-musl".into(),
            key: "00".repeat(32),
        });
        assert!(!rule.admits(&impostor));
        assert!(!rule.admits(&forge_run(Some("whisper-bundle-tar"))));
    }

    #[test]
    fn the_two_rule_kinds_do_not_leak_into_each_other() {
        // A workload rule is not satisfied by a recipe identity...
        let by_workload = SecretAccess::workloads(["rusty-v8-musl"]);
        assert!(!by_workload.admits(&forge_run(Some("rusty-v8-musl"))));
        // ...and a recipe rule is not satisfied by a same-named workload.
        let by_recipe = SecretAccess::recipes([("ingress", KEY)]);
        assert!(!by_recipe.admits(&SecretConsumer::workload("ingress")));
    }

    #[test]
    fn an_empty_recipe_list_admits_nobody_and_says_so() {
        let rule = SecretAccess::Recipes(Vec::new());
        assert!(!rule.admits(&forge_run(Some("rusty-v8-musl"))));
        assert_eq!(rule.summary(), "deny-all (no rule)");
    }

    #[test]
    fn a_recipe_rule_renders_recipe_and_key_prefix() {
        let rule = SecretAccess::recipes([("rusty-v8-musl", KEY)]);
        assert_eq!(rule.summary(), "recipe rusty-v8-musl@3d4017c3");
    }

    #[test]
    fn a_recipe_rule_round_trips_through_the_stored_record() {
        let rule = SecretAccess::recipes([("rusty-v8-musl", KEY)]);
        let json = serde_json::to_string(&rule).unwrap();
        assert_eq!(serde_json::from_str::<SecretAccess>(&json).unwrap(), rule);
        // And the pre-R555-F5 record shape still deserializes unchanged.
        let legacy: SecretAccess =
            serde_json::from_str(r#"{"workloads":[{"workload":"ingress"}]}"#).unwrap();
        assert!(legacy.admits(&SecretConsumer::workload("ingress")));
    }

    #[test]
    fn a_consumer_serialized_before_this_field_existed_carries_no_recipe() {
        // `recipe` is serde(default) on SecretConsumer, and the default is None
        // — an absent field must not become a claim.
        let c: SecretConsumer = serde_json::from_str(
            r#"{"workload":"ingress","tenant":"default","namespace":"default"}"#,
        )
        .unwrap();
        assert_eq!(c.recipe, None);
    }

    #[test]
    fn secrets_forbidden_is_externally_indistinguishable() {
        // A probing spec must not be able to tell "exists but denied" from
        // "does not exist" — see the note on SecretError::Forbidden.
        let denied = SecretError::Forbidden {
            name: "cheers/cloud-admin/verify-key".into(),
        };
        let absent = SecretError::ClusterNotFound {
            name: "cheers/cloud-admin/verify-key".into(),
        };
        assert_eq!(denied.to_string(), absent.to_string());
    }
}
