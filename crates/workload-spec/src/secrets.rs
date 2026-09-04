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
    /// node-local KEK, a truncated/tampered record, or a malformed nonce. Fails
    /// closed; the message carries only the logical name, never key or
    /// ciphertext bytes.
    #[error("cluster secret {name} failed to decrypt")]
    ClusterDecrypt { name: String },

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

/// AES-256-GCM-seal `plaintext` under the 32-byte cluster `kek`.
///
/// A cryptographically-random 12-byte nonce is drawn **per call**, so re-sealing
/// identical plaintext (a rotation, a re-ship of an unchanged value) never
/// reuses a nonce. That is the whole reason this lives in one place: nonce reuse
/// under a fixed key is catastrophic for GCM, and it is exactly the invariant
/// that erodes when two call sites each roll their own seal.
///
/// Infallible by construction: the only error `aead` can return here is a
/// plaintext-length overflow far beyond any credential.
#[cfg(feature = "seal")]
pub fn seal(kek: &[u8; 32], plaintext: &[u8]) -> Sealed {
    use aes_gcm::aead::{Aead, AeadCore, OsRng};
    use aes_gcm::{Aes256Gcm, Key, KeyInit};

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM seal of a KB-scale secret cannot fail on length");
    Sealed {
        ciphertext,
        nonce: nonce.to_vec(),
    }
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

    #[cfg(feature = "seal")]
    #[test]
    fn seal_draws_a_fresh_nonce_per_call() {
        let kek = [7u8; 32];
        let a = seal(&kek, b"same-plaintext");
        let b = seal(&kek, b"same-plaintext");
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
