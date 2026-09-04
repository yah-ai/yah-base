//! Credential registry + verdict sidecar (W337, R856-F1).
//!
//! Before this module there were three inventories of the same thing and none
//! of them agreed: `CLOUD_SECRETS` in the CLI (7 slots, 3 of which no longer
//! exist in any vault), `CRED_SLOTS` in agent-tools (10 slots, different
//! fields), and the vault itself (42 slots as of 2026-09-03). This is the one
//! registry; both of those now read from it.
//!
//! A spec is *static* description — what a slot is for, who reads it, how it
//! is minted, which TTL band it belongs to. Everything time-varying (has it
//! been probed, did the probe say yes, when does it die) lives in the
//! **sidecar**, a plain 0644 JSON file next to `credentials.enc` that can be
//! read without decrypting anything. See [`KeysStore::read_health`].
//!
//! ## What is deliberately *not* asserted here
//!
//! [`ExpiryKind::Unverified`] is the default, not [`ExpiryKind::ReviewBy`].
//! `ReviewBy` is a positive claim — "this credential does not expire at all"
//! (W337 §7.1) — and stating it about a provider whose expiry policy nobody
//! read would be a lie in the same direction as a green light on a dead key.
//! Only two slots carry `Enforced` here, and both are grounded: `npm-api-token`
//! (write-enabled granular tokens are hard-capped at 90 days, W337 §3) and
//! `openai-oauth` (an OAuth access-token bundle). Self-minted key material and
//! the not-actually-a-credential config slots carry `ReviewBy`, since nothing
//! third-party can expire them.
//!
//! Likewise `MintHelp` is populated for exactly three providers — the three
//! that had grounded dashboard URLs and scope lists in
//! `packages/yah/ui/src/components/shell/AgentsSection.tsx`. Every other slot
//! gets [`MintHelp::NONE`]. A wrong mint URL is worse than an absent one; the
//! full port is R856-F5.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Static description
// ---------------------------------------------------------------------------

/// Who mints the credential. Not a transport or an auth scheme — the entity
/// whose dashboard or API a rotation has to go through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    Cloudflare,
    CratesIo,
    DeepSeek,
    DigitalOcean,
    DockerHub,
    GitHub,
    Groq,
    Headscale,
    Hetzner,
    Mailgun,
    /// Moonshot AI, whose API the `kimi-platform-api-key` slot addresses.
    Moonshot,
    Npm,
    Ollama,
    OpenAi,
    OpenRouter,
    /// Minted by this camp itself — signing keys, KEKs, issuer material, and
    /// the vault slots that hold plain configuration rather than a secret.
    Yah,
    /// Slot exists in the vault but nothing in-tree establishes who issues it.
    Unknown,
}

impl Provider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Provider::Cloudflare => "cloudflare",
            Provider::CratesIo => "crates-io",
            Provider::DeepSeek => "deepseek",
            Provider::DigitalOcean => "digitalocean",
            Provider::DockerHub => "docker-hub",
            Provider::GitHub => "github",
            Provider::Groq => "groq",
            Provider::Headscale => "headscale",
            Provider::Hetzner => "hetzner",
            Provider::Mailgun => "mailgun",
            Provider::Moonshot => "moonshot",
            Provider::Npm => "npm",
            Provider::Ollama => "ollama",
            Provider::OpenAi => "openai",
            Provider::OpenRouter => "openrouter",
            Provider::Yah => "yah",
            Provider::Unknown => "unknown",
        }
    }
}

/// What the slot is *for*, coarse enough to drive a filter. `yah cloud secrets`
/// and `cloud.creds_check` both render [`Domain::Infra`]; without this the one
/// registry would force those two surfaces to print all 45 slots, including
/// every model API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Domain {
    /// Provisioning, networking, ingress, object storage, cluster sealing.
    Infra,
    /// Release and publish paths — registries, signing keys.
    Publish,
    /// LLM provider credentials consumed by the runner.
    Model,
    /// Credentials belonging to a deployed application workload.
    Service,
}

/// TTL band (W337 §7). The band is a function of *who rotates it*, not of what
/// the provider allows — the provider cap is a separate, intersecting fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Band {
    /// Minting requires a human behind 2FA or a dashboard. 1 year, floor *and*
    /// ceiling: shorter gets worked around, longer makes the runbook fiction.
    Manual,
    /// The provider exposes a mint API reachable from a longer-lived
    /// credential, so the machine pays the rotation cost.
    Automatable,
}

impl Band {
    pub const fn ttl_days(self) -> u32 {
        match self {
            Band::Manual => 365,
            Band::Automatable => 90,
        }
    }

    /// The shortest TTL the band tolerates. A provider cap below this is the
    /// W337 §7.3 conflict and gets flagged.
    pub const fn floor_days(self) -> u32 {
        self.ttl_days()
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Band::Manual => "manual",
            Band::Automatable => "automatable",
        }
    }
}

/// Which kind of expiry this slot is subject to (W337 §7.1). The *date* is
/// per-credential and lives in the sidecar as an [`Expiry`]; this is the
/// policy the spec declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpiryKind {
    /// The provider will stop honouring it on the date.
    Enforced,
    /// The provider supports expiry and the operator chose the date.
    Declared,
    /// The credential does not expire at all; the date means *re-mint*.
    ReviewBy,
    /// Nobody has read this provider's expiry policy. Not a synonym for
    /// `ReviewBy` — see the module docs.
    Unverified,
}

impl ExpiryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ExpiryKind::Enforced => "enforced",
            ExpiryKind::Declared => "declared",
            ExpiryKind::ReviewBy => "review-by",
            ExpiryKind::Unverified => "unverified",
        }
    }
}

/// Vantage point a probe must run from (W337 §5). A credential can be valid
/// from the operator's laptop and dead from a cloud IP — provider allowlists
/// and cloud-range SMTP blocks both look exactly like a bad password.
///
/// `Workload` carries `&'static str` rather than W337's `String` because the
/// registry is a `const`; the information is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeFrom {
    Local,
    Workload(&'static str),
    /// The provider restricts this credential to an IP allowlist, so a probe
    /// run from outside it fails *identically to revocation* — same status,
    /// same body. A prober seeing an auth failure on one of these must return
    /// [`Verdict::Indeterminate`], never [`Verdict::Revoked`]: the alternative
    /// sends an operator working from a cafe to re-mint a live credential.
    ///
    /// Measured 2026-09-03 for `npm-api-token`, the one slot that carries it:
    /// its `npm token list --json` record has a non-empty `cidr`. The
    /// allowlist itself is deliberately **not** recorded here — this crate is
    /// published, the block is the operator's own network, and a prober cannot
    /// act on it anyway (it cannot read the allowlist without first
    /// authenticating past it).
    AllowlistedNetwork,
}

/// Everything a human needs to mint a replacement. Populated only where it
/// could be grounded — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MintHelp {
    pub dashboard_url: Option<&'static str>,
    pub dashboard_label: Option<&'static str>,
    pub scopes: &'static [&'static str],
    pub nav_hint: Option<&'static str>,
}

impl MintHelp {
    pub const NONE: MintHelp = MintHelp {
        dashboard_url: None,
        dashboard_label: None,
        scopes: &[],
        nav_hint: None,
    };

    /// True when there is enough here to put in front of an operator.
    pub const fn is_populated(&self) -> bool {
        self.dashboard_url.is_some()
    }
}

/// One vault slot, fully described.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CredentialSpec {
    /// Canonical vault slot, as `yah keys list` prints it.
    pub slot: &'static str,
    /// Env-var fallback, where a consumer implements one.
    pub env: Option<&'static str>,
    pub purpose: &'static str,
    /// Files/commands that actually read it, verified by grep.
    pub consumers: &'static [&'static str],
    pub provider: Provider,
    pub domain: Domain,
    pub band: Band,
    /// Hard ceiling the provider imposes, where one is known.
    pub provider_cap_days: Option<u32>,
    pub expiry_kind: ExpiryKind,
    pub probe_from: ProbeFrom,
    pub mint: MintHelp,
    /// Blocks the core cloud commands outright when missing.
    pub required: bool,
    /// 1Password item that holds the authoritative copy, where one exists.
    pub onepassword: Option<&'static str>,
}

impl CredentialSpec {
    /// `min(band, provider_cap)` — W337 §7.3.
    pub const fn effective_ttl_days(&self) -> u32 {
        match self.provider_cap_days {
            Some(cap) if cap < self.band.ttl_days() => cap,
            _ => self.band.ttl_days(),
        }
    }

    /// The provider caps this credential *below* what its band tolerates, so
    /// it will consume repeated human rotations forever. Not cosmetic: this is
    /// the flag that makes a recurring cost visible instead of reading as a
    /// normal short TTL.
    pub const fn ttl_capped_below_band(&self) -> bool {
        match self.provider_cap_days {
            Some(cap) => cap < self.band.floor_days(),
            None => false,
        }
    }
}

/// Look up one slot. `None` for a slot the registry does not describe — which
/// is itself worth surfacing, since every vault slot should be in here.
pub fn spec(slot: &str) -> Option<&'static CredentialSpec> {
    CREDENTIAL_SPECS.iter().find(|s| s.slot == slot)
}

/// Every spec in one domain, registry order.
pub fn specs_in_domain(domain: Domain) -> impl Iterator<Item = &'static CredentialSpec> {
    CREDENTIAL_SPECS.iter().filter(move |s| s.domain == domain)
}

// ---------------------------------------------------------------------------
// Mint help — ported verbatim from the desktop rail's ProviderHelp entries
// (packages/yah/ui/src/components/shell/AgentsSection.tsx:57-105). Three
// providers is all that file grounds; R856-F5 ports the rest.
// ---------------------------------------------------------------------------

const MINT_CLOUDFLARE: MintHelp = MintHelp {
    dashboard_url: Some("https://dash.cloudflare.com/profile/api-tokens"),
    dashboard_label: Some("dash.cloudflare.com -> My Profile -> API Tokens"),
    scopes: &[
        "Account: Cloudflare Tunnel: Edit",
        "Account: Connectivity Directory: Admin",
        "Account: Cloudflare R2: Edit",
    ],
    nav_hint: Some(
        "Create a Custom Token with Account permissions: Cloudflare Tunnel -> Edit, \
         Connectivity Directory -> Admin, Cloudflare R2 -> Edit. Zone DNS is only needed \
         if your domains are Cloudflare-managed.",
    ),
};

const MINT_HETZNER: MintHelp = MintHelp {
    dashboard_url: Some("https://console.hetzner.cloud/projects"),
    dashboard_label: Some("console.hetzner.cloud -> your project -> Security -> API Tokens"),
    scopes: &["Read & Write"],
    nav_hint: Some("Pick your project -> Security -> API Tokens -> Generate API Token."),
};

const MINT_GITHUB: MintHelp = MintHelp {
    dashboard_url: Some(
        "https://github.com/settings/tokens/new?scopes=write:packages,read:packages&description=yah%20ghcr",
    ),
    dashboard_label: Some("github.com -> Settings -> Developer settings -> Tokens (classic)"),
    scopes: &["write:packages", "read:packages"],
    nav_hint: Some(
        "Generate a classic token with write:packages (it implies read:packages). If the \
         yah-ai org enforces SAML SSO, click 'Configure SSO' on the new token and authorize \
         it for yah-ai. The ghcr login user is your GitHub username; this token is the password.",
    ),
};

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// Every credential slot this camp knows about, alphabetical by slot.
///
/// Reconciled 2026-09-03 against three sources: `yah keys list` (42 slots),
/// `CLOUD_SECRETS`, and `CRED_SLOTS`. All 42 live slots are here. Three
/// entries are declared-but-not-yet-populated — `digitalocean-api-token`,
/// `hetzner-s3-access-key`, `hetzner-s3-secret-key` — kept because each has a
/// live `fob::get_or_env` call site. `iroh-node-secret` was dropped: it had no
/// consumer anywhere in the tree and conceded as much in its own comment.
pub const CREDENTIAL_SPECS: &[CredentialSpec] = &[
    CredentialSpec {
        slot: "cheers-cloud-admin-verify-key",
        env: None,
        purpose: "cheers issuer PUBLIC verify key, shipped to the yah-cloud-admin workload over \
                  the W294 secret rail so it can validate session JWTs without calling back to \
                  the issuer",
        consumers: &[
            "app/yah/cli/src/cloud_cheers.rs (VERIFY_SLOT_DEFAULT)",
            "app/yah/cli/src/cloud_secret.rs",
            ".yah/infra/secrets/cheers-cloud-admin-verify-key.toml",
        ],
        provider: Provider::Yah,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Workload("yah-cloud-admin"),
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cheers-issuer-iss",
        env: None,
        purpose: "the `iss` claim string the cheers issuer stamps on session JWTs — \
                  configuration, not a secret",
        consumers: &["app/yah/cli/src/cloud_cheers.rs:70 (ISS_SLOT)"],
        provider: Provider::Yah,
        domain: Domain::Service,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cheers-issuer-signing-key",
        env: None,
        purpose: "cheers issuer signing key — mints the session JWTs yah-cloud-admin accepts",
        consumers: &["app/yah/cli/src/cloud_cheers.rs:64 (SIGNING_SLOT)"],
        provider: Provider::Yah,
        domain: Domain::Service,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-api-token",
        env: Some("CLOUDFLARE_API_TOKEN"),
        purpose: "account-scoped Cloudflare API token — DNS records, Tunnel, R2 management. \
                  Verify it at /accounts/<id>/tokens/verify, NOT /user/tokens/verify: the \
                  user-scoped endpoint rejects account tokens with a message that reads \
                  exactly like an expired credential",
        consumers: &[
            "oss/yubaba/crates/cloud/src/provider/cloudflare.rs",
            "oss/yubaba/crates/cloud/src/reconciler/domain.rs",
            "oss/yubaba/crates/cloud/src/reconciler/cf_creds.rs",
            "app/yah/cli/src/mesh.rs",
            "scripts/cf-apex-mode.sh",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-legacy-yah",
        env: None,
        purpose: "USER-owned Cloudflare token that can manage account tokens — the bootstrap \
                  slot `yah cloud cf token create --bootstrap-slot` mints scoped tokens from. \
                  A manual root under W337 §7.2: several other Cloudflare slots are \
                  automatable only because this one exists. Verifies at /user/tokens/verify",
        consumers: &[
            ".yah/infra/providers/cloudflare.toml:38 (bootstrap-slot)",
            ".yah/docs/working/W295-fleet-def-as-almanac-release.md:546",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-mesofact-static",
        env: None,
        purpose: "scoped Cloudflare token carrying the seven MESOFACT_STATIC_GRANTS (including \
                  Workers Scripts:Write and Workers Routes:Write). This is what \
                  .yah/infra/providers/cloudflare.toml points `credentials` at; \
                  cloudflare-api-token was swapped out for it in R703 because it had no \
                  Workers grants",
        consumers: &[
            ".yah/infra/providers/cloudflare.toml:47 (credentials)",
            "oss/yubaba/crates/cloud/src/reconciler/mesofact_static.rs",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-access-key-id",
        env: Some("CF_R2_ACCESS_KEY_ID"),
        purpose: "R2 S3-compatible access key id — account-wide R2 write. A node holding this \
                  pair could rewrite the public releases index, which is why the fleet nodes \
                  get cloudflare-r2-fleet-read-* instead",
        consumers: &[
            "oss/yah-base/crates/object-store/src/r2.rs:49 (R2_ACCESS_KEY_SLOT)",
            "oss/qed/crates/scryer/src/long_tier.rs",
            "oss/yubaba/crates/cloud/src/reconciler/r2_publish.rs",
            "scripts/publish-desktop.sh",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-fleet-read-access-key-id",
        env: None,
        purpose: "read-only R2 access key id (CF token yah-fleet-index-read), shipped to fleet \
                  nodes over the W294 secret rail so yah-cloud-admin can GET \
                  yah-fleet/fleet/index.json without holding write credentials",
        consumers: &[
            ".yah/infra/secrets/cloudflare-r2-fleet-read-access-key-id.toml",
            ".yah/almanac/fleet.toml:60",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Workload("yah-cloud-admin"),
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-fleet-read-secret-key",
        env: None,
        purpose: "secret half of the read-only fleet-index R2 pair; ships alongside \
                  cloudflare-r2-fleet-read-access-key-id",
        consumers: &[
            ".yah/infra/secrets/cloudflare-r2-fleet-read-secret-key.toml",
            ".yah/almanac/fleet.toml:60",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Workload("yah-cloud-admin"),
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-secret-key",
        env: Some("CF_R2_SECRET_KEY"),
        purpose: "secret half of the account-wide R2 S3 pair",
        consumers: &[
            "oss/yah-base/crates/object-store/src/r2.rs:51 (R2_SECRET_KEY_SLOT)",
            "oss/qed/crates/scryer/src/long_tier.rs",
            "oss/yubaba/crates/cloud/src/reconciler/r2_publish.rs",
            "scripts/publish-desktop.sh",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-static-yah-dev",
        env: None,
        purpose: "Cloudflare token named for the yah.dev static site. Measured 2026-08-09 \
                  (.yah/infra/providers/cloudflare.toml:32): it returns [10000] on \
                  /accounts/<id>/workers/scripts, so it carries no Workers grants. No in-tree \
                  consumer reads this slot",
        consumers: &[],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-tunnel-token",
        env: Some("CLOUDFLARED_TOKEN"),
        purpose: "`cloudflared service install --token` for machines that declare cloudflared \
                  in machine.toml",
        consumers: &[
            "oss/yubaba/crates/cloud/src/cloud_init.rs",
            "oss/yah-base/crates/local-driver/src/cloudflared_ingress.rs",
            "app/yah/cli/src/mesh.rs",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: Some("Cloudflare Tunnel — yah-cloud"),
    },
    CredentialSpec {
        slot: "cloudflare-tunnel-token-mesh",
        env: None,
        purpose: "tunnel token for the cloud.mesh.yah.dev headscale front door. Provisioned but \
                  unused — the tunnel path was staged and never wired \
                  (oss/yubaba/crates/yubaba/src/leader.rs:40)",
        consumers: &[],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_CLOUDFLARE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-zone-id",
        env: Some("CLOUDFLARE_ZONE_ID"),
        purpose: "not a credential: the Cloudflare zone id used together with \
                  cloudflare-api-token for DNS record management",
        consumers: &[
            "oss/yubaba/crates/cloud/src/mesh.rs",
            "app/yah/cli/src/mesh.rs",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cluster-kek",
        env: None,
        purpose: "cluster key-encryption key (fingerprint 1e62fac9) that seals every W294 \
                  cluster secret. NEVER re-init with --force: every secret sealed under it \
                  becomes permanently unreadable (W256)",
        consumers: &["app/yah/cli/src/cloud_secret.rs:102 (CLUSTER_KEK_SLOT)"],
        provider: Provider::Yah,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "crates-io-token",
        env: Some("CARGO_REGISTRY_TOKEN"),
        purpose: "crates.io publish token for the oss-publish wave",
        consumers: &[
            "scripts/oss-publish.sh:46",
            "scripts/internal-publish.sh",
            "scripts/reserve-crate-names.sh",
            "scripts/set-trusted-publishers.sh",
        ],
        provider: Provider::CratesIo,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "deepseek-api-key",
        env: Some("DEEPSEEK_API_KEY"),
        purpose: "DeepSeek API key — Bearer auth on both the OpenAI-wire and Anthropic-wire \
                  endpoints",
        consumers: &["crates/yah/runner/src/resolver/mod.rs:1151 (DEEPSEEK_SLOT)"],
        provider: Provider::DeepSeek,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "digitalocean-api-token",
        env: Some("DIGITALOCEAN_TOKEN"),
        purpose: "DigitalOcean API token for the envoy adapter. Declared but not populated in \
                  this camp's vault as of 2026-09-03; kept because the call site is live",
        consumers: &["oss/yubaba/crates/cloud/src/envoy.rs:331 (default_adapters)"],
        provider: Provider::DigitalOcean,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "docker-hub-token",
        env: Some("DOCKERHUB_TOKEN"),
        purpose: "Docker Hub PAT, bridged into GitHub Actions as DOCKERHUB_TOKEN via the qed \
                  vault bridge (.yah/qed/gha-actions.toml:21-25)",
        consumers: &[".yah/qed/gha-actions.toml:25 (vault:docker-hub-token)"],
        provider: Provider::DockerHub,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "exe-dev-api-token",
        env: None,
        purpose: "purpose not established: nothing in-tree reads this slot, and no EXE_DEV* env \
                  var exists (grepped 2026-09-03). Do not assume it is exe.dev — W214's \
                  'exe-dev' names a ticket tier, not a service",
        consumers: &[],
        provider: Provider::Unknown,
        domain: Domain::Service,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "github-pat",
        env: Some("GITHUB_TOKEN"),
        purpose: "GitHub PAT fronting two surfaces off one slot: ghcr.io registry push/pull and \
                  git identity (clone/push)",
        consumers: &[
            "app/yah/cli/src/ghcr.rs:42 (GITHUB_TOKEN_SLOT)",
            "app/yah/desktop/src/identities.rs",
            "oss/qed/crates/qed/src/secrets_bridge.rs",
        ],
        provider: Provider::GitHub,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_GITHUB,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "groq-api-key",
        env: Some("GROQ_API_KEY"),
        purpose: "Groq API key",
        consumers: &["crates/yah/runner/src/resolver/mod.rs:1145 (GROQ_SLOT)"],
        provider: Provider::Groq,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "headscale-api-key",
        env: Some("HEADSCALE_API_KEY"),
        purpose: "Headscale admin API key. When mesh-url is set, provision uses it to \
                  auto-generate a single-use per-machine preauth key — preferred over the \
                  static headscale-preauth-key. `yah mesh start` stores it automatically. A \
                  manual root under W337 §7.2",
        consumers: &[
            "oss/yubaba/crates/cloud/src/mesh.rs",
            "app/yah/cli/src/mesh.rs",
            "crates/yah/cloud-client/src/lib.rs",
        ],
        provider: Provider::Headscale,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: Some("Headscale API — yah-cloud"),
    },
    CredentialSpec {
        slot: "headscale-preauth-key",
        env: Some("HEADSCALE_PREAUTH_KEY"),
        purpose: "static Headscale preauth key written into a new machine by cloud-init for \
                  mesh join, one-shot per provision. Automatable: headscale-api-key mints \
                  these, and does so per-machine when mesh-url is configured",
        consumers: &[
            "app/yah/cli/src/cloud.rs (resolve_headscale_preauth_key)",
            "oss/yubaba/crates/cloud/src/lib.rs",
        ],
        provider: Provider::Headscale,
        domain: Domain::Infra,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: Some("Headscale preauth — yah-cloud"),
    },
    CredentialSpec {
        slot: "hetzner-api-token",
        env: Some("HETZNER_API_TOKEN"),
        purpose: "Hetzner Cloud API — server provision, status, destroy, attach",
        consumers: &[
            "oss/yubaba/crates/cloud/src/provider/hetzner.rs (from_default_sources)",
            "app/yah/desktop/src/hetzner.rs",
            "oss/yubaba/crates/cloud/src/envoy.rs (default_adapters)",
        ],
        provider: Provider::Hetzner,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_HETZNER,
        required: true,
        onepassword: Some("Hetzner Cloud API — yah-cloud"),
    },
    CredentialSpec {
        slot: "hetzner-s3-access-key",
        env: Some("HETZNER_S3_ACCESS_KEY"),
        purpose: "Hetzner Object Storage S3 access key — bucket create/exists/delete. Declared \
                  but not populated in this camp's vault as of 2026-09-03; kept because the \
                  call site is live",
        consumers: &["oss/yubaba/crates/cloud/src/provider/hetzner.rs:142"],
        provider: Provider::Hetzner,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_HETZNER,
        required: false,
        onepassword: Some("Hetzner Object Storage — yah-cloud"),
    },
    CredentialSpec {
        slot: "hetzner-s3-secret-key",
        env: Some("HETZNER_S3_SECRET_KEY"),
        purpose: "Hetzner Object Storage S3 secret key. Declared but not populated in this \
                  camp's vault as of 2026-09-03; kept because the call site is live",
        consumers: &["oss/yubaba/crates/cloud/src/provider/hetzner.rs:143"],
        provider: Provider::Hetzner,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MINT_HETZNER,
        required: false,
        onepassword: Some("Hetzner Object Storage — yah-cloud"),
    },
    CredentialSpec {
        slot: "kimi-platform-api-key",
        env: Some("MOONSHOT_API_KEY"),
        purpose: "Moonshot (Kimi) platform API key — Bearer auth on the Anthropic-wire endpoint",
        consumers: &["crates/yah/runner/src/resolver/mod.rs:1156 (KIMI_SLOT)"],
        provider: Provider::Moonshot,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "mailgun-api-key",
        env: None,
        purpose: "purpose not established: nothing in-tree reads this slot or any MAILGUN* env \
                  var (grepped 2026-09-03). Provider inferred from the slot name only",
        consumers: &[],
        provider: Provider::Mailgun,
        domain: Domain::Service,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "mesh-coordinator-machine",
        env: Some("YAH_MESH_COORDINATOR_MACHINE"),
        purpose: "not a credential: name of the machine hosting the headscale coordinator, \
                  resolved through .yah/infra/machines/<name>.toml",
        consumers: &[
            "crates/yah/hub/src/coordinator.rs",
            "app/yah/cli/src/cloud.rs:10173",
            "oss/yubaba/crates/cloud/src/lib.rs",
        ],
        provider: Provider::Yah,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "mesh-coordinator-type",
        env: Some("YAH_MESH_COORDINATOR_TYPE"),
        purpose: "not a credential: `camp` or `cluster` — which headscale the mesh commands \
                  should talk to",
        consumers: &[
            "app/yah/cli/src/mesh.rs:461",
            "oss/yubaba/crates/cloud/src/lib.rs",
        ],
        provider: Provider::Yah,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "mesh-url",
        env: Some("HEADSCALE_URL"),
        purpose: "not a credential: base URL of the headscale control server \
                  (https://cloud.mesh.yah.dev)",
        consumers: &[
            "oss/yubaba/crates/cloud/src/mesh.rs:82",
            "app/yah/cli/src/cloud.rs:10463",
            "crates/yah/hub/src/coordinator.rs",
        ],
        provider: Provider::Yah,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "noisetable-account-magic-link-key",
        env: None,
        purpose: "magic-link codec key for the noisetable-account appliance. Nothing in-tree \
                  reads this vault slot (grepped 2026-09-03); the appliance takes the value as \
                  MAGIC_LINK_KEY_HEX (oss/cheers/crates/cheers-test-identity/src/lib.rs:108)",
        consumers: &[],
        provider: Provider::Yah,
        domain: Domain::Service,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Workload("noisetable-account"),
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "noisetable-account-session-key",
        env: None,
        purpose: "session-signing key for the noisetable-account appliance. Nothing in-tree \
                  reads this vault slot (grepped 2026-09-03); role inferred from the slot name",
        consumers: &[],
        provider: Provider::Yah,
        domain: Domain::Service,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Workload("noisetable-account"),
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "noisetable-account-smtp-password",
        env: None,
        purpose: "SMTP password for the noisetable-account appliance's outbound mail. Nothing \
                  in-tree reads this vault slot (grepped 2026-09-03). Probing it from the \
                  operator's laptop would be misleading either way — outbound SMTP from cloud \
                  ranges is routinely blocked in ways that look exactly like a bad password \
                  (W337 §5)",
        consumers: &[],
        provider: Provider::Yah,
        domain: Domain::Service,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Workload("noisetable-account"),
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "npm-api-token",
        env: Some("NPM_TOKEN"),
        purpose: "npm registry publish token. Write-enabled granular access tokens default to \
                  7 days and are HARD-CAPPED at 90 (W337 §3, read from npm's changelog, not \
                  memory), and classic tokens were removed in Nov-Dec 2025 — so this \
                  credential does not rot unpredictably, it expires on a knowable date. \
                  `npm token list --json` READS that date directly (`expiry`, RFC 3339), so it \
                  is measured rather than computed from the cap — the plain table omits it, \
                  which is where the retracted \"npm exposes no expiry\" claim came from",
        consumers: &["scripts/npm-publish.sh:57", ".yah/qed/npm-publish.toml"],
        provider: Provider::Npm,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: Some(90),
        expiry_kind: ExpiryKind::Enforced,
        probe_from: ProbeFrom::AllowlistedNetwork,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "ollama",
        env: Some("OLLAMA_API_KEY"),
        purpose: "Ollama API key (ollama-cloud endpoints; the local endpoint needs none). Slot \
                  name is bare `ollama`, not `ollama-api-key`",
        consumers: &["crates/yah/runner/src/resolver/mod.rs:1139 (OLLAMA_SLOT)"],
        provider: Provider::Ollama,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "openai-api-key",
        env: Some("OPENAI_API_KEY"),
        purpose: "OpenAI completion API key",
        consumers: &["crates/yah/runner/src/resolver/mod.rs:1132 (OPENAI_SLOT)"],
        provider: Provider::OpenAi,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "openai-oauth",
        env: None,
        purpose: "Codex CLI OAuth bundle (access + refresh token JSON) backing the \
                  `openai-oauth` runner provider. Automatable: the refresh token mints the \
                  access token without a human",
        consumers: &[
            "app/yah/desktop/src/api_keys.rs:412",
            "crates/yah/runner/src/codex_oauth.rs:241",
        ],
        provider: Provider::OpenAi,
        domain: Domain::Model,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Enforced,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "openrouter-api-key",
        env: Some("OPENROUTER_API_KEY"),
        purpose: "OpenRouter API key; also backs the /credits usage read",
        consumers: &[
            "crates/yah/runner/src/resolver/mod.rs:1142 (OPENROUTER_SLOT)",
            "crates/yah/runner/src/resolver/openrouter.rs",
        ],
        provider: Provider::OpenRouter,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "release-cosign-key",
        env: None,
        purpose: "cosign private key that signs release artifacts; the public half is served at \
                  https://cdn.yah.dev/keys/yah-release.pub",
        consumers: &[
            "app/yah/cli/src/qed_publish.rs:113 (COSIGN_KEY_SLOT)",
            "scripts/publish-mesofact-release.sh",
            "scripts/publish-yubaba-release.sh",
        ],
        provider: Provider::Yah,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "release-cosign-key-pw",
        env: None,
        purpose: "password protecting release-cosign-key; rotate the pair together",
        consumers: &[
            "app/yah/cli/src/qed_publish.rs:118 (COSIGN_KEY_PW_SLOT)",
            "scripts/publish-mesofact-release.sh:172",
            "scripts/publish-yubaba-release.sh:163",
        ],
        provider: Provider::Yah,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "tauri-signing-key",
        env: Some("TAURI_SIGNING_PRIVATE_KEY"),
        purpose: "Tauri updater signing key. Note the desktop bundle step does NOT read this \
                  vault slot — app/yah/desktop/camp-env.sh sources \
                  TAURI_SIGNING_PRIVATE_KEY from the camp root .env, and \
                  app/yah/desktop/tauri-bundle.sh refuses to build without it",
        consumers: &[
            "app/yah/desktop/tauri-bundle.sh:58 (via env, not the vault)",
            "oss/qed/crates/qed-gha/src/image_builder.rs:53",
        ],
        provider: Provider::Yah,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "tauri-signing-key-pw",
        env: None,
        purpose: "password protecting tauri-signing-key; rotate the pair together",
        consumers: &["oss/qed/crates/qed-gha/src/image_builder.rs:53"],
        provider: Provider::Yah,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "yah-plugin-release-key",
        env: None,
        purpose: "signing key for yah plugin and recipe releases (`cargo xtask plugin-sign` / \
                  `recipe-sign`); verified at install time by crates/yah/plugin/src/source.rs",
        consumers: &[
            "xtask/src/plugin_sign.rs:57 (VAULT_SLOT)",
            "xtask/src/recipe_sign.rs",
            "crates/yah/plugin/src/source.rs",
        ],
        provider: Provider::Yah,
        domain: Domain::Publish,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        mint: MintHelp::NONE,
        required: false,
        onepassword: None,
    },
];

// ---------------------------------------------------------------------------
// Verdict sidecar — plain, unencrypted, next to credentials.enc
// ---------------------------------------------------------------------------

/// Concrete expiry with its provenance (W337 §7.1). Not `Option<DateTime>`:
/// `ReviewBy` means *re-mint*, not *dies*, and collapsing the two renders a
/// never-expiring credential as if it were about to fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "at", rename_all = "kebab-case")]
pub enum Expiry {
    Enforced(DateTime<Utc>),
    Declared(DateTime<Utc>),
    ReviewBy(DateTime<Utc>),
    /// No date recorded yet.
    Unknown,
}

impl Expiry {
    pub const fn kind(&self) -> ExpiryKind {
        match self {
            Expiry::Enforced(_) => ExpiryKind::Enforced,
            Expiry::Declared(_) => ExpiryKind::Declared,
            Expiry::ReviewBy(_) => ExpiryKind::ReviewBy,
            Expiry::Unknown => ExpiryKind::Unverified,
        }
    }

    pub const fn at(&self) -> Option<DateTime<Utc>> {
        match self {
            Expiry::Enforced(t) | Expiry::Declared(t) | Expiry::ReviewBy(t) => Some(*t),
            Expiry::Unknown => None,
        }
    }

    /// True when the provider stops honouring the credential on [`Self::at`].
    /// False for `ReviewBy`, whose date is organizational pressure only.
    pub const fn is_fatal(&self) -> bool {
        matches!(self, Expiry::Enforced(_) | Expiry::Declared(_))
    }

    /// One-line rendering that keeps `ReviewBy` distinguishable from a real
    /// expiry at a glance.
    pub fn render(&self) -> String {
        match self {
            Expiry::Enforced(t) => format!("expires {} (provider-enforced)", t.date_naive()),
            Expiry::Declared(t) => format!("expires {} (declared)", t.date_naive()),
            Expiry::ReviewBy(t) => format!("re-mint by {} (does not expire)", t.date_naive()),
            Expiry::Unknown => "no expiry recorded".to_string(),
        }
    }
}

/// Outcome of a probe (W337 §3). `Indeterminate` is load-bearing and must
/// never be conflated with `Revoked` — a check that fails the wave when the
/// operator's wifi drops gets disabled within a month.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum Verdict {
    Valid {
        /// Identity the provider says the credential belongs to, when the
        /// probe can read one. Never the credential itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        as_identity: Option<String>,
    },
    /// Authenticated and was told no.
    Revoked,
    Expired {
        at: DateTime<Utc>,
    },
    ScopeInsufficient {
        missing: Vec<String>,
    },
    /// Valid, unexpired, correctly scoped, still fails.
    QuotaExhausted,
    /// Offline, provider 5xx, rate-limited probe.
    Indeterminate {
        why: String,
    },
}

impl Verdict {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Verdict::Valid { .. } => "valid",
            Verdict::Revoked => "revoked",
            Verdict::Expired { .. } => "expired",
            Verdict::ScopeInsufficient { .. } => "scope-insufficient",
            Verdict::QuotaExhausted => "quota-exhausted",
            Verdict::Indeterminate { .. } => "indeterminate",
        }
    }
}

/// What the sidecar records for one slot. Contains no credential material —
/// that is the property that lets this file be 0644 and read without the
/// machine key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthRecord {
    pub slot: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probe_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Expiry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_error: Option<String>,
}

impl HealthRecord {
    pub fn new(slot: impl Into<String>) -> Self {
        Self {
            slot: slot.into(),
            ..Default::default()
        }
    }
}

/// The whole sidecar file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSidecar {
    #[serde(default = "sidecar_version")]
    pub version: u32,
    #[serde(default)]
    pub slots: BTreeMap<String, HealthRecord>,
}

const fn sidecar_version() -> u32 {
    1
}

impl Default for HealthSidecar {
    fn default() -> Self {
        Self {
            version: sidecar_version(),
            slots: BTreeMap::new(),
        }
    }
}

impl HealthSidecar {
    pub fn get(&self, slot: &str) -> Option<&HealthRecord> {
        self.slots.get(slot)
    }

    /// Insert or replace one slot's record, keyed by its own `slot` field.
    pub fn upsert(&mut self, record: HealthRecord) {
        self.slots.insert(record.slot.clone(), record);
    }
}

/// Parse sidecar bytes. A corrupt file is not an error — a broken sidecar must
/// never break `yah cloud secrets` or an agent's `creds_check`, because
/// nothing in it is load-bearing for resolving a credential.
pub fn parse_sidecar(bytes: &[u8]) -> HealthSidecar {
    serde_json::from_slice::<HealthSidecar>(bytes).unwrap_or_default()
}

/// Serialize the sidecar for writing.
pub fn render_sidecar(sidecar: &HealthSidecar) -> Result<Vec<u8>> {
    let mut out = serde_json::to_vec_pretty(sidecar).context("serialize credential sidecar")?;
    out.push(b'\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn slots_are_unique_and_sorted() {
        let mut prev = "";
        for spec in CREDENTIAL_SPECS {
            assert!(
                spec.slot > prev,
                "registry must be strictly sorted by slot: {prev:?} then {:?}",
                spec.slot
            );
            prev = spec.slot;
        }
    }

    #[test]
    fn dropped_iroh_node_secret_is_absent() {
        // R856-F1: declared in two inventories, consumed by nothing, and its
        // own comment conceded as much.
        assert!(spec("iroh-node-secret").is_none());
    }

    #[test]
    fn npm_is_the_live_provider_cap_conflict() {
        let npm = spec("npm-api-token").unwrap();
        assert_eq!(npm.band, Band::Manual);
        assert_eq!(npm.effective_ttl_days(), 90);
        assert!(
            npm.ttl_capped_below_band(),
            "W337 §7.3: a 90-day cap under a 1-year band must be flagged"
        );
        // Nothing else in the registry has a known cap yet, so nothing else
        // may claim the flag.
        let flagged: Vec<&str> = CREDENTIAL_SPECS
            .iter()
            .filter(|s| s.ttl_capped_below_band())
            .map(|s| s.slot)
            .collect();
        assert_eq!(flagged, vec!["npm-api-token"]);
    }

    #[test]
    fn manual_band_defaults_to_one_year() {
        let cosign = spec("release-cosign-key").unwrap();
        assert_eq!(cosign.effective_ttl_days(), 365);
        assert!(!cosign.ttl_capped_below_band());
    }

    #[test]
    fn review_by_is_not_an_expiry() {
        let t = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
        let review = Expiry::ReviewBy(t);
        let enforced = Expiry::Enforced(t);
        assert_eq!(review.at(), enforced.at());
        assert!(!review.is_fatal());
        assert!(enforced.is_fatal());
        assert_ne!(review.render(), enforced.render());
        assert!(review.render().contains("re-mint"));
        assert!(enforced.render().contains("provider-enforced"));
    }

    #[test]
    fn expiry_round_trips_through_the_sidecar_without_collapsing() {
        let t = Utc.with_ymd_and_hms(2026, 11, 11, 0, 0, 0).unwrap();
        let mut sidecar = HealthSidecar::default();
        sidecar.upsert(HealthRecord {
            slot: "release-cosign-key".into(),
            expires_at: Some(Expiry::ReviewBy(t)),
            verdict: Some(Verdict::Valid { as_identity: None }),
            ..HealthRecord::new("release-cosign-key")
        });
        sidecar.upsert(HealthRecord {
            expires_at: Some(Expiry::Enforced(t)),
            ..HealthRecord::new("npm-api-token")
        });

        let bytes = render_sidecar(&sidecar).unwrap();
        let back = parse_sidecar(&bytes);
        assert_eq!(back, sidecar);
        assert_eq!(
            back.get("release-cosign-key").unwrap().expires_at,
            Some(Expiry::ReviewBy(t))
        );
        assert_eq!(
            back.get("npm-api-token").unwrap().expires_at,
            Some(Expiry::Enforced(t))
        );
        assert_ne!(
            back.get("release-cosign-key").unwrap().expires_at,
            back.get("npm-api-token").unwrap().expires_at
        );
    }

    #[test]
    fn corrupt_sidecar_reads_empty_rather_than_failing() {
        assert_eq!(parse_sidecar(b"not json at all"), HealthSidecar::default());
        assert_eq!(parse_sidecar(b""), HealthSidecar::default());
    }

    #[test]
    fn indeterminate_is_distinct_from_revoked() {
        let a = Verdict::Indeterminate {
            why: "offline".into(),
        };
        assert_ne!(a.as_str(), Verdict::Revoked.as_str());
        let json = serde_json::to_string(&a).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn mint_help_is_populated_only_where_grounded() {
        for spec in CREDENTIAL_SPECS {
            if spec.mint.is_populated() {
                assert!(
                    !spec.mint.scopes.is_empty(),
                    "{}: a dashboard URL without scopes is half an answer",
                    spec.slot
                );
            }
        }
        assert!(spec("hetzner-api-token").unwrap().mint.is_populated());
        // Nothing grounded these; an invented mint URL is worse than none.
        assert!(!spec("npm-api-token").unwrap().mint.is_populated());
        assert!(!spec("crates-io-token").unwrap().mint.is_populated());
    }

    #[test]
    fn infra_domain_covers_the_absorbed_inventories() {
        let infra: Vec<&str> = specs_in_domain(Domain::Infra).map(|s| s.slot).collect();
        // Everything CLOUD_SECRETS carried, minus the dropped phantom.
        for slot in [
            "hetzner-api-token",
            "hetzner-s3-access-key",
            "hetzner-s3-secret-key",
            "headscale-preauth-key",
            "headscale-api-key",
            "cloudflare-tunnel-token",
        ] {
            assert!(infra.contains(&slot), "{slot} missing from Infra");
        }
        // Everything CRED_SLOTS added.
        for slot in [
            "digitalocean-api-token",
            "cloudflare-api-token",
            "cloudflare-zone-id",
        ] {
            assert!(infra.contains(&slot), "{slot} missing from Infra");
        }
        // Model keys must NOT leak into the cloud-facing surfaces.
        assert!(!infra.contains(&"openai-api-key"));
    }

    #[test]
    fn every_spec_names_a_purpose() {
        for spec in CREDENTIAL_SPECS {
            assert!(!spec.purpose.is_empty(), "{}: empty purpose", spec.slot);
        }
    }
}
