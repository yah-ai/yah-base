//! @arch:layer(core)
//! @arch:role(secrets)
//!
//! Credential vault — AES-256-GCM at-rest encryption keyed by a per-host
//! random `machine.key`, both files living under `ProjectDirs::data_dir()`.
//!
//! Shared by:
//! - **`yah keys ...`** CLI subcommand (the user-facing affordance)
//! - **`yah-agentd`** when it needs an OpenAI / Anthropic token
//! - **`cloud` crate's `HetznerDriver::from_default_sources`** for
//!   `hetzner-api-token` / `hetzner-s3-access-key` / `hetzner-s3-secret-key`
//!
//! Threat model: defends against dragnet disk-image scanners and generic
//! `git grep -i api[_-]key`-style exfil. Does **not** defend against a
//! process running as the same user with FS access — that process can
//! read both the keyfile and the ciphertext blob and decrypt at will.
//! Acceptable on cloud VMs the operator already pays for and trusts;
//! the laptop side currently also uses the OS keychain via the desktop's
//! `api_keys` module (separate vault, different threat posture). Unifying
//! those two vaults is scoped as R043 (anchored on this file) — make this
//! crate the canonical store, drop the keyring backend once soaked.
//!
//! Layout:
//! - `machine.key`     — 32 raw bytes, mode 0600
//! - `credentials.enc` — `[12-byte nonce | ciphertext_with_tag]`,
//!                        plaintext is `serde_json::Value` map (provider → token)
//!
//! @yah:relay(R043, "Unify credential storage: desktop api_keys → keys vault (Keychain → AES file)")
//! @yah:status(handoff)
//! @yah:assignee(agent:claude)
//! @yah:handoff("Today the workspace has two parallel secret stores: the CLI/cloud uses crates/yah/keys (AES-256-GCM file at ProjectDirs::data_dir(), works headless/over-SSH/on-Linux-yubaba) while the desktop uses app/yah/desktop/src/api_keys.rs (macOS Keychain via the keyring crate). Same machine, two vaults, inconsistent slot naming (CLI 'hetzner-api-token' vs desktop 'hetzner'). User asked to bridge them with the encrypted-file backend as the canonical store so dev-machine UX (desktop) and headless infra (yubaba, agentd, ssh'd camps) share one source of truth. F9 already lifted KeysStore into a shared crate and explicitly named this as its R040-Tx follow-up.")
//! @yah:next("Three phases below — F1 lands the bridge, F2 normalizes slot names, F3 drops the keyring dep once soaked.")
//! @arch:see(crates/yah/keys/src/lib.rs)
//! @arch:see(app/yah/desktop/src/api_keys.rs)
//!
//! @yah:relay(R044, "DRY credential resolution: KeysStore::get_or_env (vault → env fallback) for CLI + headless")
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:verify("cargo test -p keys -p cloud -p desktop -p yah")
//! @arch:see(crates/yah/keys/src/lib.rs)
//! @arch:see(crates/yah/cloud/src/provider/hetzner.rs)
//! @yah:handoff("DRY landed. New keys::KeysStore::get_or_env(slot, env_var) instance method + free function keys::get_or_env(slot, env_var). The instance method propagates vault errors (corrupt machine.key, decrypt failure — real signals); the free function additionally swallows vault-OPEN errors so a machine with no vault still resolves env-supplied creds. Refactored HetznerDriver::from_default_sources from ~30 lines of hand-rolled lookup to 3 one-liners. Wired all desktop sibling modules (hetzner.rs, identities.rs, agent.rs — ~7 call sites total) to use keys::get_or_env directly with paired (slot, env) constants per credential, bypassing the api_keys layer (api_keys keeps its Tauri-validation contract for command-surface writes). Same treatment in CLI (yah agent, yah-agentd) — also caught and fixed an F2 gap there: agentd/agent had been reading bare 'openai' while desktop wrote canonical 'openai-api-key', so a token set from the desktop UI wasn't visible to yah-agentd. Now both use canonical 'openai-api-key' with OPENAI_API_KEY env fallback. handle_provision's resolve_headscale_preauth_key collapsed to a one-liner using the helper too. main.rs (yah keys CRUD) intentionally left vault-only — that's the user-facing storage surface, env fallback there would be confusing. Tests: 4 new in keys (vault-wins, env-fallback, both-miss, decrypt-error-propagates), all 10 keys + 30 cloud + 17 yah cloud:: + 81 desktop pass. Frontend typecheck + build green. Stale 'keychain read failed' / 'no token in keychain' error messages updated to mention the env var path so users see both options.")
//! @yah:next("Cleanup chance for whoever picks the bridge work back up: api_keys.rs's HetznerError::Vault(String) and GithubProbeError::Vault(String) variants (now used by hetzner.rs / identities.rs) currently take an opaque string. If keys::Result errors get richer typing later, these could carry the structured error instead.")
//! @yah:next("If a future ticket adds aws-s3-access-key / digitalocean-api-token / cloudflare-api-token slots in real consumers (today they only exist in CLOUD_SECRETS metadata), apply the same get_or_env discipline at those call sites.")
//! @yah:handoff("Credential DRY work is correct and clean. Review found two pre-existing test failures unrelated to R044 that block the verify command:\n\n1. FIXED: app/yah/desktop/tests/agent_writers_e2e.rs — two write_arch_doc calls used rel_path pointing into authored/ but omitted folder:\"authored\", causing sandbox check to fail (defaults to working). Added \"folder\":\"authored\" to both json! invocations. This fix is already in the branch.\n\n2. NEEDS FIX: app/yah/cli/tests/arch_dogfood.rs — 8 tests fail because: (a) workspace_root() goes only one level up from CARGO_MANIFEST_DIR (app/yah/cli -> app/yah) instead of two, and (b) assertions reference rs-hack era files (editor.rs, surgical.rs) and roles (emit, diff, traverse) that no longer exist in the yah workspace. Tests need to be rewritten for the current yah architecture OR workspace_root() corrected to the repo root and assertions updated to match current @arch:layer/@arch:role annotations. Once arch_dogfood is fixed, re-run cargo test -p keys -p cloud -p desktop -p yah — everything else is green.")
//!
//! @yah:ticket(R043-F4, "yah keys export/import: portable vault transfer for camp bootstrap")
//! @yah:at(2026-05-04T21:17:55Z)
//! @yah:assignee(agent:claude)
//! @yah:status(review)
//! @yah:phase(P4)
//! @yah:parent(R043)
//! @yah:next("Lands after R043-F1/F2/F3 stabilize the unified vault. Use case: operator has creds on desktop, needs them on a remote yah-camp (Path 2 SSH or Path 3 yubaba) without re-entering everything.")
//! @yah:next("Two operations: yah keys export [--plain | --password] [--slots <names>] [--out <path>] and yah keys import [--strategy {merge,replace,skip}] <file>. Symmetric — import auto-detects format, prompts for passphrase if encrypted.")
//! @yah:next("Password-protected format: Argon2id KEK derivation (sane defaults — m=64MiB, t=3, p=1) + AES-256-GCM payload. File extension .yahkeys with magic bytes + version header so future format bumps are safe.")
//! @yah:next("Selective slots from day 1: --slots anthropic,openai sends only those. Least-privilege matters — Hetzner cloud token belongs on the operator desktop, not on a Hetzner VM that already has scoped IAM.")
//! @yah:next("Plain export prints a yelling warning + refuses without --yes-really-export-plain. Pipe-friendly default (yah keys export --password | ssh box yah keys import) means stdout/stdin handling needs to coexist with TTY passphrase prompting (read passphrase from /dev/tty when stdout is a pipe).")
//! @yah:next("Bootstrap flow this unblocks: yah keys export --password --slots anthropic | ssh <box> yah keys import — passphrase in operator's head, ciphertext over SSH, no long-lived plaintext on disk anywhere.")
//! @yah:next("Yubaba integration is a follow-up: yubaba as credential broker (either operator-driven 'yah cloud machine attach' triggers vault transfer, or yubaba pulls from cluster-shared encrypted store). Punt until R040-F20 (yubaba openraft) lands; export/import is the building block.")
//! @yah:verify("yah keys export --password --out /tmp/v.yahkeys; yah keys import /tmp/v.yahkeys on a fresh ~/.config/yah — slots restored byte-identical after passphrase entry")
//! @yah:verify("yah keys export --slots anthropic --plain | yah keys import --strategy replace round-trips a single slot")
//! @yah:verify("Wrong passphrase on import returns a clean error, no partial state in the target vault")
//! @arch:see(.yah/docs/architecture/A043-yah-on-machine-daemons.md)
//!
//! @yah:relay(R219, "Agent vault-lease: time-boxed credential injection via MCP + CLI")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-18T00:10:58Z)
//! @yah:status(review)
//! @yah:parent(Q217)
//! @yah:next("Goal: an agent that needs a vault credential (e.g. mesofact-publish needs CLOUDFLARE_API_TOKEN) can request a time-boxed lease that the user approves through the existing AnswerModal, then the secret flows Rust→subprocess env without ever touching the renderer or the conversation transcript. Preserves the api_keys.rs threat-model invariant. Composes with R198 Scope::Job so default scopes can be per-job (yubaba permissive, gnome strict).")
//! @arch:see(crates/yah/agent-tools/src/approval.rs)
//! @arch:see(crates/yah/keys/src/lib.rs)
//! @arch:see(app/yah/desktop/src/api_keys.rs)
//! @yah:depends_on(R198)
//! @yah:handoff("Shipped. vault.lease tool added to agent-tools crate. Flow: agent calls vault.lease({slot, env_var, ttl_secs}) → standard approval gate (NeedsPrompt by default, user approves via AnswerModal) → VaultLeaseTool::execute reads slot from AES-256-GCM vault (keys::KeysStore), mints VaultLeaseEntry in per-session VaultLeaseTable (Arc<TokioRwLock<Vec<...>>>). Bash::execute reads active leases from ctx.vault_leases and injects them as [key,value] pairs into TaskRunParams::env for every subprocess. Credential value never appears in tool results, logs, or conversation transcript — only slot name + env_var + TTL travel through the approval gate. Key invariants: env_var validates to ASCII uppercase/digits/underscore; slot validates to alphanumeric/-/_; TTL clamped to 1..3600; expired leases pruned on each vault.lease call. wired into writer-enabled sessions in agent.rs (3 sites) and mcp/src/main.rs via .with_vault() chain. vault_leases: None added to all 17 ToolContext construction sites.")
//! @yah:verify("vault.lease tool appears in the agent tool list when writers=true: open a write-enabled session, confirm vault.lease in the schemas list")
//! @yah:verify("call vault.lease with a slot that has no credential → ToolError::Operation with 'no credential stored' message")
//! @yah:verify("set a key via `yah keys set test-slot myvalue`, spawn a write-enabled session, call vault.lease({slot:'test-slot', env_var:'TEST_TOKEN', ttl_secs:60}) → approve in AnswerModal → {lease_id, env_var, expires_in_secs:60}")
//! @yah:verify("after the lease: bash({command:'echo $TEST_TOKEN'}) → output contains 'myvalue' without the secret appearing in any tool result JSON")
//! @yah:verify("cargo test -p agent-tools --lib vault (3/3 pass)")
//! @yah:verify("cargo check --workspace clean")
//!
//!
//! @yah:ticket(R856-F1, "CredentialSpec registry + verdict sidecar covering all 42 live slots")
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-09-03T22:18:26Z)
//! @yah:phase(P1)
//! @yah:parent(R856)
//! @yah:next("W337 §3 and §10.1. This is the highest-value item in the doc and the only phase with zero provider-integration risk — every later ticket reads from it.")
//! @yah:next("Shape: CredentialSpec { slot, env, purpose, consumers, provider, mint } + Expiry::{Enforced(date), Declared(date), ReviewBy(date)} + the manual/automatable band (W337 §7). ReviewBy is the one a naive Option<expires_at> silently drops — a never-expiring token still gets a 1-year date meaning re-mint, not dies.")
//! @yah:next("Verdict sidecar is a PLAIN file next to credentials.enc, never inside it: { slot, last_probe_at, verdict, expires_at, scopes, probe_error }. Verdicts are not secret and the desktop must render health without decrypting anything.")
//! @yah:next("ABSORB THE OTHER TWO INVENTORIES IN THIS SAME CHANGE, or a fourth gets born: CLOUD_SECRETS (app/yah/cli/src/cloud.rs:9901, 7 slots) and cloud.creds_check (crates/yah/agent-tools/src/cloud_tools.rs:1571). creds_check is the AGENT-facing one — leaving it on its own list is how an agent tells the operator a revoked credential is fine.")
//! @yah:next("Populating 42 slots is a day of dashboard archaeology. That is the work, not a preamble to it.")
//! @yah:verify("The registry enumerates exactly the slots `yah keys list` returns (42 as of 2026-09-03), with no phantom entries and no unlisted ones")
//! @yah:verify("cloud.creds_check and the `yah cloud secrets` table both read the registry — grep shows no second hardcoded slot list left in cloud.rs or cloud_tools.rs")
//! @yah:verify("A ReviewBy(date) spec round-trips through the sidecar and renders distinctly from Enforced(date) — not collapsed into one Option<DateTime>")
//! @yah:gotcha("CLOUD_SECRETS is already stale in BOTH directions — 3 of its 7 declared slots (hetzner-s3-access-key, hetzner-s3-secret-key, iroh-node-secret) do not exist in the vault at all, and iroh-node-secret concedes in its own comment that it is not yet consumed. Do not port the list verbatim; reconcile it against `yah keys list` first.")
//! @yah:gotcha("There is no `anthropic` vault slot despite what several docs imply. The LLM slots are openai-api-key, openai-oauth, deepseek-api-key, groq-api-key, kimi-platform-api-key, openrouter-api-key, ollama.")
//! @arch:see(.yah/docs/working/W337-credential-health-and-rotation.md)
//! @yah:tier(Wizard)
//! @yah:handoff("LANDED. New module oss/yah-base/crates/keys/src/spec.rs (~1100 lines) re-exported from fob's lib.rs: CredentialSpec { slot, env, purpose, consumers, provider, domain, band, provider_cap_days, expiry_kind, probe_from, mint, required, onepassword } + Provider/Domain/Band/ExpiryKind/ProbeFrom/MintHelp + the sidecar types Expiry/Verdict/HealthRecord/HealthSidecar. fob's Cargo.toml gained chrono 0.4 (serde) and serde 1 (derive), spelled out because oss/yah-base is an independent workspace.")
//! @yah:handoff("REGISTRY = 45 specs, verified by diffing extracted slot literals against `yah keys list` under LC_ALL=C: all 42 live slots present, zero unlisted. The 3 extras are declared-but-unpopulated slots kept because each has a live fob::get_or_env call site — digitalocean-api-token (oss/yubaba/crates/cloud/src/envoy.rs:331), hetzner-s3-access-key and hetzner-s3-secret-key (oss/yubaba/crates/cloud/src/provider/hetzner.rs:142-143). DROPPED iroh-node-secret: grepped the slot name and IROH_NODE_SECRET across the whole tree and the only hits were the two inventories themselves plus its own comment conceding it is unconsumed. Test spec::tests::dropped_iroh_node_secret_is_absent pins that.")
//! @yah:handoff("SIDECAR is a separate plain file credential-health.json in KeysStore::dir(), mode 0644, written by a new write_plain() (tmp+rename, NOT write_secure's 0600 — 0600 would block the desktop reader the sidecar exists for). read_health() is infallible: missing or corrupt yields an empty sidecar, so a damaged health file can never break `yah cloud secrets` or creds_check. Reading it decrypts nothing — proven by keys::tests::sidecar_is_readable_without_the_machine_key, which reads verdicts back from a store that has no machine.key and no credentials.enc. New testability seam KeysStore::at(dir) (open() unchanged) is what makes that test possible without writing to the developer's real vault (the trap app/yah/cli/src/camp.rs:708 documents).")
//! @yah:handoff("EXPIRY IS THREE-VALUED, not Option<DateTime>. Expiry::{Enforced,Declared,ReviewBy,Unknown} with is_fatal() false for ReviewBy and render() emitting 're-mint by <date> (does not expire)' vs 'expires <date> (provider-enforced)'. Two tests cover the verify criterion: spec::tests::review_by_is_not_an_expiry and expiry_round_trips_through_the_sidecar_without_collapsing, plus a real-file round-trip through KeysStore in keys::tests::sidecar_round_trips_and_preserves_review_by.")
//! @yah:handoff("TTL BANDS per W337 §7: Band::{Manual=365d, Automatable=90d}, effective_ttl_days() = min(band, provider_cap), ttl_capped_below_band() flags §7.3. npm-api-token is the sole flagged instance (Manual band, provider_cap_days=Some(90), grounded in the doc's npm-changelog reading), and a test asserts it is the ONLY flagged slot so a later careless cap cannot slip in unnoticed. `yah cloud secrets` renders the flag inline. Automatable band assigned to exactly 4 slots, each grounded: cloudflare-mesofact-static and cloudflare-r2-fleet-read-* (W295 line 546 — rotation automatable from the camp via cloudflare-legacy-yah), headscale-preauth-key (headscale-api-key mints per-machine keys), openai-oauth (refresh token).")
//! @yah:handoff("BOTH CONSUMERS REPOINTED. app/yah/cli/src/cloud.rs: struct Secret + CLOUD_SECRETS deleted, handle_secrets now iterates fob::specs_in_domain(Domain::Infra) (22 slots vs the old stale 7) and gained rotation-band, health and mint lines; resolve_headscale_preauth_key now reads its slot/env pair off the registry instead of hardcoding it. The dead keys_supported field went with it — it was true for all seven despite its own doc comment, so the `[env-only]` tag it drove was unreachable. crates/yah/agent-tools/src/cloud_tools.rs: struct CredSlot + CRED_SLOTS deleted, creds_check reads the same registry filter plus the sidecar. Verified by grep: no second hardcoded slot list remains in either file (the surviving literals are single get_or_env call sites and clap default_values, not inventories).")
//! @yah:handoff("The doc comment at cloud_tools.rs:1502 that justified the duplication ('so agent-tools doesn't gain a cloud crate dependency just for a name list') was rewritten rather than left asserting something false — the registry lives in fob, which agent-tools already depended on, so there was never a new edge to avoid.")
//! @yah:handoff("MINT HELP populated for exactly 3 providers — Cloudflare, Hetzner, GitHub — ported verbatim from packages/yah/ui/src/components/shell/AgentsSection.tsx:57-105. Everything else is MintHelp::NONE. A test asserts npm-api-token and crates-io-token are NOT populated, so a future agent cannot quietly invent a mint URL. Full port is R856-F5.")
//! @yah:handoff("PROBE_FROM carried as ProbeFrom::{Local, Workload(&'static str)} — &'static str rather than W337's String because the registry is a const; same information. Four slots are Workload: cloudflare-r2-fleet-read-* and cheers-cloud-admin-verify-key (yah-cloud-admin, per the W294 secret declarations) and noisetable-account-smtp-password (the exact §5 case — cloud-range SMTP blocks look like a bad password). Nothing consumes the field yet; F8 does.")
//! @yah:handoff("PURPOSE + CONSUMERS populated per slot from grep, with file:line where a named const exists. Where nothing could be grounded the spec SAYS SO instead of guessing: exe-dev-api-token, mailgun-api-key, cloudflare-static-yah-dev, cloudflare-tunnel-token-mesh and the three noisetable-account-* slots each carry an explicit 'nothing in-tree reads this slot (grepped 2026-09-03)' with what was grepped. exe-dev-api-token is also marked Provider::Unknown with a warning not to assume exe.dev — W214's 'exe-dev' names a ticket tier, not a service.")
//! @yah:handoff("Tree anchor at handoff: dbe6954b48a66734f6664f9474dc2dedb89bfa8d — the shared tree as I left it. Diff against it (`git diff dbe6954b48a66734f6664f9474dc2dedb89bfa8d..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("cargo test --manifest-path oss/yah-base/crates/keys/Cargo.toml -> 36 passed, 0 failed (baseline before this change: 20 passed, 0 failed)")
//! @yah:verify("cargo test -p yah-agent-tools -> 1221 passed, 0 failed, 1 ignored — identical to the baseline recorded before any edit")
//! @yah:verify("cargo test -p yah --lib -> 1338 passed, 0 failed, 1 ignored; cargo build -p yah clean (warnings only, all pre-existing)")
//! @yah:verify("Registry completeness re-checkable with: rg -o '^        slot: \"[a-z0-9-]+\"' oss/yah-base/crates/keys/src/spec.rs | sed 's/.*slot: \"//;s/\"//' | LC_ALL=C sort, then comm against `yah keys list`. Expect empty on the vault-not-in-registry side and exactly digitalocean-api-token / hetzner-s3-access-key / hetzner-s3-secret-key on the other.")
//! @yah:verify("./target/debug/yah cloud secrets --quiet renders 22 infra slots with rotation/health/mint lines and reports '19 of 22 configured, 0 required missing'")
//! @yah:gotcha("ExpiryKind::Unverified is the DEFAULT in the registry, deliberately, and it is not a synonym for ReviewBy. ReviewBy is a positive claim ('this credential does not expire at all'), so asserting it about a provider whose expiry policy nobody actually read would be wrong in the same direction as a green light on a dead key. Only npm-api-token and openai-oauth carry Enforced; the self-minted key material and the not-really-credential config slots (mesh-*, cloudflare-zone-id) carry ReviewBy. R856-F2/F6 should convert Unverified -> Enforced/Declared as each provider's docs get read, not before.")
//! @yah:gotcha("DISCOVERED, NOT FIXED, out of this ticket's reconciliation mandate: crates/yah/runner/src/resolver/mod.rs:1136-1137 declares OPENAI_ADMIN_SLOT = 'openai-admin-key' / OPENAI_ADMIN_ENV, and line 1130 declares ANTHROPIC_ADMIN_ENV = 'ANTHROPIC_ADMIN_KEY'. Neither slot is in `yah keys list` nor in either absorbed inventory, so neither is in the registry. If they are real credential slots they need specs; if they are dead they should be deleted. Worth one grep by whoever takes F2.")
//! @yah:gotcha("`yah cloud secrets` now lists 22 slots where it listed 7. That is the point (the old list was stale in both directions), but it is a visible output change for anyone with the old table memorised.")
//! @yah:gotcha("`yah keys list` sorts with Rust byte ordering; plain `sort` under a non-C locale orders release-cosign-key / release-cosign-key-pw differently and makes `comm` report a phantom difference. Use LC_ALL=C when diffing the registry against the vault.")
//! @yah:gotcha("CROSS-WORKSPACE: fob gained chrono+serde, and all four workspaces that consume it are consistent — oss/yah-base (--all-targets), oss/qed (-p yah-qed --locked) and oss/yubaba (-p fob --locked) all pass, and the yubaba/qed lockfiles already carried both deps so no lockfile edit was needed. NOTE the package id is `yah-qed`, not `qed` — `cargo check -p qed` fails with 'did not match any packages' and is NOT a real failure. `cargo check --manifest-path oss/yubaba/Cargo.toml -p yah-cloud` DOES fail, independently of fob: a live peer's uncommitted rewrite of oss/kamaji/crates/kamaji/src/ports.rs (+677/-171) renamed PortAllocator::resolve to resolve_one/resolve_set and the call site at oss/yubaba/crates/cloud/src/reconciler/mesofact_static.rs:634 still calls .resolve(). Left untouched — it belongs to that peer.")
//! @yah:verify("INDEPENDENTLY VERIFIED 2026-09-03 (Glimmerstone, session:00f48ab8, anchor dbe6954b): all six claimed criteria hold. Counts reproduced exactly — fob 36/0, yah --lib 1338/0/1, yah-agent-tools 1221/0/1 (on re-run; see the flake gotcha), `./target/debug/yah cloud secrets --quiet` renders 22 infra slots and prints '19 of 22 configured, 0 required missing' verbatim from a freshly-rebuilt binary. Registry/vault comm diff under LC_ALL=C is empty on the vault-not-in-registry side and exactly digitalocean-api-token / hetzner-s3-access-key / hetzner-s3-secret-key on the other. No second inventory array survives in cloud.rs or cloud_tools.rs (remaining literals are clap default_values and one get_or_env). Expiry distribution is 27 Unverified / 16 ReviewBy / 2 Enforced / 0 Declared, and the registry contains NO date literals at all — dates exist only in the sidecar, so a fabricated expiry is structurally impossible. Expiry is adjacently-tagged serde (tag=kind, content=at), so ReviewBy cannot collapse into Enforced; both round-trip tests assert the distinction rather than passing vacuously. sidecar_is_readable_without_the_machine_key genuinely asserts !machine_key_path().exists() && !credentials_path().exists(). A 0644 test already existed (keys::tests::sidecar_is_0644_not_0600, lib.rs:1034) — it asserts 0644 on the sidecar AND 0600 on credentials.enc, so nothing needed adding. MintHelp is populated for exactly Cloudflare/Hetzner/GitHub; every other slot is the MintHelp::NONE const, which has no URL field set, so an invented dashboard URL is impossible by construction. One cosmetic deviation from 'verbatim': the ported Cloudflare nav_hint drops the TS source's trailing '— otherwise point a CNAME at the *.cfargotunnel.com hostname from your registrar' clause and renders arrows as -> instead of →. Both are removals/transliterations, not inventions. Nothing was fixed because nothing was broken.")
//! @yah:gotcha("FLAKY TEST, not a regression: camp_tools::tests::camp_character_update_allows_class_subclass_mismatch failed once on a full `cargo test -p yah-agent-tools` (1220 passed / 1 failed) with 'subclass \"smoke-wizard\" not found — call camp.subclasses_list to discover valid ids' at camp_tools.rs:3347. It passes in isolation and the very next full-suite run was 1221/0/1. camp_tools.rs and every subclass/character/preroll source are unmodified in the tree, so this is order/parallelism-dependent shared state in the camp subclass registry, entirely unrelated to fob or credentials. If it bites someone again, that is the cause — do not chase it into R856.")
//! @yah:handoff("INDEPENDENTLY VERIFIED by a second courier (not the implementer), 2026-09-03, at relay-leader request. All three ticket verify criteria hold. Counts reproduced in the foreground on a contended shared target dir: fob 36 passed/0 failed (baseline 20/0), yah --lib 1338/0/1 ignored, yah-agent-tools 1221/0/1 ignored, cargo build -p yah clean. A freshly rebuilt ./target/debug/yah cloud secrets --quiet renders 22 infra slots and prints '19 of 22 configured, 0 required missing' verbatim. The registry-vs-vault comm diff under LC_ALL=C came back exactly as predicted: nothing on the vault-not-in-registry side, exactly digitalocean-api-token / hetzner-s3-access-key / hetzner-s3-secret-key on the other. No surviving inventory array in either repointed file. The two expiry tests and the sidecar test were opened and confirmed substantive rather than vacuous, and Expiry serializes adjacently-tagged (tag=kind, content=at) so Enforced and ReviewBy cannot collapse. No fabricated dates: 27 Unverified / 16 ReviewBy / 2 Enforced / 0 Declared, and zero date literals in registry data. MintHelp is one of exactly four values by construction, so a NONE slot cannot carry an invented URL.")
//! @yah:handoff("Tree anchor at handoff: dbe6954b48a66734f6664f9474dc2dedb89bfa8d — the shared tree as I left it. Diff against it (`git diff dbe6954b48a66734f6664f9474dc2dedb89bfa8d..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("R856-F2 is now unblocked and is the next dependency-wave ticket (T3 and F8 also key off F1). F2 should convert ExpiryKind::Unverified to Enforced/Declared per slot AS EACH PROVIDER'S LIVE DOCS ARE READ, never before — Unverified is the deliberate default and is not a synonym for ReviewBy. F2 should also resolve the discovered orphan pair recorded in this ticket's gotchas: crates/yah/runner/src/resolver/mod.rs:1130-1137 declares OPENAI_ADMIN_SLOT / OPENAI_ADMIN_ENV / ANTHROPIC_ADMIN_ENV for slots that exist in neither the vault nor the registry — spec them or delete them.")
//! @yah:verify("CROSS-WORKSPACE RISK CHECKED AND CLEAR (the implementer had only built the root workspace). fob is consumed by nine dependents across four workspaces, and adding chrono+serde to it touches every lockfile. All four are consistent — `cargo check --locked` succeeded for oss/yah-base (--all-targets), oss/qed (-p yah-qed; note the package is yah-qed, not qed), and fob itself inside oss/yubaba. No lockfile needed updating.")
//! @yah:gotcha("PRE-EXISTING, NOT FROM THIS TICKET, and it blocks `cargo check --manifest-path oss/yubaba/Cargo.toml -p yah-cloud` camp-wide: a live peer holds an uncommitted rewrite of oss/kamaji/crates/kamaji/src/ports.rs (+677/-171) renaming PortAllocator::resolve to resolve_one/resolve_set, and the call site at oss/yubaba/crates/cloud/src/reconciler/mesofact_static.rs:634 still uses the old name. Reproduced under --locked, and fob compiles fine in that same workspace, so it is independent of R856-F1. oss/yubaba/crates/cloud/src/reconciler/ingress.rs also changed mid-verification — someone is live in that crate. Left untouched per shared-tree doctrine.")
//!
//! @yah:ticket(R856-F7, "Tier-2 probed expiry where the provider exposes it, and tier-3 scope drift")
//! @yah:at(2026-09-03T21:09:27Z)
//! @yah:status(open)
//! @yah:phase(P3)
//! @yah:parent(R856)
//! @yah:next("W337 §3 tiers 2-3 and §10.6. Tier 3 (scope drift) is the least available signal and the most valuable when present, because it is the ONLY tier that catches a break before the failing call.")
//! @yah:next("Tier 2 upgrades Declared(date) to Enforced(date) where a provider introspection endpoint exposes it. Declared stays the floor everywhere else — this ticket narrows the unknown, it does not replace the registry answer.")
//! @yah:next("Same rule as R856-F2: every endpoint and every scope-carrying header must be read from the provider live docs. A wrong endpoint here produces a confident green on a dead key.")
//! @yah:verify("At least one provider reports Enforced(date) read from the provider itself, and the sidecar shows it superseding a prior Declared(date)")
//! @yah:verify("A deliberately narrowed token reports ScopeInsufficient { missing } naming the actual missing scope, not a generic failure")
//! @yah:gotcha("npm is the known-hard case and is already handled without this ticket: `npm token list` returns id, token prefix, created date and CIDR whitelist with NO expiry field — confirmed both by running it and against npm documented field list. Reading npm expiry needs the registry HTTP API and whether the granular-token endpoint exposes it is UNVERIFIED. Do not block this ticket on npm; declared-at-rotation already covers it.")
//! @arch:see(.yah/docs/working/W337-credential-health-and-rotation.md)
//! @yah:depends_on(R856-F2)
//! @yah:tier(Wizard)
//! @yah:next("SCOPE NARROWED 2026-09-03 by R856-T4: npm's probed expiry is NOT yours — it moved to R856-F2. Measured: `npm token list --json` returns `expiry` (RFC 3339) alongside `permissions`, `scopes`, `cidr`, `bypass_2fa`, `revoked`, so npm's tier-2 answer is one field on the same call F2's tier-1 auth probe already makes; parsing it here would mean parsing the same response twice, one phase apart. F7 keeps tier-2 probed expiry for the OTHER providers, plus tier-3 scope drift everywhere including npm. W337 §10 step 6 and §3.2 are both reworded to match — read §3.2's \"Ownership\" paragraph before starting. Trap recorded there: `--json` carries NO `id` field (`key` is `***`, `token` is the masked npm_XXXX...YYYY form), so a record cannot be joined to a vault slot by id — match on the masked token prefix.")
//!
//! @yah:ticket(R856-F9, "Overlap slots: slot / slot.next, so rotation is never atomic")
//! @yah:at(2026-09-03T21:09:41Z)
//! @yah:status(open)
//! @yah:phase(P4)
//! @yah:parent(R856)
//! @yah:next("W337 §6 and §10.8. The strongest defence against rot is not detection, it is making rotation non-atomic. Consumers try current-then-next; rotation becomes mint -> write .next -> probe -> promote -> revoke old, with no window where the only live credential is unverified.")
//! @yah:next("Where a provider permits two live keys this removes the outage shape from rotation entirely. Not every provider does — the CredentialSpec needs a flag for it, and slots without it fall back to the R856-F5 probe-before-write path.")
//! @yah:next("Reuse the vault.lease (R219) vocabulary for time-boxing rather than inventing a second one — VaultLeaseEntry / VaultLeaseTable in crates/yah/agent-tools/src/tools.rs:435 already model \"credential valid for N seconds, then gone\".")
//! @yah:verify("A full mint -> .next -> probe -> promote -> revoke cycle completes with a consumer reading successfully at every intermediate step")
//! @yah:verify("A slot whose provider forbids two live keys refuses the overlap path and routes to `yah keys rotate` instead")
//! @arch:see(.yah/docs/working/W337-credential-health-and-rotation.md)
//! @yah:depends_on(R856-F5)
//! @yah:tier(Wizard)
//!
//! @yah:ticket(R856-T11, "Clobber-recovery store for overwritten vault slots — NOT a `&lt;slot&gt;.prev` entry in the slot namespace")
//! @yah:at(2026-09-03T22:29:32Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R856)
//! @yah:next("WHY THIS EXISTS: R856-T10 removed the --overwrite guard from `yah keys set` (it lost send-once credentials: provider shows a token once at registration, the guard refuses because the slot holds a stale value, secret gone). A vaulted secret still has no version history, so an overwrite is still permanent. This ticket is the recovery half the guard used to stand in for.")
//! @yah:next("DO NOT IMPLEMENT THIS AS `&lt;slot&gt;.prev` IN THE SLOT NAMESPACE — operator ruled that out on 2026-09-03, and the reason is not obvious. R856-F1 made `yah keys list` the authority the fob credential registry is diffed against, and it ships a test asserting the registry contains no slot the vault does not have and none it does not list. A `.prev` entry would read as an unlisted vault slot, break that invariant, and add a shadow row per rotated credential to the `yah cloud secrets` table. The clobber-recovery idea is sound; it needs a store that is NOT the slot namespace (a sidecar history file under the keys dir, encrypted with the same machine key, bounded depth, invisible to list_slots).")
//! @yah:verify("`yah keys list` output is byte-identical before and after an overwrite that stashes a prior value — the R856-F1 registry-vs-vault diff test still passes")
pub mod spec;

pub use spec::{
    parse_sidecar, render_sidecar, spec, specs_in_domain, Band, CredentialSpec, Domain, Expiry,
    ExpiryKind, HealthRecord, HealthSidecar, MintHelp, ProbeFrom, Provider, Verdict,
    CREDENTIAL_SPECS,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use directories::ProjectDirs;
use rand::RngCore;
use serde_json::{Map, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MACHINE_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const MACHINE_KEY_FILE: &str = "machine.key";
const CREDENTIALS_FILE: &str = "credentials.enc";
/// Verdict sidecar (W337 §4). Deliberately a separate, unencrypted file: the
/// desktop must be able to render credential health without touching
/// plaintext, and nothing in it is secret.
const HEALTH_FILE: &str = "credential-health.json";

pub struct KeysStore {
    dir: PathBuf,
}

impl KeysStore {
    /// Open the store at the conventional location. Creates the parent
    /// directory if absent (mode 0700 on Unix); does **not** create the
    /// machine key — that's `init`'s job, lazily invoked by `set` so
    /// first-time use Just Works.
    pub fn open() -> Result<Self> {
        let proj = ProjectDirs::from("com", "yah", "yah")
            .context("could not determine yah data directory")?;
        let dir = proj.data_dir().to_path_buf();
        ensure_dir_secure(&dir)?;
        Ok(Self { dir })
    }

    /// Open a store rooted at an explicit directory.
    ///
    /// [`Self::open`] resolves through `ProjectDirs` with no HOME override, so
    /// anything that exercises a real round-trip in-process would write to the
    /// developer's actual vault (see the note at `app/yah/cli/src/camp.rs:708`).
    /// This is the seam that makes the sidecar testable; `open` is unchanged.
    pub fn at(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        ensure_dir_secure(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of the verdict sidecar. Plain JSON, mode 0644, alongside
    /// `credentials.enc` but never inside it.
    pub fn health_path(&self) -> PathBuf {
        self.dir.join(HEALTH_FILE)
    }

    /// Read the verdict sidecar. Infallible by construction: a missing file,
    /// an unreadable one, or malformed JSON all yield an empty sidecar, so a
    /// damaged health file can never break `yah cloud secrets` or an agent's
    /// `creds_check`. Decrypts nothing.
    pub fn read_health(&self) -> spec::HealthSidecar {
        match fs::read(self.health_path()) {
            Ok(bytes) => spec::parse_sidecar(&bytes),
            Err(_) => spec::HealthSidecar::default(),
        }
    }

    /// Replace the verdict sidecar atomically at mode 0644.
    pub fn write_health(&self, sidecar: &spec::HealthSidecar) -> Result<()> {
        write_plain(&self.health_path(), &spec::render_sidecar(sidecar)?)
    }

    /// Read-modify-write one slot's health record.
    pub fn record_health(&self, record: spec::HealthRecord) -> Result<()> {
        let mut sidecar = self.read_health();
        sidecar.upsert(record);
        self.write_health(&sidecar)
    }

    /// Record one slot's expiry without disturbing the rest of its record.
    ///
    /// [`Self::record_health`] takes a whole [`spec::HealthRecord`] and
    /// replaces the stored one, so using it to write a date would silently drop
    /// whatever `verdict` / `scopes` / `last_probe_at` a probe had already
    /// left there. Expiry and probe verdict arrive from different places at
    /// different times — the date is read from the provider's token listing,
    /// the verdict from an authenticated call — so the two writers must not
    /// clobber each other. R856-T4 needed this to record npm's enforced
    /// expiry before any probe venue exists (R856-F2/T3).
    pub fn record_expiry(&self, slot: &str, expiry: spec::Expiry) -> Result<()> {
        let mut sidecar = self.read_health();
        let mut record = sidecar
            .get(slot)
            .cloned()
            .unwrap_or_else(|| spec::HealthRecord::new(slot));
        record.expires_at = Some(expiry);
        sidecar.upsert(record);
        self.write_health(&sidecar)
    }

    fn machine_key_path(&self) -> PathBuf {
        self.dir.join(MACHINE_KEY_FILE)
    }

    fn credentials_path(&self) -> PathBuf {
        self.dir.join(CREDENTIALS_FILE)
    }

    /// Generate a fresh machine key. Idempotent unless `force` is set:
    /// existing key is preserved (rotating it would orphan any existing
    /// credentials.enc, since this layer doesn't yet do re-encryption).
    pub fn init(&self, force: bool) -> Result<bool> {
        let path = self.machine_key_path();
        if path.exists() && !force {
            return Ok(false);
        }
        let mut key = [0u8; MACHINE_KEY_BYTES];
        rand::thread_rng().fill_bytes(&mut key);
        write_secure(&path, &key)?;
        Ok(true)
    }

    fn load_machine_key(&self) -> Result<[u8; MACHINE_KEY_BYTES]> {
        let path = self.machine_key_path();
        if !path.exists() {
            bail!(
                "machine key missing at {} — run `yah keys init`",
                path.display()
            );
        }
        let mut buf = Vec::new();
        File::open(&path)
            .with_context(|| format!("open {}", path.display()))?
            .read_to_end(&mut buf)?;
        if buf.len() != MACHINE_KEY_BYTES {
            bail!(
                "machine key at {} is {} bytes, expected {}",
                path.display(),
                buf.len(),
                MACHINE_KEY_BYTES
            );
        }
        let mut out = [0u8; MACHINE_KEY_BYTES];
        out.copy_from_slice(&buf);
        Ok(out)
    }

    fn cipher(&self) -> Result<Aes256Gcm> {
        let key = self.load_machine_key()?;
        Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("AES key construction failed: {e}"))
    }

    fn read_creds(&self) -> Result<Map<String, Value>> {
        let path = self.credentials_path();
        if !path.exists() {
            return Ok(Map::new());
        }
        let mut blob = Vec::new();
        File::open(&path)
            .with_context(|| format!("open {}", path.display()))?
            .read_to_end(&mut blob)?;
        if blob.len() < NONCE_BYTES + 16 {
            bail!("credentials blob at {} is truncated", path.display());
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_BYTES);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher()?
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("decrypt failed — wrong machine key, or credentials.enc corrupted"))?;
        let parsed: Value = serde_json::from_slice(&plaintext)
            .context("decrypted credentials JSON is malformed")?;
        match parsed {
            Value::Object(m) => Ok(m),
            _ => bail!("decrypted credentials are not a JSON object"),
        }
    }

    fn write_creds(&self, creds: &Map<String, Value>) -> Result<()> {
        let plaintext =
            serde_json::to_vec(&Value::Object(creds.clone())).context("serialize creds")?;
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher()?
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut blob = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        write_secure(&self.credentials_path(), &blob)
    }

    pub fn set(&self, provider: &str, token: &str) -> Result<()> {
        validate_provider(provider)?;
        if !self.machine_key_path().exists() {
            self.init(false)?;
        }
        let mut creds = self.read_creds()?;
        creds.insert(provider.to_string(), Value::String(token.to_string()));
        self.write_creds(&creds)
    }

    pub fn get(&self, provider: &str) -> Result<Option<String>> {
        validate_provider(provider)?;
        let creds = self.read_creds()?;
        Ok(creds.get(provider).and_then(|v| v.as_str()).map(str::to_string))
    }

    /// Read `slot` from this vault, falling back to `env_var` on miss.
    /// Vault errors propagate (corrupt machine.key, decrypt failure —
    /// real signals the caller should see); a clean miss falls through
    /// to the env. The free-function form
    /// [`get_or_env`] additionally swallows vault-open errors so a
    /// machine without a vault still picks up env-supplied creds —
    /// useful in CI / headless contexts where the env path is the
    /// entire deployment story (R044).
    pub fn get_or_env(&self, slot: &str, env_var: &str) -> Result<Option<String>> {
        if let Some(v) = self.get(slot)? {
            return Ok(Some(v));
        }
        Ok(std::env::var(env_var).ok())
    }

    pub fn list(&self) -> Result<Vec<String>> {
        let creds = self.read_creds()?;
        let mut names: Vec<String> = creds.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    pub fn delete(&self, provider: &str) -> Result<bool> {
        validate_provider(provider)?;
        let mut creds = self.read_creds()?;
        let removed = creds.remove(provider).is_some();
        if removed {
            self.write_creds(&creds)?;
        }
        Ok(removed)
    }
}

/// Read `slot` from the canonical vault, falling back to `env_var`. Lenient
/// with vault-open failure — a machine without a `machine.key` (CI runners,
/// fresh installs, headless containers) still resolves credentials supplied
/// purely via env. Vault decrypt / corruption errors still propagate so a
/// real problem isn't masked.
///
/// Convention: slot is canonical kebab-case (`hetzner-api-token`), env var
/// is SCREAMING_SNAKE (`HETZNER_API_TOKEN`). Caller passes both because env
/// names occasionally diverge from the slot (e.g. `github-pat` ↔
/// `GITHUB_TOKEN`).
pub fn get_or_env(slot: &str, env_var: &str) -> Result<Option<String>> {
    match KeysStore::open() {
        Ok(store) => store.get_or_env(slot, env_var),
        Err(_) => Ok(std::env::var(env_var).ok()),
    }
}

// ---------------------------------------------------------------------------
// Export / import (.yahkeys format)
// ---------------------------------------------------------------------------

/// Magic + version header for .yahkeys files.
///
/// Layout:
///   [0..4]  magic b"YAHK"
///   [4]     version 0x01
///   [5]     format  0x00=plain  0x01=argon2id+aes256gcm
///
/// Encrypted continuation:
///   [6..22]  argon2id salt (16 bytes)
///   [22..34] AES-256-GCM nonce (12 bytes)
///   [34..]   ciphertext + 16-byte GCM tag
///
/// Plain continuation:
///   [6..]    UTF-8 JSON object
const EXPORT_MAGIC: &[u8; 4] = b"YAHK";
const EXPORT_VERSION: u8 = 0x01;
const FORMAT_PLAIN: u8 = 0x00;
const FORMAT_ENCRYPTED: u8 = 0x01;

// Argon2id parameters: m=64MiB, t=3, p=1, output=32 bytes.
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// How to handle slot name collisions during `import_map`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeStrategy {
    /// Add all incoming slots, overwriting any existing value (default).
    Merge,
    /// Replace the entire vault with the incoming set; drop everything else.
    Replace,
    /// Add only slots that are not already present; never overwrite.
    Skip,
}

impl KeysStore {
    /// Return (a filtered copy of) the vault contents suitable for export.
    /// `slots` = `None` means "all slots".
    pub fn export_map(&self, slots: Option<&[String]>) -> Result<Map<String, Value>> {
        let all = self.read_creds()?;
        if let Some(names) = slots {
            Ok(all.into_iter().filter(|(k, _)| names.contains(k)).collect())
        } else {
            Ok(all)
        }
    }

    /// Write an imported slot map into this vault.
    ///
    /// Returns the number of slots actually written.
    pub fn import_map(
        &self,
        incoming: &Map<String, Value>,
        strategy: MergeStrategy,
    ) -> Result<usize> {
        if !self.machine_key_path().exists() {
            self.init(false)?;
        }
        let mut creds = match strategy {
            MergeStrategy::Replace => Map::new(),
            _ => self.read_creds()?,
        };
        let mut count = 0usize;
        for (k, v) in incoming {
            validate_provider(k)?;
            match strategy {
                MergeStrategy::Merge | MergeStrategy::Replace => {
                    creds.insert(k.clone(), v.clone());
                    count += 1;
                }
                MergeStrategy::Skip => {
                    if !creds.contains_key(k) {
                        creds.insert(k.clone(), v.clone());
                        count += 1;
                    }
                }
            }
        }
        self.write_creds(&creds)?;
        Ok(count)
    }
}

/// Encode a slot map as a plain `.yahkeys` blob.
///
/// Caller must gate this behind `--yes-really-export-plain` and print a
/// warning — this function performs no checks.
pub fn encode_plain(slots: &Map<String, Value>) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(&Value::Object(slots.clone()))
        .context("serialize slot map")?;
    let mut out = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(EXPORT_MAGIC);
    out.push(EXPORT_VERSION);
    out.push(FORMAT_PLAIN);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Encode a slot map as an Argon2id+AES-256-GCM encrypted `.yahkeys` blob.
pub fn encode_encrypted(slots: &Map<String, Value>, passphrase: &str) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(&Value::Object(slots.clone()))
        .context("serialize slot map")?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = derive_kek(passphrase.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&kek)
        .map_err(|e| anyhow!("cipher init: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, payload.as_ref())
        .map_err(|_| anyhow!("encryption failed"))?;

    // salt(16) + nonce(12) + ciphertext+tag
    let mut out = Vec::with_capacity(6 + 16 + NONCE_BYTES + ciphertext.len());
    out.extend_from_slice(EXPORT_MAGIC);
    out.push(EXPORT_VERSION);
    out.push(FORMAT_ENCRYPTED);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decode a `.yahkeys` blob (auto-detects plain vs encrypted).
///
/// `passphrase` is required for encrypted blobs; ignored (may be `None`)
/// for plain blobs.
pub fn decode_export(bytes: &[u8], passphrase: Option<&str>) -> Result<Map<String, Value>> {
    if bytes.len() < 6 {
        bail!("not a valid .yahkeys file (too short)");
    }
    if &bytes[..4] != EXPORT_MAGIC {
        bail!("not a .yahkeys file (wrong magic bytes — expected YAHK)");
    }
    let version = bytes[4];
    if version != EXPORT_VERSION {
        bail!("unsupported .yahkeys version {version:#04x} — upgrade yah");
    }
    let format = bytes[5];
    let rest = &bytes[6..];

    let json_bytes: Vec<u8> = match format {
        FORMAT_PLAIN => rest.to_vec(),
        FORMAT_ENCRYPTED => {
            // salt(16) + nonce(12) + ciphertext_with_tag(≥16)
            if rest.len() < 16 + NONCE_BYTES + 16 {
                bail!(".yahkeys encrypted blob is truncated");
            }
            let (salt, rest2) = rest.split_at(16);
            let (nonce_bytes, ciphertext) = rest2.split_at(NONCE_BYTES);

            let passphrase = passphrase
                .ok_or_else(|| anyhow!("passphrase required for encrypted .yahkeys file"))?;
            let kek = derive_kek(passphrase.as_bytes(), salt)?;

            let cipher = Aes256Gcm::new_from_slice(&kek)
                .map_err(|e| anyhow!("cipher init: {e}"))?;
            let nonce = Nonce::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| anyhow!("wrong passphrase or corrupted .yahkeys file"))?
        }
        other => bail!("unknown .yahkeys format byte {other:#04x}"),
    };

    let parsed: Value =
        serde_json::from_slice(&json_bytes).context("decrypted .yahkeys JSON is malformed")?;
    match parsed {
        Value::Object(m) => Ok(m),
        _ => bail!(".yahkeys payload is not a JSON object"),
    }
}

fn derive_kek(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut kek)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(kek)
}

fn validate_provider(name: &str) -> Result<()> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        bail!("invalid provider name: {name:?} (use [a-zA-Z0-9_-]+)");
    }
    Ok(())
}

fn ensure_dir_secure(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    Ok(())
}

/// Write `bytes` to `path` atomically with mode 0600 on Unix. Tempfile
/// in the same directory then rename — no half-written secrets visible.
fn write_secure(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("path {} has no parent", path.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("write")
    ));

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    {
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Write `bytes` to `path` atomically with mode 0644 on Unix. Same tmp+rename
/// discipline as [`write_secure`], deliberately *not* the same mode: the
/// verdict sidecar is not secret, and 0600 would stop a non-root reader (the
/// desktop, a health dashboard) from doing the one thing the sidecar exists
/// for — reading credential health without decrypting anything.
fn write_plain(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("path {} has no parent", path.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("write")
    ));

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }

    {
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store_in(dir: &Path) -> KeysStore {
        ensure_dir_secure(dir).unwrap();
        KeysStore { dir: dir.to_path_buf() }
    }

    #[test]
    fn init_is_idempotent_unless_forced() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        assert!(s.init(false).unwrap());
        let key1 = std::fs::read(tmp.path().join("machine.key")).unwrap();
        assert!(!s.init(false).unwrap());
        let key2 = std::fs::read(tmp.path().join("machine.key")).unwrap();
        assert_eq!(key1, key2);
        assert!(s.init(true).unwrap());
        let key3 = std::fs::read(tmp.path().join("machine.key")).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn roundtrip_and_list() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("anthropic", "sk-ant-test").unwrap();
        s.set("openai", "sk-openai-test").unwrap();
        assert_eq!(s.get("anthropic").unwrap().as_deref(), Some("sk-ant-test"));
        assert_eq!(s.get("openai").unwrap().as_deref(), Some("sk-openai-test"));
        assert_eq!(s.get("missing").unwrap(), None);
        let names = s.list().unwrap();
        assert_eq!(names, vec!["anthropic".to_string(), "openai".to_string()]);
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("anthropic", "sk-ant-DRAGNET-CANARY").unwrap();
        let blob = std::fs::read(tmp.path().join("credentials.enc")).unwrap();
        assert!(!blob.windows(b"sk-ant-DRAGNET-CANARY".len())
            .any(|w| w == b"sk-ant-DRAGNET-CANARY"));
        assert!(!blob.windows(b"anthropic".len())
            .any(|w| w == b"anthropic"));
    }

    #[test]
    fn delete_removes_only_named_provider() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("anthropic", "a").unwrap();
        s.set("openai", "b").unwrap();
        assert!(s.delete("anthropic").unwrap());
        assert!(!s.delete("anthropic").unwrap());
        assert_eq!(s.list().unwrap(), vec!["openai".to_string()]);
    }

    #[test]
    fn wrong_machine_key_fails_decrypt() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("anthropic", "tok").unwrap();
        // Rotate the machine key — existing creds blob now undecryptable.
        s.init(true).unwrap();
        let err = s.get("anthropic").unwrap_err().to_string();
        assert!(err.contains("decrypt"), "expected decrypt error, got: {err}");
    }

    #[test]
    fn rejects_bad_provider_names() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        assert!(s.set("", "x").is_err());
        assert!(s.set("has space", "x").is_err());
        assert!(s.set("ok-name_v2", "x").is_ok());
    }

    #[test]
    fn get_or_env_prefers_vault_over_env() {
        // Unique env-var name per test to avoid collisions with parallel
        // cargo test runs / the shell's existing env.
        const ENV_VAR: &str = "YAH_TEST_GETORENV_PREFER_VAULT";
        std::env::set_var(ENV_VAR, "from-env");
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("hetzner-api-token", "from-vault").unwrap();
        assert_eq!(
            s.get_or_env("hetzner-api-token", ENV_VAR).unwrap().as_deref(),
            Some("from-vault"),
            "vault wins over env when both are present"
        );
        std::env::remove_var(ENV_VAR);
    }

    #[test]
    fn get_or_env_falls_back_to_env_on_vault_miss() {
        const ENV_VAR: &str = "YAH_TEST_GETORENV_FALLBACK";
        std::env::set_var(ENV_VAR, "from-env");
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        // Vault is empty — get returns Ok(None) — env should win.
        assert_eq!(
            s.get_or_env("hetzner-api-token", ENV_VAR).unwrap().as_deref(),
            Some("from-env"),
        );
        std::env::remove_var(ENV_VAR);
    }

    #[test]
    fn get_or_env_returns_none_when_both_miss() {
        const ENV_VAR: &str = "YAH_TEST_GETORENV_BOTH_MISS";
        std::env::remove_var(ENV_VAR);
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        assert_eq!(s.get_or_env("hetzner-api-token", ENV_VAR).unwrap(), None);
    }

    // --- export / import tests ---

    #[test]
    fn plain_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let src = store_in(tmp.path());
        src.set("anthropic", "sk-ant-plain").unwrap();
        src.set("openai", "sk-oai-plain").unwrap();

        let map = src.export_map(None).unwrap();
        let blob = encode_plain(&map).unwrap();
        let decoded = decode_export(&blob, None).unwrap();

        assert_eq!(decoded.get("anthropic").and_then(|v| v.as_str()), Some("sk-ant-plain"));
        assert_eq!(decoded.get("openai").and_then(|v| v.as_str()), Some("sk-oai-plain"));
    }

    #[test]
    fn encrypted_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let src = store_in(tmp.path());
        src.set("anthropic", "sk-ant-enc").unwrap();

        let map = src.export_map(None).unwrap();
        let blob = encode_encrypted(&map, "hunter2").unwrap();
        let decoded = decode_export(&blob, Some("hunter2")).unwrap();

        assert_eq!(decoded.get("anthropic").and_then(|v| v.as_str()), Some("sk-ant-enc"));
    }

    #[test]
    fn encrypted_wrong_passphrase_returns_clean_error() {
        let tmp = TempDir::new().unwrap();
        let src = store_in(tmp.path());
        src.set("anthropic", "tok").unwrap();

        let map = src.export_map(None).unwrap();
        let blob = encode_encrypted(&map, "correct-horse").unwrap();
        let err = decode_export(&blob, Some("wrong-password")).unwrap_err().to_string();
        assert!(err.contains("wrong passphrase") || err.contains("corrupted"), "got: {err}");
    }

    #[test]
    fn slot_filter_on_export() {
        let tmp = TempDir::new().unwrap();
        let src = store_in(tmp.path());
        src.set("anthropic", "a").unwrap();
        src.set("openai", "b").unwrap();
        src.set("hetzner-api-token", "c").unwrap();

        let slots = vec!["anthropic".to_string()];
        let map = src.export_map(Some(&slots)).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("anthropic"));
        assert!(!map.contains_key("openai"));
    }

    #[test]
    fn import_merge_strategy() {
        let tmp = TempDir::new().unwrap();
        let dst = store_in(tmp.path());
        dst.set("existing", "old").unwrap();

        let mut incoming = Map::new();
        incoming.insert("existing".into(), Value::String("new".into()));
        incoming.insert("fresh".into(), Value::String("val".into()));

        let count = dst.import_map(&incoming, MergeStrategy::Merge).unwrap();
        assert_eq!(count, 2);
        assert_eq!(dst.get("existing").unwrap().as_deref(), Some("new"));
        assert_eq!(dst.get("fresh").unwrap().as_deref(), Some("val"));
    }

    #[test]
    fn import_skip_strategy() {
        let tmp = TempDir::new().unwrap();
        let dst = store_in(tmp.path());
        dst.set("existing", "old").unwrap();

        let mut incoming = Map::new();
        incoming.insert("existing".into(), Value::String("new".into()));
        incoming.insert("fresh".into(), Value::String("val".into()));

        let count = dst.import_map(&incoming, MergeStrategy::Skip).unwrap();
        assert_eq!(count, 1); // only "fresh" was added
        assert_eq!(dst.get("existing").unwrap().as_deref(), Some("old")); // unchanged
        assert_eq!(dst.get("fresh").unwrap().as_deref(), Some("val"));
    }

    #[test]
    fn import_replace_strategy() {
        let tmp = TempDir::new().unwrap();
        let dst = store_in(tmp.path());
        dst.set("will-be-gone", "old").unwrap();
        dst.set("keep", "keep").unwrap();

        let mut incoming = Map::new();
        incoming.insert("keep".into(), Value::String("new-keep".into()));

        dst.import_map(&incoming, MergeStrategy::Replace).unwrap();
        assert_eq!(dst.get("keep").unwrap().as_deref(), Some("new-keep"));
        assert_eq!(dst.get("will-be-gone").unwrap(), None); // cleared by replace
    }

    #[test]
    fn export_import_full_roundtrip_encrypted() {
        let src_tmp = TempDir::new().unwrap();
        let dst_tmp = TempDir::new().unwrap();
        let src = store_in(src_tmp.path());
        let dst = store_in(dst_tmp.path());

        src.set("anthropic", "sk-ant-secret").unwrap();
        src.set("openai", "sk-oai-secret").unwrap();

        // Export from src
        let map = src.export_map(None).unwrap();
        let blob = encode_encrypted(&map, "passphrase123").unwrap();

        // Import into dst (simulates a fresh vault on a remote camp)
        let decoded = decode_export(&blob, Some("passphrase123")).unwrap();
        let count = dst.import_map(&decoded, MergeStrategy::Merge).unwrap();
        assert_eq!(count, 2);

        // Verify byte-identical values
        assert_eq!(dst.get("anthropic").unwrap().as_deref(), Some("sk-ant-secret"));
        assert_eq!(dst.get("openai").unwrap().as_deref(), Some("sk-oai-secret"));
    }

    #[test]
    fn bad_magic_returns_clean_error() {
        let err = decode_export(b"NOPE\x01\x00{}", None).unwrap_err().to_string();
        assert!(err.contains("magic") || err.contains("YAHK"), "got: {err}");
    }

    #[test]
    fn encrypted_blob_ciphertext_does_not_contain_plaintext() {
        let mut m = Map::new();
        m.insert("slot".into(), Value::String("DRAGNET-CANARY-ENC".into()));
        let blob = encode_encrypted(&m, "passphrase").unwrap();
        assert!(!blob.windows(b"DRAGNET-CANARY-ENC".len())
            .any(|w| w == b"DRAGNET-CANARY-ENC"),
            "plaintext token visible in encrypted blob");
    }

    #[test]
    fn get_or_env_propagates_vault_decrypt_errors() {
        // A real decrypt failure (rotated machine.key) is a signal the
        // user should see — we don't want to silently mask it with
        // env-var fallback. The free-function form of get_or_env
        // *does* swallow vault-open errors (no machine.key at all),
        // but a vault that exists and won't decrypt is different.
        const ENV_VAR: &str = "YAH_TEST_GETORENV_DECRYPT_FAIL";
        std::env::set_var(ENV_VAR, "would-be-fallback");
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("hetzner-api-token", "tok").unwrap();
        s.init(true).unwrap(); // rotate key — existing blob undecryptable
        let err = s.get_or_env("hetzner-api-token", ENV_VAR).unwrap_err().to_string();
        assert!(err.contains("decrypt"), "expected decrypt error, got: {err}");
        std::env::remove_var(ENV_VAR);
    }

    // ── W337 / R856-F1: verdict sidecar ────────────────────────────────────

    #[test]
    fn at_opens_an_explicit_dir_without_touching_project_dirs() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("vault");
        let s = KeysStore::at(&nested).unwrap();
        assert_eq!(s.dir(), nested);
        assert!(nested.is_dir());
    }

    #[test]
    fn sidecar_round_trips_and_preserves_review_by() {
        use chrono::{TimeZone, Utc};

        let tmp = TempDir::new().unwrap();
        let s = KeysStore::at(tmp.path()).unwrap();
        assert_eq!(s.read_health(), spec::HealthSidecar::default());

        let t = Utc.with_ymd_and_hms(2026, 11, 11, 0, 0, 0).unwrap();
        s.record_health(spec::HealthRecord {
            expires_at: Some(spec::Expiry::Enforced(t)),
            verdict: Some(spec::Verdict::Valid {
                as_identity: Some("yah-ai".into()),
            }),
            last_probe_at: Some(t),
            ..spec::HealthRecord::new("npm-api-token")
        })
        .unwrap();
        s.record_health(spec::HealthRecord {
            expires_at: Some(spec::Expiry::ReviewBy(t)),
            ..spec::HealthRecord::new("release-cosign-key")
        })
        .unwrap();

        let back = s.read_health();
        assert_eq!(
            back.get("npm-api-token").unwrap().expires_at,
            Some(spec::Expiry::Enforced(t))
        );
        assert_eq!(
            back.get("release-cosign-key").unwrap().expires_at,
            Some(spec::Expiry::ReviewBy(t))
        );
        assert!(back.get("release-cosign-key").unwrap().expires_at.as_ref().unwrap().render().contains("re-mint"));
    }

    #[test]
    fn record_expiry_preserves_the_probe_verdict() {
        // R856-T4. The expiry and the verdict have different writers: the date
        // is read off the provider's token listing, the verdict comes from an
        // authenticated probe. If recording one clobbered the other, whichever
        // ran second would blank the first — so `record_expiry` must merge
        // rather than replace, which is exactly what `record_health` does not do.
        use chrono::{TimeZone, Utc};

        let tmp = TempDir::new().unwrap();
        let s = KeysStore::at(tmp.path()).unwrap();
        let probed = Utc.with_ymd_and_hms(2026, 9, 3, 0, 0, 0).unwrap();
        s.record_health(spec::HealthRecord {
            verdict: Some(spec::Verdict::Valid {
                as_identity: Some("yah-human".into()),
            }),
            last_probe_at: Some(probed),
            scopes: vec!["package:write".into()],
            ..spec::HealthRecord::new("npm-api-token")
        })
        .unwrap();

        let dies = Utc.with_ymd_and_hms(2026, 12, 1, 5, 42, 33).unwrap();
        s.record_expiry("npm-api-token", spec::Expiry::Enforced(dies))
            .unwrap();

        let back = s.read_health();
        let rec = back.get("npm-api-token").unwrap();
        assert_eq!(rec.expires_at, Some(spec::Expiry::Enforced(dies)));
        assert_eq!(
            rec.verdict,
            Some(spec::Verdict::Valid {
                as_identity: Some("yah-human".into())
            })
        );
        assert_eq!(rec.last_probe_at, Some(probed));
        assert_eq!(rec.scopes, vec!["package:write".to_string()]);

        // …and it still creates a record for a slot the sidecar has never seen.
        s.record_expiry("crates-io-token", spec::Expiry::ReviewBy(dies))
            .unwrap();
        assert_eq!(
            s.read_health().get("crates-io-token").unwrap().expires_at,
            Some(spec::Expiry::ReviewBy(dies))
        );
    }

    #[test]
    fn sidecar_is_readable_without_the_machine_key() {
        // The whole point of a separate plain file: the desktop renders
        // credential health without decrypting anything.
        let tmp = TempDir::new().unwrap();
        let s = KeysStore::at(tmp.path()).unwrap();
        s.record_health(spec::HealthRecord {
            verdict: Some(spec::Verdict::Revoked),
            ..spec::HealthRecord::new("crates-io-token")
        })
        .unwrap();
        assert!(!s.machine_key_path().exists());
        assert!(!s.credentials_path().exists());

        let reader = KeysStore::at(tmp.path()).unwrap();
        // No credentials.enc at all, so the secret side yields nothing…
        assert_eq!(reader.get("crates-io-token").unwrap(), None);
        // …while the sidecar still answers in full.
        assert_eq!(
            reader.read_health().get("crates-io-token").unwrap().verdict,
            Some(spec::Verdict::Revoked)
        );
    }

    #[test]
    fn sidecar_is_0644_not_0600() {
        let tmp = TempDir::new().unwrap();
        let s = KeysStore::at(tmp.path()).unwrap();
        s.write_health(&spec::HealthSidecar::default()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(s.health_path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "verdict sidecar is not secret; 0600 would block the desktop reader");
            // …and the secrets next to it are still 0600.
            s.set("crates-io-token", "tok").unwrap();
            let creds = fs::metadata(s.credentials_path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(creds, 0o600);
        }
    }

    #[test]
    fn corrupt_sidecar_does_not_break_the_read_path() {
        let tmp = TempDir::new().unwrap();
        let s = KeysStore::at(tmp.path()).unwrap();
        fs::write(s.health_path(), b"{ this is not json").unwrap();
        assert_eq!(s.read_health(), spec::HealthSidecar::default());
    }
}
