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
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-09-04T21:12:43Z)
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
//! @yah:handoff("Relay-leader sign-off request. The registry + sidecar landed and were independently re-verified by a second courier (not the implementer) against anchor dbe6954b; all six ticket verify criteria hold and are recorded above. Moving to review so the dependency gate treats F1 as terminal — F2, T3 and F8 all key off it and were withheld as 'waiting on R856-F1 (not yet terminal)'.")
//!
//! @yah:ticket(R856-F7, "Tier-2 probed expiry where the provider exposes it, and tier-3 scope drift")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-09-05T01:59:32Z)
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
//! @yah:handoff("LANDED 2026-09-04. Tier 2: GitHub's `GitHub-Authentication-Token-Expiration` header is read off the tier-1 `GET /user` response (both observed formats parse, an unrecognised third goes quiet rather than wrong); an absent header records NOTHING, since `ReviewBy` is the positive claim \"never expires\" and the registry already carries it for github-pat. Cloudflare's `expires_on` was reclassified `Declared` -> `Enforced`: W337 §7.1's axis is provenance (read from the provider) not who picked the number, and under F2's reading tier 2 could never upgrade anything but npm. Hetzner (`GET /v1/tokens` 404) and crates.io (`/api/v1/me/tokens` 403, cookie-only) expose no introspection — measured, not assumed. Tier 3: new `CredentialSpec::required_scopes` (machine vocabulary, deliberately NOT `MintHelp::scopes` which is dashboard prose), `scope_guarded()` applied at both venues — the sweep in `collect_with` and the write gate in `gate()`, which finally reaches the `ScopeInsufficient` arm F5 wrote. npm's prober now reads both axes (`permissions` + `scopes`, target axis prefixed `scope:`), because a token keeping `package:write` but losing org `mesofact` passes auth, presence and expiry and dies at publish. Only two of five probed providers expose scopes at all; only two slots carry a baseline (github-pat `write:packages`, npm-api-token `package:write` + `scope:org:mesofact`), and empty means no drift check — never a red. GitHub's package scopes are siblings, not nested: MINT_GITHUB's \"write:packages implies read:packages\" nav hint was wrong and is corrected. Files: app/yah/cli/src/keys_doctor.rs, oss/yah-base/crates/keys/src/spec.rs, W337 §3 + §7.1.")
//! @yah:verify("Both verify criteria hold. (1) `yah keys doctor` reports cloudflare-legacy-yah `expires 2029-04-20 (provider-enforced)` and the sidecar record flipped kind `declared` -> `enforced`, superseding the prior declared date. (2) `a_narrowed_incoming_token_is_refused_by_name_before_it_overwrites_a_good_one` asserts the gate refuses with detail `missing scopes: scope:org:mesofact` — the actual scope, not a generic failure. `cargo test -p yah --lib keys_doctor` green (61 tests); rustfmt divergence on keys_doctor.rs is 15, identical to the committed baseline, and spec.rs is 0.")
//! @yah:gotcha("The implementing session (session:8bccad3b) died on limits mid-verification; a second session finished it. Two defects from that session were found and fixed on pickup, both from edits landing at the wrong anchor: (1) `a_narrowed_incoming_token…`'s `#[test]` was inserted such that the function carried TWO `#[test]` attributes and inherited `a_slot_with_no_prober…`'s doc comment — it compiled and ran, but registered 62 descriptors for 61 tests; (2) the W337 §7.1 prose block landed between the `Declared` and `ReviewBy` bullets, splitting the three-kind list in two. Worth a reviewer's glance at any other insertion from that session.")
//!
//! @yah:ticket(R856-F9, "Overlap slots: slot / slot.next, so rotation is never atomic")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-09-05T03:00:08Z)
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
//! @yah:handoff("LANDED, but NOT as the ticket's own wording. The brief said \"support slot and slot.next\"; a `<slot>.next` vault entry is exactly the shape the operator ruled out on 2026-09-03 for its mirror `<slot>.prev` (R856-T11), because R856-F1 made `yah keys list` the authority the fob registry is diffed against and a dotted sibling would read as an unlisted vault slot plus a shadow row per rotated credential in `yah cloud secrets`. What shipped is a slot-ADJACENT sidecar outside the slot namespace: new module oss/yah-base/crates/keys/src/adjacent.rs (AdjacentStore/AdjacentRecord/AdjacentValue, parse_adjacent/render_adjacent, MAX_PREVIOUS=3, ADJACENT_VERSION=1) persisted to `credentials-adjacent.enc` in KeysStore::dir(), AES-256-GCM under the SAME machine key at 0600 — unlike the health sidecar, which stays plain 0644 because verdicts are not secret and this file's contents are.")
//! @yah:handoff("STORE API on KeysStore (oss/yah-base/crates/keys/src/lib.rs): adjacent_path / read_adjacent / write_adjacent, stage_overlap(slot,value,ttl_secs) -> lease_id, overlap + overlap_at, candidates + candidates_at (the consumer accessor — current-then-overlap, deduped, and strictly additive: an unreadable sidecar still yields the current value), promote_overlap + promote_overlap_at, discard_overlap, stash_previous, previous. Constants OVERLAP_DEFAULT_TTL_SECS=24h, OVERLAP_MAX_TTL_SECS=30d. Refactored read_creds/write_creds onto new private read_encrypted/write_encrypted so credentials.enc and the sidecar cannot drift into two at-rest formats. Promote writes the VAULT FIRST then the sidecar on purpose: a crash between them leaves the value both promoted and staged (idempotent on re-promote), the reverse order would drop it. An expired lease DEMOTES the staged value into `previous` rather than deleting it — a staged credential may be send-once, and the lease's job is only to stop `candidates` handing out a stale second key.")
//! @yah:handoff("THE FLAG, and what it is grounded on. New CredentialSpec.overlap: Overlap::{Permitted(&str), Forbidden(&str), Unproven} (spec.rs), plus permits_overlap() / overlap_evidence(). Both decided variants CARRY THEIR EVIDENCE as a string, because \"some agent believed it\" is not re-checkable. Default Unproven on all 49 specs. Only two measurements moved slots off it, both taken 2026-09-04: (1) CLOUDFLARE — this host's credential-health.json shows one sweep at 2026-09-04T23:55:19Z returning valid for THREE DISTINCT token ids (623b42a4, 28091f06, 2e976eaf) on one account simultaneously; applied to the four API-token slots cloudflare-api-token / cloudflare-legacy-yah / cloudflare-mesofact-static / cloudflare-static-yah-dev only, NOT to the R2 keys, tunnel tokens or zone-id, which are different credential kinds nothing measured. (2) NPM — `npm token list --json` (read-only, the same call the tier-1 probe makes) returned three unrevoked tokens with future expiries (publish 2026-12-01, yah2 and yah 2026-11-11). GitHub, Hetzner and crates.io were deliberately left Unproven: GitHub exposes no list API for classic PATs, and the vault holds only one live token for each of the other two, so there was nothing to measure. Guessing there would have been the one guess that costs an outage.")
//! @yah:handoff("CLI + policy (app/yah/cli/src/keys_doctor.rs, cli.rs): OverlapRoute::{Overlap{evidence}, Rotate{why}} + overlap_route(slot) turn the registry flag into a message — Forbidden and Unproven both refuse but say different things, which is why the flag is a 3-variant enum and not a bool. overlap_begin(_with) / overlap_promote(_with) / overlap_status / overlap_abort, wired as `yah keys overlap {begin,promote,status,abort}` next to Sweep/Rotate. The policy gate lives ONLY in this layer, not in KeysStore: the store is the general primitive R856-T11 reuses for clobber recovery on slots that can never overlap. One deliberate asymmetry with `rotate`: begin stages an UNVALIDATED value without prompting, because staging cannot clobber a live credential by construction; promote inherits rotate's rule that only a positive refusal blocks and re-probes the staged value, since that probe guards the moment the slot actually flips, possibly hours after begin's.")
//! @yah:handoff("VERIFIED. `cargo test -p fob --manifest-path oss/yah-base/Cargo.toml` 55 pass / 0 fail (baseline 42, +13: 5 in adjacent.rs, 6 in lib.rs, 2 in spec.rs). `cargo test -p yah --lib keys_doctor` 69 pass / 0 fail (baseline 61, +8). Criterion 1 is keys_doctor::tests::a_consumer_reads_a_live_value_at_every_step_of_an_overlap_cycle (full mint->stage->probe->promote->revoke against cloudflare-legacy-yah, asserting store.candidates() yields a provider-honoured value after EVERY step) plus the store-level twin fob::tests::a_consumer_reads_successfully_at_every_step_of_the_cycle. Criterion 2 is a_slot_without_a_measured_overlap_refuses_and_routes_to_rotate (github-pat: exit 1, nothing staged, sidecar not even created) and forbidden_and_unproven_refuse_with_different_sentences, which also pins overlap_route against every registry slot's own flag. Criterion 3 is staging_an_overlap_leaves_keys_list_byte_identical + keys_list_is_byte_identical_with_an_overlap_in_flight. Also ran `cargo xtask install` per app/yah/cli/CLAUDE.md (installed ~/.local/bin/yah, sha256 7fa0687a…, PATH resolves there) and smoke-tested the read-only verbs against the REAL vault: status prints the grounded evidence for cloudflare-api-token, the refusal sentence for github-pat, `yah keys list` md5 unchanged, and no credentials-adjacent.enc was created by a status or a refusal.")
//! @yah:handoff("DISCOVERED WORK, done in this pass, not filed: .yah/docs/working/W337-credential-health-and-rotation.md §6 still told the next reader to \"support `slot` and `slot.next`\" — the shape the operator ruled out. Leaving it would have sent whoever reads the design doc straight back into the invariant break. Corrected in place with an as-built note naming the sidecar, the Overlap enum, the default-refuses argument and the two measurements. The doc's own wording was the only thing changed; §10 step 8 ordering is untouched.")
//! @yah:gotcha("R856-T11 (clobber recovery) can take the primitive as-is: KeysStore::stash_previous / previous already exist, bounded at fob::adjacent::MAX_PREVIOUS, in the same sidecar, outside the slot namespace. What is deliberately NOT wired is stash-on-overwrite — `KeysStore::set` does not call stash_previous, and fob::tests::stash_previous_is_available_and_bounded_without_being_wired_into_set pins that so this ticket cannot pre-empt T11's decision about which write paths stash. Turning it on is a one-line change in `set` plus whatever T11 concludes about `yah keys recover`.")
//! @yah:gotcha("Nothing on the credential-RESOLUTION path calls KeysStore::candidates yet — fob::get_or_env and every consumer still read the single current value, which is correct today (the overlap value only matters when the current one is dead, and the cycle never leaves it dead). If a future ticket wants a consumer to fail over to the staged value automatically, candidates() is the accessor to move it to; do NOT reintroduce name-mangling of the slot string.")
//! @yah:assumes("The Cloudflare and npm overlap measurements are of the PROVIDER's behaviour on this account, read on 2026-09-04. Both are re-runnable (`yah keys sweep` / `npm token list --json`) and the evidence string in each Overlap::Permitted says how. Neither is a claim about a plan tier other than this account's.")
//! @yah:handoff("CALLS MADE RATHER THAN ASKED: (1) 3-variant Overlap enum carrying evidence strings instead of a bool, so \"measured, and no\" and \"nobody checked\" reach the operator as different sentences. (2) Lease magnitudes 24h default / 30d cap — vault.lease's VOCABULARY is reused (lease_id, expires_at, ttl_secs, prune-then-write) but not its 1h ceiling, which is sized for a bash subprocess, not for a rotation an operator finishes by hand. (3) Expired leases demote rather than delete. (4) Promote is non-interactive about the expiry date (`--expires` or the derived default via rotation_expiry) where `rotate` prompts — begin already had the operator's attention and a second prompt hours later is where an in-flight rotation gets abandoned. (5) Nothing was committed; the working tree carries the change.")
//!
//! @yah:ticket(R856-T11, "Clobber-recovery store for overwritten vault slots — NOT a `&lt;slot&gt;.prev` entry in the slot namespace")
//! @yah:status(review)
//! @yah:at(2026-09-05T04:23:32Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R856)
//! @yah:next("WHY THIS EXISTS: R856-T10 removed the --overwrite guard from `yah keys set` (it lost send-once credentials: provider shows a token once at registration, the guard refuses because the slot holds a stale value, secret gone). A vaulted secret still has no version history, so an overwrite is still permanent. This ticket is the recovery half the guard used to stand in for.")
//! @yah:next("DO NOT IMPLEMENT THIS AS `&lt;slot&gt;.prev` IN THE SLOT NAMESPACE — operator ruled that out on 2026-09-03, and the reason is not obvious. R856-F1 made `yah keys list` the authority the fob credential registry is diffed against, and it ships a test asserting the registry contains no slot the vault does not have and none it does not list. A `.prev` entry would read as an unlisted vault slot, break that invariant, and add a shadow row per rotated credential to the `yah cloud secrets` table. The clobber-recovery idea is sound; it needs a store that is NOT the slot namespace (a sidecar history file under the keys dir, encrypted with the same machine key, bounded depth, invisible to list_slots).")
//! @yah:verify("`yah keys list` output is byte-identical before and after an overwrite that stashes a prior value — the R856-F1 registry-vs-vault diff test still passes")
//! @yah:handoff("LANDED on F9's store — nothing was redesigned. R856-F9 had already built the primitive (credentials-adjacent.enc, stash_previous/previous, MAX_PREVIOUS=3, outside the slot namespace) and deliberately left it unwired. T11 wires it and adds the surface. (a) KeysStore::set now retains what it displaces, via a new private stash_superseded/retain_superseded pair in oss/yah-base/crates/keys/src/lib.rs. (b) New `yah keys recover <slot> [--restore N]`, implemented as keys_doctor::recover_list / recover_restore and wired as KeysCommands::Recover next to Overlap/Rotate/Sweep. (c) New KeysStore::restore_previous(slot, index) -> masked string. The `<slot>.prev` shape stays ruled out and nothing here resurrects it.")
//! @yah:handoff("THE STASH RULE, and the two-sided invariant that was NOT in the brief. stash_superseded skips a no-op rewrite (same value re-set) so a repeated Settings save cannot churn a 3-deep ring, and skips a first write. It also runs BEFORE the vault write — the value at risk is the incumbent, which lives in the vault, so the write that can destroy it goes last (promote_overlap_at orders the two the other way for the mirror reason: there the at-risk value is the staged one, which lives in the sidecar). And it CANNOT FAIL THE WRITE: a stash error is warned and swallowed, because refusing to store a credential over an unwritable recovery file would resurrect the exact R856-T10 failure this replaces. Beyond the brief: the rule is two-sided — the displaced value ENTERS the history and the incoming value LEAVES it. A test I wrote for A -> B -> A caught that a one-sided rule leaves A both current and retained, which is a restore that does nothing while occupying one of only three slots. push_previous also dedupes by value for the same reason. That invariant made restore_previous's own bookkeeping redundant: it now has no retention logic at all, it just calls set.")
//! @yah:handoff("DISCOVERED WORK, fixed in this pass, and a deviation from the brief's letter worth reading. The brief said \"set is the single choke point every overwrite goes through\". It is not: KeysStore::import_map writes the whole creds map directly, so `yah keys import --strategy merge` over a live slot was a permanent clobber with no recovery — the exact failure T11 exists for, on a path the wiring would have missed. Rather than route import through set (which would let a partial import leave the vault half-merged), import_map now calls the same stash_superseded helper itself, so there is one RULE even though there are two writers. MergeStrategy::Skip never overwrites so it never retains. Covered by fob::tests::an_import_that_overwrites_a_live_slot_is_as_recoverable_as_a_set.")
//! @yah:handoff("MASKING. No recovery verb prints a credential. AdjacentValue::masked() renders `<first 8 chars>... (N chars)`, and the width is not arbitrary — 8 is the join key this codebase already uses, since npm publishes each token as `npm_XXXX...YYYY` and keys_doctor::npm_record_for matches a vault value to a provider record on its first 8 characters (W337 §3.2). Reusing it means a `yah keys recover` listing reads straight across against `npm token list --json` output, and for npm those 8 characters are not a disclosure at all — npm publishes them itself to any read-only token list. No suffix is shown (npm's own masked form has one; there is no join value in it here and it is strictly more of the secret). NARROWED at sign-off: 8 was a fixed width with a 12-char floor under it, which rendered `abcdefgh... (12 chars)` — two thirds of the secret plus its exact length — for anything short, and the npm rationale covers a 40-char minted token, not whatever an operator puts in a slot. 8 is now a CEILING under MASK_MAX_FRACTION=4: show min(len/4, 8), drop the prefix below 4 shown chars (len < 16), and in that short case report `<hidden, under 16 chars>` rather than the exact count, since for a human-chosen secret the length is the disclosure. npm and GitHub both mint 40, so every real provider token still gets the full 8-char join prefix. The method lives on AdjacentValue, not in the CLI, so the safe rendering is the nearest one to hand and reaching for `.value` in display code reads as deliberate. restore_previous returns the mask, never the value — the credential moves vault-to-vault and never crosses stdout.")
//! @yah:handoff("VERIFIED. `cargo test -p fob --manifest-path oss/yah-base/Cargo.toml` 62 pass / 0 fail (F9 baseline 55, +7). `cargo test -p yah --lib keys_doctor` 75 pass / 0 fail (F9 baseline 69, +6). ACCEPTANCE CRITERION covered on both sides: fob::tests::keys_list_is_byte_identical_across_an_overwrite_that_stashes and keys_doctor::tests::keys_list_is_byte_identical_across_a_stashing_overwrite, the latter also re-asserting the R856-F1 registry-vs-vault direction (every slot the vault lists is one fob::spec describes, which a `.prev` entry would break) and checking no listed slot contains `.prev` or `.next`. The F9 pinning test was FLIPPED, not deleted, as instructed: fob::tests::stash_previous_is_available_and_bounded_without_being_wired_into_set is now stash_previous_is_wired_into_set_and_stays_bounded, asserting a first write retains nothing and an overwrite retains what it displaced. Also ran `cargo xtask install` per app/yah/cli/CLAUDE.md and smoke-tested `yah keys recover` read-only against the real vault.")
//! @yah:gotcha("`yah keys delete` still destroys a value permanently — it does NOT stash. Deliberate and out of scope: T11's mandate is the OVERWRITE that R856-T10 made unconditional, and delete is an explicitly-named destructive verb rather than an accident of pasting. MergeStrategy::Replace has the same shape: it retains values it overwrites, but slots the incoming set omits are DROPPED and not retained. Both are one call to stash_superseded away if a later ticket wants them.")
//! @yah:gotcha("Recovery is deliberately NOT gated on the credential registry. `recover_list` / `recover_restore` never call fob::spec, unlike `rotate` and `overlap` which need one — so an ad-hoc slot written by `yah keys set foo bar` is recoverable too. That is the slot with the least other protection, so gating it on a registry entry would withhold the safety net from exactly the case that needs it most. Slot names are still charset-validated through KeysStore::validate_provider.")
//! @yah:gotcha("History only exists going forward. A slot last written before T11 landed has nothing retained, and `yah keys recover` says so and exits 1 rather than implying the safety net was always there. The retention ring is 3 deep per slot (fob::adjacent::MAX_PREVIOUS), so the fourth overwrite evicts the oldest — recovery is a short-window undo, not an archive, and every retained entry is a live secret on disk the provider may never have been told to revoke.")
//! @yah:verify("Live smoke against the REAL vault after `cargo xtask install` (sha256 6781ecbd..., PATH resolves there): `yah keys recover github-pat` prints the no-history message and exits 1; `yah keys list` md5 is 54d3638e7988a9eaf1ca22b370dd9165, identical to the value measured during R856-F9 before any of this landed; and no credentials-adjacent.enc was created, since nothing overwrote a real slot. `--restore` was deliberately NOT exercised against the real vault — that path is covered by tests on a tempdir store.")
//! @yah:handoff("MID-RUN INCIDENT worth recording, since it briefly broke the camp. A python heredoc I used to append the T11 test block over-escaped a newline and wrote a literal two-character `\\n` into app/yah/cli/src/keys_doctor.rs:4331, which made the file fail to PARSE and took `cargo check --workspace` red for everyone. @Ashguard:polaris (R860-T1) caught it, correctly did not edit my in-flight file, and pinged; fixed with Edit inside ~2 minutes and confirmed back to them. Lesson for the next agent appending a test block here: splice with a real newline or use Edit, and re-run the suite before moving on — a parse error in this file is camp-wide, not local. Separately, three of my verification runs failed inside oss/yubaba/crates/cloud/src/config.rs (repel_archetype -> repel_archetypes, then admission_spec gaining a second parameter) — a peer's in-flight W338 placement-group refactor, not mine and not touched; the suite went green once they landed.")
//! @yah:verify("cargo test -p fob --manifest-path oss/yah-base/Cargo.toml -> 62 pass / 0 fail (F9 baseline 55). cargo test -p yah --lib keys_doctor -> 75 pass / 0 fail (F9 baseline 69).")
pub mod adjacent;
pub mod spec;

pub use adjacent::{AdjacentRecord, AdjacentStore, AdjacentValue};
pub use spec::{
    parse_sidecar, render_sidecar, spec, specs_in_domain, Band, CredentialSpec, Domain, Expiry,
    ExpiryKind, HealthRecord, HealthSidecar, MintHelp, Overlap, ProbeFrom, Provider, Verdict,
    CREDENTIAL_SPECS,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Utc};
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
/// Slot-adjacent store (W337 §6). Encrypted, unlike [`HEALTH_FILE`], because
/// what it holds *is* credential material — and separate from
/// [`CREDENTIALS_FILE`] because anything inside that one is a vault slot, and
/// `yah keys list` is the authority the credential registry is diffed against.
/// See `adjacent` for the full argument.
const ADJACENT_FILE: &str = "credentials-adjacent.enc";

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

    /// Read and decrypt one `[nonce | ciphertext+tag]` file under this store's
    /// machine key. `Ok(None)` for a file that is not there — the caller
    /// decides whether absence is "empty" or an error.
    ///
    /// Shared by `credentials.enc` and the slot-adjacent sidecar (R856-F9) so
    /// the two cannot drift into different at-rest formats.
    fn read_encrypted(&self, path: &Path, what: &str) -> Result<Option<Vec<u8>>> {
        if !path.exists() {
            return Ok(None);
        }
        let mut blob = Vec::new();
        File::open(path)
            .with_context(|| format!("open {}", path.display()))?
            .read_to_end(&mut blob)?;
        if blob.len() < NONCE_BYTES + 16 {
            bail!("{what} blob at {} is truncated", path.display());
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_BYTES);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self.cipher()?.decrypt(nonce, ciphertext).map_err(|_| {
            anyhow!(
                "decrypt failed — wrong machine key, or {} corrupted",
                path.display()
            )
        })?;
        Ok(Some(plaintext))
    }

    /// Encrypt `plaintext` under this store's machine key and write it at 0600.
    fn write_encrypted(&self, path: &Path, plaintext: &[u8]) -> Result<()> {
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher()?
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut blob = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        write_secure(path, &blob)
    }

    fn read_creds(&self) -> Result<Map<String, Value>> {
        let Some(plaintext) = self.read_encrypted(&self.credentials_path(), "credentials")? else {
            return Ok(Map::new());
        };
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
        self.write_encrypted(&self.credentials_path(), &plaintext)
    }

    /// Write `token` into `provider`, stashing whatever it displaces (R856-T11).
    ///
    /// Unconditional, as R856-T10 made it: the `--overwrite` guard that used to
    /// live here destroyed the credentials it was meant to protect, because a
    /// provider that shows a token exactly once at registration hands it to
    /// this function and a refusal loses it forever. What replaces the guard is
    /// recovery rather than refusal — the displaced value goes to the
    /// slot-adjacent store, bounded at [`adjacent::MAX_PREVIOUS`], where
    /// `yah keys recover` can put it back.
    pub fn set(&self, provider: &str, token: &str) -> Result<()> {
        validate_provider(provider)?;
        if !self.machine_key_path().exists() {
            self.init(false)?;
        }
        let mut creds = self.read_creds()?;
        let superseded = creds
            .get(provider)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        self.stash_superseded(provider, token, superseded.as_deref());
        creds.insert(provider.to_string(), Value::String(token.to_string()));
        self.write_creds(&creds)
    }

    /// The one place that decides whether a write is a recoverable clobber.
    ///
    /// Two things are deliberate and neither is obvious.
    ///
    /// **It runs before the vault write.** The value at risk is the incumbent,
    /// which lives in the vault, so the write that can destroy it goes last.
    /// (`promote_overlap_at` orders the two the other way for the mirror
    /// reason: there the value at risk is the *staged* one, which lives in the
    /// sidecar, so the sidecar clear goes last.) A crash in between leaves a
    /// history entry for a value that is still current — harmless and
    /// self-correcting, where the other order would lose the credential.
    ///
    /// **It cannot fail the write.** A stash error is warned about and
    /// swallowed: refusing to store a credential because a *recovery* file was
    /// unwritable would resurrect the exact R856-T10 failure this store was
    /// built to replace. Recovery is a safety net, and a safety net that can
    /// stop the trapeze is worse than none.
    ///
    /// Skips a no-op rewrite entirely (the same value re-set would otherwise
    /// evict real history through a bounded ring).
    ///
    /// **The invariant it maintains is two-sided**, which is why it is not a
    /// bare call to [`Self::stash_previous`]: the displaced value enters the
    /// history *and* the incoming value leaves it. A credential that is current
    /// is not "previous", so offering it in `yah keys recover` would be a
    /// restore that does nothing while occupying one of the few retention
    /// slots. It matters on more paths than it looks: A -> B -> A, a
    /// `restore_previous` (which is exactly that), and a promotion of a staged
    /// value a lease expiry had already demoted.
    fn stash_superseded(&self, slot: &str, incoming: &str, current: Option<&str>) {
        if current == Some(incoming) {
            return;
        }
        if let Err(e) = self.retain_superseded(slot, incoming, current) {
            eprintln!("warning: could not retain the superseded value for {slot}: {e:#}");
        }
    }

    /// [`Self::stash_superseded`]'s fallible half, as one read-modify-write so
    /// the push and the forget cannot land separately.
    fn retain_superseded(&self, slot: &str, incoming: &str, current: Option<&str>) -> Result<()> {
        let mut store = self.read_adjacent()?;
        let mut changed = false;
        {
            let record = store.entry(slot);
            if let Some(old) = current {
                record.push_previous(adjacent::AdjacentValue {
                    value: old.to_string(),
                    lease_id: mint_lease_id(),
                    written_at: Utc::now(),
                    expires_at: None,
                });
                changed = true;
            }
            changed |= record.forget_previous(incoming);
        }
        store.compact();
        if changed {
            self.write_adjacent(&store)?;
        }
        Ok(())
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

// ---------------------------------------------------------------------------
// Slot-adjacent store (W337 §6, R856-F9)
// ---------------------------------------------------------------------------

/// Default overlap lease. A rotation is an operator action with a manual tail —
/// stage, probe, redeploy consumers, confirm, only then revoke at the provider —
/// so the horizon is a working day rather than `vault.lease`'s minutes.
pub const OVERLAP_DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// Ceiling on an overlap lease. Past this, a "rotation in flight" is really an
/// abandoned one, and a second live credential nobody is tracking is the state
/// this whole design exists to avoid leaving behind.
pub const OVERLAP_MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;

impl KeysStore {
    /// Path of the slot-adjacent sidecar. Encrypted under the same machine key
    /// as `credentials.enc` and at the same 0600, because unlike the *health*
    /// sidecar its contents are credential material.
    pub fn adjacent_path(&self) -> PathBuf {
        self.dir.join(ADJACENT_FILE)
    }

    /// Read the slot-adjacent sidecar. A missing file is an empty store; a
    /// malformed decrypted body is too (see [`adjacent::parse_adjacent`]). A
    /// *decrypt* failure propagates — that is the same real signal
    /// [`Self::get`] would raise, and swallowing it would hide a broken vault.
    pub fn read_adjacent(&self) -> Result<adjacent::AdjacentStore> {
        match self.read_encrypted(&self.adjacent_path(), "slot-adjacent")? {
            Some(plaintext) => Ok(adjacent::parse_adjacent(&plaintext)),
            None => Ok(adjacent::AdjacentStore::default()),
        }
    }

    /// Replace the slot-adjacent sidecar. Deletes the file outright once the
    /// store is empty, so a completed rotation leaves nothing behind.
    pub fn write_adjacent(&self, store: &adjacent::AdjacentStore) -> Result<()> {
        if store.slots.is_empty() && self.adjacent_path().exists() {
            fs::remove_file(self.adjacent_path())
                .with_context(|| format!("removing {}", self.adjacent_path().display()))?;
            return Ok(());
        }
        if store.slots.is_empty() {
            return Ok(());
        }
        if !self.machine_key_path().exists() {
            self.init(false)?;
        }
        let plaintext = adjacent::render_adjacent(store).context("serialize slot-adjacent store")?;
        self.write_encrypted(&self.adjacent_path(), &plaintext)
    }

    /// Stage an incoming value next to `slot` under a lease of `ttl_secs`,
    /// clamped to [`OVERLAP_MAX_TTL_SECS`]. Returns the lease id.
    ///
    /// Writes nothing to the slot itself, which is the entire point: staging is
    /// the step that *cannot* clobber a live credential. A value already staged
    /// is superseded and demoted to `previous` rather than dropped.
    ///
    /// This is the general primitive. Whether a given slot is *allowed* to use
    /// the overlap path is a registry question ([`CredentialSpec::permits_overlap`])
    /// enforced by the CLI, not here — R856-T11 will reuse this same store for
    /// clobber recovery on slots that can never overlap.
    pub fn stage_overlap(&self, slot: &str, value: &str, ttl_secs: u64) -> Result<String> {
        validate_provider(slot)?;
        let now = Utc::now();
        let ttl = ttl_secs.clamp(1, OVERLAP_MAX_TTL_SECS);
        let lease_id = mint_lease_id();
        let mut store = self.read_adjacent()?;
        store.prune(now);
        let record = store.entry(slot);
        if let Some(superseded) = record.next.take() {
            record.push_previous(adjacent::AdjacentValue {
                expires_at: None,
                ..superseded
            });
        }
        record.next = Some(adjacent::AdjacentValue {
            value: value.to_string(),
            lease_id: lease_id.clone(),
            written_at: now,
            expires_at: Some(now + chrono::Duration::seconds(ttl as i64)),
        });
        self.write_adjacent(&store)?;
        Ok(lease_id)
    }

    /// The live staged value for `slot`, or `None` when nothing is staged or
    /// the lease has run out.
    pub fn overlap(&self, slot: &str) -> Result<Option<adjacent::AdjacentValue>> {
        self.overlap_at(slot, Utc::now())
    }

    /// [`Self::overlap`] against an explicit clock.
    pub fn overlap_at(
        &self,
        slot: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<adjacent::AdjacentValue>> {
        validate_provider(slot)?;
        Ok(self
            .read_adjacent()?
            .get(slot)
            .and_then(|r| r.next.clone())
            .filter(|v| v.is_live(now)))
    }

    /// Values a consumer should try for `slot`, **current first**, then any
    /// live overlap value (W337 §6). Deduplicated, so a slot whose staged value
    /// has already been promoted yields one candidate rather than two.
    ///
    /// The overlap half is strictly additive: if the sidecar cannot be read at
    /// all, this still returns the current value rather than failing. A staging
    /// area must never be able to break credential resolution.
    pub fn candidates(&self, slot: &str) -> Result<Vec<String>> {
        self.candidates_at(slot, Utc::now())
    }

    /// [`Self::candidates`] against an explicit clock.
    pub fn candidates_at(&self, slot: &str, now: DateTime<Utc>) -> Result<Vec<String>> {
        let mut out = Vec::new();
        if let Some(current) = self.get(slot)? {
            out.push(current);
        }
        if let Ok(Some(staged)) = self.overlap_at(slot, now) {
            if !out.contains(&staged.value) {
                out.push(staged.value);
            }
        }
        Ok(out)
    }

    /// Promote the staged value into the slot: the old slot value moves to
    /// `previous`, the staged value becomes current, the lease is cleared.
    /// `Ok(false)` when nothing live is staged.
    ///
    /// **Order is deliberate.** The vault write lands *first*, then the sidecar
    /// update. A crash between them leaves the new value both promoted and
    /// still staged, which a second `promote` resolves idempotently; the
    /// reverse order would drop the staged value on the floor with nothing
    /// holding it.
    ///
    /// The displaced credential is retained by [`Self::set`] under the one
    /// stash rule (R856-T11), not by a second rule here: a promotion *is* an
    /// overwrite, and giving it its own retention logic is how two rules drift
    /// apart. Because the vault write happens before the sidecar is rewritten,
    /// the entry `set` pushed has to be carried across — hence the re-read.
    pub fn promote_overlap(&self, slot: &str) -> Result<bool> {
        self.promote_overlap_at(slot, Utc::now())
    }

    /// [`Self::promote_overlap`] against an explicit clock.
    pub fn promote_overlap_at(&self, slot: &str, now: DateTime<Utc>) -> Result<bool> {
        validate_provider(slot)?;
        let mut store = self.read_adjacent()?;
        store.prune(now);
        let Some(staged) = store.get(slot).and_then(|r| r.next.clone()) else {
            self.write_adjacent(&store)?;
            return Ok(false);
        };

        // Writes the vault and stashes the credential this promotion displaces.
        self.set(slot, &staged.value)
            .with_context(|| format!("promoting the staged value into {slot}"))?;

        /* Re-read rather than mutating the copy taken above: `set` just wrote
        the stash into this same file, and writing the stale copy back would
        erase the retention that is the entire point of routing through it.
        `push_previous` dedupes by value, so the staged value cannot end up in
        `previous` twice even if a lease-expiry demote already put it there. */
        let mut store = self.read_adjacent()?;
        store.prune(now);
        let record = store.entry(slot);
        record.next = None;
        store.compact();
        self.write_adjacent(&store)?;
        Ok(true)
    }

    /// Abandon an in-flight overlap. The staged value is demoted to `previous`
    /// rather than destroyed — see [`adjacent::AdjacentStore::prune`] for why.
    /// `Ok(false)` when nothing was staged.
    pub fn discard_overlap(&self, slot: &str) -> Result<bool> {
        validate_provider(slot)?;
        let mut store = self.read_adjacent()?;
        let record = store.entry(slot);
        let Some(staged) = record.next.take() else {
            store.compact();
            self.write_adjacent(&store)?;
            return Ok(false);
        };
        record.push_previous(adjacent::AdjacentValue {
            expires_at: None,
            ..staged
        });
        self.write_adjacent(&store)?;
        Ok(true)
    }

    /// Retain a superseded value for `slot`, newest first, bounded by
    /// [`adjacent::MAX_PREVIOUS`].
    ///
    /// The primitive R856-T11's clobber recovery needs. Nothing calls it from
    /// [`Self::set`] today — turning a plain overwrite into a stashing one is
    /// that ticket's decision to make, not this one's.
    pub fn stash_previous(&self, slot: &str, value: &str) -> Result<()> {
        validate_provider(slot)?;
        let mut store = self.read_adjacent()?;
        store.entry(slot).push_previous(adjacent::AdjacentValue {
            value: value.to_string(),
            lease_id: mint_lease_id(),
            written_at: Utc::now(),
            expires_at: None,
        });
        self.write_adjacent(&store)
    }

    /// Superseded values retained for `slot`, newest first.
    pub fn previous(&self, slot: &str) -> Result<Vec<adjacent::AdjacentValue>> {
        validate_provider(slot)?;
        Ok(self
            .read_adjacent()?
            .get(slot)
            .map(|r| r.previous.clone())
            .unwrap_or_default())
    }

    /// Put a retained value back into `slot` (R856-T11). `index` is into
    /// [`Self::previous`], newest first, as `yah keys recover` prints it.
    ///
    /// Reversible by construction, and with no retention logic of its own: the
    /// restore goes through [`Self::set`], whose one rule already both retains
    /// the credential it displaces and drops the restored entry from the
    /// history (it is no longer *previous* — it is current). Running `recover`
    /// twice returns the slot to where it started rather than filling the ring
    /// with copies of two values.
    ///
    /// Returns the restored value's masked form, never the value: this is the
    /// one operation that moves a secret and it does so without handing it
    /// back to the caller to print.
    pub fn restore_previous(&self, slot: &str, index: usize) -> Result<String> {
        validate_provider(slot)?;
        let retained = self.previous(slot)?;
        let entry = retained.get(index).ok_or_else(|| {
            anyhow!(
                "{slot} has {} retained value{} — there is no #{index}",
                retained.len(),
                if retained.len() == 1 { "" } else { "s" }
            )
        })?;

        self.set(slot, &entry.value)
            .with_context(|| format!("restoring a retained value into {slot}"))?;
        Ok(entry.masked())
    }
}

/// `overlap-<hex>` — the same shape `vault.lease` mints, minus the agent-tools
/// request-id plumbing this crate has no business depending on.
fn mint_lease_id() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::from("overlap-");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
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
    ///
    /// R856-T11: this is the *second* overwrite path, and it does not route
    /// through [`Self::set`] — it writes the whole map in one pass so a partial
    /// import cannot leave the vault half-merged. It therefore calls
    /// [`Self::stash_superseded`] itself rather than reimplementing the rule,
    /// so `yah keys import --strategy merge` over a live slot is as recoverable
    /// as `yah keys set` is. `Skip` never overwrites, so it never stashes.
    pub fn import_map(
        &self,
        incoming: &Map<String, Value>,
        strategy: MergeStrategy,
    ) -> Result<usize> {
        if !self.machine_key_path().exists() {
            self.init(false)?;
        }
        let existing = self.read_creds()?;
        let mut creds = match strategy {
            MergeStrategy::Replace => Map::new(),
            _ => existing.clone(),
        };
        let mut count = 0usize;
        for (k, v) in incoming {
            validate_provider(k)?;
            match strategy {
                MergeStrategy::Merge | MergeStrategy::Replace => {
                    if let Some(new) = v.as_str() {
                        self.stash_superseded(
                            k,
                            new,
                            existing.get(k).and_then(|old| old.as_str()),
                        );
                    }
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

    // -----------------------------------------------------------------------
    // Slot-adjacent store (R856-F9)
    // -----------------------------------------------------------------------

    /// R856-F9's third acceptance criterion, and the reason the overlap value
    /// is not a `<slot>.next` vault entry: the slot namespace `yah keys list`
    /// prints — the authority the credential registry is diffed against — must
    /// not move at all.
    #[test]
    fn staging_an_overlap_leaves_keys_list_byte_identical() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "the-live-one").unwrap();
        s.set("npm-api-token", "npm_live").unwrap();
        let before = s.list().unwrap();

        s.stage_overlap("github-pat", "the-incoming-one", OVERLAP_DEFAULT_TTL_SECS)
            .unwrap();

        assert_eq!(s.list().unwrap(), before, "the slot namespace moved");
        assert_eq!(
            s.get("github-pat").unwrap().as_deref(),
            Some("the-live-one"),
            "staging must never touch the live value"
        );
        assert!(
            s.adjacent_path().exists(),
            "the staged value has to be somewhere"
        );
    }

    /// The lifecycle the ticket asks for, at the store layer: a consumer
    /// resolving through `candidates` reads a usable value at every step, and
    /// the window where the only live credential is unverified never opens.
    #[test]
    fn a_consumer_reads_successfully_at_every_step_of_the_cycle() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("cloudflare-api-token", "old").unwrap();

        // 1. minted, nothing staged yet.
        assert_eq!(s.candidates("cloudflare-api-token").unwrap(), vec!["old"]);

        // 2. staged. Both are live at the provider; current still answers first.
        s.stage_overlap("cloudflare-api-token", "new", OVERLAP_DEFAULT_TTL_SECS)
            .unwrap();
        assert_eq!(
            s.candidates("cloudflare-api-token").unwrap(),
            vec!["old", "new"]
        );

        // 3. promoted.
        assert!(s.promote_overlap("cloudflare-api-token").unwrap());
        assert_eq!(
            s.get("cloudflare-api-token").unwrap().as_deref(),
            Some("new")
        );
        assert_eq!(s.candidates("cloudflare-api-token").unwrap(), vec!["new"]);

        // 4. the superseded value is recoverable until the operator has
        //    revoked it at the provider.
        let previous = s.previous("cloudflare-api-token").unwrap();
        assert_eq!(previous.len(), 1);
        assert_eq!(previous[0].value, "old");
    }

    #[test]
    fn an_expired_lease_stops_being_a_candidate() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "live").unwrap();
        s.stage_overlap("github-pat", "staged", 1).unwrap();

        let later = Utc::now() + chrono::Duration::seconds(120);
        assert_eq!(s.candidates_at("github-pat", later).unwrap(), vec!["live"]);
        assert!(s.overlap_at("github-pat", later).unwrap().is_none());
        // Promoting an expired lease is a no-op, not a silent clobber.
        assert!(!s.promote_overlap_at("github-pat", later).unwrap());
        assert_eq!(s.get("github-pat").unwrap().as_deref(), Some("live"));
    }

    #[test]
    fn the_adjacent_sidecar_is_encrypted_and_0600() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "live").unwrap();
        s.stage_overlap("github-pat", "SUPER-SECRET-VALUE", 600)
            .unwrap();

        let raw = fs::read(s.adjacent_path()).unwrap();
        assert!(
            !raw.windows(18).any(|w| w == b"SUPER-SECRET-VALUE"),
            "the staged credential is sitting in plaintext on disk"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(s.adjacent_path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    /// Aborting is not deletion. The staged value may be send-once, so it is
    /// demoted into the recovery history and the file only disappears once
    /// there is genuinely nothing left.
    #[test]
    fn discarding_an_overlap_retains_the_value_and_eventually_removes_the_file() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "live").unwrap();
        s.stage_overlap("github-pat", "abandoned", 600).unwrap();

        assert!(s.discard_overlap("github-pat").unwrap());
        assert!(s.overlap("github-pat").unwrap().is_none());
        assert_eq!(s.previous("github-pat").unwrap()[0].value, "abandoned");
        assert_eq!(s.candidates("github-pat").unwrap(), vec!["live"]);

        assert!(!s.discard_overlap("github-pat").unwrap());

        // Clearing the history clears the file.
        let mut adj = s.read_adjacent().unwrap();
        adj.slots.clear();
        s.write_adjacent(&adj).unwrap();
        assert!(!s.adjacent_path().exists());
    }

    /// R856-F9 left this test asserting that `set` did *not* stash, because the
    /// decision was T11's to make. T11 made it: every genuine overwrite is now
    /// retained, so the same test pins the same decision, inverted.
    #[test]
    fn stash_previous_is_wired_into_set_and_stays_bounded() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "one").unwrap();
        assert!(
            s.previous("github-pat").unwrap().is_empty(),
            "a first write displaces nothing, so it must retain nothing"
        );

        s.set("github-pat", "two").unwrap();
        assert_eq!(
            s.previous("github-pat")
                .unwrap()
                .iter()
                .map(|v| v.value.as_str())
                .collect::<Vec<_>>(),
            vec!["one"],
            "an overwrite must retain what it displaced — this is the whole ticket"
        );

        for v in ["a", "b", "c", "d", "e"] {
            s.stash_previous("github-pat", v).unwrap();
        }
        let previous = s.previous("github-pat").unwrap();
        assert_eq!(previous.len(), adjacent::MAX_PREVIOUS);
        assert_eq!(previous[0].value, "e");
    }

    /// R856-T11's acceptance criterion. The recovery history is a sidecar, not
    /// a `<slot>.prev` entry, so the slot namespace `yah keys list` prints —
    /// the authority the R856-F1 registry diff is taken against — cannot move.
    #[test]
    fn keys_list_is_byte_identical_across_an_overwrite_that_stashes() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "first").unwrap();
        s.set("npm-api-token", "npm_first").unwrap();
        let before = s.list().unwrap();

        s.set("github-pat", "second").unwrap();
        s.set("npm-api-token", "npm_second").unwrap();
        s.set("github-pat", "third").unwrap();

        assert_eq!(s.list().unwrap(), before, "the slot namespace moved");
        assert!(
            before.iter().all(|slot| !slot.contains(".prev")),
            "the retained values leaked into the slot namespace"
        );
        // …and the history is really there, so this is not passing by doing
        // nothing at all.
        assert_eq!(s.previous("github-pat").unwrap().len(), 2);
    }

    /// A no-op rewrite must not consume a slot in a bounded ring — otherwise
    /// re-saving the same value from a Settings panel three times silently
    /// evicts the one credential somebody needed back.
    #[test]
    fn re_setting_the_same_value_retains_nothing_and_evicts_nothing() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "old").unwrap();
        s.set("github-pat", "new").unwrap();

        for _ in 0..5 {
            s.set("github-pat", "new").unwrap();
        }

        let previous = s.previous("github-pat").unwrap();
        assert_eq!(previous.len(), 1, "a no-op rewrite churned the history");
        assert_eq!(previous[0].value, "old");
    }

    /// A -> B -> A must leave one entry per distinct value. The ring is three
    /// deep, so a duplicate does not merely look untidy: it evicts the oldest
    /// value, which may be the only copy of something left.
    #[test]
    fn a_value_that_comes_back_occupies_one_entry_not_two() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "a").unwrap();
        s.set("github-pat", "b").unwrap();
        s.set("github-pat", "a").unwrap();

        let previous = s.previous("github-pat").unwrap();
        assert_eq!(
            previous.iter().map(|v| v.value.as_str()).collect::<Vec<_>>(),
            vec!["b"],
            "'a' is current, so it is not history; 'b' is the only displaced value"
        );
    }

    /// Restoring is reversible: it goes through `set`, so it retains what it
    /// displaces, and the restored value stops being history because it is
    /// current again.
    #[test]
    fn restoring_is_reversible_and_does_not_leave_the_value_in_two_places() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "the-good-one").unwrap();
        s.set("github-pat", "the-clobber").unwrap();

        let masked = s.restore_previous("github-pat", 0).unwrap();
        assert!(
            !masked.contains("the-good-one"),
            "restore handed back the secret it was asked to move: {masked}"
        );
        assert_eq!(
            s.get("github-pat").unwrap().as_deref(),
            Some("the-good-one")
        );
        assert_eq!(
            s.previous("github-pat")
                .unwrap()
                .iter()
                .map(|v| v.value.as_str())
                .collect::<Vec<_>>(),
            vec!["the-clobber"],
            "the restored value must leave the history, and the clobber must enter it"
        );

        // And back again.
        s.restore_previous("github-pat", 0).unwrap();
        assert_eq!(s.get("github-pat").unwrap().as_deref(), Some("the-clobber"));
    }

    #[test]
    fn restoring_an_index_that_is_not_there_fails_without_touching_the_slot() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "live").unwrap();
        let err = s.restore_previous("github-pat", 0).unwrap_err().to_string();
        assert!(err.contains("0 retained values"), "{err}");
        assert_eq!(s.get("github-pat").unwrap().as_deref(), Some("live"));
    }

    /// `yah keys import --strategy merge` is the *other* overwrite path and it
    /// does not route through `set`, so it wires the same rule itself.
    #[test]
    fn an_import_that_overwrites_a_live_slot_is_as_recoverable_as_a_set() {
        let tmp = TempDir::new().unwrap();
        let s = store_in(tmp.path());
        s.set("github-pat", "the-live-one").unwrap();
        s.set("npm-api-token", "npm_untouched").unwrap();

        let mut incoming = Map::new();
        incoming.insert("github-pat".into(), Value::String("from-the-file".into()));
        s.import_map(&incoming, MergeStrategy::Merge).unwrap();

        assert_eq!(
            s.previous("github-pat").unwrap()[0].value,
            "the-live-one",
            "an import clobbered a live credential with no way back"
        );
        assert!(
            s.previous("npm-api-token").unwrap().is_empty(),
            "a slot the import did not touch must retain nothing"
        );

        // Skip never overwrites, so it never retains.
        let mut second = Map::new();
        second.insert("npm-api-token".into(), Value::String("ignored".into()));
        s.import_map(&second, MergeStrategy::Skip).unwrap();
        assert!(s.previous("npm-api-token").unwrap().is_empty());
        assert_eq!(
            s.get("npm-api-token").unwrap().as_deref(),
            Some("npm_untouched")
        );
    }

    /// A masked rendering is for printing; it must not be a credential.
    #[test]
    fn a_masked_value_shows_a_join_prefix_and_never_the_rest() {
        let v = adjacent::AdjacentValue {
            value: "npm_B0Q8xxxxxxxxxxxxxxxxxxxxxxxxxxxxFF7x".into(),
            lease_id: "overlap-test".into(),
            written_at: Utc::now(),
            expires_at: None,
        };
        let masked = v.masked();
        assert!(masked.starts_with("npm_B0Q8"), "{masked}");
        assert!(!masked.contains("FF7x"), "the suffix is more secret, not less");
        assert!(
            masked.contains(&format!("{} chars", v.value.chars().count())),
            "{masked}"
        );

        // Too short to mask meaningfully: show nothing at all, and not the
        // length either — for a secret this short the count is the disclosure.
        let short = adjacent::AdjacentValue {
            value: "abc123".into(),
            ..v.clone()
        };
        assert_eq!(short.masked(), "<hidden, under 16 chars>");
    }

    /// The eight-character join prefix is a ceiling, not a width. npm justifies
    /// eight characters of a 40-character token; nothing justifies eight of a
    /// twelve-character one, so the prefix is bounded by a fraction of the
    /// value and falls away entirely once there is no join value left in it.
    #[test]
    fn a_masked_value_never_shows_more_than_a_quarter_of_itself() {
        let at = |value: &str| adjacent::AdjacentValue {
            value: value.into(),
            lease_id: "mask-ratio".into(),
            written_at: Utc::now(),
            expires_at: None,
        };

        // The old floor was 12, which showed 8 of 12 characters plus the count.
        assert_eq!(at("abcdefghijkl").masked(), "<hidden, under 16 chars>");
        assert_eq!(at("abcdefghijklmno").masked(), "<hidden, under 16 chars>");

        // At the bound the prefix reappears, still a quarter of the value.
        assert_eq!(at("abcdefghijklmnop").masked(), "abcd... (16 chars)");
        assert_eq!(
            at(&"x".repeat(28)).masked(),
            format!("{}... (28 chars)", "x".repeat(7))
        );

        // And it stops growing at the npm join width no matter how long the
        // value gets, so a 400-character value discloses no more than a 40.
        for len in [32usize, 40, 64, 400] {
            let m = at(&"y".repeat(len)).masked();
            assert_eq!(m, format!("{}... ({len} chars)", "y".repeat(8)), "{m}");
        }
    }
}
