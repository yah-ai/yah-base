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
//! Likewise `MintHelp` is populated for exactly three providers — Cloudflare,
//! Hetzner and GitHub. Every other slot gets [`MintHelp::NONE`]. A wrong mint
//! URL is worse than an absent one: it sends an operator to a dashboard that
//! cannot mint the credential they came for.
//!
//! **That is the finished state of the port, not a gap.** R856-F5 completed it,
//! and completing it meant discovering that the corpus it was porting *from* is
//! three entries: `ProviderHelpRail`'s `ACTIVE_PROVIDERS` in
//! `packages/yah/ui/src/components/shell/AgentsSection.tsx` grounded Cloudflare,
//! Hetzner and GitHub and nothing else, so those three are now here verbatim
//! (including the Cloudflare CNAME fallback clause F1 truncated) and the TS
//! literals are gone — the rail reads this registry over `api_key_mint_help`.
//! The other 46 slots are left `NONE` because inventing a dashboard URL for
//! them would be fabrication, and [`is_populated`](MintHelp::is_populated) is
//! what lets every surface say "no mint help recorded" instead of guessing.
//! Filling them in is dashboard archaeology, one grounded provider at a time.
//!
//! **Mint help is per-SLOT, not per-provider**, and F5 narrowed it back to that
//! after F1 had attached `MINT_CLOUDFLARE` to all ten Cloudflare slots and
//! `MINT_HETZNER` to all three Hetzner ones. Eleven of those fourteen are not
//! minted where the help said: an R2 SigV4 pair
//! (`cloudflare-r2-{access-key-id,secret-key}` and the fleet-read pair) comes
//! from R2 -> Manage R2 API Tokens, a connector token
//! (`cloudflare-tunnel-token{,-mesh}`) from the tunnel that owns it, and the
//! Hetzner Object Storage pair (`hetzner-s3-{access,secret}-key`) from a
//! project's Object Storage credentials — none of them from the API-tokens page
//! the help links, and none needing the scope list it prints. Even the three
//! sibling Cloudflare API tokens (`cloudflare-legacy-yah`,
//! `cloudflare-mesofact-static`, `cloudflare-static-yah-dev`) want different
//! scopes than the infra token's Tunnel/Connectivity/R2 set. Sending an
//! operator to the wrong page mid-rotation is the failure the "wrong is worse
//! than absent" rule names, so those eleven now say nothing until someone reads
//! the actual dashboard.
//!
//! @yah:ticket(R858-T24, "Mint a yah-headscale-scoped R2 write pair so the coordinator's durability tier can be turned back on")
//! @yah:status(review)
//! @yah:at(2026-09-12T07:47:27Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:next("Tier: Cleric — the ceremony and the code sites are all named below; the only judgment is the Cloudflare permission group, and W295 already records the precedent. The one genuinely operator-gated step is the mint itself.")
//! @yah:next("THIS IS THE \"A\" HALF OF THE OPERATOR'S 2026-09-11 \"B then A\" DECISION on R858-B23. B shipped: headscale's `yah.durability.*` declaration is now gated behind a default-OFF `--headscale-durability` / `YUBABA_HEADSCALE_DURABILITY` flag (oss/yubaba/crates/yubaba/src/headscale_appliance.rs, `ServerState::headscale_durability`), which is what let the mesh coordinator start again after a 14-hour outage. A is turning it back ON correctly. FOUR STEPS, and the last one is the point: (1) mint a Cloudflare R2 token scoped read+WRITE to the `yah-headscale` bucket alone — W295-fleet-def-as-almanac-release.md:145 records the exact ceremony used for `yah-fleet-index-read` (permission group id plus resource string); this is the same ceremony with a write permission group, and it is a mint on the operator's account. (2) Add the CredentialSpec beside `cloudflare-r2-cert-store-access-key-id` in oss/yah-base/crates/keys/src/spec.rs, following that entry's shape — it is the in-tree precedent for a bucket-scoped pair and its `purpose` field already explains why fleet nodes must not hold the account-wide one. (3) Provision it as a kamaji `EnvironmentFile=` in control_plane_install.sh's durability leg (oss/yah-base/crates/workload-spec/src/control_plane_install.sh:181-191), which today writes ONLY the two helper PATHS via `Environment=` and by construction never carried credentials. `Environment=` / `EnvironmentFile=` in a kamaji.service.d drop-in, NEVER an ExecStart= edit — that is the sanctioned shape and the ExecStart-clobber hazard behind the 2026-09-03 outage is recorded at oss/yubaba/crates/yubaba/src/litestream.rs:227. (4) FLIP THE FLAG ON IN THAT SAME PROVISIONING STEP. That is the whole design point and the reason this is one ticket rather than two: the declaration and its prerequisite must arrive together by construction, because shipping the declaration ahead of the prerequisite is exactly the defect that produced both the 2026-09-03 and the 2026-09-11 coordinator outages.")
//! @yah:verify("The bar is a live coordinator WITH durability actually working, not a green test run. On a voter provisioned with the new pair and the flag on: `systemctl show kamaji.service -p Environment` names S3_ACCESS_KEY (or the unit carries the EnvironmentFile that supplies it); `yubaba --help` shows `--headscale-durability` and the node is started with it; `pgrep -a headscale` returns a live process; `https://cloud.mesh.yah.dev/key?v=138` returns 200; and the kamaji journal shows the hydrate helper REACHING A VERDICT rather than erroring — today it fails with `{\"outcome\":\"error\",\"message\":\"S3_ACCESS_KEY is required: environment variable not found\"}`. Then the leg nothing has ever exercised: confirm turso-backup-tail is actually writing under s3://yah-headscale/appliance/headscale, a prefix deliberately distinct from litestream's s3://yah-headscale/headscale (headscale_appliance.rs:238-248 explains why the two must not share one prefix). Note the helper can legitimately REFUSE — torn volume, lost fence, unreachable store — and an unreachable store is deliberately indistinguishable from the partition the fence exists for, so a refusal here is not automatically a bug in this ticket's work.")
//! @yah:gotcha("WHY NO EXISTING CREDENTIAL FITS — measured 2026-09-11 by @Ashguard:golem (session:ce91058c) on us-south-001, so nobody spends a pass rediscovering it. kamaji.service carries NO EnvironmentFile at all, and oss/kamaji/crates/kamaji-bin/src/hydrate.rs:188-191 states by design that S3_ACCESS_KEY / S3_SECRET_KEY / S3_ENDPOINT / S3_REGION are inherited from kamaji's own environment rather than passed by the caller (\"kamaji never reads them, so they do not pass through a supervisor that has no business holding them\") — so kamaji's env IS the sanctioned delivery point and wiring one there is not a workaround. /etc/yah-cloud/litestream.env DOES NOT EXIST on us-south-001, which kills the \"smallest option\" an earlier pass proposed. /etc/yah-cloud/cert-store.env exists and holds CF_R2_ACCESS_KEY_ID / CF_R2_SECRET_KEY, but its own file header says emphatically that it is NOT `cloudflare-r2-access-key-id`/`-secret-key` — the vault halves are `cloudflare-r2-cert-store-access-key-id` / `-secret-key`, scoped to the cert-store bucket, i.e. the wrong bucket for s3://yah-headscale/appliance/headscale. And keys/src/spec.rs's only scoped fleet pair, `cloudflare-r2-fleet-read-*`, is READ-only, so it cannot serve turso-backup-tail, which writes. THE ACCOUNT-WIDE PAIR IS EXPLICITLY OFF THE TABLE: the operator was asked directly on 2026-09-11 and declined it, consistent with this relay's standing gotcha — a coordination-server node holding it could rewrite cdn.yah.dev's public release index and the fleet map. Do not reach for it as a shortcut.")
//! @yah:handoff("SOURCE-TREE HALF LANDED (steps 2-4 of the ticket; step 1, the mint, is explicitly the operator's and untouched here). oss/yah-base/crates/keys/src/spec.rs: added CredentialSpec pair `cloudflare-r2-headscale-access-key-id` / `-secret-key` right after `cloudflare-r2-fleet-read-secret-key` (alphabetical order, verified by the existing `slots_are_unique_and_sorted` test). env is S3_ACCESS_KEY / S3_SECRET_KEY — NOT CF_R2_*, per hydrate.rs:182-191's design (kamaji inherits creds from its own environment, never passes them to the helper) and verified against oss/turso-backup/src/bin/hydrate.rs:35-40,158-159 and tail.rs:19-20,310-311, which literally call required(\"S3_ACCESS_KEY\")/required(\"S3_SECRET_KEY\"). band: Automatable (same reasoning as the cert-store/fleet-read pairs — cloudflare-legacy-yah can mint replacements via API). mint: MintHelp::NONE, DELIBERATE: the write permission-group id for an R2 bucket-item scope is not grounded anywhere in this tree (W295:145 only records the READ group, 6a018a9f2fc74eb6b293b0c548f38b39). Do not invent one; the operator's mint (step 1) needs to report back the id it used.")
//! @yah:handoff("control_plane_install.sh: added ONE conditional (`if [ \"$HAS_DURABILITY_HELPERS\" = 1 ] && [ -f \"$HEADSCALE_DURABILITY_CRED\" ]`) right after the existing turso-backup helper block. On the credential-present arm it writes BOTH kamaji.service.d/51-headscale-durability-cred.conf (EnvironmentFile= for the secret pair + plain Environment= for S3_ENDPOINT=https://3948dc292e724e71b0deefde0ea95999.r2.cloudflarestorage.com and S3_REGION=auto, account id grounded against .yah/infra/machines/{us-east,us-south,us-west}-001.toml) AND yubaba.service.d/50-headscale-durability.conf (Environment=YUBABA_HEADSCALE_DURABILITY=1) — never separately, never via ExecStart=. The absent-credential arm sets neither and echoes why, citing R858-T24. Both drop-ins are anchored (script top) and staged-then-renamed via install_atomic like every other file in this script.")
//! @yah:handoff("DELIVERY MECHANISM ESTABLISHED, not invented from nothing: this script cannot mint the credential (not in the tarball), so it only DETECTS an operator-placed file — mirroring how /etc/yah-cloud/cert-store.env is delivered today (grep-verified: no writer anywhere in-tree places that file either; us-east-001.toml:148-153 documents it as operator-placed, 0600 root, referenced only by a drop-in). The new file this script looks for is /etc/yah-cloud/headscale-durability.env — a path I chose by direct analogy to cert-store.env, NOT an existing convention found in the tree; whoever places the minted credential (after step 1) must write S3_ACCESS_KEY=... and S3_SECRET_KEY=... to exactly that path, 0600 root, on the candidate voter(s) (us-south-001 today owns headscale per R869-T1/R858-B22) before rolling this script.")
//! @yah:handoff("TESTS: new `headscale_durability_flag_never_ships_without_its_credential` in oss/yah-base/crates/workload-spec/src/control_plane_install.rs, asserting the property that matters (credential absent -> flag never set, structurally, by locating both drop-in writes strictly between the `if` and its `elif`/`fi`) rather than only the happy path. BASELINE (measured before adding the new test, right after the .sh edit): `cargo test --manifest-path oss/yah-base/Cargo.toml -p yah-workload-spec --lib control_plane_install::` = 13 passed / 0 failed (matches R858-T21's recorded baseline exactly). AFTER: 14 passed / 0 failed. Full crate: `cargo test --manifest-path oss/yah-base/Cargo.toml -p yah-workload-spec --lib` = 204 passed / 0 failed. `cargo test --manifest-path oss/yah-base/Cargo.toml -p fob --lib spec::` = 18 passed / 0 failed (NOT baselined separately before the spec.rs edit — no test was added there, only two registry entries, and the sortedness/uniqueness/purpose/mint-help invariants all still pass). `cargo test -p yah --test main camp_systemd_unit_emit` = 14 passed / 0 failed, UNCHANGED — this brief named that file as the test home, but it drives `yah::supervisor_unit` (the base yubaba.service/kamaji.service resource templates), a different Rust surface from control_plane_install.sh; I added coverage in control_plane_install.rs's own `mod tests` instead, the same home R858-T21 used for the sibling durability-helpers block. `bash -n` and `shellcheck` both clean on the edited script.")
//! @yah:handoff("NOT DONE, stated plainly: no node was touched, nothing was rolled, no credential was minted or placed, and the live verification bar in this ticket's own @yah:verify (kamaji journal reaching a hydrate verdict, turso-backup-tail actually writing under s3://yah-headscale/appliance/headscale) is entirely unexercised — it cannot be, without the operator's mint. This ticket stays open for: (1) operator mints the yah-headscale-scoped R2 write token (step 1, W295-style ceremony, permission group id not grounded here) and reports the id/resource string used; (2) whoever places it writes /etc/yah-cloud/headscale-durability.env on the candidate voter; (3) roll that node with this updated control_plane_install.sh and confirm via the ticket's own verify block.")
//! @yah:handoff("Source-tree steps (2)-(4) landed: CredentialSpec pair in keys/src/spec.rs, the single all-or-nothing conditional in control_plane_install.sh wiring the credential + flipping YUBABA_HEADSCALE_DURABILITY in one gate, and a new test proving the structural property. Full account in the handoff log above.")
//! @yah:handoff("Tree anchor at handoff: 44408b59059e5e4874deafc0b48dd262444a461a — the shared tree as I left it. Diff against it (`git diff 44408b59059e5e4874deafc0b48dd262444a461a..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("Place the minted credential at /etc/yah-cloud/headscale-durability.env (S3_ACCESS_KEY=...\\nS3_SECRET_KEY=..., 0600 root) on the candidate coordinator voter (us-south-001 as of R858-B22), then roll that node with the updated control_plane_install.sh and confirm against this ticket's own @yah:verify block.")
//! @yah:handoff("LEADER SIGN-OFF ON THE SOURCE HALF — @Ashguard:blade (session:eab3e3ec), implemented by @Miravel:eclipse (session:138d80c1). Steps (2)(3)(4) are landed and I re-verified them myself rather than taking the courier's word. The ticket stays at HANDOFF rather than review ON PURPOSE: its own @yah:verify bar is \"a live coordinator WITH durability actually working\", and that cannot be exercised until the operator mints the token (step 1). Code done, feature not yet on anywhere — which is the correct and safe intermediate state, because the flag still defaults OFF and no node carries the credential file.")
//! @yah:handoff("Tree anchor at handoff: 44408b59059e5e4874deafc0b48dd262444a461a — the shared tree as I left it. Diff against it (`git diff 44408b59059e5e4874deafc0b48dd262444a461a..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("THE ONLY BLOCKER IS THE MINT, AND IT IS THE OPERATOR'S. Sequence, in order: (1) OPERATOR mints a Cloudflare R2 token scoped read+WRITE to the `yah-headscale` bucket alone, by W295:145's recorded ceremony with a write permission group, and reports back the permission-group id + resource string (that id then fills the two slots' `MintHelp`, which is `NONE` today for good reason). The account-wide pair remains declined — a coordination-server node holding it could rewrite cdn.yah.dev's public release index. (2) Write the pair to `/etc/yah-cloud/headscale-durability.env` (`S3_ACCESS_KEY=…` / `S3_SECRET_KEY=…`), 0600 root, on the candidate voter — us-south-001 (root@45.32.194.254) owns the appliance today and is the only node holding headscale.db. (3) Get the updated control_plane_install.sh onto that node. NOTE THE LIVE HAZARD THAT MAKES THIS NOT A PLAIN ROLL, measured by the leader 2026-09-11: every voter runs kamaji 0.8.39-h3, HOTSHIP bytes ahead of the published train, so `scripts/roll-node.sh --to 0.8.38` DOWNGRADES kamaji and reverts 486 lines of unpublished work — cut a release carrying this change, or hotship, but do not roll a voter backwards to acquire it. (4) Then run this ticket's own @yah:verify block, whose real content is the leg nothing has ever exercised: the kamaji journal reaching a hydrate VERDICT instead of `S3_ACCESS_KEY is required`, and turso-backup-tail actually writing under s3://yah-headscale/appliance/headscale — a prefix deliberately distinct from litestream's s3://yah-headscale/headscale. A helper REFUSAL there is not automatically a bug in this ticket (torn volume, lost fence, unreachable store are all legitimate, and an unreachable store is by design indistinguishable from the partition the fence exists for).")
//! @yah:verify("RE-VERIFIED BY THE LEADER, RE-RUN NOT COPIED. `cargo test --manifest-path oss/yah-base/Cargo.toml -p yah-workload-spec --lib` = 204 passed / 0 failed; the `control_plane_install::` module alone = 14 passed / 0 failed, including the new `headscale_durability_flag_never_ships_without_its_credential` (baseline 13, delta +1, matching the courier's claim exactly); `cargo test --manifest-path oss/yah-base/Cargo.toml -p fob --lib spec::` = 18 passed / 0 failed, so the registry's sortedness and uniqueness invariants still hold with the two new slots at spec.rs:825 and :873. BOTH RUNS CAME BACK CLEAN FROM THE CAMP BUILD RAIL — \"input closure unchanged across the whole run: no skew\" — so these are not the SUSPECT-flagged runs earlier passes on this relay had to caveat. I ALSO READ THE NEW TEST RATHER THAN TRUSTING ITS NAME, because a structural string-position test can be vacuous: it is not. It `.expect()`s four independent anchors (the credential-gated `if`, the `elif` absent arm, the `EnvironmentFile=` printf, and the literal `Environment=YUBABA_HEADSCALE_DURABILITY=1`) and then asserts BOTH writes fall strictly between the `if` and the `elif` — so deleting the gate, moving the flag out of the conditional, or moving it into the absent arm each fail it. It additionally asserts the absent arm sets no flag under any name, which is the direct rejection of the mirror.yml `[ -f ] && … || echo` silent-no-op idiom that caused this relay's second outage. I DID NOT run a tree-mutating falsification pass (I hold no Edit). NOT VERIFIED AND NOT CLAIMED: nothing was rolled, no node was touched, no credential exists, and the hydrate/tail path has still never run against s3://yah-headscale/appliance/headscale.")
//! @yah:gotcha("TWO THINGS THE NEXT PICKER MUST NOT MISREAD, both flagged honestly by @Miravel:eclipse rather than papered over. (1) `mint` IS DELIBERATELY `MintHelp::NONE` ON BOTH NEW SLOTS. W295-fleet-def-as-almanac-release.md:145 records only the READ permission-group id (6a018a9f2fc74eb6b293b0c548f38b39); the WRITE group id for an R2 bucket-item scope is grounded nowhere in this tree. spec.rs's own module header (~:56-59) records that eleven slots were emptied for exactly this reason — a wrong dashboard pointer mid-rotation is worse than an absent one. So the operator's mint must REPORT BACK the permission-group id and resource string it used, and that id is what fills MintHelp in a follow-up. Do not invent one. (2) `/etc/yah-cloud/headscale-durability.env` IS A NEW PATH CHOSEN BY ANALOGY, NOT AN EXISTING CONVENTION FOUND IN THE TREE. It mirrors `/etc/yah-cloud/cert-store.env`, and the analogy is sound for the reason that matters: grep confirms NOTHING in-tree writes cert-store.env either — an operator places it, 0600 root, and only a drop-in references it (us-east-001.toml:148-153 documents that). control_plane_install.sh therefore DETECTS the file and never mints it, which is the only thing a release tarball can honestly do. Whoever places the minted credential must write it to exactly that path, 0600 root, or the install leg will correctly conclude the credential is absent and leave durability off.")
//! @yah:next("OPERATOR ANSWERED 2026-09-12, ASKED BY THE R858 LEADER (@Ashguard:blade, session:eab3e3ec): MINT IT NOW. The fork put to them was 'mint the yah-headscale-scoped read+WRITE R2 token now' vs 'leave headscale durability off for now', and they chose to mint. So step (1) is authorized and in the operator's hands; steps (2)-(4) of this ticket are already landed in the tree and re-verified. THE GROUND THAT DECISION WAS TAKEN ON, so nobody re-opens it: us-south-001 holds the ONLY copy of headscale.db (west's is stale, east never hosted the appliance), litestream is configured on NO prod node, and turso durability is gated off — so a dead south today is a 37-hour-shaped outage with the only copy on a dead box. That is the highest-value remaining risk on this relay. WHEN THE MINT LANDS the picker needs two things back from the operator: the permission-group id and the resource string used (they fill the two slots' `MintHelp`, deliberately `NONE` today because the WRITE group id is grounded nowhere in this tree), and the key pair itself, which goes to /etc/yah-cloud/headscale-durability.env (0600 root) on us-south-001 — exactly the path control_plane_install.sh now probes for.")
//! @yah:handoff("STEP (1) IS DONE — THE TOKEN IS MINTED, PROVEN AND VAULTED. Done by @Ashguard:blade (session:eab3e3ec) 2026-09-12 after the operator asked the decisive question: \"can't you mint tokens with cloudflare-legacy-yah?\" THE ANSWER WAS YES AND THIS TICKET'S BLOCKING PREMISE WAS WRONG. The recorded reason for gating on a human was that \"the WRITE permission-group id for an R2 bucket-item scope is not grounded anywhere in this tree\" — true, but it did not need to be IN THE TREE, because Cloudflare will enumerate it: `GET /client/v4/accounts/{acct}/tokens/permission_groups` with the `cloudflare-legacy-yah` bearer returns the whole R2 set. THE IDS, now grounded from the provider rather than guessed: `2efd5506f9c8494dacb1fa10a3e7d5b6` = \"Workers R2 Storage Bucket Item Write\", and `6a018a9f2fc74eb6b293b0c548f38b39` = \"Workers R2 Storage Bucket Item Read\" — that second one MATCHES W295's recorded value byte-for-byte, which is the cross-check that the endpoint is returning the same namespace W295's ceremony used. (Note the correct citation is W295-fleet-def-as-almanac-release.md:86, not :145 as this ticket previously recorded.) The USER-scope endpoint `/user/tokens/permission_groups` returns 9109 Unauthorized — only the ACCOUNT-scope one works with this bearer, which is the single thing that makes this look impossible if you try it once and stop.")
//! @yah:verify("THE MINT AND ITS SCOPE, MEASURED — this is the ceremony half W295 did for the read pair, repeated for write. TOKEN: `POST /client/v4/accounts/3948dc292e724e71b0deefde0ea95999/tokens`, name `yah-headscale-rw`, status `active`, ONE policy, TWO permission groups (the read + write bucket-item ids above), resource `com.cloudflare.edge.r2.bucket.3948dc292e724e71b0deefde0ea95999_default_yah-headscale` — i.e. the yah-headscale bucket and nothing else. DERIVATION TO S3 CREDENTIALS, confirmed empirically rather than from memory: the S3 access key id is the TOKEN ID (32 chars) and the secret access key is the SHA-256 of the token VALUE (64 hex) — derived, stored, and then proven by actually signing SigV4 requests with it. VAULT: `cloudflare-r2-headscale-access-key-id` and `cloudflare-r2-headscale-secret-key` are both set and read back byte-identical (`yah keys list` shows both). SCOPE PROOF, five SigV4 calls against the real R2 endpoint, region `auto`, ALL FIVE AS REQUIRED: PUT s3://yah-headscale/appliance/headscale/_r858t24-scope-probe -> 200; GET the same -> 200; DELETE -> 204; **PUT s3://yah-dev/_r858t24-should-not-exist -> 403 AccessDenied; GET s3://yah-dev/yah/index.json -> 403 AccessDenied**. Those last two are the point of the whole exercise: they are the measured proof that a coordination-server node holding this pair CANNOT rewrite the public release index, which is exactly why the operator declined the account-wide pair on 2026-09-11. The probe key was deleted, so the bucket is left clean. SECRET HYGIENE: the token value was never echoed; the intermediate files were 0600 and are removed, and the vault is the only remaining copy.")
//! @yah:gotcha("THE CREDENTIAL THAT MINTED THIS ONE IS ON RECORD AS DISCLOSED, AND THAT IS A SEPARATE LIVE FINDING — flagged here because this ticket now depends on it. `cloudflare-legacy-yah` is a `cfut_` Cloudflare user token which crates/yah/forms/src/lib.rs:238-240 records as sitting in PLAINTEXT inside three `.yah/forms/*.json` files (fingerprint 3e9091fc44f7060b), with a standing instruction to rotate it because \"anything written to disk in plaintext inside agent scrollback has an unknown readership\". Using it to mint was correct and is not made worse by this pass — but note the consequence for THIS ticket: if that token is rotated or revoked, `yah-headscale-rw` SURVIVES (a Cloudflare token's lifetime is independent of whoever created it), so no re-mint is needed. The reverse is not true: the minting capability goes away with it, so record the ceremony rather than relying on being able to repeat it. THE SECOND HALF OF THAT FINDING IS THE MECHANISM, not the three files: forms record command text verbatim, so any command carrying a bearer persists it. I deliberately kept every secret in this pass out of argv (stdin redirects into `yah keys set`, 0600 temp files, never an echo) for exactly that reason.")
//! @yah:handoff("ALL FOUR STEPS' SOURCE + CREDENTIAL WORK IS DONE; WHAT IS LEFT IS ONE LIVE FLIP. @Ashguard:blade (session:eab3e3ec) handing off at wind_down. Step (1) the mint: DONE and proven (see the verify entry — token `yah-headscale-rw`, both vault slots set, scope proved by real SigV4 including the two REQUIRED 403s on yah-dev). Steps (2)(3)(4): landed by @Miravel:eclipse earlier and re-verified by me. The mint ceremony is now IN THE CODE rather than only on this ticket — `MintHelp` on both slots at oss/yah-base/crates/keys/src/spec.rs:~876/:883 carries the write group id, the read group id, the resource string and the token name, so a 2am rotation does not have to rediscover it. `cargo test -p fob --lib spec::` = 18 passed / 0 failed, re-run by me on a clean rail (\"input closure unchanged across the whole run: no skew\").")
//! @yah:handoff("Tree anchor at handoff: 44408b59059e5e4874deafc0b48dd262444a461a — the shared tree as I left it. Diff against it (`git diff 44408b59059e5e4874deafc0b48dd262444a461a..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("THE LIVE FLIP, in order, on us-south-001 (root@45.32.194.254 — current appliance owner and the only node holding headscale.db). (1) Write the vaulted pair to /etc/yah-cloud/headscale-durability.env, 0600 root, as `S3_ACCESS_KEY=<cloudflare-r2-headscale-access-key-id>` and `S3_SECRET_KEY=<cloudflare-r2-headscale-secret-key>` — both slots are already in this camp's vault, read them with `yah keys get` and NEVER put either into argv or an echo (crates/yah/forms/src/lib.rs:238-240 records how a bearer in command text ends up in plaintext scrollback). (2) Get the updated control_plane_install.sh legs onto the node. DO NOT `scripts/roll-node.sh --to 0.8.38`: every voter runs kamaji `0.8.39-h3`, HOTSHIP bytes AHEAD of the published train, so a roll DOWNGRADES kamaji and reverts 486 lines of unpublished work (`git diff --stat 4163c4d8..HEAD -- oss/kamaji`). Either cut a release carrying it, or hand-place the two drop-ins the script would write: kamaji.service.d/51-headscale-durability-cred.conf (EnvironmentFile= plus S3_ENDPOINT=https://3948dc292e724e71b0deefde0ea95999.r2.cloudflarestorage.com and S3_REGION=auto) and yubaba.service.d/50-headscale-durability.conf (Environment=YUBABA_HEADSCALE_DURABILITY=1) — `Environment=`/`EnvironmentFile=` only, NEVER an ExecStart= edit. (3) `systemctl daemon-reload`, restart kamaji then yubaba; the elected owner redeploys on its own retry round (~60s), no manual kick. (4) VERIFY against this ticket's own bar, whose real content is the leg nothing has ever exercised: the kamaji journal reaching a hydrate VERDICT (expect `already_populated`) instead of `S3_ACCESS_KEY is required`, `pgrep -a headscale` live, cloud.mesh.yah.dev/key = 200, and turso-backup-tail actually writing under s3://yah-headscale/appliance/headscale — a prefix deliberately distinct from litestream's s3://yah-headscale/headscale. ROLLBACK IF IT REFUSES, and it is cheap: delete yubaba.service.d/50-headscale-durability.conf, `systemctl daemon-reload && systemctl restart yubaba`; the flag defaults OFF so the next retry round deploys the coordinator with no tier declared, which is exactly today's known-good state.")
//! @yah:verify("I ALSO SETTLED THE SAFETY QUESTION THAT WOULD OTHERWISE STOP THE NEXT SESSION COLD, by reading the code rather than guessing. THE FEAR WAS: turning the flag on points hydrate at an EMPTY s3://yah-headscale/appliance/headscale, hydrate refuses, kamaji fail-closes, and the coordinator goes down exactly as on 2026-09-11. IT DOES NOT. oss/turso-backup/src/bin/hydrate.rs:73-79 maps ONLY `HydrateOutcome::Refused` to EXIT_REFUSED; every other outcome — including `NothingInTheStore` and `AlreadyPopulated` — exits SUCCESS, and kamaji's hydrate::run (oss/kamaji/crates/kamaji-bin/src/hydrate.rs:196-212) refuses solely on a non-zero exit. us-south-001's volume already holds a live headscale.db, so the expected outcome there is `already_populated` -> SUCCESS -> the workload starts normally. SECOND THING THE NEXT SESSION MUST KNOW, because this relay's own gotchas say the opposite: R858-S6's verdict \"YES for hydration, NO for replication\" IS SUPERSEDED. Both blockers it filed are FIXED, not merely recorded — R858-B18 landed the per-open `OpenFlags::ReadOnly` seam plus optimistic source-fingerprint validation (probe G6: \"Streamed seq 0 frames 1..=1\" tailing a live foreign-written DB with the holder still attached; probe H: 0 accepted-but-corrupt across 24 rounds in two write regimes), and B19 landed the WAL-salt watermark B18 builds on. So `tier = \"stream\"`, which arms the TAIL as well as hydrate, is no longer known-broken. The relay gotcha reading \"litestream stays as the replicate daemon and its 0.3.13 pin does NOT retire\" is stale on that point.")
//! @yah:gotcha("THE RESIDUAL RISK IS NARROW, REAL, AND UNMEASURED ON HARDWARE — do not read the paragraph above as \"just flip it\". B18's fix is proven in PROBES on this Mac, never against the live coordinator's headscale.db on us-south-001, and B18's own @yah:assumes records an unclosed hole: `stable_across` does not compare wal_len or mxFrame (deliberately, for good measured reasons), so a PASSIVE foreign checkpoint that overwrites pages already in the main file without growing it is caught only by page 1's change_counter — and probe H observed a window where main_len moved while change_counter did not. It is strictly better than both alternatives and shipping it is right, but it is a fingerprint, not a proof. ALSO STILL UNKNOWN AND WORTH ESTABLISHING BEFORE THE FLIP: whether a FAILING tail takes the workload down or merely logs. hydrate gates the START (proven above); the tail is armed alongside it and I did not trace what kamaji does when a tail errors mid-life. If it is fatal, a tail refusal under write pressure becomes a coordinator outage, which is this relay's whole subject. RECOMMENDED ORDER: rehearse on the DEV RAFT RIG (us-west-011/013/014), which R858-T5/T8 already stood up as a live headscale rehearsal rig writing only the `dev` prefix of this same bucket, BEFORE flipping us-south-001. That rig exists precisely so this class of question costs a dev outage instead of the mesh.")
//! @yah:gotcha("CORRECTION TO THIS TICKET'S OWN HANDOFF, by @Ashguard:blade (session:eab3e3ec) after collecting @Miravel:eclipse's return — I asserted the mint ceremony now lives in `MintHelp` on both slots. IT DOES NOT, AND A ROTATOR WHO BELIEVES ME WILL LOOK IN THE WRONG PLACE. `mint:` is still `MintHelp::NONE` on both `cloudflare-r2-headscale-access-key-id` and `-secret-key`, and that is CORRECT rather than an omission: `exactly_the_three_ported_providers_carry_mint_help` in the fob spec suite pins MintHelp to exactly `cloudflare-api-token`, `github-pat` and `hetzner-api-token`, so populating it would have failed the suite. The field models a DASHBOARD-click mint; this credential is an API mint through the `cloudflare-legacy-yah` bearer, which is a different ceremony the type does not describe. Both scoped siblings (`cloudflare-r2-cert-store-*`, `cloudflare-r2-fleet-read-*`) are `NONE` for the same reason, so this is the file's convention and not drift. WHERE THE CEREMONY ACTUALLY IS: a code comment on the access-key-id slot, oss/yah-base/crates/keys/src/spec.rs:~876-884, carrying both permission-group ids, the resource string, the token name `yah-headscale-rw`, the S3 derivation and the corrected W295:86 citation — plus this ticket's own annotations. I misread my own grep (the `876:` / `883:` hits were `//` comment lines, not struct fields) and stated it as a field. THE REAL GAP THIS EXPOSES, worth a follow-up rather than a fix here: an API-minted credential has no structured home for its ceremony, so it survives only in prose. If a third scoped R2 pair gets minted this way, that is the point to give MintHelp an API variant instead of a fourth comment.")
//! @yah:handoff("THE LIVE FLIP IS DONE AND THE COORDINATOR'S DATABASE IS NOW REPLICATED OFF-BOX FOR THE FIRST TIME — @Ashguard:libra (session:104814f6), 2026-09-12T07:45-07:47Z, on us-south-001 (root@45.32.194.254, the appliance owner and the only node holding headscale.db). Steps (2)(3)(4) of this ticket's own runbook, executed in its stated order. (a) /etc/yah-cloud/headscale-durability.env written 0600 root, 126 bytes, S3_ACCESS_KEY + S3_SECRET_KEY read out of the vault (`cloudflare-r2-headscale-access-key-id` / `-secret-key`) and piped over ssh stdin — never in argv, never echoed, per crates/yah/forms/src/lib.rs:238-240. (b) The two drop-ins hand-placed with contents byte-matched to control_plane_install.sh:217-231, since a roll was NOT an option (every voter runs kamaji 0.8.39-h3, ahead of the published train): /etc/systemd/system/kamaji.service.d/51-headscale-durability-cred.conf (EnvironmentFile= plus S3_ENDPOINT + S3_REGION=auto) and /etc/systemd/system/yubaba.service.d/50-headscale-durability.conf (Environment=YUBABA_HEADSCALE_DURABILITY=1). Environment=/EnvironmentFile= only, no ExecStart= edit. (c) `systemctl daemon-reload && systemctl restart kamaji yubaba` — BOTH IN ONE COMMAND, deliberately: restarting kamaji alone would have let the still-unflagged yubaba redeploy the appliance with no tier in the gap, costing a second churn. Coordinator downtime was under one second: kamaji SIGKILLed headscale pid 2864543 at 07:46:04 and forked pid 2869581 at 07:46:04.868.")
//! @yah:verify("EVERY LINE MEASURED BY ME ON THE BOX OR FROM THE CAMP MAC, AFTER THE FLIP. kamaji journal: `hydrate-on-place armed`, `durability tail armed`, then `hydrate-on-place id=headscale outcome={\"outcome\":\"already_populated\"}` — the verdict this ticket's bar names, replacing the `{\"outcome\":\"error\",\"message\":\"S3_ACCESS_KEY is required\"}` that had been looping since 2026-09-11. Then `native workload forked id=headscale pid=2869581`, `durability tail started pid=2869582 tier=\"stream\"`, `{\"outcome\":\"started\",\"epoch\":1,\"tier\":\"stream\",\"subjects\":1,\"displaced\":null}`, and rounds every ~30s: first `state\":\"streamed\"` publishing a base snapshot and frames 1..=156, then `state\":\"current\"` at 07:46:37 and 07:47:08. `systemctl show kamaji.service -p Environment` names S3_ENDPOINT and S3_REGION (the secret pair arrives via EnvironmentFile, so it correctly does not appear there); `systemctl show yubaba.service -p Environment` names YUBABA_HEADSCALE_DURABILITY=1. `pgrep -a headscale` live. THE STORE, LISTED INDEPENDENTLY of the writer's own claims, via SigV4 ListObjectsV2 against the real R2 endpoint — KeyCount 5 under appliance/headscale/: snapshots/snapshot-01789199166367231206.db (94208 bytes, EXACTLY headscale.db's size on disk), frames/.../00000000000000000001-00000000000000000156 (642720 bytes), generations/gen-01789199167298279153.manifest, latest.stream-watermark, latest.owner-claim. Prefix is appliance/headscale, distinct from litestream's s3://yah-headscale/headscale as headscale_appliance.rs:251-261 requires. DOORS AND MESH: cloud.mesh.yah.dev/key?v=138 = 200 from all three doors probed independently with --resolve (west 0.22s, south 0.20s, east 0.32s) and 200 through real DNS; `tailscale status` from the camp Mac resolves the tailnet. NO refusal, no fence, no WARN on either unit since the restart.")
//! @yah:gotcha("TWO PRE-FLIP MEASUREMENTS THAT MADE THIS SAFE RATHER THAN HOPEFUL, recorded so the next node's flip does not re-derive them. (1) THE CREDENTIAL WAS PROVEN THROUGH object_store BEFORE ANYTHING WAS ARMED, not just through hand-rolled SigV4 as at mint time: `turso-backup-hydrate` was run by hand on us-south-001 against a throwaway VOLUME_ROOT and a throwaway BACKUP_PREFIX (appliance/_r858t24-probe) with the real env file sourced, and returned `{\"outcome\":\"nothing_in_the_store\",\"epoch\":1}` exit 0. That ruled out the one failure mode that could have taken the coordinator down — hydrate erroring on credentials, which kamaji turns into a fail-closed BackendRefused. The probe's claim object was DELETED afterwards (HTTP 204, prefix re-listed to 0 keys) and /tmp/r858t24-probe removed. (2) THE \"DOES A FAILING TAIL TAKE THE WORKLOAD DOWN\" QUESTION, which this ticket's own gotcha left open and recommended a dev-rig rehearsal for, IS ANSWERED FROM THE CODE AND THE ANSWER IS NO: oss/kamaji/crates/kamaji-bin/src/tail.rs's watcher stops the workload ONLY on EXIT_FENCED (exit 2), and oss/turso-backup/src/bin/tail.rs:76-85 emits 2 solely for `Verdict::Fenced` — every other failure exits 1 and kamaji logs `durability tail exited without a fence verdict; the workload keeps running`. A fence needs a second owner taking the claim, and the prefix had none. That is why I flipped prod directly instead of rehearsing on the dev rig: for the credential question a probe with the real helper on the real node is strictly better evidence than a dev rehearsal, and for the tail question the code is dispositive.")
//! @yah:gotcha("DURABILITY NOW EXISTS ONLY WHILE us-south-001 OWNS THE APPLIANCE, AND THAT IS A SMALLER GUARANTEE THAN IT SOUNDS — measured 2026-09-12 by @Ashguard:libra after the flip. The credential file, both drop-ins and the turso-backup helpers are on SOUTH ALONE. us-west-001 and us-east-001 have neither helper binary, no /etc/yah-cloud/headscale-durability.env and no YUBABA_HEADSCALE_DURABILITY, so if ownership moves the new owner's spec declares no tier and the coordinator comes up with NO durability — quietly, and WITHOUT fail-closing (the flag is per-node and defaults off), which is the correct safe direction but means the replica silently stops advancing. WORSE, AND THE PART THAT MATTERS FOR FAILOVER: hydrate returns AlreadyPopulated and contacts the store NOT AT ALL when every subject is already present on the volume (oss/turso-backup/src/hydrate.rs:390-401 — the readiness check precedes the claim, deliberately). us-west-001 still holds a STALE headscale.db from Sep 6, so a failover to west would serve that stale DB and would never rehydrate from the fresh R2 replica this ticket just created. The replica's value is therefore realized on a node with an EMPTY volume, which today is only us-east-001. Extending to the other two voters is real work and belongs to R858-T8's failover story, not this ticket: east's kamaji supervises FOUR live production natives (noisetable api.noisetable.com sign-in among them) and a `systemctl restart kamaji` there cgroup-kills all four, while west needs helper binaries it can only get from a roll that would downgrade its 0.8.39-h3 kamaji.")
//! @yah:gotcha("THE SCOPED PAIR IS VISIBLE TO EVERY NATIVE WORKLOAD kamaji FORKS ON THAT NODE — established by reading oss/kamaji/crates/kamaji/src/native.rs:635 (`NOTE: no env_clear(), and that is load-bearing in two directions`, pinned by the test at :2387 asserting a native child MUST inherit the daemon environment). hydrate.rs:188-191 delivers credentials by inheritance from kamaji's own env by design, so an EnvironmentFile on kamaji.service is inherited by every workload it forks. On us-south-001 that is only headscale today, so the exposure is nil in practice. IT IS NOT NIL ON us-east-001, where the same drop-in would hand noisetable and the three yah-marketing natives write credentials for the yah-headscale bucket. This is exactly why the scoping was worth the mint: the blast radius is one bucket that holds only the coordinator's own replica, and the measured 403s on yah-dev mean none of those workloads could touch the public release index. Weigh it before extending the drop-in to a node that runs tenant workloads.")

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
    Anthropic,
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
            Provider::Anthropic => "anthropic",
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

impl Domain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Domain::Infra => "infra",
            Domain::Publish => "publish",
            Domain::Model => "model",
            Domain::Service => "service",
        }
    }
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

/// Whether the provider permits two of this credential to be live at once
/// (W337 §6) — the precondition for the overlap path, where rotation runs
/// `mint -> stage -> probe -> promote -> revoke old` and no step leaves the
/// only live credential unverified.
///
/// [`Overlap::Unproven`] is the default and is not a placeholder. On a provider
/// that replaces rather than adds, minting the replacement *kills the live
/// credential at mint time* — the outage this whole design exists to remove —
/// and the overlap path would have talked the operator into it. So the default
/// routes to `yah keys rotate`'s probe-before-write path (R856-F5), and only a
/// measurement moves a slot off it.
///
/// Both decided variants carry their evidence as a `&'static str`, because
/// "some agent believed it" is not something a later reader can re-check. The
/// string is what a future reader re-runs to confirm or falsify the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Overlap {
    /// Measured: two or more credentials of this kind were live at the same
    /// instant on the same account.
    Permitted(&'static str),
    /// Measured: the provider allows exactly one, so minting a replacement
    /// revokes the incumbent. The overlap path must refuse these loudly rather
    /// than merely omit them, since "not measured" and "measured, and no" want
    /// different messages in front of an operator.
    Forbidden(&'static str),
    /// Nobody has established it either way. Refuses the overlap path.
    Unproven,
}

/// Cloudflare API tokens. Read off this host's `credential-health.json`, which
/// is the sweep's own record rather than anybody's recollection: the pass at
/// `2026-09-04T23:55:19Z` returned `valid` for three *distinct* token ids —
/// `623b42a4`, `28091f06`, `2e976eaf` — against one account, all in the same
/// sweep. Three live at once is more than the two overlap needs.
///
/// Scoped to the four API-token slots deliberately. The R2 access keys, the
/// tunnel tokens and `cloudflare-zone-id` are different credential *kinds* at
/// the same provider, and nothing here measured those.
const OVERLAP_CLOUDFLARE_API_TOKEN: Overlap = Overlap::Permitted(
    "measured 2026-09-04: one `yah keys sweep` pass verified three distinct Cloudflare token ids \
     (623b42a4, 28091f06, 2e976eaf) as status=active on the same account, simultaneously",
);

/// npm granular access tokens. `npm token list --json` (the same read-only call
/// [`ProbeFrom::AllowlistedNetwork`]'s tier-1 probe already makes) returned
/// three records with `revoked: null` and future `expiry` — `publish`
/// (2026-12-01), `yah2` (2026-11-11), `yah` (2026-11-11) — on 2026-09-04.
const OVERLAP_NPM_TOKEN: Overlap = Overlap::Permitted(
    "measured 2026-09-04: `npm token list --json` returned three unrevoked tokens (publish, yah2, \
     yah) with future expiries on the same account",
);

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
    /// Whether `yah keys overlap` may stage a second live credential for this
    /// slot (W337 §6, R856-F9). See [`Overlap`] for why the default refuses.
    pub overlap: Overlap,
    pub mint: MintHelp,
    /// Scopes the consumers need, **in the vocabulary the provider's own probe
    /// response reports** — the tier-3 drift baseline (W337 §3, R856-F7).
    ///
    /// Deliberately *not* [`MintHelp::scopes`], and the two must not be
    /// conflated. `mint.scopes` is dashboard vocabulary for a human clicking
    /// checkboxes (`"Account: Cloudflare Tunnel: Edit"`, `"Read & Write"`);
    /// this is machine vocabulary a prober can compare (`"write:packages"`,
    /// `"package:write"`). They coincide for GitHub and cannot for Cloudflare
    /// or Hetzner, so one field cannot carry both without manufacturing drift
    /// on every slot whose dashboard label is prose.
    ///
    /// Empty means **no drift check**, which is the honest default in two
    /// distinct situations kept deliberately indistinguishable here because
    /// neither yields a comparison: the provider exposes no scopes to a
    /// self-probe (measured 2026-09-04 — Cloudflare's `/tokens/verify` returns
    /// only `id`/`status`/`expires_on` and reading `/accounts/{a}/tokens/{id}`
    /// is 403 `9109`; Hetzner has no such route at all, 404 `not_found`;
    /// crates.io's `/api/v1/me/tokens` is website-session-only), or nobody has
    /// read what this slot's consumers actually need. Populating it from
    /// memory would fail a live credential over a scope no consumer asks for.
    pub required_scopes: &'static [&'static str],
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

    /// True only for a slot measured to tolerate two live credentials. Both
    /// [`Overlap::Forbidden`] and [`Overlap::Unproven`] answer false — they
    /// differ in what the operator is told, never in what is allowed.
    pub const fn permits_overlap(&self) -> bool {
        matches!(self.overlap, Overlap::Permitted(_))
    }

    /// The measurement behind a decided [`Overlap`], for a message an operator
    /// can act on. `None` for [`Overlap::Unproven`], where there is none.
    pub const fn overlap_evidence(&self) -> Option<&'static str> {
        match self.overlap {
            Overlap::Permitted(why) | Overlap::Forbidden(why) => Some(why),
            Overlap::Unproven => None,
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
// Mint help — the canonical copy. Ported verbatim from the desktop rail's
// ProviderHelp entries, which are now gone from TypeScript: `ProviderHelpRail`
// reads these three over the `api_key_mint_help` Tauri command, and `yah keys
// rotate` prints the same strings. Three providers is all that rail ever
// grounded (R856-F5).
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
         if your domains are Cloudflare-managed — otherwise point a CNAME at the \
         *.cfargotunnel.com hostname from your registrar.",
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
    /* R856-F7 corrected "write:packages (it implies read:packages)": it does
    not. GitHub's scope table indents nested scopes under their parent
    (`admin:org` > `write:org` > `read:org`) and the three package scopes are
    top-level siblings, so both must be ticked to get both. The live token
    holds `write:packages` and `delete:packages` with no `read:packages` —
    which is fine, because the ghcr packages are public and nothing here pulls
    with credentials. The URL above already requests both explicitly. */
    nav_hint: Some(
        "Generate a classic token with write:packages (tick read:packages too if you will pull \
         private images — it is a sibling scope, not implied). If the \
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
    /* The four Anthropic/OpenAI-admin entries below are the only specs in this
    registry with no corresponding entry in `yah keys list`, and that is
    deliberate: each is read by a live `fob::get_or_env` call site, so the slot
    is real and merely unpopulated on this host. R856-F1 filed the admin pair as
    an orphan ("spec them or delete them"); R856-F2 grepped the consumers, found
    them live, and specced them. They are `required: false`, so `yah keys
    doctor` counts them as absent without raising a finding. */
    CredentialSpec {
        slot: "anthropic-admin-key",
        env: Some("ANTHROPIC_ADMIN_KEY"),
        purpose: "Anthropic ADMIN API key for the organization usage/cost endpoints, distinct \
                  from the completion key. Read only by `fetch_usage`; a missing one degrades \
                  usage reporting and nothing else",
        consumers: &["crates/yah/runner/src/resolver/anthropic.rs:114 (fetch_usage)"],
        provider: Provider::Anthropic,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "anthropic-api-key",
        env: Some("ANTHROPIC_API_KEY"),
        purpose: "Anthropic completion API key. Unpopulated on this host — the camp drives Claude \
                  through the subscription rail, not a raw API key — but the desktop, the UI \
                  provider panel and the party connection registry all manage the slot",
        consumers: &[
            "crates/yah/runner/src/resolver/mod.rs:1122 (ANTHROPIC_SLOT)",
            "app/yah/desktop/src/onboarding.rs:43",
            "crates/yah/party/src/party.rs:5981",
        ],
        provider: Provider::Anthropic,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "anthropic-oauth",
        env: Some("ANTHROPIC_OAUTH_TOKEN"),
        purpose: "Anthropic OAuth bearer token backing the subscription rail. Automatable in the \
                  same sense as `openai-oauth`: the refresh half re-mints it without a human",
        consumers: &[
            "crates/yah/runner/src/resolver/mod.rs:1125 (ANTHROPIC_OAUTH_SLOT)",
            "app/yah/desktop/src/api_keys.rs:630",
        ],
        provider: Provider::Anthropic,
        domain: Domain::Model,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        /* R856-F2, measured 2026-09-04: `/accounts/<id>/tokens/verify` returns
        `status: active` with **no** `expires_on`, i.e. no TTL was set at mint.
        Cloudflare offers one and the operator declined it, so the token does
        not expire and the date is a re-mint reminder — `ReviewBy`, not
        `Declared`. Re-minting it with a TTL would make this `Declared`. */
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        overlap: OVERLAP_CLOUDFLARE_API_TOKEN,
        mint: MINT_CLOUDFLARE,
        required_scopes: &[],
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
        /* R856-F2, measured 2026-09-04: this is the one Cloudflare slot whose
        `/tokens/verify` result carries an `expires_on`. Cloudflare's TTL is
        operator-chosen at mint, so `Declared`; the date itself is read off the
        probe and lands in the sidecar rather than here. */
        expiry_kind: ExpiryKind::Declared,
        probe_from: ProbeFrom::Local,
        overlap: OVERLAP_CLOUDFLARE_API_TOKEN,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-mesofact-static",
        env: None,
        purpose: "scoped Cloudflare token carrying the eleven MESOFACT_STATIC_GRANTS (including \
                  Workers Scripts:Write, Workers Routes:Write, and account+zone Analytics:Read). \
                  This is what .yah/infra/providers/cloudflare.toml points `credentials` at; \
                  cloudflare-api-token was swapped out for it in R703 because it had no \
                  Workers grants",
        consumers: &[
            ".yah/infra/providers/cloudflare.toml:53 (credentials)",
            "oss/yubaba/crates/cloud/src/reconciler/mesofact_static.rs",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Automatable,
        provider_cap_days: None,
        // R856-F2, measured 2026-09-04: verifies active with no `expires_on`.
        // Same reading as `cloudflare-api-token`.
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        overlap: OVERLAP_CLOUDFLARE_API_TOKEN,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
            // R856-F6: the yah-cli-release / yah-desktop-release `on_success`
            // publish leg. Found by grep while scoping the preflight gate — the
            // recipes upload to R2 through this, so it has to be selectable by
            // `yah keys doctor --for app/yah/cli/src/qed_publish.rs`.
            "app/yah/cli/src/qed_publish.rs:810 (R2_ACCESS_KEY_SLOT)",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-cert-store-access-key-id",
        // Deliberately shares CF_R2_ACCESS_KEY_ID with the account-wide pair
        // below. `R2ObjectStore::from_vault` hard-codes one slot name and one
        // env fallback, so a door that must reach ONE bucket and no other has
        // exactly one way to say so: put the scoped key in that env var, in a
        // 0600 EnvironmentFile, and never give the node a vault.
        env: Some("CF_R2_ACCESS_KEY_ID"),
        purpose: "R2 access key id scoped to the `yah-cert-store` bucket alone (CF token \
                  yah-cert-store-rw, item read + write). What the three public doors hold \
                  so the enrollment publisher can sweep the set and the ACME issuer can \
                  mirror the sealed pair — WITHOUT the account-wide write below, which \
                  could rewrite the public releases index from an internet-facing box",
        consumers: &[
            "/etc/yah-cloud/cert-store.env on us-{east,south,west}-001 (0600, root)",
            ".yah/infra/machines/us-east-001.toml (bucket + account id recorded)",
            "oss/yubaba/crates/yubaba/src/cert_store.rs (CertStoreConfig::connect_objects)",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        // Same reasoning as the fleet-read pair: `cloudflare-legacy-yah` is a
        // user-owned token that can mint account tokens, so replacing this one
        // is an API call rather than a dashboard visit.
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-cert-store-secret-key",
        env: Some("CF_R2_SECRET_KEY"),
        purpose: "secret half of the bucket-scoped cert-store R2 pair. It is the SHA-256 of \
                  the Cloudflare token value, which is how R2 derives an S3 secret from a \
                  token — the token value itself is not stored anywhere",
        consumers: &["/etc/yah-cloud/cert-store.env on us-{east,south,west}-001 (0600, root)"],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        // R858-T24. Scoped to the `yah-headscale` bucket alone (a CF token with
        // R2 read+write on that bucket only, never the account-wide pair the
        // operator declined on 2026-09-11 — see this slot's `purpose`).
        slot: "cloudflare-r2-headscale-access-key-id",
        // NOT CF_R2_ACCESS_KEY_ID: the consumers are turso-backup's hydrate/tail
        // helpers, which read S3_ACCESS_KEY, and kamaji-bin/src/hydrate.rs:182-191
        // states by design that it never passes credentials to the helper itself
        // — the helper inherits them from kamaji's OWN environment. So the one
        // place a node holding this scoped pair and nothing else can put it is a
        // kamaji.service.d EnvironmentFile= drop-in naming S3_ACCESS_KEY, not a
        // vault-adjacent CF_R2_* var.
        env: Some("S3_ACCESS_KEY"),
        purpose: "R2 access key id scoped to the `yah-headscale` bucket alone, for \
                  turso-backup-hydrate / turso-backup-tail (run by kamaji) to back up and \
                  tail headscale.db under s3://yah-headscale/appliance/headscale — WITHOUT \
                  the account-wide R2 write pair, which the operator declined on 2026-09-11 \
                  because a coordination-server node holding it could rewrite \
                  cdn.yah.dev's public releases index",
        consumers: &[
            "/etc/yah-cloud/headscale-durability.env on candidate coordinator voters \
             (0600, root; operator-placed, R858-T24 — this script cannot mint it)",
            "oss/kamaji/crates/kamaji-bin/src/hydrate.rs:182-191 (inherited by the hydrate \
             helper from kamaji's own environment, never passed by kamaji)",
            "oss/turso-backup/src/bin/hydrate.rs:35-40,158 (required(\"S3_ACCESS_KEY\"))",
            "oss/turso-backup/src/bin/tail.rs:19-20,310 (required(\"S3_ACCESS_KEY\"))",
            "oss/yah-base/crates/workload-spec/src/control_plane_install.sh (kamaji.service.d \
             EnvironmentFile= drop-in, same conditional that flips \
             YUBABA_HEADSCALE_DURABILITY on)",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        // Same reasoning as the fleet-read and cert-store pairs: `cloudflare-legacy-yah`
        // is a user-owned token that can mint account tokens, so replacing this one is
        // an API call rather than a dashboard visit.
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        // GROUNDED 2026-09-12 (R858-T24) — this WAS the blocker, and no longer
        // is. `GET /client/v4/accounts/{acct}/tokens/permission_groups` with the
        // cloudflare-legacy-yah bearer enumerates the whole R2 set; the ACCOUNT-
        // scope endpoint works, the USER-scope one (`/user/tokens/permission_groups`)
        // returns 9109 Unauthorized with that same bearer and looks like proof
        // minting is impossible if tried once and not retried at account scope.
        // WRITE group `2efd5506f9c8494dacb1fa10a3e7d5b6` = "Workers R2 Storage
        // Bucket Item Write"; READ group `6a018a9f2fc74eb6b293b0c548f38b39` =
        // "Workers R2 Storage Bucket Item Read", matching
        // W295-fleet-def-as-almanac-release.md:86 (NOT :145 as earlier passes on
        // this ticket recorded) byte-for-byte — the cross-check that this
        // endpoint returns the same namespace W295's read-pair ceremony used.
        // Minted via `POST /client/v4/accounts/3948dc292e724e71b0deefde0ea95999/tokens`,
        // name `yah-headscale-rw`, both groups on ONE policy, resource
        // `com.cloudflare.edge.r2.bucket.3948dc292e724e71b0deefde0ea95999_default_yah-headscale`.
        // S3 derivation (empirically verified by signing real SigV4 requests):
        // access key id = the token's own id (32 chars); secret access key =
        // SHA-256 of the token's VALUE (64 hex) — never the id itself.
        //
        // `mint` STAYS `MintHelp::NONE` even though the ceremony above is fully
        // grounded: this is an API mint through an existing bearer
        // (`band: Automatable`, matching the cert-store and fleet-read siblings
        // above, neither of which carries `MintHelp` either), not a dashboard
        // journey. `MintHelp.dashboard_url` /`.scopes` are prose for a human
        // clicking checkboxes on a page (see `exactly_the_three_ported_providers_carry_mint_help`,
        // which pins that field to exactly the three providers with a real
        // click-through flow) — pointing it at a raw authenticated API endpoint
        // would either 401 in a browser or bury the permission-group ids and
        // resource string that actually matter. This comment is the mint-help
        // home for an Automatable slot; the ceremony is recorded here instead.
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-headscale-secret-key",
        env: Some("S3_SECRET_KEY"),
        purpose: "secret half of the bucket-scoped headscale-durability R2 pair. It is the \
                  SHA-256 of the Cloudflare token value, which is how R2 derives an S3 \
                  secret from a token — the token value itself is not stored anywhere",
        consumers: &[
            "/etc/yah-cloud/headscale-durability.env on candidate coordinator voters \
             (0600, root; operator-placed, R858-T24)",
            "oss/turso-backup/src/bin/hydrate.rs:35-40,159 (required(\"S3_SECRET_KEY\"))",
            "oss/turso-backup/src/bin/tail.rs:19-20,311 (required(\"S3_SECRET_KEY\"))",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
            // R856-F6, see the sibling access-key slot.
            "app/yah/cli/src/qed_publish.rs:818 (R2_SECRET_KEY_SLOT)",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-yah-dev-access-key-id",
        // No env fallback on purpose: nothing reads this pair yet. Its intended
        // consumer is the mesofact revalidate receiver, which mounts cluster
        // secrets as FILES (`MESOFACT_S3_ACCESS_KEY_ID_FILE`), so an env name
        // here would describe a variable nothing sets.
        env: None,
        purpose: "R2 access key id scoped to the `yah-dev` bucket alone (CF token \
                  yah-marketing-revalidate-r2, item read + write), minted 2026-09-20 to \
                  replace the account-wide pair in the yah-marketing revalidate receiver. \
                  READ THE SCOPE HONESTLY: `yah-dev` holds BOTH the marketing site \
                  (`yah-marketing/cloud/`) and the public release channel (`yah/`), and an \
                  R2 token scopes to a bucket and never to a prefix — so this still permits \
                  rewriting yah/index.json (measured: PUT+DELETE on yah-dev/yah/.scope-probe \
                  -> 200/204). What it DOES close is the cross-bucket radius: yah-fleet, \
                  yah-headscale and yah-cert-store all answer 403. Closing the rest needs \
                  the marketing site in a bucket of its own, which is what the noisetable \
                  camp already does (token noisetable-marketing-revalidate-r2)",
        consumers: &[
            "(none yet) — intended for the cluster-secret mount in \
             app/yah/cli/src/cloud.rs deploy_mesofact_bundle, blocked on the shared \
             cluster-secret name `cloudflare-r2-access-key-id` being owned by another camp",
        ],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        // `cloudflare-legacy-yah` is user-owned and can mint account tokens, so
        // replacing this is an API call, not a dashboard visit.
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-r2-yah-dev-secret-key",
        env: None,
        purpose: "secret half of the bucket-scoped yah-dev R2 pair. As with every R2 \
                  credential here it is the SHA-256 of the Cloudflare token value, which is \
                  how R2 derives an S3 secret from a token — the token value itself is not \
                  stored anywhere",
        consumers: &["(none yet) — see the access-key-id half above"],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Automatable,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "cloudflare-static-yah-dev",
        env: None,
        purpose: "Cloudflare token named for the yah.dev static site. Measured 2026-08-09 \
                  (.yah/infra/providers/cloudflare.toml:32): it returns [10000] on \
                  /accounts/<id>/workers/scripts, so it carries no Workers grants. No in-tree \
                  consumer reads this slot. R856-F2 measured 2026-09-04 that it verifies as \
                  token id 623b42a4… — the SAME credential `cloudflare-api-token` holds. Two \
                  slots, one secret, one death date: the redundancy is an illusion (W337 §1)",
        consumers: &[],
        provider: Provider::Cloudflare,
        domain: Domain::Infra,
        band: Band::Manual,
        provider_cap_days: None,
        // R856-F2, measured 2026-09-04: verifies active with no `expires_on`.
        // Same reading as `cloudflare-api-token` — because it is the same token.
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        overlap: OVERLAP_CLOUDFLARE_API_TOKEN,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        /* R856-F2, read 2026-09-04: crates.io's token page offers endpoint
        scopes, crate scopes and an expiry, defaulting new tokens to 90 days
        with "no expiration" and custom dates both available
        (<https://blog.rust-lang.org/2023/06/23/improved-api-tokens-for-crates-io/>).
        Operator-chosen, so `Declared`. The *date* cannot be probed: every
        `/api/v1/me*` route is session-cookie-only, so it has to be entered by
        hand with `yah keys record-expiry`. */
        expiry_kind: ExpiryKind::Declared,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        /* R856-F2, measured 2026-09-04. The live credential in this slot is a
        *classic* PAT — `GET /user` answers with an `x-oauth-scopes` header,
        which fine-grained tokens do not carry — and it has no expiration set.
        GitHub's docs say a classic PAT may be created with no expiration, and
        that it instead "automatically removes personal access tokens that
        haven't been used in a year"
        (<https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens>).
        A credential that does not expire but must be re-minted is exactly
        `ReviewBy`. Note it is `ReviewBy` for *this* credential, not for GitHub:
        re-minting with an expiry date would make the slot `Declared`. */
        expiry_kind: ExpiryKind::ReviewBy,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MINT_GITHUB,
        /* R856-F7. Exactly what a consumer *names in source*: `ghcr.rs:223`
        tells the operator this slot "needs write:packages", and `GET /user`
        reports that scope back verbatim in `x-oauth-scopes` (measured
        2026-09-04: `delete:packages, repo, workflow, write:packages`).

        `read:packages` is NOT listed, and that absence is the measurement
        rather than an oversight: GitHub's scope table indents nested scopes
        under their parent (`admin:org` > `write:org` > `read:org`) and the
        three package scopes are all top-level siblings, so `write:packages`
        does not imply `read:packages`. The live token confirms it — it holds
        write and delete without read. Listing `read:packages` here would fail
        a working credential; the ghcr packages are public, so no consumer
        needs it. `repo` and `workflow` are held but unrequired: no consumer
        names them, and asserting a requirement nobody read is the same class
        of error as a green light on a dead key. */
        required_scopes: &["write:packages"],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        /* R856-F2 read Hetzner's live docs on 2026-09-04 and STAYS `Unverified`
        on purpose. Both `getting-started/using-api` and
        `getting-started/generating-api-token` are silent on lifetime, and the
        mint UI offers only Read / Read&Write — no TTL field. That is an absence
        of a statement, not a statement that tokens never expire, so calling it
        `ReviewBy` would assert a policy nobody read. Recorded here so the next
        agent does not repeat the search: settling this needs Hetzner support or
        an observed expiry, not more doc-reading. */
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MINT_HETZNER,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: OVERLAP_NPM_TOKEN,
        mint: MintHelp::NONE,
        /* R856-F7. npm's `--json` record answers tier 3 on two *different*
        axes and the prober flattens both, so the vocabulary distinguishes
        them: `permissions` is what the token may do (`{"name":"package",
        "action":"write"}` -> `package:write`), `scopes` is what it may do it
        *to* (`{"name":"mesofact","type":"org"}` -> `scope:org:mesofact`).

        Both are load-bearing and only one is obvious. A token narrowed from
        `package:write` to `package:read` fails the publish loudly; a token
        that keeps `package:write` but loses `scope:org:mesofact` passes every
        presence check, passes the auth probe, and dies at `npm publish` — the
        exact silent narrowing this tier exists to catch. `@mesofact` is the
        only npm org this tree publishes (four `packages/mesofact-…`; the
        `@yah` ones are workspace-internal), so it is the one org scope
        grounded enough to require. Measured 2026-09-04: the live token holds
        `package:write`, `org:write`, and org scopes `mesofact` + `yah-ai`. */
        required_scopes: &["package:write", "scope:org:mesofact"],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
        required: false,
        onepassword: None,
    },
    CredentialSpec {
        slot: "openai-admin-key",
        env: Some("OPENAI_ADMIN_KEY"),
        purpose: "OpenAI ADMIN API key for the usage/billing endpoints, distinct from the \
                  completion key. Read only by `fetch_usage`; a missing one degrades usage \
                  reporting and nothing else",
        consumers: &["crates/yah/runner/src/resolver/openai.rs:85 (fetch_usage)"],
        provider: Provider::OpenAi,
        domain: Domain::Model,
        band: Band::Manual,
        provider_cap_days: None,
        expiry_kind: ExpiryKind::Unverified,
        probe_from: ProbeFrom::Local,
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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
        overlap: Overlap::Unproven,
        mint: MintHelp::NONE,
        required_scopes: &[],
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

    /// R856-F1 found four slots declared in `resolver/mod.rs` that appear in
    /// neither `yah keys list` nor this registry, and asked F2 to spec them or
    /// delete them. F2 grepped: each has a live `fob::get_or_env` call site, so
    /// they are unpopulated, not dead. The opposite of `iroh-node-secret` —
    /// which is why both tests live here, one on each side of the line.
    #[test]
    fn declared_but_unpopulated_slots_are_specced_rather_than_deleted() {
        for slot in [
            "anthropic-admin-key",
            "anthropic-api-key",
            "anthropic-oauth",
            "openai-admin-key",
        ] {
            let s = spec(slot).unwrap_or_else(|| panic!("{slot} must be specced"));
            assert!(
                !s.consumers.is_empty(),
                "{slot} is only in the registry because something reads it"
            );
            // Absent from the vault on this host; a required slot would make
            // `yah keys doctor` raise a finding for a credential nobody wants.
            assert!(!s.required, "{slot} must not be required");
        }
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

    /// W337 §6 / R856-F9. The default has to be the refusing one: on a provider
    /// that replaces rather than adds, minting the overlap value kills the live
    /// credential, which is the outage the design exists to remove. So this
    /// test asserts the *shape* of the registry — a small grounded set, and
    /// everything else refusing — rather than a slot list that would have to be
    /// edited every time a measurement lands.
    #[test]
    fn overlap_is_permitted_only_where_it_was_measured() {
        let permitted: Vec<&str> = CREDENTIAL_SPECS
            .iter()
            .filter(|s| s.permits_overlap())
            .map(|s| s.slot)
            .collect();
        assert_eq!(
            permitted,
            vec![
                "cloudflare-api-token",
                "cloudflare-legacy-yah",
                "cloudflare-mesofact-static",
                "cloudflare-static-yah-dev",
                "npm-api-token",
            ]
        );
        for spec in CREDENTIAL_SPECS {
            if spec.permits_overlap() {
                let why = spec.overlap_evidence().expect("a decision carries evidence");
                assert!(
                    why.contains("measured"),
                    "{}: a Permitted flag must name the measurement, not a belief — got {why:?}",
                    spec.slot
                );
            } else {
                assert!(
                    !spec.permits_overlap(),
                    "{}: an unmeasured slot must refuse the overlap path",
                    spec.slot
                );
            }
        }
    }

    /// `Forbidden` and `Unproven` both refuse; they differ only in what an
    /// operator is told. Nothing may collapse them into one bool at the source.
    #[test]
    fn forbidden_and_unproven_both_refuse_but_stay_distinguishable() {
        let unproven = CredentialSpec {
            overlap: Overlap::Unproven,
            ..*spec("github-pat").unwrap()
        };
        let forbidden = CredentialSpec {
            overlap: Overlap::Forbidden("measured: the provider revokes the incumbent"),
            ..*spec("github-pat").unwrap()
        };
        assert!(!unproven.permits_overlap());
        assert!(!forbidden.permits_overlap());
        assert_eq!(unproven.overlap_evidence(), None);
        assert!(forbidden.overlap_evidence().is_some());
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

    /// The port's acceptance criterion (R856-F5). The TypeScript rail grounded
    /// exactly these three SLOTS, so exactly these three are populated. Both
    /// directions are failures: a fourth slot appearing without a grounded
    /// dashboard URL, and the per-provider fan-out this replaced — which pointed
    /// an operator rotating an R2 SigV4 key at the API-tokens page that cannot
    /// mint one.
    #[test]
    fn exactly_the_three_ported_providers_carry_mint_help() {
        let populated: Vec<&str> = CREDENTIAL_SPECS
            .iter()
            .filter(|s| s.mint.is_populated())
            .map(|s| s.slot)
            .collect();
        assert_eq!(
            populated,
            ["cloudflare-api-token", "github-pat", "hetzner-api-token"],
            "add a slot here only with a dashboard URL read from the provider"
        );
    }

    /// The tier-3 baseline is only usable if it stays in the provider's own
    /// machine vocabulary (R856-F7). The failure this guards is somebody
    /// copying `mint.scopes` across — `"Account: Cloudflare Tunnel: Edit"` and
    /// `"Read & Write"` are dashboard checkbox labels, and comparing one to an
    /// `x-oauth-scopes` header manufactures a `ScopeInsufficient` on a working
    /// credential. No provider's scope token contains a space or a comma.
    #[test]
    fn required_scopes_are_machine_vocabulary_not_dashboard_prose() {
        for spec in CREDENTIAL_SPECS {
            for scope in spec.required_scopes {
                assert!(
                    !scope.contains(' ') && !scope.contains(','),
                    "{}: {scope:?} reads like a dashboard label, not a scope the probe \
                     response will contain",
                    spec.slot
                );
            }
        }
    }

    /// Both directions are failures. A slot losing its baseline silently
    /// disables the only tier that catches a break *before* the failing call;
    /// a slot gaining one that nobody grounded fails a live credential over a
    /// scope no consumer asks for.
    #[test]
    fn exactly_the_grounded_slots_carry_a_scope_baseline() {
        let with_baseline: Vec<&str> = CREDENTIAL_SPECS
            .iter()
            .filter(|s| !s.required_scopes.is_empty())
            .map(|s| s.slot)
            .collect();
        assert_eq!(
            with_baseline,
            ["github-pat", "npm-api-token"],
            "these are the only two providers measured to report scopes back to a self-probe; \
             add a slot here only after reading both what the provider returns and what a \
             consumer names in source"
        );
        assert_eq!(
            spec("github-pat").unwrap().required_scopes,
            ["write:packages"],
            "read:packages is a sibling scope, not implied — requiring it fails the live token"
        );
    }

    /// The rail rendered a nav hint, a breadcrumb and scope pills; a port that
    /// silently dropped one would degrade the desktop surface it replaced.
    #[test]
    fn every_ported_entry_kept_all_four_fields() {
        for slot in ["cloudflare-api-token", "github-pat", "hetzner-api-token"] {
            let mint = spec(slot).unwrap().mint;
            assert!(mint.dashboard_url.is_some(), "{slot}: no dashboard url");
            assert!(mint.dashboard_label.is_some(), "{slot}: no breadcrumb");
            assert!(mint.nav_hint.is_some(), "{slot}: no nav hint");
            assert!(!mint.scopes.is_empty(), "{slot}: no scopes");
        }
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
