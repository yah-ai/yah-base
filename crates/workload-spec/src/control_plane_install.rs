//! Shared install-script builder for a control-plane (yubaba + kamaji) roll.
//!
//! This is the ONE net-new mechanism of the rolling-upgrade envelope (R608):
//! the atomic fetch→verify→anchor→install→assert→restart of the signed
//! yubaba+kamaji pair. It lives here — in the crate BOTH the CLI orchestrator
//! and yubaba itself depend on — so the two apply transports share a single,
//! trusted script and cannot drift:
//!
//! - **SSH transport** (R608-F5, `app/yah/cli/src/rollout/apply.rs::apply_over_ssh`)
//!   pipes the script to `ssh <node> bash -s` from the orchestrator.
//! - **Mesh transport** (R608-F10, yubaba `POST /self-update`) runs the *same*
//!   script locally on the node via a `systemd-run` transient unit — no SSH.
//!
//! **The script body is not written here.** It lives beside this file as
//! [`control_plane_install.sh`](./control_plane_install.sh) and is `include_str!`d,
//! because a third caller — `scripts/roll-node.sh`, the one-node operator SSH
//! job (R755-F3) — has to run the identical bytes from bash with no Rust in the
//! loop. This function only prepends the four-variable prologue the template
//! declares (`URL` / `SHA` / `VER` / `SUDO`); `roll-node.sh` prepends the same
//! four. Keeping the body in a `format!` string would have forced that script to
//! become a fourth transcription of the most safety-critical code in the fleet
//! (`stand-up-yubaba.sh`'s install tail is already the second).
//!
//! The script is a state-preserving, atomic transcription of the install tail of
//! `stand-up-yubaba.sh`: fetch the signed release tarball, `sha256 -c` it against
//! the digest the signed manifest already resolved (callers only ever pass
//! manifest-derived values — there is no path for an AI or a wire request to
//! fabricate a version/url/digest), extract, leave a dated rollback anchor beside
//! every file it is about to replace, stage each file next to its target on the
//! same filesystem, then `mv` it into place so a half-written
//! `/usr/local/bin/yubaba` can never appear. yubaba + kamaji install as one
//! atomic pair (W275 OQ5).
//!
//! **Success is proved by content, never by `--version`.** After the rename the
//! script hashes each installed binary against the file it extracted from the
//! manifest-verified tarball. The version string is the workspace version baked
//! in at build time and can be right on a binary that predates the code it
//! claims — us-east-001 reported kamaji 0.8.22 while carrying none of the 0.8.22
//! tree (R746-T3). The hash chain manifest → tarball → extracted → installed has
//! no version string in it.
//!
//! **Everything a node needs to run the tier rides the roll, not just the
//! binaries.** R858-T21: the two `turso-backup` durability helpers and the
//! `kamaji.service.d/50-durability-helpers.conf` drop-in that points kamaji at
//! them used to be placed only by *provisioning* (`stand-up-yubaba.sh`,
//! `mirror.yml`), so a node that had been ROLLED could never acquire them —
//! and kamaji hard-refuses any workload declaring a `yah.durability.tier` on a
//! node missing either. A capability delivered by only one of the two install
//! paths is a capability half the fleet silently lacks.
//!
//! **Never touches durable state.** The script contains no reference to
//! `/var/lib/yah-cloud/identity.json` (the ed25519 host identity — wiping it
//! forces a re-TOFU and breaks hostkey-drift detection, the R589 gotcha) or the
//! raft log dir. A roll moves `/usr/local/bin` bytes + unit files, nothing else.
//! The [`tests::script_never_touches_durable_state`] test is the guard.
//!
//! @yah:ticket(R858-T21, "Rolled nodes can never acquire the durability helpers: control_plane_install.sh installs ten files and no turso-backup-*")
//! @yah:status(review)
//! @yah:at(2026-09-11T07:19:35Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:gotcha("THE DEFECT: kamaji's --tail-helper / --hydrate-helper are fully implemented (oss/kamaji/crates/kamaji-bin/src/main.rs:195,197 read KAMAJI_HYDRATE_HELPER / KAMAJI_TAIL_HELPER; :263,:270 parse the two flags; :333 usage line; :371-380 help text; :740,:752,:766,:778 are the hard refusals that reject a tier-declaring workload when a helper is missing), and scripts/publish-yubaba-release.sh builds and hard-asserts both helper binaries into the release tarball (:230-233 build both via cross-build-guarded.sh, :261-262 stage from oss/turso-backup/target/$triple/release/, :326-327 assert the tarball layout contains each one). But oss/yah-base/crates/workload-spec/src/control_plane_install.sh - the SINGLE SHARED install body that SSH standup, yubaba POST /self-update, scripts/roll-node.sh (:121 reads exactly that template) and `yah cloud rollout` (app/yah/cli/src/rollout/apply.rs:143 calls workload_spec::control_plane_install::build_install_script) all build from - installs exactly TEN named files via install_atomic (:86-90 yubaba, kamaji, yubaba.slice, kamaji.service, yubaba.service; :100-101 yah-scryer + its unit; :122-123 passway + passway-demux; :132 passway-http-router; :147 passway-graceful-upgrade) and contains ZERO turso references (`rg -c turso <that file>` exits 1, measured 2026-09-10). Its only *_HELPER identifier is passway's unrelated HAS_UPGRADE_HELPER (:144,:146,:180,:198).")
//! @yah:gotcha("THE CONSEQUENCE: both helper binaries and the kamaji.service.d/50-durability-helpers.conf env drop-in are placed ONLY by PROVISIONING. Measured 2026-09-10, the drop-in has exactly three source homes and all three are provisioning paths: .yah/infra/cloud-init/mirror.yml:123, .yah/infra/cloud-init/stand-up-yubaba.sh:111-121 (install -m0755 of both binaries, then the drop-in, then a WARNING branch at :123 naming R858-F17 when the tarball lacks them), and the template twin oss/yubaba/crates/cloud/templates/mirror.yml:123. Nothing in the roll path writes either. So a node that was ROLLED rather than freshly provisioned can never acquire the helpers, and a declared durability tier can therefore never activate on it. R858-F17's own operator instruction at oss/yubaba/crates/yubaba/src/litestream.rs:229 tells the reader to cut a release, roll it, and then verify over ssh that turso-backup-tail and 50-durability-helpers.conf are present - that verification can never pass on a rolled node. The instruction and the install body disagree, and the install body wins.")
//! @yah:gotcha("FIELD EVIDENCE, reported by the noisetable camp (ticket R131-T16) against us-east-001, a ROLLED node - relayed by the filer, NOT re-measured in this session, so re-run it before acting: `kamaji --help` matches hydrate-helper twice but tail-helper zero times; kamaji.service ExecStart is `/usr/local/bin/kamaji --socket /run/kamaji/kamaji.sock --containerd-socket /run/containerd/containerd.sock --native-exec-dir /var/lib/yah/kamaji/native`, passing neither flag; /usr/local/bin holds turso-backup-snapshot only, with turso-backup-tail and turso-backup-hydrate both absent. That is exactly the shape this ticket's static reading predicts. SANCTIONED SHAPE FOR THE FIX, so it is not done the wrong way: the flags must arrive via `Environment=` in a kamaji.service.d/ drop-in and NEVER by editing ExecStart - oss/yubaba/crates/yubaba/src/litestream.rs:227 records the pre-existing 20-bundle.conf ExecStart-clobber hazard behind the 2026-09-03 outage, and both existing provisioning homes already use the Environment= form.")
//! @yah:gotcha("WHO IS WAITING: noisetable R131-T16. The noisetable-account service is live production holding real accounts and passkeys, and its only backup today is a 10-minute-RPO snapshot timer with no fencing and a human-run restore. It cannot declare yah.durability.* until a ROLLED node can actually carry the helpers, because declaring before that makes kamaji REFUSE the deploy (oss/kamaji/crates/kamaji-bin/src/main.rs:752,:778) - i.e. it takes the service down rather than backing it up. Tier: Warrior - a small, well-specified install-list change in a shared script whose blast radius is every fleet node, so it needs care but not design work.")
//! @yah:gotcha("STALE TEXT, NOT A LIVE CONTRADICTION - correcting the premise this ticket was filed under. .yah/infra/machines/us-west-001.toml:42 (the RELEASE-ORDER TRAP gotcha) still asserts that `scripts/cross-build-guarded.sh turso-backup <triple> turso-backup-hydrate \"\" oss/turso-backup` \"has never been executed\" and that the musl leg is unproven, while :47's @yah:next says \"Its musl build is proven (see gotcha)\". Read in isolation those look contradictory, but they are not: :44, added 2026-09-10 by @Ashguard:hydra, explicitly CLOSES the gap (\"MUSL LEG OF THE TWO turso-backup HELPERS IS NOW PROVEN\"), reporting all four bin-by-triple legs producing static musl ELFs with zero GLIBC symbol references at exactly the paths scripts/publish-yubaba-release.sh:261-262 packages from. So the residual hazard is a READING hazard, not an unproven build: an operator who reaches :42 first and stops will defer a release that is already unblocked. Worth correcting :42's wording in place before the next cut rather than leaving the superseded claim beside its own retraction.")
//! @yah:next("EITHER: add turso-backup-hydrate, turso-backup-tail and the kamaji.service.d/50-durability-helpers.conf drop-in to control_plane_install.sh's install set (install_atomic alongside :86-90, plus the Environment= drop-in written the way stand-up-yubaba.sh:119-120 already writes it, and absent-tolerant the way mirror.yml:123 already is so an older tarball still rolls cleanly), AND add a corresponding entry to scripts/hotship.sh's APP_NAMES, which at :239 reads exactly `yubaba,yubaba-tenant-streamer,kamaji,yah-scryer,passway,passway-demux,passway-http-router,mesofact` and names no turso binary. OR: decide explicitly that helper delivery is provisioning-only, and correct R858-F17's verification step at oss/yubaba/crates/yubaba/src/litestream.rs:229 to say so - today it instructs an ssh check that a rolled node can never satisfy.")
//! @yah:handoff("scripts/hotship.sh, the second half of the ticket's next: APP_NAMES gains turso-backup-hydrate + turso-backup-tail, app_spec() gains both (package turso-backup, explicit --bin because that package builds turso-backup-snapshot too, no features — matching publish-yubaba-release.sh's own empty features arg), and the activation legend gains a documented `none` with a dispatch arm that says so out loud. `none` is the correct answer rather than a gap: kamaji forks a FRESH helper per hydrate/tail, so the next deploy picks the bytes up with nothing restarted, whereas unit:kamaji would kill every workload on the box to refresh a binary nobody is running. The comment states plainly that hotship does NOT write the drop-in — roll the node once, then hot-ship the helpers freely. @Glimmerstone:spade holds hotship.sh in-flight for R881-B7; my three regions do not overlap their diff and they were notified by party.chat with the exact line ranges.")
//! @yah:verify("NOT VERIFIED, STATED PLAINLY: nothing was rolled and no node was touched, so the drop-in has never been written on a real box by this path and no kamaji has been observed picking the env up from it. The install, the drop-in bytes and the Environment= shape are transcribed from stand-up-yubaba.sh's durability-helpers block, which is the provisioning path that HAS run — but the roll leg's live proof is the first `yah cloud rollout` of the helpers release, and roll-node.sh's four new assertions are what will report it.")
//! @yah:gotcha("FIELD EVIDENCE FROM noisetable R131-T16 WAS NOT RE-MEASURED — this ticket's own gotcha said to re-run it before acting and I did not, because no ssh was in scope for a source-only change. The static reading it predicts is confirmed in the tree (the install body had zero turso references before this change), so the fix does not depend on it; but if you are about to tell noisetable they are unblocked, the honest statement is 'the roll path now carries the helpers as of the next release', not 'us-east-001 has them'. us-east-001 acquires them on its next roll of a 0.8.37-or-later tarball, and roll-node.sh will say so or fail.")
//! @yah:handoff("THE FIX, branch A (add to the roll), not branch B (declare provisioning-only). oss/yah-base/crates/workload-spec/src/control_plane_install.sh — the single shared install body all four roll transports build from — now installs turso-backup-hydrate + turso-backup-tail and writes /etc/systemd/system/kamaji.service.d/50-durability-helpers.conf, so `yah cloud rollout`, yubaba POST /self-update, scripts/roll-node.sh and the SSH standup path all carry the capability at once. Five properties, each matching what the file already does for the passway and scryer legs rather than inventing a shape: (1) conditional on the tarball carrying BOTH members, so a pre-0.8.37 rollback still rolls clean — half a pair is not a pair, and kamaji refuses when either is missing; (2) rollback anchors for both binaries AND the drop-in, before anything is replaced (a .rollback-YYYYMMDD sibling inside a .d dir is inert — systemd reads only *.conf there — so the anchor cannot itself change the unit); (3) both installs are staged-then-renamed via install_atomic, and so is the drop-in: it is printf'd into $WORK and install_atomic'd, never written in place; (4) content-asserted by sha256 against the extracted tarball member, like the pair, never by a version string; (5) the drop-in lands BEFORE the daemon-reload and kamaji restarts after it, so the env is live on the SAME roll rather than the next one. The flags arrive as Environment=, never ExecStart= — the sanctioned shape the ticket named, and a test now asserts that no executable line in the whole script mentions ExecStart at all.")
//! @yah:handoff("DISCOVERED WORK, DONE IN THIS PASS, NOT FILED AS FOLLOWUPS. (1) scripts/roll-node.sh had its OWN before/after verification enumerating binaries by name (:197 snapshot, per-binary WANT_* expectations, post-roll sha assertions) and would have installed the helpers while reporting nothing about them. It now snapshots both helper hashes, adds a `--durability--` section, and asserts FOUR things post-roll: both binaries hash to the published artifact, the drop-in is present, and `systemctl show kamaji.service -p Environment` names BOTH KAMAJI_HYDRATE_HELPER and KAMAJI_TAIL_HELPER. That third and fourth are the half a sha256sum cannot see — bytes perfect, kamaji never told, every tier-declaring workload still refused — which is precisely the state R858-F17's operator instruction asks an ssh session to rule out by hand. It now fails the roll instead. (2) .yah/infra/machines/us-west-001.toml:42, the RELEASE-ORDER TRAP gotcha, ended with 'the musl leg has never been executed, run cross-build-guarded.sh before either release'; @Ashguard:hydra had proved it the same day, two gotchas below. That superseded clause is cut from the entry in place and replaced with a pointer to the retraction — leaving it beside its own correction is what makes an operator defer an unblocked cut. (3) R858-F17's own annotation carried a stale scope-boundary handoff saying publish-yubaba-release.sh 'still needs the build+package+version-gate treatment'; it has had it since a8f0d501, ~27 min before the v0.8.37 release commit e2d707e1. A gotcha on F17 now records both closures with file:line. NOT TOUCHED, deliberately: the two mirror.yml twins and stand-up-yubaba.sh already do this correctly and are the source I transcribed from.")
//! @yah:verify("cargo test --manifest-path oss/yah-base/crates/workload-spec/Cargo.toml --lib = 193 passed / 0 failed; the control_plane_install module alone = 13 passed / 0 failed, one of them new (the_durability_helpers_ride_the_roll_with_their_kamaji_dropin) and one extended (script_anchors_every_file_it_replaces_before_replacing_it now demands anchors for both helpers and the drop-in). FALSIFICATION, single-variable, demanded of the riskiest assertion: replacing the drop-in's install_atomic with a plain `$SUDO cp` — which still produces a correct-looking file on the node — fails exactly the new test ('the drop-in must be staged-then-renamed, not written in place', 12 passed / 1 failed) and nothing else; restored and re-run green. cargo clippy on the crate: 9 pre-existing warnings, ZERO naming control_plane_install (grep -c = 0). `bash -n` clean on the assembled roll script (prologue + template), on scripts/hotship.sh and on scripts/roll-node.sh; shellcheck clean on the roll script, and on the two scripts only the pre-existing SC2016/SC2034/SC2012 findings, none on a line I wrote. The remote snapshot command roll-node.sh would send was printed verbatim through a node_sh stub and read back — the quoting survives (literal backticks, `tr ' ' '\\n'`, the line continuation). Tarball paths grounded rather than assumed: publish-yubaba-release.sh:261-262 stages both helpers into STAGE_NAME='yubaba-$VERSION-$triple' (:267), which is what the template's `find x -maxdepth 1 -type d -name 'yubaba-*'` resolves $D to, so $D/turso-backup-{hydrate,tail} exist. One suspect-result flag from the camp build rail on an early run (a peer edited oss/yubaba/.../integration_service_records.rs mid-run, a different workspace); the later runs were clean.")
//!
//! @yah:ticket(R858-B22, "Rolling us-east-001 for the durability helpers reverts R881-B7's container-DNS fix: durability and noisetable sign-in are currently mutually exclusive")
//! @yah:status(review)
//! @yah:at(2026-09-12T06:45:43Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:severity(high)
//! @yah:gotcha("THE CONFLICT, measured on us-east-001 (51.81.85.145) 2026-09-11 by two independent couriers from the noisetable camp. That node runs kamaji 0.8.38-h5. Those are HOTSHIP BYTES ON NO CDN MANIFEST — put there by `scripts/hotship.sh --nodes us-east-001 --binaries kamaji,yubaba`, per R881-B7's own handoff — so they exist on that one box and in no published tarball. That binary is the ONLY reason noisetable production sign-in works: it carries R881-B7's container-DNS fix, which points the workload's /etc/resolv.conf at /run/systemd/resolve/resolv.conf (nameserver 213.186.33.99) instead of the 127.0.0.53 systemd-resolved stub, so `getent hosts smtp.mailgun.org` now succeeds inside the netns. Mailgun's log carries an accepted+delivered pair to human@yah.dev at 2026-09-11T07:02:28/29Z, SMTP 250 from smtp.google.com, originating-ip 51.81.85.145. Before that fix every magic-link request 502'd with EAI_AGAIN and zero mail had ever left. THE SAME 0.8.38-h5 binary is also the first one on that node to carry --tail-helper and --hydrate-helper (`kamaji --help` matches each twice; yesterday tail-helper matched zero times). BUT THE NODE STILL HAS NO DURABILITY HELPERS INSTALLED: /usr/local/bin holds only turso-backup-snapshot (placed by noisetable R131-T17); turso-backup-tail and turso-backup-hydrate are ABSENT. There is no /etc/systemd/system/kamaji.service.d/50-durability-helpers.conf (that dir holds only 10-logdir.conf, 20-bundle.conf, 20-bundle.conf.rollback-20260906-coffee, 30-container-net.conf). `systemctl show kamaji.service -p Environment` names neither KAMAJI_HYDRATE_HELPER nor KAMAJI_TAIL_HELPER, and ExecStart passes neither flag. SO: getting the helpers onto that node requires a ROLL. But scripts/roll-node.sh installs from a PUBLISHED TARBALL, and the DNS fix lives only in unpublished hotship bytes. ROLLING us-east-001 TO GET DURABILITY REVERTS THE DNS FIX AND KILLS NOISETABLE'S PRODUCTION SIGN-IN. Durability and availability are, right now, mutually exclusive on that node.")
//! @yah:gotcha("NEITHER UPSTREAM TICKET SAYS THIS, BECAUSE EACH ONLY SEES ITS OWN HALF — and the two instructions directly contradict each other. R858-T21 (status `review`, anchored in this same file, oss/yah-base/crates/workload-spec/src/control_plane_install.rs:57) landed the install-side fix in control_plane_install.sh + scripts/roll-node.sh + scripts/hotship.sh, and its own verify block says plainly: \"NOT VERIFIED, STATED PLAINLY: nothing was rolled and no node was touched, so the drop-in has never been written on a real box by this path and no kamaji has been observed picking the env up from it\" — and, in its gotchas, \"us-east-001 acquires them on its next roll of a 0.8.37-or-later tarball\". WRITTEN, NOT DEPLOYED. Its instruction is therefore \"roll it, then verify the helpers are present\". R881-B7's caveat is the opposite: a roll-node.sh back to a published tarball REVERTS the DNS fix. Nothing in the tree reconciles the two. THIS IS WHY IT IS A TICKET AND NOT A NOTE: R850-F1, R858-T21, R876-B9 and R881-B7 are ALL at status `review`, where an appended gotcha reaches nobody but a signing reviewer. The reconciliation needs an OWNER who can cut and roll, not another annotation on a ticket nobody will claim again.")
//! @yah:gotcha("THE CONSEQUENCE OF GETTING IT WRONG, IN EACH DIRECTION. (A) ROLL FIRST, before a release carries R881-B7: noisetable production sign-in dies again. Every magic-link request 502s with EAI_AGAIN because the container's resolv.conf goes back to the 127.0.0.53 systemd-resolved stub, `getent hosts smtp.mailgun.org` fails inside the netns, and ZERO MAIL LEAVES — that was the state from the service's creation until 2026-09-11T07:02Z, and api.noisetable.com is now serving real sign-in traffic. (B) NEVER ROLL: noisetable's account volume — /var/lib/yah/kamaji/volumes/noisetable-account-data, four databases (account.db, grants.db, projects.db, sessions.db), holding every real account and passkey — keeps riding a 10-minute-RPO snapshot timer with no fencing and a human-run restore (noisetable R131-T17, its W124 section 8.2). It cannot declare yah.durability.* until the helpers are present, because kamaji HARD-REFUSES a tier-declaring workload when a helper is missing (oss/kamaji/crates/kamaji-bin/src/main.rs:740,:752,:766,:778) — i.e. declaring early takes the service DOWN rather than backing it up. A passkey has no password-reset path, so an unrecoverable loss there is permanent for the account.")
//! @yah:next("THE REQUIRED ORDERING — decided by the operator 2026-09-11, do NOT re-derive it and do NOT propose rolling first. (1) CUT A PUBLISHED RELEASE CARRYING BOTH R881-B7's container-DNS fix AND R858-T21's install-side helper delivery (control_plane_install.sh's turso-backup-hydrate + turso-backup-tail install_atomic legs and the kamaji.service.d/50-durability-helpers.conf Environment= drop-in). Confirm before cutting that the DNS fix is actually IN THE SOURCE the release builds from, not only in the 0.8.38-h5 hotship bytes on us-east-001 — that is the single thing that makes this ordering work, and it is the one thing the hotship route lets slip. (2) THEN roll us-east-001. Only that ordering gets durability without regressing sign-in.")
//! @yah:next("AFTER THE ROLL, RUN BOTH HALVES OF THE VERIFY BLOCK — the durability half AND the noisetable regression half. A green durability check with a dead sign-in is a failed roll, and the two are measured on the same box in the same pass. Then tell noisetable R131-T16 (which is watching this ID) so it can re-run its precondition-2 lines and paste W124 section 8.1's yah.durability.* block.")
//! @yah:verify("DURABILITY HALF, re-runnable on us-east-001 (ssh -i ~/.ssh/yah debian@51.81.85.145), all four must hold after the roll: (1) `kamaji --help | grep -c tail-helper` NON-ZERO (and hydrate-helper likewise); (2) `ls /usr/local/bin` holds BOTH turso-backup-tail AND turso-backup-hydrate (today it holds only turso-backup-snapshot); (3) `sudo test -f /etc/systemd/system/kamaji.service.d/50-durability-helpers.conf` succeeds (today that dir holds only 10-logdir.conf, 20-bundle.conf, 20-bundle.conf.rollback-20260906-coffee, 30-container-net.conf); (4) `systemctl show kamaji.service -p Environment` names BOTH KAMAJI_HYDRATE_HELPER and KAMAJI_TAIL_HELPER — bytes present with kamaji never told is the failure mode a sha256 cannot see.")
//! @yah:verify("NOISETABLE REGRESSION HALF — THIS IS THE CRUCIAL ONE AND IT IS WHY THIS TICKET EXISTS. After the roll, inside the noisetable-account workload's netns on us-east-001: (1) the container's /etc/resolv.conf must still NOT be `nameserver 127.0.0.53` — it must resolve through /run/systemd/resolve/resolv.conf (nameserver 213.186.33.99), which is R881-B7's fix; (2) `getent hosts smtp.mailgun.org` must still SUCCEED inside that netns. If either regresses, the roll reverted R881-B7 and production sign-in is dead — 502/EAI_AGAIN on every magic-link request, zero mail leaving. Roll back or re-hotship kamaji immediately; do not leave the node in that state to chase the durability half. End-to-end corroboration if you want it: a magic-link request should produce an accepted+delivered pair in Mailgun's log with originating-ip 51.81.85.145, as it did at 2026-09-11T07:02:28/29Z.")
//! @yah:gotcha("Tier: Wizard — the ordering itself is decided, but the picker-up must first establish whether R881-B7's container-DNS fix exists in the source a release would build from or ONLY in the 0.8.38-h5 hotship bytes on one box, reconcile two `review`-column tickets that give opposite instructions, and then sequence an irreversible production roll whose failure mode is a live sign-in outage. That is judgment across camps, not an install-list edit.")
//! @yah:gotcha("PRECONDITION SETTLED 2026-09-11 BY THE R858 LEADER (@Ashguard:golem, session:ce91058c) — the one thing this ticket said must be established before the cut, established. R881-B7's container-DNS fix IS IN THE SOURCE, not only in the 0.8.38-h5 hotship bytes: `resolver_mount_source` + `HostResolvers::read()` + the HOST_RESOLV_CONF / SYSTEMD_RESOLVED_UPSTREAM consts live in oss/kamaji/crates/kamaji-containerd-core/src/lib.rs, which is COMMITTED IN HEAD and not even dirty in the working tree (`git status --porcelain` does not list it). The discriminator against the published train: `git show v0.8.37:oss/kamaji/crates/kamaji-containerd-core/src/lib.rs | grep -c resolver_mount_source` = 0, HEAD = 12 — so v0.8.37 genuinely carries neither half and rolling to it is what would revert the fix. R858-T21's install legs are likewise in HEAD and absent from the tag: control_plane_install.sh:181-191 installs both turso helpers and printf's 50-durability-helpers.conf, while `git show v0.8.37:<same path> | grep -c turso-backup-hydrate` = 0. HEAD is 3 commits past v0.8.37 (0084982f / 8aa2dc6a / 494e22fa) and the tree version still reads 0.8.37, so the cut is a patch bump to 0.8.38. ALSO MEASURED, and it answers the standing 0.8.35 provenance objection rather than repeating it: the ENTIRE working-tree delta over HEAD inside the release blast radius is rustfmt reflow plus @yah: board annotations, zero behavioral code — oss/kamaji/.../sandbox.rs +34/-9 is four pure reformats (build_ruleset signature wrap, an add_rule call wrap, a bind() vec wrap, an iterator chain wrap), oss/yubaba/src/lib.rs +20/-0 and headscale_appliance.rs +17/-0 are the newly-filed R876-B13 and R858-B23 annotation blocks, oss/yah-base/.../lib.rs +16/-8 is rustfmt on tests, control_plane_install.rs is -1 annotation line. So a release built from this tree is behaviorally identical to HEAD. Cluster-epoch drift guard re-run here: `cargo test -p xtask --test main --locked -q -- cluster_epoch_drift::` = 8 passed / 0 failed.")
//! @yah:handoff("ROLL-PATH DEFECT FOUND AND FIXED IN scripts/roll-node.sh, landed 2026-09-11 by agent:bundle-anthropic-glimmerstone (session:63644932) under R858-B23 — recorded here because B22 owns the roll path. THE DEFECT: the UP_TO_DATE short-circuit at :387-399 was computed from SIX BINARY HASHES ONLY (yubaba, kamaji, yah-scryer, passway, passway-demux, passway-http-router) and then exited 0 with \"ALREADY ON THIS BUILD — Nothing to do.\" R858-T21 added the durability leg to the install body, the `--durability--` probe to the snapshot at :202-211 and the post-roll assertions at :477-489, but never taught the short-circuit about any of it. Net effect: a node could be byte-perfect on every binary and PERMANENTLY unable to run any workload declaring a `yah.durability.tier`, and the script would print `dropin absent` / `no helper env on kamaji` in its own snapshot two screens above and then declare there was nothing to do. That is exactly the state us-south-001 was in, and it is why the mesh coordinator stayed down 13.7 hours. Same class of miss as the one T21 itself fixed, one layer up.")
//! @yah:handoff("THE FIX (scripts/roll-node.sh:400-419, new block between the HAS_HTTP_ROUTER leg and the UP_TO_DATE exit): guarded on `HAS_DURABILITY_HELPERS = 1` in the same idiom as the HAS_SCRYER / HAS_PASSWAY / HAS_HTTP_ROUTER legs above, so a pre-0.8.37 tarball that could not deliver the helpers anyway still short-circuits cleanly. It clears UP_TO_DATE when the before-snapshot lacks either helper's expected hash, OR reports `dropin absent`, OR kamaji's Environment fails to name KAMAJI_HYDRATE_HELPER or KAMAJI_TAIL_HELPER — that last pair being the half a sha256sum structurally cannot see, and the exact state south was in. Reuses WANT_HYDRATE / WANT_TAIL already computed at :344-355 and adds a `durability_before()` twin of the existing `durability_after()` at :482. The \"ALREADY ON THIS BUILD\" message gained one line so it no longer claims more than it verified. No restructuring; no test added (scripts/ has no test home for this file). `bash -n` passes; shellcheck is not installed here and was not run. VERIFIED AGAINST THE LIVE NODE: before the fix `--dry-run` exited at \"ALREADY ON THIS BUILD\"; after it, it reaches \"DRY RUN — stopping here\", and since all seven installed binaries hash EXACTLY to published 0.8.37, the durability clauses are demonstrably the only ones firing. The subsequent `--yes` roll of us-south-001 installed both helpers + the drop-in and both env vars are now live on kamaji.service. NOTE FOR B22's OWN 0.8.38 ROLL: us-east-001 and us-west-001 were deliberately NOT touched — east carries unpublished 0.8.38-h5 kamaji (sha 4c54cfe2...) which is the only carrier of R881-B7's container-DNS fix, and rolling it to 0.8.37 would revert that. With this fix in place, a 0.8.38 roll of east/west will now correctly report the durability work as outstanding rather than short-circuiting past it.")
//! @yah:next("ROLL ORDER FOR THE 0.8.38 CUT, AND THE HAZARD THAT SETS IT — derived by the R858 leader (@Ashguard:golem) from live state, 2026-09-11. THE TARGET LIST GREW: this ticket was scoped to us-east-001, but R858-B23 turned out to be the same incident from the other end, so all THREE voters need 0.8.38 — east for R881-B7's container-DNS fix, west and south for R858-B23's durability gate (without which kamaji keeps fail-closing the mesh coordinator). ORDER: us-east-001 and us-west-001 FIRST, us-south-001 LAST. WHY: `/cluster/singletons` records us-south-001 as ingress owner and raft leader is node 1 = us-south-001 (term 22, measured by @Glimmerstone:spade), so rolling south restarts the leader and forces an election. THE HAZARD THAT MAKES THE ORDER NON-NEGOTIABLE: us-south-001 is the ONLY node holding headscale.db (plus config.yaml and the noise key) — west's copy is stale and east never hosted the appliance. With the new durability gate OFF by default there is no hydration, so if the post-restart election moves appliance ownership to a node WITHOUT headscale.db, that node starts headscale on an EMPTY DATABASE: it will look healthy, answer /health 200, and have lost all 10 node registrations, 4 pre-auth keys and the policy. R858-T8's rehearsal falsified the noise-identity half of this fear (a client re-reads /key every connect and authenticates by machine key, so a changed server identity does NOT reject registered nodes) — but it falsified the IDENTITY half only. The DATABASE is still the thing a failover must carry, and nothing carries it today: litestream is configured on no prod node and turso durability is now gated off. MITIGATION, do this BEFORE rolling south: take a read-only copy of /var/lib/yah-cloud/headscale/headscale.db (and its -wal) to /tmp on south, record its sha256, and leave the originals in place. Then roll south and WATCH where ownership lands — `curl http://<mesh-ip>:7443/cluster/singletons` on each node, noting that `yubaba raft status` hardcodes 127.0.0.1:7443 and connection-refuses on every prod voter, so use the mesh IP and curl. If ownership does not return to us-south-001, stop before headscale serves anywhere else and move the DB deliberately rather than letting an empty one come up.")
//! @yah:handoff("LEADER PASS — @Ashguard:golem (session:ce91058c), 2026-09-11, handing off at context budget with the cut IN FLIGHT. THE PRECONDITION THIS TICKET EXISTED TO SETTLE IS SETTLED AND THE ANSWER IS YES: R881-B7's container-DNS fix is committed in HEAD (`resolver_mount_source` + `HostResolvers::read()` in oss/kamaji/crates/kamaji-containerd-core/src/lib.rs, a file that is not even dirty), so a release built from this tree carries it — `git show v0.8.37:<that file> | grep -c resolver_mount_source` = 0 against HEAD's 12, which is exactly why rolling to 0.8.37 would revert it. R858-T21's install legs are likewise in HEAD and absent from the tag. I ALSO ANSWERED THE PROVENANCE OBJECTION rather than repeating 0.8.35's: the entire working-tree delta over HEAD inside the release blast radius (oss/kamaji, oss/yubaba, oss/yah-base) is rustfmt reflow plus @yah: board annotations — I read every hunk — so this cut is behaviorally identical to HEAD. Cluster-epoch drift guard re-run by me: 8 passed / 0 failed. OPERATOR AUTHORIZED the cut and the roll explicitly, 2026-09-11. @Ashguard:polaris (session:8dcfb4ce) holds the cut: it has bumped to 0.8.38 via `cargo xtask release patch` and is running `scripts/publish-yubaba-release.sh --publish`. Nothing is committed or tagged — this camp's git policy is defer mode, so the operator sweeps git; the command a sweeper wants is a pathspec-scoped commit of the bumped manifests plus the four oss source files, tagged v0.8.38.")
//! @yah:handoff("Tree anchor at handoff: 4163c4d83802865ffe83d09007adbd5d14507dbf — the shared tree as I left it. Diff against it (`git diff 4163c4d83802865ffe83d09007adbd5d14507dbf..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("FILE THE FOLLOW-UP THE OPERATOR ALREADY CHOSE — it is decided work, not a proposal, and it is deliberately NOT appended here as unowned scope. The operator picked \"B then A\" on 2026-09-11: B is the default-off gate that just landed; A is the real durability path and needs its own ticket. A = mint a Cloudflare R2 token scoped read+write to the `yah-headscale` bucket by W295's recorded ceremony (the one used for yah-fleet-index-read — permission group id plus resource string, same ceremony with a write permission group), add the CredentialSpec beside `cloudflare-r2-cert-store-access-key-id` in oss/yah-base/crates/keys/src/spec.rs, provision it as a kamaji EnvironmentFile in control_plane_install.sh's durability leg at :181-191 (which today writes only the two helper PATHS and by construction never carried credentials), and flip `--headscale-durability` ON in that SAME provisioning step — so the declaration and its prerequisite arrive together by construction, which is the defect this entire outage is made of. GROUNDING, measured: there is no existing credential that fits. kamaji.service carries no EnvironmentFile at all; hydrate.rs:188-191 states by design that credentials come from kamaji's own environment; /etc/yah-cloud/litestream.env does not exist on us-south-001; /etc/yah-cloud/cert-store.env's CF_R2_* pair is cert-store-scoped by its own header; and keys/src/spec.rs's only scoped fleet pair, cloudflare-r2-fleet-read-*, is READ-only and so cannot serve turso-backup-tail. The account-wide pair was explicitly DECLINED by the operator, so do not reach for it.")
//! @yah:verify("RE-RUN BY ME, NOT TAKEN FROM A COURIER. `cargo test -p xtask --test main --locked -q -- cluster_epoch_drift::` = 8 passed / 0 failed (the guard publish-yubaba-release.sh runs before it builds anything). `cargo test -p yubaba --lib` FROM oss/yubaba = 867 passed / 0 failed — note the root workspace REFUSES that invocation (\"package `yubaba` cannot be tested because it requires dev-dependencies and is not a member of the workspace\"), so run it from oss/yubaba or you will read a false negative; the relay's older 788 figure is stale. Live node state measured directly over ssh: us-south-001 = published yubaba+kamaji 0.8.37, and AFTER the R858-B23 roll it now carries both turso helpers, 50-durability-helpers.conf and both KAMAJI_*_HELPER vars; us-east-001 = yubaba 0.8.37 with kamaji 0.8.38-h5 (sha256 4c54cfe29f155d1deae8f272f796a78965c613e6c08a76e466027515654e947f), still the only carrier of R881-B7's DNS fix and still with NO durability helpers. NOT VERIFIED AND NOT CLAIMED: the 0.8.38 manifest was not live when I handed off, no node has been rolled to it, and neither half of this ticket's own verify block has been run.")
//! @yah:gotcha("THE SCOPE OF THIS TICKET GREW MID-PASS AND THE TARGET LIST IS NO LONGER ONE NODE. R858-B23, filed hours earlier, turned out to be the SAME INCIDENT seen from the other end: the 2026-09-11 06:40 roll shipped R858-F17's `yah.durability.tier = \"stream\"` declaration onto voters with no hydrate helper, kamaji correctly fail-closed, and the mesh coordinator has been down since — i.e. this relay's own RELEASE-ORDER TRAP gotcha did not just predict a hazard, IT ALREADY FIRED. So 0.8.38 must carry FOUR things, not the two this ticket was filed for: R881-B7's DNS fix, R858-T21's install legs, the scripts/roll-node.sh:400-418 short-circuit fix, and R858-B23's new default-OFF durability gate in oss/yubaba/crates/yubaba/src/headscale_appliance.rs. I held polaris's publish until that gate landed, because versioned CDN keys are immutable — cutting 0.8.38 without the gate would have burned a version number on a build that still could not run the coordinator. VERIFY BEFORE ROLLING that the published tarball's yubaba actually carries the gate; the cheapest content check is that `--headscale-durability` appears in `yubaba --help` on a rolled node.")
//! @yah:handoff("BUMP LANDED (2026-09-11). `cargo xtask release patch` from repo root: 0.8.37 -> 0.8.38, 235 edits written, no field hand-edited. The four versions publish-yubaba-release.sh hard-gates on by name all read 0.8.38 in [workspace.package]: oss/yubaba, oss/kamaji, oss/qed, oss/passway (the script also gates oss/turso-backup at :154 — that one is bumped too). DISCOVERED WORK DONE IN THIS PASS: xtask bumps manifests but does NOT refresh Cargo.lock, and scripts/cross-build-guarded.sh:114 builds `--locked`, so every release leg would have died instantly on a stale lockfile. Refreshed all six via `cargo metadata --manifest-path <ws>/Cargo.toml` (root, oss/yubaba, oss/kamaji, oss/qed, oss/passway, oss/turso-backup) — root relocked 20 path packages, yubaba 5, kamaji 4, qed 2, passway+turso-backup already consistent. xtask's own closing hint only says `cargo metadata` for the root; the five oss/ workspaces are separate Cargo workspaces and need it individually.")
//! @yah:gotcha("`cargo xtask release patch` reports 9 files still pinning the OLD version and calls them \"either a pin to move by hand or a frozen literal\". Checked at 0.8.37->0.8.38: 8 are frozen test literals in app/yah/cli/src/qed_publish.rs (cas_merge_index fixtures — correctly frozen, do not touch). The 9th, oss/mesofact/crates/mesofact/src/cli/new/curated.rs:121 `version: \"0.8.37\"`, is a scaffolding template default and is OUTSIDE the yubaba release blast radius — left alone deliberately, but it is drifting one patch version per cut and somebody should decide whether it should track the workspace version.")
//! @yah:gotcha("THE TREE IS NOW AT 0.8.38 AND EVERY RELEASE WORKSPACE'S Cargo.lock WAS REFRESHED — collected 2026-09-11 by @Ashguard:golem (session:ce91058c) from @Ashguard:polaris (session:8dcfb4ce) mid-cut. This matters to every OTHER live session in this camp, not just to R858, which is why it is recorded here rather than only in a courier's return: eight sessions share this working tree, the bump touched `[workspace.package].version` in the root plus every `oss/*/Cargo.toml` and every oss-provided dependency requirement tree-wide, and the lockfile refresh was NOT optional — `scripts/cross-build-guarded.sh:114` builds `--locked`, so a stale lock fails the release build outright. Consequences a peer should expect and NOT diagnose as breakage: their next `cargo` invocation rebuilds more than they changed; any binary they build now reports 0.8.38; and a peer holding uncommitted edits to a `Cargo.toml` may see a conflict with the bump. The bump is mechanical and owned by `cargo xtask release patch` (xtask/src/release.rs) — do NOT hand-edit or `sed` a version field to reconcile, and do not revert the lockfiles. PUBLISH STATE AT HANDOFF: `scripts/publish-yubaba-release.sh --publish` was RUNNING (polaris's background task b98wge47b, monitor armed) and had not completed, so cdn.yah.dev/yubaba/release-manifest.json still read 0.8.37 when this was written. Confirm the manifest actually says 0.8.38 before rolling anything — the script writes the mutable pointer LAST, so a partial failure leaves an unreferenced yubaba/0.8.38/ prefix and a pointer still aimed at 0.8.37, which is the safe shape rather than a broken one.")
//! @yah:handoff("PUBLISH SUCCEEDED — yubaba/kamaji 0.8.38 IS LIVE ON THE CDN (2026-09-11 14:01). `scripts/publish-yubaba-release.sh --publish` exit 0, cut from commit 4163c4d83802865ffe83d09007adbd5d14507dbf (reported DIRTY under oss/* — the version bump and the peers' in-flight edits are uncommitted; see the git note below). Pointer manifest `https://cdn.yah.dev/yubaba/release-manifest.json` now reads version=0.8.38, cluster_protocol=7, state_epoch=6 — the expected triple. BOTH musl triples carry url+sha256: x86_64-unknown-linux-musl sha256 80b1a43a051c4be0f0e2690a04956801cfae1ad5c2450e89f9df1b79830fa84a (60168907 bytes), aarch64-unknown-linux-musl sha256 1bb9b0d594be669b44f508a3efb5e71e3913d1b3c9efd780841fc8a397968318 (56295182 bytes); each also carries blake3 `hash`, `bootstrap_hash` and a `bundle_url` sigstore bundle. check-release-manifest-published.sh PASSED TWICE, which is the download-side proof and not a self-report: once against the per-version key before the pointer was touched, once against the pointer after — each run re-downloaded both tarballs and re-hashed the bytes (scripts/check-release-manifest-published.sh:97-106), printing \"OK: <triple> verified\" for both and \"names version 0.8.38; 2 triple(s) verified\". Upload order was artifacts -> per-version manifest -> proof -> pointer last, as designed.")
//! @yah:handoff("PAYLOAD PROOF — all four things 0.8.38 had to carry are VERIFIED PRESENT IN THE SHIPPED BYTES, not merely in HEAD. Method: the staged tarballs under target/yubaba-release/0.8.38/ hash to exactly the sha256s the CDN proof re-downloaded and confirmed, so the staged tree IS the published tree; `strings -a <binary> | grep -c` on both triples. (1) R858-B23's durability gate: `headscale-durability` x1 and `YUBABA_HEADSCALE_DURABILITY` x1 in `yubaba`, BOTH triples. Source is oss/yubaba/crates/yubaba/src/main.rs:455-460 — `#[arg(long, env = \"YUBABA_HEADSCALE_DURABILITY\", action = clap::ArgAction::SetTrue, ...)] headscale_durability: bool`, so the CLI spelling a roller wants is `--headscale-durability` / the env var, and ArgAction::SetTrue means ABSENT == FALSE == the old safe behaviour. A node rolled to 0.8.38 without that flag does NOT declare the tier. (2) R881-B7's container-DNS fix: `/run/systemd/resolve/resolv.conf` (the value of SYSTEMD_RESOLVED_UPSTREAM) x1 in `kamaji`, BOTH triples. NOTE FOR THE NEXT VERIFIER: grepping the binary for the identifier `SYSTEMD_RESOLVED_UPSTREAM` returns 0 and looks like the fix is missing — it is a `pub const &str`, so only its VALUE is in the binary. Grep the path, not the const name. (3) R858-T21's install legs: `turso-backup-hydrate` x6 and `50-durability-helpers.conf` x4 in `yubaba`, and both helper binaries ship as real files in the tarball (turso-backup-hydrate 25166832 B, turso-backup-tail 25278512 B). (4) roll-node.sh's durability short-circuit is a REPO script, not a tarball artifact — it is not in the published bytes by design and the roller runs it from this working tree.")
//! @yah:handoff("NOT DONE, DELIBERATELY — NO NODE WAS ROLLED. Part 2 (the three-voter roll) was withheld by the leader as a production sequence needing a leader watching it. The next leader picks up from here with all three voters still on 0.8.37 and headscale still down; the script's own closing line is `scripts/roll-node.sh <machine> --to 0.8.38`, and per @Ashguard:golem the target list is ALL THREE voters (us-east-001, us-west-001, us-south-001), not just us-east-001, because west and south need the gate too. GIT: this camp is in defer mode and `git commit` / `git tag` are refused by the PreToolUse hook, working as designed. Nothing was committed or tagged. The command the operator should run to capture this cut (scoped to the release paths rather than `git add -A`, because 8 live sessions share this tree and a blanket add would sweep their in-flight work): `git add Cargo.toml Cargo.lock oss/*/Cargo.toml oss/*/Cargo.lock oss/*/crates/*/Cargo.toml app/yah/desktop/tauri.conf.json packages/*/*/package.json xtask/Cargo.toml && git commit -m \"release: 0.8.38\" && git tag v0.8.38`. That commits the 235 manifest edits `cargo xtask release patch` wrote plus the six refreshed Cargo.lock files. NOTE the tag would NOT match the bytes on the CDN: 0.8.38 was cut from a dirty tree at 4163c4d8, so the tag points at the parent of the bump. If exact provenance matters, tag the bump commit once it exists rather than 4163c4d8.")
//! @yah:verify("0.8.38 IS PUBLISHED AND LIVE — confirmed by the leader (@Ashguard:golem) with an independent `curl -s https://cdn.yah.dev/yubaba/release-manifest.json | jq`, not taken from the courier: version 0.8.38, cluster_protocol 7, state_epoch 6, and BOTH musl triples carry url + sha256 (aarch64 1bb9b0d594be669b…, 56295182 bytes; x86_64 80b1a43a051c4be0…, 60168907 bytes). @Ashguard:polaris reports publish-yubaba-release.sh --publish exited 0 with check-release-manifest-published.sh's download-side proof passing TWICE (pre-pointer and post-pointer, re-hashing both tarballs each time), and — the claim that actually matters for the roll — that both triples' SHIPPED BINARIES verifiably carry all three things: the `--headscale-durability` gate (default OFF), the /run/systemd/resolve/resolv.conf DNS fix, and the turso-backup helpers. That check is by BINARY CONTENT rather than by version string, which is the correct shape and the one roll-node.sh itself insists on. I verified the manifest leg myself; I did NOT independently re-extract the tarballs to re-check the three content claims, and say so plainly rather than implying I did.")
//! @yah:gotcha("PROVENANCE CAVEAT ON 0.8.38 — narrower than 0.8.35's hole, but state it exactly rather than overclaiming. Earlier in this pass I cleared the shared-tree objection by reading every working-tree hunk in the release blast radius and finding only rustfmt reflow plus @yah: annotations. THAT READING WAS A SNAPSHOT: the camp's build-skew rail afterwards flagged two of my own verification runs SUSPECT because peers modified `oss/kamaji/crates/kamaji/src/sandbox.rs` and `oss/yah-base/crates/workload-spec/src/control_plane_install.rs` mid-run, and polaris's release build ran against the same moving tree. THE TREE ALSO MOVED UNDER ME AT THE COMMIT LEVEL during this single session: the dispatch anchor was 0084982f221fda70abd0007833f85fc062767343 and by the end of the pass the branch tip was 4163c4d83802865ffe83d09007adbd5d14507dbf — a peer wip-commit swept in mid-cut. SO THE HONEST GUARANTEE IS: the published bytes verifiably CONTAIN the three features the roll depends on (gate, DNS fix, helpers), checked against the shipped binaries; they are NOT guaranteed byte-equal to either of those commits, and nothing was committed or tagged for the release itself. CONSEQUENCE FOR ANY FUTURE REVERT INSTRUCTION touching oss/kamaji, oss/yubaba or oss/yah-base: name a SHA, never a symbolic ref — 4163c4d83802865ffe83d09007adbd5d14507dbf is the tip as of this writing and is the closest thing to an anchor for what 0.8.38 was built from, but it is an upper bound rather than a proof. ALSO RECORD MY 867/0 yubaba FIGURE WITH ITS CAVEAT: `cargo test -p yubaba --lib` from oss/yubaba returned 867 passed / 0 failed, matching @Ashguard:blade's independently-measured count exactly, but the skew rail flagged that run for the same two files. I let it stand because two independent runs agreed and neither changed file is in the yubaba crate itself — a re-run on a quiet tree is one cheap call and worth it before sign-off. THE COMMIT THE OPERATOR NEEDS TO SWEEP, refused here by the defer-mode git hook and printed rather than retried: `git add Cargo.toml Cargo.lock oss/*/Cargo.toml oss/*/Cargo.lock oss/*/crates/*/Cargo.toml app/yah/desktop/tauri.conf.json packages/*/*/package.json xtask/Cargo.toml && git commit -m \"release: 0.8.38\" && git tag v0.8.38` — 235 manifest edits from `cargo xtask release patch` plus six Cargo.lock refreshes that xtask does not touch but `cross-build-guarded.sh:114`'s `--locked` requires.")
//! @yah:gotcha("MEASURED FROM THE noisetable CAMP ON us-east-001, 2026-09-11 (@Ashguard:hydra, session:4d85def5, ticket noisetable R131-T16) — THIS TICKET'S CENTRAL CONFLICT HAS CHANGED SHAPE AND THE OPEN QUESTION IS NOW A DIFFERENT ONE. Read live off the box: `kamaji 0.8.39-h2`, `yubaba 0.8.38`, and `kamaji --help | grep -c -- --tail-helper` = 2. So (a) 0.8.38 IS published — cdn.yah.dev/yubaba/release-manifest.json reads 0.8.38 — and (b) the node's kamaji is HOTSHIP BYTES ONE MINOR AHEAD of that published train. The \"rolling reverts R881-B7's container-DNS fix\" framing no longer describes the hazard: 30-container-net.conf is present, the container resolves Mailgun, and noisetable sign-in is serving. THE HAZARD IS NOW THE OPPOSITE DIRECTION — rolling us-east-001 to published 0.8.38 would DOWNGRADE kamaji from 0.8.39-h2, and nothing outside this camp's reach documents what 0.8.39-h2 carries that 0.8.38 does not. WHAT IS STILL GENUINELY MISSING IS ONLY THE INSTALL SIDE, and it is all three legs: /usr/local/bin holds ONLY turso-backup-snapshot (placed by noisetable R131-T17) — turso-backup-tail and turso-backup-hydrate ABSENT; no 50-durability-helpers.conf in /etc/systemd/system/kamaji.service.d/ (which holds 10-logdir, 20-bundle, 20-bundle.conf.rollback-20260906-coffee, 30-container-net, 40-setpcap); `systemctl show kamaji.service -p Environment` names neither KAMAJI_TAIL_HELPER nor KAMAJI_HYDRATE_HELPER. SUGGESTED RE-FRAME FOR WHOEVER CLAIMS THIS: the cheapest safe move may be a targeted `scripts/hotship.sh` of the two turso-backup-* binaries plus writing the drop-in, leaving the daemons untouched — it delivers exactly what noisetable R131-T16 is blocked on without re-litigating a version downgrade on the one node serving production sign-in. Deliberately NOT performed from the noisetable camp: it is a production action on this camp's ticket.")
//! @yah:handoff("DURABILITY HELPERS INSTALLED ON BOTH REMAINING NODES — us-west-001 and us-east-001. Done WITHOUT scripts/roll-node.sh and WITHOUT hotship, per the relay leader decision: kamaji stayed 0.8.39-h3 and yubaba stayed 0.8.38 on both boxes, verified byte-identical by sha256 before and after (kamaji 4a37d223..., yubaba edb3a690... on both nodes). us-south-001 not touched.\n\nPROVENANCE: bytes came from the published 0.8.38 x86_64-unknown-linux-musl tarball named by https://cdn.yah.dev/yubaba/release-manifest.json. Downloaded sha256 80b1a43a051c4be0f0e2690a04956801cfae1ad5c2450e89f9df1b79830fa84a, 60168907 bytes — matches the manifest sha256/bootstrap_hash and the expected value in the brief. Verified BEFORE extraction. Extracted only turso-backup-hydrate (sha256 95624460...) and turso-backup-tail (sha256 8b30b136...); both static x86-64 ELF. Same two hashes confirmed on both nodes after install. Drop-in written byte-exact from control_plane_install.sh:185 — three lines, Environment= only, no ExecStart=, sha256 ce86d03a..., mode 0644. Install used stage-then-mv-f (the install_atomic idiom), never write-in-place.\n\nus-west-001 (15.204.89.240) PASS — all four checks. (a) both helpers 0755 in /usr/local/bin; (b) /etc/systemd/system/kamaji.service.d/50-durability-helpers.conf present with exactly the three lines, 30-container-net.conf left untouched (sha 343866a3... unchanged); (c) systemctl show kamaji.service -p Environment names BOTH KAMAJI_HYDRATE_HELPER and KAMAJI_TAIL_HELPER alongside the pre-existing KAMAJI_CONTAINER_NET; (d) journal prints hydrate-on-place armed and durability tail armed, each naming its helper path. resumed=0, zero children as expected. Mesh key?v=138 = 200 from the node and from the laptop.\n\nus-east-001 (51.81.85.145) PASS — both halves.\nDURABILITY HALF: same four checks green. ls /usr/local/bin now holds turso-backup-hydrate, turso-backup-snapshot, turso-backup-tail. Drop-in dir intact — 10-logdir, 20-bundle, 20-bundle.conf.rollback-20260906-coffee, 30-container-net, 40-setpcap all still present, 50- ADDED beside them; 30-container-net.conf sha 09f46ebc... unchanged; merged Environment still carries KAMAJI_BUNDLE_CACHE_DIR, KAMAJI_BUNDLE_ORIGIN and KAMAJI_CONTAINER_NET=10.128.0.0/9.\nNOISETABLE REGRESSION HALF: NO REGRESSION. Container /etc/resolv.conf reads nameserver 213.186.33.99 with ZERO occurrences of 127.0.0.53 (grep -c returned 0), i.e. the R881-B7 container-DNS fix is intact. getent hosts smtp.mailgun.org SUCCEEDS inside the container namespaces. All four natives replayed — yah-marketing, yah-marketing-feed, yah-marketing-revalidate, noisetable all back under kamaji.service with fresh pids. All three listeners rebound on the same ports and answer identically to the pre-restart baseline: 100.64.0.3:41507=200, :34759=200, :40995=404 (404 on / is the revalidate hook baseline, identical before and after). Mesh 200.\n\nCORRECTION TO THE BLAST-RADIUS MODEL, worth carrying forward: the production sign-in path is NOT only the four natives. There is a FIFTH workload on us-east-001 — a containerd task named noisetable-account, pid 663145, its own netns with eth0 10.128.3.2/24 on bridge yah0 — and THAT is the one holding the container-DNS fix and doing the mailgun SMTP. Its cgroup is 0::/yah/noisetable-account under containerd, NOT under /yubaba.slice/kamaji.service, so systemctl restart kamaji does NOT cgroup-kill it: it kept pid 663145 straight through the restart. Meanwhile the four natives run in the HOST netns and host mount ns, where /etc/resolv.conf is still the 127.0.0.53 systemd-resolved stub — so inspecting resolv.conf via a native pid reads the stub and looks like a regression when nothing is wrong. The check that actually means something is nsenter -t CONTAINER_PID -m -n. Recording this because the brief modelled the restart as killing everything that matters, and it does not.\n\nDURABILITY REMAINS OFF, as instructed: --headscale-durability / YUBABA_HEADSCALE_DURABILITY left unset on both nodes. This landed the PREREQUISITE only; the credential work stays R858-T24. No source-tree edits, no git writes.")
//! @yah:handoff("RESOLVED — AND NOT BY THE ROLL THIS TICKET PLANNED. Led by @Ashguard:blade (session:eab3e3ec), implemented by @Glimmerstone:polaris (session:e93bbd8e), 2026-09-11. THE CENTRAL CONFLICT IS DISSOLVED: durability and noisetable sign-in are no longer mutually exclusive on us-east-001, and both are live on the same box at the same time. WHY THE PLANNED ROLL WAS THE WRONG INSTRUMENT BY THE TIME IT WAS RUNNABLE: all three voters had already moved to published yubaba 0.8.38 and to kamaji 0.8.39-h3 — HOTSHIP bytes one minor AHEAD of the published train, on no CDN manifest. `scripts/roll-node.sh --to 0.8.38` installs published binaries, so it would have DOWNGRADED kamaji on the one node running production sign-in, reverting 486 lines of unpublished work (`git diff --stat 4163c4d8..HEAD -- oss/kamaji`: sandbox.rs +326, server.rs +81, native.rs, jit.rs, container_net.rs, containerd.rs, and kamaji-proto codec.rs/lib.rs — the wire protocol may have moved). The ticket's own last gotcha had already reframed the hazard to exactly this and suggested the targeted route; I took it. WHAT WAS ACTUALLY DONE: installed ONLY `turso-backup-hydrate` + `turso-backup-tail` (0755) and `/etc/systemd/system/kamaji.service.d/50-durability-helpers.conf` (0644, `Environment=` only, never a second `ExecStart=`) on us-west-001 and us-east-001, extracted from the PUBLISHED 0.8.38 x86_64-musl tarball with its sha256 verified against the manifest BEFORE extraction, staged-then-renamed per control_plane_install.sh:181-191's install_atomic idiom. `/usr/local/bin/{yubaba,kamaji}` were never written on any node. us-south-001 was not touched (it already had all three from R858-B23's 0.8.37 roll). Durability stays OFF — `--headscale-durability` / `YUBABA_HEADSCALE_DURABILITY` unset everywhere; this delivers the PREREQUISITE, and turning the feature on is R858-T24.")
//! @yah:verify("RE-RUN BY THE LEADER OVER SSH AFTER THE COURIER RETURNED, NOT COPIED FROM ITS REPORT. DURABILITY HALF — all four lines PASS on BOTH us-west-001 (debian@15.204.89.240) and us-east-001 (debian@51.81.85.145), identically: both helpers present at 0755, 25166832 B / 25278512 B, sha256 prefixes 956244606eb4dc02 (hydrate) and 8b30b136851bf150 (tail) — BYTE-IDENTICAL ACROSS THE TWO NODES, which is the cross-check that they came from one verified tarball rather than two local builds; 50-durability-helpers.conf present with exactly the three expected lines and no ExecStart=; `systemctl show kamaji.service -p Environment` NAMES BOTH KAMAJI_HYDRATE_HELPER and KAMAJI_TAIL_HELPER (the half a sha256 structurally cannot see, and the exact state us-south-001 was stuck in) while PRESERVING the pre-existing KAMAJI_CONTAINER_NET on both and KAMAJI_BUNDLE_CACHE_DIR / KAMAJI_BUNDLE_ORIGIN on east; and `journalctl -u kamaji` matches the armed lines twice on each node. NO BINARY MOVED: `kamaji --version` = 0.8.39-h3 and `yubaba --version` = 0.8.38 on both, after the fact. NOISETABLE REGRESSION HALF — PASSES, checked by me inside the container's own namespaces: `nsenter -t 663145 -m -- cat /etc/resolv.conf` returns the `/run/systemd/resolve/resolv.conf managed by systemd-resolved` file, NOT the 127.0.0.53 stub, and `nsenter -t 663145 -m -n -- getent hosts smtp.mailgun.org` RESOLVES (34.149.236.64) — that second line is the functional bar and R881-B7's fix is intact. All four kamaji natives are back in the cgroup and the three listeners answer their pre-restart codes exactly (41507=200, 34759=200, 40995=404 on `/`, which was the recorded baseline, not a regression). MESH UNAFFECTED THROUGHOUT: `https://cloud.mesh.yah.dev/key?v=138` = 200 after east's kamaji restart. NOT VERIFIED AND NOT CLAIMED: I did not send a live magic-link through Mailgun end-to-end, and I read the resolv.conf header rather than grepping its nameserver line — `getent` succeeding inside the netns is what I am resting the DNS claim on.")
//! @yah:gotcha("MODEL CORRECTION, measured on us-east-001 by @Glimmerstone:polaris and confirmed by the leader — THIS TICKET, hotship.sh's blast-radius table, and my own dispatch brief all had the noisetable workload in the wrong supervision tree, and the error made the job look riskier than it is. THE FOUR kamaji NATIVES on that box (noisetable 100.64.0.3:41507, yah-marketing :34759, yah-marketing-revalidate :40995, yah-marketing-feed) are mesofact bundle-serve processes in the HOST netns under `/yubaba.slice/kamaji.service`, and they ARE cgroup-killed and replayed by a kamaji restart. But the thing R881-B7's container-DNS fix actually protects is a FIFTH workload nobody had listed: `noisetable-account`, a CONTAINERD task (shim pid 663124, payload `/usr/local/bin/noisetable-account` pid 663145) living in cgroup `/yah/noisetable-account` on the yah0 bridge in its OWN network namespace — NOT a kamaji child. It therefore RODE THROUGH the kamaji restart untouched, same pid before and after. That matches hotship.sh's own line that 'containerd-backed workloads are not children and ride through', which this ticket never connected to the sign-in path. CONSEQUENCE FOR THE NEXT OPERATOR: a kamaji restart on us-east-001 costs ~seconds of the three mesofact listeners and costs the sign-in container NOTHING; the DNS half can only regress from a kamaji BINARY change or a 30-container-net.conf change, not from a restart.")

/// Single-quote a value for safe embedding inside the generated bash. Callers
/// only ever embed manifest-derived URLs/digests (already constrained) and a
/// version string, but we quote defensively regardless.
fn sh_squote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The canonical roll script body, shared verbatim with `scripts/roll-node.sh`.
/// Expects the four-variable prologue [`build_install_script`] emits.
pub const INSTALL_SCRIPT_TEMPLATE: &str = include_str!("control_plane_install.sh");

/// Build the self-contained install script for the yubaba+kamaji pair.
///
/// `sudo` is `true` when the executing user is not root (e.g. an SSH login as
/// `debian@…`), matching `stand-up-yubaba.sh`'s `SUDO` convention. The mesh
/// (self-update) path runs the script as root inside a `systemd-run` transient
/// unit, so it passes `sudo = false`. The script is idempotent and atomic; it
/// anchors what it is about to replace, restarts kamaji then yubaba (W154
/// supervision order) and echoes the installed versions so the caller can log
/// them — after having already proved the install by hash, not by those strings.
///
/// `version`/`url`/`sha256` MUST come from a signed release manifest — this
/// builder does no verification of its own beyond emitting the `sha256sum -c`
/// check; integrity rests on the caller only ever passing manifest-resolved
/// values.
pub fn build_install_script(version: &str, url: &str, sha256: &str, sudo: bool) -> String {
    let sudo_kw = if sudo { "sudo" } else { "" };
    format!(
        "SUDO={sudo_kw}\nURL={url}\nSHA={sha}\nVER={ver}\n{body}",
        sudo_kw = sudo_kw,
        url = sh_squote(url),
        sha = sh_squote(sha256),
        ver = sh_squote(version),
        body = INSTALL_SCRIPT_TEMPLATE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_embeds_the_signed_digest_and_url() {
        let url = "https://cdn.yah.dev/yubaba/0.8.19/yubaba-0.8.19-x86_64-unknown-linux-musl.tar.gz";
        let sha = "abc123def456";
        let s = build_install_script("0.8.19", url, sha, false);
        assert!(s.contains(sha), "script must carry the manifest sha256");
        assert!(s.contains(url), "script must carry the manifest url");
        assert!(s.contains("sha256sum -c -"), "script must verify the digest");
    }

    #[test]
    fn script_is_atomic_and_installs_the_whole_pair() {
        let s = build_install_script("0.8.19", "u", "d", false);
        // Atomic: stage-then-rename, never a direct write to the live path.
        assert!(s.contains("mv -f"), "install must be an atomic rename");
        assert!(s.contains(".roll-new.$$"), "install must stage to a temp name");
        // Every binary + all four unit files (scryer and the passway pair
        // conditionally — see the dedicated tests below).
        for target in [
            "/usr/local/bin/yubaba",
            "/usr/local/bin/kamaji",
            "/usr/local/bin/yah-scryer",
            "/usr/local/bin/passway",
            "/usr/local/bin/passway-demux",
            "/etc/systemd/system/yubaba.slice",
            "/etc/systemd/system/kamaji.service",
            "/etc/systemd/system/yubaba.service",
            "/etc/systemd/system/yah-scryer.service",
        ] {
            assert!(s.contains(target), "script must install {target}");
        }
        // Restart order: kamaji before yubaba (W154).
        let k = s.find("restart kamaji.service").unwrap();
        let y = s.find("restart yubaba.service").unwrap();
        assert!(k < y, "kamaji must restart before yubaba");
        assert!(s.contains("daemon-reload"));
    }

    #[test]
    fn scryer_install_is_conditional_on_the_tarball_carrying_it() {
        // R556-F6 gate (b): yah-scryer joined the tarball at 0.8.32. A
        // rollback to a pre-scryer release must still succeed — the script
        // must gate every scryer action on the member existing rather than
        // failing on it, and must leave an already-installed scryer alone.
        let s = build_install_script("0.8.32", "u", "d", true);
        assert!(
            s.contains(r#"if [ -e "$D/yah-scryer" ]; then"#),
            "scryer install must be gated on the tarball carrying the binary"
        );
        assert!(
            s.contains(r#"assert_installed_bytes "$D/yah-scryer" /usr/local/bin/yah-scryer"#),
            "installed scryer bytes must be content-asserted like the pair"
        );
        // First install has never been enabled; later rolls no-op.
        assert!(s.contains("enable yah-scryer.service"));
        // The scryer restart must come after the W154 pair restart — it is
        // located by yubaba, not driven by it (A049), and must not perturb
        // the kamaji→yubaba order.
        assert!(
            s.find("restart yubaba.service").unwrap()
                < s.find("restart yah-scryer.service").unwrap(),
            "scryer restarts after the supervision pair"
        );
    }

    #[test]
    fn passway_installs_conditionally_and_never_restarts_the_front_door() {
        // R870-B2: passway + passway-demux joined the tarball at 0.8.33, giving
        // the sovereign front door its first distribution path. Same
        // conditional shape as scryer, so a rollback to a pre-0.8.33 release
        // still succeeds.
        let s = build_install_script("0.8.33", "u", "d", true);
        assert!(
            s.contains(r#"if [ -e "$D/passway" ]; then"#),
            "passway install must be gated on the tarball carrying the binary"
        );
        for bin in ["passway", "passway-demux"] {
            assert!(
                s.contains(&format!(
                    r#"assert_installed_bytes "$D/{bin}"       /usr/local/bin/{bin}"#
                )) || s.contains(&format!(
                    r#"assert_installed_bytes "$D/{bin}" /usr/local/bin/{bin}"#
                )),
                "installed {bin} bytes must be content-asserted like the pair"
            );
        }
        // THE LOAD-BEARING NEGATIVE. passway cannot hot-swap a cert (tls.rs
        // "The reload gap"), so `systemctl restart` on a door drops in-flight
        // connections on public :443. A roll stages the bytes; the operator
        // chooses when to take the blip. If someone later adds a restart here,
        // every fleet roll starts cutting live traffic on yah.dev — and it
        // would look like an obvious omission being fixed.
        let exec = executable_lines(&s);
        for unit in [
            "passway.service",
            "passway-test.service",
            "passway-demux.service",
            "passway-http-router.service",
        ] {
            assert!(
                !exec.contains(unit),
                "a roll must not name {unit} — see R870-T3 for the graceful path"
            );
        }
    }

    #[test]
    fn the_http_router_rides_its_own_conditional_not_the_passway_pairs() {
        // R870-F1: the :80 tier joined at 0.8.34, one release AFTER the passway
        // pair. Gating it on HAS_PASSWAY would make this script fail against
        // every 0.8.33 tarball — which is exactly the rollback path the
        // conditional shape exists to keep working.
        let s = build_install_script("0.8.34", "u", "d", true);
        assert!(
            s.contains(r#"if [ -e "$D/passway-http-router" ]; then"#),
            "the :80 tier must be gated on its own tarball member"
        );
        assert!(
            s.contains(
                r#"assert_installed_bytes "$D/passway-http-router" /usr/local/bin/passway-http-router"#
            ),
            "installed http-router bytes must be content-asserted like the pair"
        );
        assert!(
            s.contains("anchor /usr/local/bin/passway-http-router"),
            "there must be a way back from a :80 roll"
        );
    }

    #[test]
    fn the_graceful_upgrade_helper_rides_the_roll_but_its_dropin_does_not() {
        // R870-T3. The helper is the ExecReload= that makes a cert rotation a
        // process swap: fleet-wide, no node state, so it installs like a binary
        // and gets the same rollback anchor and content assertion.
        let s = build_install_script("0.8.34", "u", "d", true);
        assert!(
            s.contains(r#"if [ -e "$D/passway-graceful-upgrade" ]; then"#),
            "the helper must be gated on its own tarball member, like the :80 tier"
        );
        assert!(
            s.contains(
                r#"assert_installed_bytes "$D/passway-graceful-upgrade" /usr/local/bin/passway-graceful-upgrade"#
            ),
            "installed helper bytes must be content-asserted"
        );
        assert!(
            s.contains("anchor /usr/local/bin/passway-graceful-upgrade"),
            "there must be a way back from a helper roll"
        );
        // The DROP-IN that arms it is node state: it lands in
        // /etc/systemd/system/<unit>.service.d/ and the unit name differs per
        // door. Naming it in an `echo` is how an operator learns the reload verb
        // exists; writing it would put a roll in the business of rewriting a
        // live door's unit configuration.
        for line in executable_lines(&s)
            .lines()
            .filter(|l| l.contains("passway-graceful-upgrade.conf"))
        {
            assert!(
                line.trim_start().starts_with("echo "),
                "the script may print the drop-in's name, never install it: {line}"
            );
        }
    }

    #[test]
    fn the_durability_helpers_ride_the_roll_with_their_kamaji_dropin() {
        // R858-T21. kamaji hard-refuses to deploy any workload declaring a
        // `yah.durability.tier` when either helper is missing, and until this
        // block the two turso-backup binaries were placed ONLY by provisioning
        // — so a node that was ROLLED could never acquire them, and R858-F17's
        // "roll it, then verify the helpers are on the node" could never pass.
        let s = build_install_script("0.8.38", "u", "d", true);
        assert!(
            s.contains(
                r#"if [ -e "$D/turso-backup-hydrate" ] && [ -e "$D/turso-backup-tail" ]; then"#
            ),
            "the helpers must be gated on the tarball carrying BOTH — a pre-0.8.37 \
             rollback must still roll cleanly, and half a pair is not a pair"
        );
        for bin in ["turso-backup-hydrate", "turso-backup-tail"] {
            assert!(
                s.contains(&format!("anchor /usr/local/bin/{bin}\n")),
                "there must be a way back from a {bin} roll"
            );
            assert!(
                s.contains(&format!(r#"install_atomic "$D/{bin}""#)),
                "{bin} must be staged-then-renamed like every other file here"
            );
            assert!(
                s.contains(&format!(
                    r#"assert_installed_bytes "$D/{bin}" /usr/local/bin/{bin}"#
                )) || s.contains(&format!(
                    r#"assert_installed_bytes "$D/{bin}"    /usr/local/bin/{bin}"#
                )),
                "installed {bin} bytes must be content-asserted like the pair"
            );
        }
        // UNLIKE passway's drop-in, THIS one IS the roll's business: the unit
        // name is fleet-wide (`kamaji.service`, installed by this very script)
        // and the file carries no node state — it is two absolute paths that are
        // the same on every box.
        let dropin = "/etc/systemd/system/kamaji.service.d/50-durability-helpers.conf";
        assert!(
            s.contains(r#"install_atomic "$WORK/50-durability-helpers.conf" 0644 \"#),
            "the drop-in must be staged-then-renamed, not written in place"
        );
        assert!(s.contains(dropin), "the drop-in must land at {dropin}");
        assert!(
            s.contains("Environment=KAMAJI_HYDRATE_HELPER=/usr/local/bin/turso-backup-hydrate")
                && s.contains("Environment=KAMAJI_TAIL_HELPER=/usr/local/bin/turso-backup-tail"),
            "both helper paths must reach kamaji's environment"
        );
        // The single most important property, and the reason this is a test
        // rather than a comment: a drop-in that redeclares ExecStart= silently
        // drops every flag the unit added after it — measured on us-south-001,
        // half of the 2026-09-03 outage. The flags arrive as Environment=, and
        // no line this script executes may mention ExecStart at all.
        let exec = executable_lines(&s);
        assert!(
            !exec.contains("ExecStart"),
            "the helper flags must never arrive by rewriting kamaji's ExecStart"
        );
        // Live on THIS roll, not the next one: the drop-in must be in place
        // before the daemon-reload, and kamaji must restart after it.
        let install = s
            .find(r#"install_atomic "$WORK/50-durability-helpers.conf""#)
            .expect("drop-in install");
        let reload = s.find("systemctl daemon-reload").expect("daemon-reload");
        let restart = s
            .find("systemctl restart kamaji.service")
            .expect("kamaji restart");
        assert!(
            install < reload && reload < restart,
            "drop-in must land before daemon-reload, and kamaji restart after it, \
             or the helpers only take effect on the following roll"
        );
    }

    /// The script with every comment line removed — i.e. only the lines bash
    /// will actually execute. The template documents the durable-state rule in
    /// prose *by naming the paths it must not touch*, so the guard below has to
    /// look at commands, not at the whole file, or the doc comment describing
    /// the property would be what breaks the test asserting it.
    fn executable_lines(script: &str) -> String {
        script
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn headscale_durability_flag_never_ships_without_its_credential() {
        // R858-T24. This relay is a 37-hour and a 14-hour outage caused by the
        // same defect twice: a declaration shipped ahead of its prerequisite.
        // The property that matters is not "the on-path works" (that would
        // have passed before both outages too) — it is that no path through
        // this script can set YUBABA_HEADSCALE_DURABILITY without also having
        // just wired the S3 credential kamaji's hydrate helper needs.
        let s = build_install_script("0.8.40", "u", "d", true);

        let cred_if = s
            .find(
                r#"if [ "$HAS_DURABILITY_HELPERS" = 1 ] && [ -f "$HEADSCALE_DURABILITY_CRED" ]; then"#,
            )
            .expect("the credential-gated if must exist");
        let cred_elif = s
            .find(r#"elif [ "$HAS_DURABILITY_HELPERS" = 1 ]; then"#)
            .expect("the absent-credential branch must exist");
        assert!(
            cred_if < cred_elif,
            "the credential check must be the first arm, the absent case the second"
        );
        let elif_end = cred_elif + s[cred_elif..].find("\nfi\n").expect("closing fi");

        // Both the kamaji credential wiring and the yubaba flag must sit
        // strictly inside the `if` arm — never in the `elif` arm, and never
        // outside the conditional altogether.
        let cred_env_file = s
            .find("printf '[Service]\\nEnvironmentFile=%s")
            .expect("kamaji EnvironmentFile= drop-in must reference the credential file");
        let flag_line = s
            .find("Environment=YUBABA_HEADSCALE_DURABILITY=1")
            .expect("the flag itself must be emitted somewhere in the script");
        assert!(
            cred_if < cred_env_file && cred_env_file < cred_elif,
            "the credential EnvironmentFile= wiring must be inside the credential-gated if arm"
        );
        assert!(
            cred_if < flag_line && flag_line < cred_elif,
            "YUBABA_HEADSCALE_DURABILITY must be set ONLY inside the same conditional \
             that wired the credential — never on a path that can run without it"
        );

        // The absent-credential arm must say so loudly, and must not set the
        // flag under any name — the mirror.yml `[ -f … ] && … || echo` trap
        // this relay explicitly rejected copying.
        let elif_body = &s[cred_elif..elif_end];
        assert!(
            elif_body.contains("R858-T24"),
            "the absent-credential branch must say plainly why the tier stayed off"
        );
        assert!(
            !elif_body.contains("Environment=YUBABA_HEADSCALE_DURABILITY"),
            "the absent-credential branch must not set the flag under any name \
             (a plain mention in the operator-facing echo is fine; an assignment is not)"
        );

        // Both drop-ins are staged-then-renamed, like every other file this
        // script writes — never written in place.
        assert!(s.contains(r#"install_atomic "$WORK/51-headscale-durability-cred.conf""#));
        assert!(s.contains(r#"install_atomic "$WORK/50-headscale-durability.conf""#));

        // Never an ExecStart= edit — the sanctioned shape, and the hazard
        // behind half of the 2026-09-03 outage (litestream.rs:227).
        let exec = executable_lines(&s);
        assert!(
            !exec.contains("ExecStart"),
            "the flag and credential must arrive as Environment=/EnvironmentFile=, \
             never by rewriting a service's ExecStart="
        );
    }

    #[test]
    fn script_never_touches_durable_state() {
        // The load-bearing safety property: a roll moves binaries + unit files
        // ONLY. Wiping identity.json forces a re-TOFU (R589 gotcha); touching
        // the raft dir corrupts consensus. The script must reference neither.
        let s = executable_lines(&build_install_script("0.8.19", "u", "d", true));
        assert!(!s.contains("identity.json"), "must not touch host identity");
        assert!(!s.contains("/var/lib/yah-cloud"), "must not touch state dir");
        assert!(!s.contains("raft"), "must not touch the raft log dir");
        assert!(!s.contains("rm -rf /"), "must not wipe system paths");
        // Scryer's events.db is durable per-node state the same way — a roll
        // replaces the binary + unit, never the store (R556-F6 gate (b)).
        assert!(
            !s.contains("/var/lib/yah/scryer"),
            "must not touch the scryer event store"
        );
    }

    #[test]
    fn script_anchors_every_file_it_replaces_before_replacing_it() {
        // R755-F3. Every path the script installs must first be copied to a
        // dated `.rollback-YYYYMMDD` sibling — the convention the fleet's boxes
        // already carry — and the anchoring must happen BEFORE the install, or
        // the anchor holds the new build and there is no way back.
        let s = build_install_script("0.8.19", "u", "d", true);
        let first_anchor = s.find("anchor /usr/local/bin/yubaba").expect("anchors");
        let first_install = s.find("install_atomic \"$D/yubaba\"").expect("installs");
        assert!(
            first_anchor < first_install,
            "anchors must be written before anything is replaced"
        );
        assert!(s.contains(r#"STAMP="$(date -u +%Y%m%d)""#));
        for target in [
            "/usr/local/bin/yubaba",
            "/usr/local/bin/kamaji",
            "/usr/local/bin/yah-scryer",
            "/usr/local/bin/passway",
            "/usr/local/bin/passway-demux",
            "/etc/systemd/system/yubaba.slice",
            "/etc/systemd/system/kamaji.service",
            "/etc/systemd/system/yubaba.service",
            "/etc/systemd/system/yah-scryer.service",
            // R858-T21: the durability helpers and the drop-in that arms them.
            "/usr/local/bin/turso-backup-hydrate",
            "/usr/local/bin/turso-backup-tail",
            "/etc/systemd/system/kamaji.service.d/50-durability-helpers.conf",
        ] {
            assert!(
                s.contains(&format!("anchor {target}\n")),
                "every installed path needs a rollback anchor, missing {target}"
            );
        }
    }

    #[test]
    fn anchoring_is_idempotent_within_a_day() {
        // The subtle half: a second roll on the same day must NOT re-anchor,
        // or the escape hatch gets overwritten with the build being escaped.
        let s = build_install_script("0.8.19", "u", "d", true);
        assert!(
            s.contains(r#"if [ ! -e "$1.rollback-$STAMP" ]; then"#),
            "anchor must refuse to overwrite an existing same-day anchor"
        );
    }

    #[test]
    fn success_is_asserted_by_content_not_by_version_string() {
        // R746-T3's trap: `--version` reports the workspace version baked in at
        // build time and was right on a binary carrying none of that version's
        // code. The proof has to be a hash of the installed bytes against the
        // bytes extracted from the manifest-verified tarball.
        let s = build_install_script("0.8.19", "u", "d", true);
        for pair in [
            r#"assert_installed_bytes "$D/yubaba" /usr/local/bin/yubaba"#,
            r#"assert_installed_bytes "$D/kamaji" /usr/local/bin/kamaji"#,
        ] {
            assert!(s.contains(pair), "missing content assertion: {pair}");
        }
        // …and a mismatch must fail the roll, not merely print.
        let body = &s[s.find("assert_installed_bytes() {").expect("assert fn")..];
        assert!(
            body.contains("content assertion FAILED") && body.contains("exit 1"),
            "a content mismatch must exit nonzero so the caller sees a failed roll"
        );
        // The assertion must land before the restart — restarting onto bytes
        // you haven't proved is the failure mode this closes.
        assert!(
            s.find("assert_installed_bytes \"$D/yubaba\"").unwrap()
                < s.find("systemctl restart kamaji.service").unwrap(),
            "content must be proved before the supervision tree restarts"
        );
    }

    #[test]
    fn the_template_is_the_only_copy_of_the_body() {
        // scripts/roll-node.sh runs these same bytes with no Rust in the loop,
        // so build_install_script must be a prologue over the template and
        // nothing more. If this drifts, the SSH job and the mesh self-update
        // stop being the same roll.
        let s = build_install_script("0.8.19", "u", "d", false);
        assert!(
            s.ends_with(INSTALL_SCRIPT_TEMPLATE),
            "the built script must be prologue + the shared template, verbatim"
        );
        let prologue = &s[..s.len() - INSTALL_SCRIPT_TEMPLATE.len()];
        assert_eq!(
            prologue.lines().count(),
            4,
            "the prologue is exactly URL/SHA/VER/SUDO — anything else belongs in the template"
        );
    }

    #[test]
    fn sudo_prefix_tracks_the_caller() {
        let s = build_install_script("0.8.19", "u", "d", true);
        assert!(s.contains("SUDO=sudo"));
        let s = build_install_script("0.8.19", "u", "d", false);
        assert!(s.contains("SUDO=\n") || s.contains("SUDO="));
    }
}
