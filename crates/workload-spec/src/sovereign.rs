//! The sovereign-group join rule — W305 / R742-F1, reshaped by R605-F35.
//!
//! One sentence of logic, deliberately given a home of its own because it is
//! asked in two crates that cannot see each other:
//!
//! - **camp-side**, `cloud::judge_join`, which reads two `MachineConfig`s and
//!   answers "may these two boxes be in one quorum" while planning;
//! - **node-side**, `yubaba`'s `POST /raft/add-learner` gate, which reads its
//!   own `--sovereign-group` and asks the joiner for its own, and refuses.
//!
//! `yubaba` deliberately does **not** depend on `cloud` (R374-F3 moved
//! `local-driver` out precisely to avoid that edge), so the rule cannot simply
//! live in one of them. It lives here for the same reason
//! [`PUBLIC_IP_TAINT`](crate::PUBLIC_IP_TAINT) does: this crate is the shared
//! vocabulary both the planner and the daemon already link, and it depends on
//! neither.
//!
//! What is **not** shared is the prose. A camp-side refusal points at
//! `.yah/infra/machines/<name>.toml`; a node-side refusal has no machine name
//! to interpolate and must also name `yubaba serve --sovereign-group`, because
//! editing the TOML alone does not change what the running daemon declares.
//! Two renderings, one predicate — which is the split that keeps them from
//! disagreeing about what counts as a refusal.
//!
//! # Three declarations, three owners (R605-F35)
//!
//! A sovereign group's raft is described by three facts, and each has exactly
//! one owner:
//!
//! - **which blast radius** a node is in — the node's `sovereign_group`;
//! - **whether it takes part in that group's raft at all** — the node's
//!   [`Participation`];
//! - **which participants hold quorum seats** — the *group's* voter list
//!   (`.yah/infra/sovereign-groups/<group>.toml` camp-side, `yubaba serve
//!   --sovereign-voters` on the daemon).
//!
//! The third used to be a per-node `sovereign_role = voter | non-voter`
//! (R605-F12). The operator moved it to the group on 2026-10-06, and the reason
//! is the whole design: a per-node flag spreads quorum composition across N
//! machine files, so no single declaration can say "these three, on three
//! different hosts" — and the moment several members share one physical box
//! (R605-F16's VMs on the dev Pis), *where* voters sit is the property that
//! decides whether losing one box loses consensus. Only a list held in one
//! place can be checked for that.
//!
//! So joining is uniform: **every participant joins learner-first**
//! (`POST /raft/add-learner`), and the leader then promotes it only if the
//! group lists it. That is raft's own safe-add pattern — catch up as a learner,
//! then change membership — and it means a participant the group does not list
//! is a learner for good, which is the shape the dev VMs want (3 voters + N
//! learners, quorum unchanged).
//!
//! [`join_permitted`] below judges only the first two facts. Promotion is a
//! separate, leader-side question answered from the voter list.
//!
//! # Reading a live cluster against these declarations
//!
//! **The declared group and the raft voter set are different sets, and the gap
//! between them is the design working rather than drift.** An `out` node is
//! never joined, so it is absent from `/raft/status`'s `members` map *by
//! construction* — us-west-003 declaring `sovereign_group = "prod"` while
//! appearing nowhere in prod's membership is the expected observation: a prod
//! worker, inside the blast radius, outside the raft. An `in` node the group
//! does not list is present as a **learner** and never as a voter.
//!
//! The observations that **are** worth an alarm:
//!
//! - a **listed voter** absent from its group's voter set — it was granted a
//!   seat and never took it, so either a join failed or the list is
//!   aspirational;
//! - an **unlisted** node holding a voter seat — the guarantee is broken, which
//!   means a promotion bypassed the leader's list rather than merely mis-read it;
//! - an **`out`** node present in a raft membership at all;
//! - a node in a membership whose declared group differs from the cluster's —
//!   the cross-group join [`join_permitted`] exists to refuse.
//!
//! Note also that a node's *running* daemon is the authority on what it
//! declares, not its TOML: `/raft/status` reporting `sovereign_group: null` on a
//! box whose file says `prod` means the daemon was started without the flag,
//! and a missing key means the binary predates the field.
//!
//! @yah:ticket(R605-F35, "Group-level voter set: a sovereign group owns its quorum composition; members join learner-first and only listed voters are promoted")
//! @yah:status(review)
//! @yah:at(2026-10-07T00:36:34Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R605)
//! @yah:next("OPERATOR DECISION 2026-10-06 (ask_user to R605's leader, session:46658430): quorum composition is GROUP-level, not per-member. This replaces F12's per-member Voter/NonVoter axis. A node declares only whether it PARTICIPATES in its group's raft. The group declares which members hold quorum seats. Every participant joins as a learner (POST /raft/add-learner, R569-F3), and only listed voters are promoted. A per-member `learner` role value was offered and declined, because it spreads quorum across N machine files and cannot guard voter placement.")
//! @yah:next("TODAY (from scoping, verify at edit time): SovereignRole::{Voter, NonVoter} in oss/yah-base/crates/workload-spec/src/sovereign.rs:90-104, read as --sovereign-role at oss/yubaba/crates/yubaba/src/main.rs:392-412. join_permitted refuses NonVoter outright (pinned by raft_sovereign_group.rs:161 and :227). The sovereign gate sits in front of /raft/add-learner (lib.rs:3313). check_unroled_sovereign_members (cloud.rs:13885) requires every member to declare a role, and .yah/infra/cloud-init/dev-raft-node.sh passes no --sovereign-role.")
//! @yah:next("DELIVER: (1) a group-level declaration home for each group's voter list (find where sovereign groups are defined; create one if none exists). (2) A per-node participation field replacing sovereign_role. (3) A join path that is always learner-first, promoting only listed voters. (4) A validator: a voter list naming a non-participant, or two voters sharing a physical host, is an error. VM members declare their host; that field is new and lands with R605-F16's VM machine files. (5) Migration of every machine file's sovereign_role, with no alias or shim (pre-1.0 rule). (6) dev-raft-node.sh updated to match. The prod group's existing 3 voters must read as no-op voters under the new code.")
//! @yah:next("Tier: Wizard. This is a raft membership-semantics change on the join path every prod and dev member uses, and a wrong default promotes the wrong node to a quorum seat.")
//! @yah:handoff("LANDED — quorum composition is GROUP-level. (1) HOME: new .yah/infra/sovereign-groups/<group>.toml (prod.toml, dev.toml), type cloud::config::SovereignGroupConfig {name, voters: [[voters]] {machine, raft_node_id}} (deny_unknown_fields), loaded into CloudConfig.sovereign_groups (camp-local; load + load_from_config_dir), path helper cloud::paths::sovereign_groups_dir, schema .yah/schema/sovereign-group.toml.schema.json (new xtask SCHEMA_KINDS entry). Lives in infra/ beside machines/ because it is a per-group declaration the camp owns; raft_node_id is in the group file because the leader judges promotion by raft id (a daemon does not know its machine-file name; MemberInfo.machine is a hostname). Accessors: CloudConfig::sovereign_group_decl / voting_group(m) / seated_voters(group), SovereignGroupConfig::lists / voters_flag.")
//! @yah:handoff("(2) PARTICIPATION: SovereignRole and MachineConfig.sovereign_role deleted outright (no alias, no read-both). New workload_spec::sovereign::Participation {In, Out} (TOML/CLI/JSON spelling \"in\"/\"out\", default In — safe because an unlisted `in` node is at most a learner), MachineConfig.sovereign_participation (serde default, omitted when in), Membership{group, participation}; join_permitted = same non-None group AND both In. NonVoter -> Out. Old `voter`/`non-voter` strings are refused by name in FromStr.")
//! @yah:handoff("(3) JOIN PATH (yubaba): every permitted add-learner is a learner join; after add_learner(blocking) returns, the leader promotes via ChangeMembers::AddVoterIds iff ITS OWN --sovereign-voters lists the joiner AND ClusterPolicy.voter_admission admits (new promote_listed_voter in lib.rs); 200 body gains voter_listed/promoted/promotion. The list is read LEADER-SIDE from daemon config, never from the joiner: new yubaba_consensus::cluster_policy::VoterSeats {NoGroup, Listed{group,voters}} via ServerState::voter_seats(); gates POST /raft/promote-voter (403 naming the list), add-learner promotion, AND the membership ratchet's plan_rehydrate (new gate 2b) — the rig profile's ratchet would otherwise auto-promote F16's stable VM learners within one 300s hold-down. Group declared + no list = Listed(empty) = promotes nobody (fail-closed, warned at boot). Disagreement pinned: the_leaders_voter_list_decides_and_the_joiners_own_list_does_not. raft init is deliberately NOT gated (founding names every voter; total-loss recovery re-inits prod mid-outage).")
//! @yah:handoff("(4) VALIDATOR: cloud::validate::check_sovereign_groups replaces check_unroled_sovereign_members (ERROR in `yah cloud validate`, preflight WARNING in apply, app/yah/cli/src/cloud.rs). Findings: Undeclared group, Unparseable file, NameMismatch, UnknownVoter, VoterNotInGroup, VoterOutOfRaft, DuplicateSeat (machine or raft id), VotersShareAHost (by MachineConfig::physical_host()), UnknownHost. HOST FIELD NAME FOR F36: `host_machine` (Option<String>, machine name of the metal box; None = metal is its own host). F36's us-west-141.toml already uses it and validates clean.")
//! @yah:handoff("(5) MIGRATION: 7 machine files (sovereign lines only, re-read at edit time): us-west-001/us-east-001/us-south-001/us-west-011/013/014 -> sovereign_participation = \"in\"; us-west-003 -> \"out\". prod.toml seats us-west-001=1, us-south-001=2, us-east-001=3; dev.toml seats 011=11, 013=13, 014=14 — the six live voters, so the new code is a no-op on today's clusters. dev-raft-node.sh ExecStart now carries `--sovereign-participation in --sovereign-voters 11,13,14` (xtask test pins it against dev.toml). Also migrated: .yah/qed/yah-release-wizard.toml roll-the-fleet script + advance now split --voter/--node from the group file's voter list instead of sovereign_role; W325 §3d gained a SUPERSEDED note; topology.rs quorum arithmetic + Mermaid labels read seats (RaftSeat {NoGroup, Voter, Learner, Out}; denominator = seated voters).")
//! @yah:handoff("WIRE (prod runs matched 0.8.42): CHANGED, yubaba-to-yubaba operator path only. GET /raft/status drops `sovereign_role`, adds `sovereign_participation` and `sovereign_voters`; POST /raft/add-learner 200 body gains keys and may now promote a listed joiner; POST /raft/promote-voter gains a 403. NO change to YubabaRequest/YubabaResponse/YubabaState or raft RPCs; NO yubaba-to-kamaji change. Mixed-version reads degrade safely both ways (old joiner -> read as `in`; new joiner asked by 0.8.42 leader -> read as `voter`, and old leaders never auto-promote). cluster-epochs.json: re-recorded with a 2026-10-06 surface_rerecords verdict, NOT BREAKING, cluster_protocol stays 8.")
//! @yah:handoff("EXTRA WORK beyond the six deliverables: membership_ratchet gate (see 3); yah-release-wizard.toml roll script; topology.rs seat model; fleet_build_placement.rs now asks cfg.voting_group(); harness solo_node_with_sovereign_role -> solo_node_with_sovereign_participation + new solo_node_listing_voters; added us-west-141 (F36's new VM file) to fleet_sovereign_groups EXPECTED and told @Glimmerstone:dove (session:e7135418) by party.chat + notify_on(R605-F36) that each further VM file needs a row.")
//! @yah:handoff("GIT (policy defer, not run): the human sweep should include .yah/infra/sovereign-groups/ (new), .yah/schema/sovereign-group.toml.schema.json (new), and the modified files under oss/yah-base/crates/workload-spec, oss/yubaba/crates/{yubaba,yubaba-consensus,yubaba-test-harness,cloud}, app/yah/cli/src/{cloud,lan_tunnel}.rs, xtask/, .yah/infra/{machines,cloud-init}, .yah/qed/yah-release-wizard.toml, .yah/schema/machine.toml.schema.json, W325 — e.g. `git add -A .yah/infra/sovereign-groups .yah/schema/sovereign-group.toml.schema.json && git commit` after review.")
//! @yah:verify("BASELINES (pre-change tree, sovereign.rs restored to index + claim annotation): yubaba `cargo test -p yubaba --test main -- raft_` 64 passed/0 failed; `cargo test -p yubaba-consensus --lib` 134/0; `cargo test -p yubaba --lib sovereign` 14/0; `cargo test -p yah-cloud --lib` 1285 passed/0 failed/6 ignored; `cargo check -p yah` EXIT=0; `cargo test -p xtask --test main -- fleet_sovereign_groups:: fleet_build_placement:: schema_drift:: cluster_epoch_drift::` 19/0.")
//! @yah:verify("AFTER: raft_ 67/0 (+3: a_listed_participant_is_promoted_and_an_unlisted_one_stays_a_learner, the_leaders_voter_list_decides_and_the_joiners_own_list_does_not, a_group_with_no_voter_list_promotes_nobody; :161/:227 converted to an_out_member_of_the_same_group_is_refused / an_out_leader_refuses_to_grow_its_raft); raft_add_learner now asserts voter_listed/promoted false — re-run of raft_add_learner/sovereign_group/membership_ratchet/cell_tagging/promote_voter subset after that edit: 32/0. consensus lib 138/0 (+3 VoterSeats, +1 only_learners_the_group_lists_are_rehydrated). yubaba lib sovereign 15/0. yah-workload-spec --lib sovereign 9/0. yah-cloud --lib 1294/0/6 ignored (incl. two_listed_voters_on_one_physical_host_is_an_error, a_voter_list_naming_a_non_participant_is_an_error, a_seat_needs_the_stamp_participation_and_the_groups_list). cargo check -p yah EXIT=0. xtask suite 21/0 (+each_groups_voter_list_is_the_reviewed_set_and_validates — runs check_sovereign_groups over the REAL fleet clean — and dev_raft_node_sh_carries_the_dev_groups_voter_list); schema_drift and cluster_epoch_drift green after emit-schemas + cluster-epochs --write.")
//! @yah:verify("Logs: /tmp/r605f35_base1_*.log, /tmp/r605f35_base2_xtask.log, /tmp/r605f35_after{1,2,3}_*.log. Several runs carry advisory skew notices from peer edits in kamaji/board/camp-service — outside this ticket's closure.")
//! @yah:gotcha("ROLL ORDER for F16 (nothing was rolled here): a pre-F35 yubaba REJECTS --sovereign-participation/--sovereign-voters (clap unknown flag -> unit fails to start), and a post-F35 yubaba REJECTS --sovereign-role. Roll the binary and swap the drop-in flags together, per node. Check us-west-003's unit for a leftover --sovereign-role before it gets an F35 build. dev-raft-node.sh's pinned DEV_RAFT_VERSION 0.8.19 predates the new flags (comment added at the pin).")
//! @yah:gotcha("FAIL-CLOSED ON THE LIVE DEV GROUP: today's dev drop-ins carry --sovereign-group dev and no voter list. On an F35 build without `--sovereign-voters 11,13,14` added, the leader promotes nobody — including the rig ratchet's rehydrate of a returning Pi. dev-raft-node.sh refuses nodes with raft state, so the existing 40-raft.conf on 011/013/014 must be edited by hand. Prod (fleet = LearnerOnly + Frozen) is unaffected either way; adding `--sovereign-voters 1,2,3` there is for visibility on /raft/status.")
//! @yah:gotcha("cloud::judge_join still has no non-test caller (pre-existing; its doc says operator-driven joins go through it). The camp-side half of the node-side backstop window described in sovereign_group::read_group therefore rests on a function nothing calls.")
//! @yah:verify("PART1 re-run 2026-10-06: raft_ 67/0 (matches courier), yubaba-consensus --lib 138/0 (matches), yah-cloud --lib 1294/0/6 ignored (matches); logs /tmp/r605f35v-a{1,2,3}.log, all EXIT=0. xtask suite and cargo check -p yah: see following entry.")
//! @yah:gotcha("RELEASE-HAZARD CENSUS 2026-10-06 (read-only, systemctl cat yubaba over ssh; logs /tmp/r605f35v-ssh-*.log): NO node carries --sovereign-role. Effective ExecStart (last drop-in) per node: us-west-001/us-south-001/us-east-001 = ...--raft-node-id N --raft-dir ... --sovereign-group prod (95-sovereign-group.conf; east also --scryer-endpoint); us-west-011/013 = ...--cluster-profile rig --sovereign-group dev (95-); us-west-014 = same, 95- carries --sovereign-group dev; us-west-003 = standalone, 10-yah.conf/20-standalone.conf, NO --sovereign-* flag at all (only 85-cluster-key, 96-region). All 7 answered. Consequence: an F35 yubaba will NOT clap-reject on any live unit (the only sovereign flag present is --sovereign-group, which F35 keeps). The hazard runs the other way: no node passes --sovereign-participation/--sovereign-voters, so a pre-F35->F35 roll alone leaves dev (011/013/014) fail-closed (promotes nobody, incl. rig-ratchet rehydrate) until `--sovereign-voters 11,13,14` is added to each 95-sovereign-group.conf (every one of those drop-ins re-declares the whole ExecStart, so the edit goes in the 95- file, the last one). Prod is unaffected (LearnerOnly+Frozen). Note 014's earlier 10-yah.conf also carries --sovereign-group dev but is superseded by 95-.")
//! @yah:gotcha("ROLL PATH DOES NOT REWRITE --sovereign-* FLAGS (read 2026-10-06): scripts/roll-node.sh and scripts/hotship.sh contain zero 'sovereign' references; they swap the binary and touch only the helper/graceful-upgrade drop-ins (kamaji 50-durability-helpers, passway-graceful-upgrade), never yubaba's ExecStart drop-ins. The yah-release-wizard.toml roll script only READS .yah/infra/machines/*.toml sovereign_group and .yah/infra/sovereign-groups/<group>.toml to pick --voter/--node sets for `yah cloud rollout plan`; it writes no drop-in. So rolling an F35 binary leaves the drop-in flags exactly as they are: the operator must add `--sovereign-voters 11,13,14` (and optionally `--sovereign-participation in`, plus `--sovereign-voters 1,2,3` on prod for visibility) to each 95-sovereign-group.conf by hand.")
//! @yah:verify("PART1 cont. 2026-10-06: xtask suite 21/0 (matches), no fleet_ failure; `cargo check -p yah` EXIT=0 (logs /tmp/r605f35v-b{1,2}.log). CAVEAT: camp skew verdict flagged workload-spec/src/sovereign.rs and yubaba/src/main.rs as modified DURING that run (a peer or the F35 owner edited F35's own files), so the xtask/check green describes a slightly earlier tree; a re-run was not done.")
//!
//! @yah:ticket(R605-F37, "One owner for yubaba's sovereign unit flags: roll tooling renders 95-sovereign-group.conf from .yah/infra/sovereign-groups + the machine file, and refuses a roll whose live drop-in disagrees")
//! @yah:status(review)
//! @yah:at(2026-10-07T02:25:01Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:next("MEASURED 2026-10-06 by R605's F35 census, read-only on all 7 yubaba nodes. The live --sovereign-group flag sits in /etc/systemd/system/yubaba.service.d/95-sovereign-group.conf (prod on us-west-001/us-south-001/us-east-001, dev on us-west-011/013/014; us-west-003 has none). scripts/roll-node.sh, scripts/hotship.sh and the roll script in .yah/qed/yah-release-wizard.toml NEVER rewrite --sovereign-* flags. So R605-F35's voter list (.yah/infra/sovereign-groups/<group>.toml) only reaches a node when someone hand-edits that drop-in, which R605-F16 is doing on the dev Pis right now. The voter list therefore lives in three places: the group file, dev-raft-node.sh (pinned by an xtask test), and N hand-edited drop-ins. Only the first two are checked, so the live copy can drift silently. A voter-list change in dev.toml would never reach a node, and a dev voter left without --sovereign-voters fails closed, promoting nobody, including the ratchet's rehydrate of a returning Pi.")
//! @yah:next("DELIVER: a single renderer for the yubaba sovereign drop-in, a pure function of the group file plus the node's machine file that produces --sovereign-group, --sovereign-participation and --sovereign-voters. Use it in the roll path (roll-node.sh, hotship.sh, the release-wizard roll), so every roll installs the rendered drop-in. Before writing, diff the live drop-in against the rendered one: refuse on an unexplained difference, and print the diff. dev-raft-node.sh should consume the same renderer instead of carrying its own copy of the flags. Pin it with an xtask test that renders every node in .yah/infra/machines/ and checks the output against the group files. Prove it is a no-op on today's fleet with a read-only render-vs-live diff on all 7 nodes, taken AFTER R605-F16 has added the voter list to the dev Pis. The R858 lesson applies here: one owner per piece of node config.")
//! @yah:next("Tier: Warrior. The scope is bounded (scripts + xtask + one renderer), but it sits on the roll path for every prod and dev node, and a wrong render bricks a node at its next roll.")
//! @yah:depends_on(R605-F35)
//! @yah:soft_depends_on(R605-F16)
//! @yah:handoff("LANDED - ONE OWNER. oss/yubaba/crates/cloud/src/sovereign_unit.rs (new, pub mod in lib.rs): flags_for/render/render_flags are a pure function of the group file + machine file (errors, never guesses, on a group with no .yah/infra/sovereign-groups file); parse_systemctl_cat/effective_exec_start/check_live judge a node's live unit -> Verdict NoOp|Install|Remove|Refuse{why,diff}. 8 unit tests. CLI: `yah cloud sovereign-dropin <machine> [--live <systemctl-cat file>] [--accept-sovereign-change]` (app/yah/cli/src/cloud.rs, handle_sovereign_dropin): prints the drop-in; with --live the first stderr line is VERDICT and an unexplained difference exits 3 with the diff. Chosen as a yah subcommand because the roll scripts are bash and xtask/rollout link the cloud crate directly, so one Rust implementation serves all three.")
//! @yah:handoff("MECHANISM DECISION (recorded in sovereign_unit.rs module doc): the drop-in is 90-sovereign.conf carrying ONLY Environment=YUBABA_SOVEREIGN_{GROUP,PARTICIPATION,VOTERS}, never ExecStart=. yubaba serve gained env= fallbacks for --sovereign-group/--sovereign-participation/--sovereign-voters (oss/yubaba/crates/yubaba/src/main.rs). Reason: every live ExecStart also carries per-node flags (raft id, --scryer-endpoint on east, --cluster-profile rig), so an owner of ExecStart would have to own all of them or drop them (R858-T4). Env is also version-safe: an older yubaba ignores an unknown env var where clap rejects an unknown flag. It is a NEW file, not a rewrite of 95-sovereign-group.conf, because removing 95-'s ExecStart= on prod would fall back to an earlier drop-in's command line. Legacy literal --sovereign-* flags in the effective ExecStart win over env (argv beats env), so check_live REFUSES on any literal that disagrees with the render (even with --accept-sovereign-change), refuses any other fragment setting YUBABA_SOVEREIGN_*, refuses a differing 90- file unless --accept-sovereign-change, and reports agreeing literals as a NOTE (a shadowing copy, not a second source).")
//! @yah:handoff("ROLL PATHS: scripts/lib/sovereign-dropin.sh (new; sovereign_dropin_check/apply, transport only, no flag facts). scripts/roll-node.sh judges before the up-to-date short-circuit (refusal stops even --dry-run; a needed install forces the roll), installs right before the template's daemon-reload+restart, new --accept-sovereign-change. scripts/hotship.sh syncs per node when yubaba is shipped AND restarted, --dry-run judges only, new --accept-sovereign-change. `yah cloud rollout` (release wizard): rollout/apply.rs sync_sovereign_dropin over SSH runs before EITHER transport in YubabaAdapter::apply_version; YubabaAdapter::new renders every member up front so a declaration error fails the plan before any node is touched (from_topology, test-only, has no declarations and skips it). This adds one SSH round-trip to the mesh /self-update path, deliberately, since /self-update cannot carry a drop-in.")
//! @yah:handoff("dev-raft-node.sh (re-read after F16 landed; F16's JOIN mode, required DEV_RAFT_VERSION, pair dir and cluster key are kept): 40-raft.conf's ExecStart no longer carries any --sovereign-* flag. The script now REQUIRES DEV_RAFT_SOVEREIGN_CONF (a rendered `yah cloud sovereign-dropin <machine>` file copied to the box), sanity-checks it is a dev render, installs it verbatim as 90-sovereign.conf, and refuses a yubaba whose `serve --help` lacks YUBABA_SOVEREIGN_VOTERS. dev.toml's header comment was updated. The xtask pin dev_raft_node_sh_carries_the_dev_groups_voter_list was replaced by dev_raft_node_sh_installs_the_render_and_carries_no_sovereign_flag, and the new every_machines_sovereign_dropin_renders_from_the_group_files test renders every .yah/infra/machines file and reads it back against the group files and participation, with no ExecStart, and expects a NoOp on a node already carrying the render.")
//! @yah:handoff("LIVE NO-OP DIFF, read-only (only `systemctl cat yubaba.service` ran remotely), taken after F16 reached review. All 7 nodes answered. 0 refusals and 0 disagreements; every node returns VERDICT install because no node has 90-sovereign.conf yet. Literal flags agreeing with the render: prod us-west-001/us-south-001/us-east-001 `--sovereign-group prod` in 95-sovereign-group.conf; dev 011/013/014 `--sovereign-group dev --sovereign-participation in --sovereign-voters 11,13,14` in 40-raft.conf (F16 layout, no 95-). us-west-003 has no sovereign flag today and renders group prod / participation out, so its next roll ADDS that (an intended declaration, harmless on a raft-less node). PROD LAYOUT CHOICE: neither existing layout wins; both converge on 90-sovereign.conf at the next roll. Prod's 95- file and dev's literal flags stay until each node runs an env-capable yubaba, then get stripped. No live drop-in was edited. Files: /tmp/r605f37-live-e/*.{cat,verdict}.")
//! @yah:verify("BASELINE (cloud module unregistered): `cargo test -p xtask --test main -- fleet_` 20 passed/0 failed; `cargo check -p yah` EXIT=0 (/tmp/r605f37-base-{xtask,check}-a.log). AFTER: fleet_ 21/0 (+every_machines_sovereign_dropin_renders_from_the_group_files; the dev_raft_node pin was replaced, not added); `cargo check -p yah` EXIT=0 (one pre-existing unused-import warning at rollout/apply.rs:49 `Version`); `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib sovereign_unit` 8/0; `cargo check --manifest-path oss/yubaba/Cargo.toml -p yubaba` EXIT=0 (/tmp/r605f37-after-*-c.log). `bash -n` OK on scripts/roll-node.sh, scripts/hotship.sh, scripts/lib/sovereign-dropin.sh, .yah/infra/cloud-init/dev-raft-node.sh. `cargo build -p yah` EXIT=0, with a W298 skew advisory for crates/yah/camp-service/src/service.rs (a peer's edit, outside the subcommand's code path).")
//! @yah:gotcha("ROLL-ORDER: the rendered drop-in only takes effect on a yubaba built with this ticket's env= fallbacks. Until then it is inert and the agreeing literal flags still decide, which is safe both ways. Consequence for dev: dev-raft-node.sh now REFUSES the live dev builds (0.8.43-h3, pre-F37), so the next F16 VM join needs an F37-capable dev hotship first. INFERRED, not run: clap applies value_delimiter=',' to the YUBABA_SOVEREIGN_VOTERS env value the same as to the flag; no yubaba binary was executed with the env set.")
//! @yah:gotcha("Roll scripts now require an installed `yah` with `cloud sovereign-dropin`. Run `cargo xtask install` before the next roll-node/hotship/rollout, or they refuse with a clear message. .yah/infra/cloud-init/stand-up-yubaba.sh still passes a literal --sovereign-group (R911-T6) in 10-yah.conf. check_live tolerates it while it agrees, but it is the last literal writer and was left alone because a fresh stand-up may install a pre-F37 published binary.")
//! @yah:cleanup("Once every node runs an env-capable yubaba: strip the literal --sovereign-* flags from prod's 95-sovereign-group.conf ExecStart and dev's 40-raft.conf on the nodes (keep every other flag), move stand-up-yubaba.sh onto the render, then make check_live REFUSE (not NOTE) any literal --sovereign-* flag.")
//! @yah:handoff("TRANSITION CLOSED (leader follow-up): literal-flag retirement is now part of the roll. ONE node-side script: oss/yubaba/crates/cloud/src/sovereign_retire.sh, exposed as cloud::sovereign_unit::RETIRE_LITERALS_SCRIPT and printed by `yah cloud sovereign-dropin _ --retire-script`. Every path pipes that one copy. EXACT SEQUENCE ON THE NODE: (0) GATE: if the INSTALLED /usr/local/bin/yubaba's `serve --help` lacks YUBABA_SOVEREIGN_VOTERS, print SKIP and touch nothing, so an old binary never loses its flags. (1) No 90-sovereign.conf: NOOP if the argv has no literal, REFUSE if it has one. (2) Strip --sovereign-{group,participation,voters} from every ExecStart= line in every yubaba.service.d/*.conf, keeping every other flag, with a .pre-f37 copy, then daemon-reload. (3) Move 95-sovereign-group.conf aside and daemon-reload. Keep it removed only if the effective argv (systemctl show -p ExecStart) is unchanged; otherwise restore it, stripped, because it re-declares the whole ExecStart and may be the only carrier of e.g. --scryer-endpoint. (4) ASSERT that the effective argv carries no literal --sovereign-*; REFUSE otherwise. Prints RETIRED, NOOP or SKIP. The script never restarts yubaba; the caller does. Unit test the_retire_script_is_gated_on_the_installed_binary_reading_the_env pins gate-before-edit and no-restart. The strip regex was checked locally on a dev-shaped ExecStart: the sovereign flags were removed and --raft-node-id, --cluster-profile and --scryer-endpoint were kept.")
//! @yah:handoff("WHERE IT RUNS: scripts/hotship.sh, inside the unit:yubaba activation, AFTER the new bytes are installed and BEFORE `systemctl restart yubaba`, so the env-reading binary comes up with no literal flags in the SAME restart. scripts/roll-node.sh: the shared template installs and restarts in one step, so the retire runs after it; on RETIRED it restarts yubaba once more. That extra restart happens once per node, on the crossing roll. `yah cloud rollout` (rollout/apply.rs retire_sovereign_literals, called in apply_version after sync_sovereign_dropin): neither transport has a gap between install and restart, so on this path the literals retire on the first roll AFTER the node runs an env-reading yubaba (the restart that roll performs drops them). For the crossing roll itself, use hotship.sh or roll-node.sh. Helper: scripts/lib/sovereign-dropin.sh sovereign_literals_retire (sets SOVEREIGN_RETIRED).")
//! @yah:handoff("OPERATOR SEQUENCE: (1) `cargo xtask install`, so the roll scripts' `yah` has `cloud sovereign-dropin` and `--retire-script`. (2) Build an env-reading (post-F37) yubaba pair. (3) Roll the dev voters us-west-011/013/014 with hotship.sh (or roll-node.sh): each installs 90-sovereign.conf, then on the new binary strips the literals from 40-raft.conf and asserts none remain. (4) Only then can dev-raft-node.sh join new members. It REFUSES the current dev pair (0.8.43-h4), whose `serve --help` lacks YUBABA_SOVEREIGN_VOTERS, and in JOIN mode it installs the leader's pair, so R605-F36's us-west-131/132 join needs step 3 first. (5) Prod gets the same at its next release roll: 90- installed, the literal --sovereign-group stripped from 95-sovereign-group.conf, and 95- removed only where that leaves the argv unchanged.")
//! @yah:verify("AFTER RETIRE STEP: yah-cloud --lib sovereign_unit 9/0 (+1); xtask fleet_ 21/0 (baseline 20/0); `cargo check -p yah` EXIT=0 (/tmp/r605f37-after-{cloud,xtask,check}-f.log). bash -n OK: roll-node.sh, hotship.sh, scripts/lib/sovereign-dropin.sh, cloud/src/sovereign_retire.sh. The retire script itself has NOT been run on any node (no live writes in this ticket).")

use serde::{Deserialize, Serialize};

/// Whether a node in a sovereign group takes part in that group's raft at all
/// — R605-F35, replacing R605-F12's per-node `SovereignRole`.
///
/// This is the **only** quorum-related thing a node declares about itself.
/// Whether a participant holds a *seat* is the group's call, made from its
/// voter list; see the module docs for why that moved off the node.
///
/// [`Self::In`] is the default because it is what declaring a group has always
/// meant: every stamped member of prod and dev runs in its group's raft. Unlike
/// the role it replaces, the default can no longer hand out a quorum seat — an
/// `in` node the group does not list joins as a learner and stays one — so a
/// silent default here costs at most a learner, never a vote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Participation {
    /// Takes part in its group's raft: joins learner-first, and is promoted
    /// only if the group lists it as a voter.
    #[default]
    In,
    /// In the group's blast radius — shares its upgrade cadence, its secrets,
    /// its destruction — but absent from its raft entirely, as neither voter nor
    /// learner. Refused by [`join_permitted`] on either side of a join.
    ///
    /// Consequently a node stamped this way is **absent from its group's
    /// `/raft/status` `members` map, and that absence is correct** — see the
    /// module docs' "Reading a live cluster" section before reporting it as
    /// declared-vs-actual drift. us-west-003 is the case: a residential-uplink
    /// build box that must never hold a raft node id.
    Out,
}

impl Participation {
    /// The wire/TOML spelling: `"in"` / `"out"`. Matches the serde rename so
    /// the CLI flag, the TOML value and the `/raft/status` JSON can never
    /// disagree about how the value is written.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }

    /// True for [`Self::In`]. Named rather than matched at call sites so the
    /// join rule reads as one predicate.
    pub fn is_in(&self) -> bool {
        matches!(self, Self::In)
    }
}

impl std::fmt::Display for Participation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Participation {
    type Err = String;

    /// Parses the two legal spellings and nothing else. The error names both,
    /// because this is reached from a CLI flag where the operator has a typo in
    /// hand and no schema to consult — and because the near-misses are the
    /// retired R605-F12 values, which must not be read as a synonym.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "in" => Ok(Self::In),
            "out" => Ok(Self::Out),
            other => Err(format!(
                "unknown sovereign participation {other:?} — expected \"in\" or \"out\". \
                 (`voter` / `non-voter` were retired by R605-F35: which members vote is \
                 now the group's voter list, not a per-node field.)"
            )),
        }
    }
}

/// What one node declares about its place in a sovereign group.
///
/// `group` is `None` for a standalone node — **in no group**, which is a
/// declaration and not a gap; see [`join_permitted`]. `participation` only
/// means anything when `group` is `Some`: a standalone box has no group raft to
/// take part in, so it is never consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Membership<'a> {
    /// The declared group label, or `None` for standalone.
    pub group: Option<&'a str>,
    /// Whether the node takes part in that group's raft.
    pub participation: Participation,
}

impl<'a> Membership<'a> {
    /// A declared member of `group` with the given participation.
    pub fn new(group: &'a str, participation: Participation) -> Self {
        Self {
            group: Some(group),
            participation,
        }
    }

    /// A node in no group at all. Distinct from an `out` member: standalone
    /// asserts no blast-radius relationship to anything, where an `out` member
    /// shares the group's fate and only stays out of its raft.
    pub fn standalone() -> Self {
        Self {
            group: None,
            participation: Participation::default(),
        }
    }
}

/// May a node declaring `joiner` join — **as a learner** — a cluster whose
/// nodes declare `target`?
///
/// **Permitted iff both sides declare the same, non-`None` group *and* both
/// participate ([`Participation::In`]).** One rule, no special cases.
///
/// Note what this does **not** answer: whether the joiner then gets a vote.
/// Every join is learner-first; promotion is decided afterwards by the leader,
/// from its group's voter list (R605-F35). So a permit here grants replication,
/// never a quorum seat.
///
/// The case it exists for is two *different* declared groups — joining a dev Pi
/// into prod is refused rather than trusted, where the only prior guard was a
/// comment in a TOML saying not to. But an undeclared side is refused too, and
/// that is the deliberate half: **`None` means "in no group", not "unknown"**,
/// so growing prod with an unstamped box is exactly as much a cross-group join
/// as the dev case is. Failing open there would leave the operator believing a
/// guarantee that was never evaluated.
///
/// The distinction that word carries matters most at the *node* boundary. A
/// `MachineConfig` with no `sovereign_group` has genuinely declared standalone.
/// A daemon started without `--sovereign-group` has declared nothing — the
/// declaration never reached the box — and a caller that cannot tell those
/// apart must not pass `None` here and read the answer as "standalone". Resolve
/// the unknown first; this function only judges declarations.
///
/// # Why participation is checked on both sides
///
/// A join grows a raft, and it takes two nodes to do it. Refusing an `out`
/// *joiner* is us-west-003's case. Refusing an `out` *target* is the same
/// assertion read from the other end: a box declared out of its group's raft
/// should not be holding a raft seat to be joined *into*, so if one is, the
/// operator has a contradiction between the declaration and the running
/// cluster, and a permit here would paper over it.
pub fn join_permitted(joiner: Membership<'_>, target: Membership<'_>) -> bool {
    matches!((joiner.group, target.group), (Some(a), Some(b)) if a == b)
        && joiner.participation.is_in()
        && target.participation.is_in()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(group: &str) -> Membership<'_> {
        Membership::new(group, Participation::In)
    }

    fn out_of(group: &str) -> Membership<'_> {
        Membership::new(group, Participation::Out)
    }

    #[test]
    fn one_group_joins_itself() {
        assert!(join_permitted(member("dev"), member("dev")));
        assert!(join_permitted(member("prod"), member("prod")));
    }

    /// The refusal the field was added for.
    #[test]
    fn two_groups_do_not_merge() {
        assert!(!join_permitted(member("dev"), member("prod")));
    }

    /// `None` is a declaration, not a gap — so it never matches, including
    /// against itself. Two unstamped boxes forming a group nobody declared is
    /// the shape that leaves nothing to reason about later.
    #[test]
    fn undeclared_never_joins_anything() {
        assert!(!join_permitted(Membership::standalone(), member("prod")));
        assert!(!join_permitted(member("dev"), Membership::standalone()));
        assert!(!join_permitted(
            Membership::standalone(),
            Membership::standalone()
        ));
    }

    /// Group labels are compared exactly. A `"Dev"`/`"dev"` typo mints a
    /// phantom group rather than silently joining the real one, which is the
    /// safe direction: the refusal names both values, so the typo is visible
    /// at the moment it bites.
    #[test]
    fn labels_are_compared_exactly() {
        assert!(!join_permitted(member("Dev"), member("dev")));
        assert!(!join_permitted(member("dev "), member("dev")));
    }

    /// Same group, and still refused: us-west-003 is *in* prod's blast radius
    /// and must never hold a prod raft node id, not even as a learner.
    #[test]
    fn an_out_member_does_not_join_its_own_group() {
        assert!(!join_permitted(out_of("prod"), member("prod")));
    }

    /// Read from the other end: a box declared out of its group's raft has no
    /// raft to grow, so it cannot be the target of a join either.
    #[test]
    fn an_out_target_has_no_raft_to_join() {
        assert!(!join_permitted(member("prod"), out_of("prod")));
        assert!(!join_permitted(out_of("prod"), out_of("prod")));
    }

    /// Declaring a group means taking part in its raft unless said otherwise —
    /// and since R605-F35 that default costs at most a learner, never a seat.
    #[test]
    fn the_default_participation_is_in() {
        assert_eq!(Participation::default(), Participation::In);
        assert!(join_permitted(
            Membership::new("prod", Participation::default()),
            Membership::new("prod", Participation::default())
        ));
    }

    /// The TOML value, the CLI flag and the `/raft/status` JSON are all this
    /// one spelling; a round-trip is what keeps them from drifting apart.
    #[test]
    fn participation_round_trips_through_its_one_spelling() {
        for p in [Participation::In, Participation::Out] {
            assert_eq!(p.as_str().parse::<Participation>().unwrap(), p);
            assert_eq!(serde_json::to_string(&p).unwrap(), format!("\"{}\"", p.as_str()));
            assert_eq!(
                serde_json::from_str::<Participation>(&format!("\"{}\"", p.as_str())).unwrap(),
                p
            );
        }
    }

    /// The retired R605-F12 values are the near-misses an operator will
    /// actually type, so they are refused by name — accepting `voter` as a
    /// synonym for `in` would put a quorum claim back on the node that the
    /// group now owns.
    #[test]
    fn the_retired_role_spellings_are_errors_naming_both_legal_values() {
        for wrong in ["voter", "non-voter", "learner", "In", ""] {
            let err = wrong.parse::<Participation>().unwrap_err();
            assert!(err.contains("\"in\"") && err.contains("\"out\""), "{err}");
        }
    }
}
