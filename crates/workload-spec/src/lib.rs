//! `WorkloadSpec` — typed wire format for yubaba workloads.
//!
//! This crate is the schema source of truth. It has zero dependencies on
//! yubaba; yubaba depends on it, not the other way around. Agents and desktop
//! code that construct specs can link this crate without pulling in yubaba's
//! containerd client.
//!
//! Three validation layers live in [`validate`]: shape (sync, no I/O),
//! semantic (reads yubaba state), and environment (deploy-time). The schema
//! types live at the top level.
//!
//! @yah:ticket(R222-T3, "Workload schema doesn't match per-kind on-disk shapes (mesofact-static)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-18T16:47:03Z)
//! @yah:status(review)
//! @yah:parent(R222)
//! @yah:handoff("Picked option (a): tagged-enum Workload envelope with per-kind variants. Added Workload { MesofactStatic(MesofactStaticWorkload), Container(WorkloadSpec) } + BuildConfig in workload-spec. WorkloadSpec stays the containerd RPC wire type (now also the kind=\"container\" variant payload). xtask emit-schemas now renders workload.toml.schema.json as a oneOf over kind; schema drift test green. TS export updated. Arch doc 'workloads — colocated, not registered' rewritten to describe the envelope + both example kinds; B4 outlook updated to point at Workload.")
//! @yah:verify("cargo check -p cloud && cargo test -p cloud && cargo check -p yah && cargo check -p agent-tools && cargo check -p yah --tests && cargo check -p agent-tools --tests")
//! @yah:verify("cargo test -p xtask  # schema drift test must stay green")
//! @yah:verify("cargo run -p workload-spec --bin export-ts  # idempotent regen")
//!
//! @yah:ticket(R256-F7, "Model mesofact container as two roles: transient build/publish job vs long-lived SSR/SPA runtime")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-25T20:08:29Z)
//! @yah:status(review)
//! @yah:parent(R256)
//! @yah:next("role A — build/publish job: transient task that runs the build and PUTs to the object store, then exits/GC'd; needed whenever there is a build step (SSR or not)")
//! @yah:next("role B — SSR/SPA runtime: long-lived container, only present when the app has realtime/dynamic pages (this is what the 'only if SSR/SPA' gate applies to)")
//! @yah:next("decide the fidelity knob: does the build run in-container (matches CI, max fidelity, costs image+cold-start) or on host with yubaba orchestrating only the serving edge?")
//! @yah:assumes("in cloud these are separate: CI/build job produces artifacts, R2+CDN serve them, and a distinct worker serves any SSR — so one merged 'mesofact container' is the trap")
//! @yah:handoff("BuildMode enum added to workload-spec with HostSide (default) and InContainer { image } variants. MesofactStaticWorkload gains build_mode: BuildMode (skip_serializing_if default) and ssr_runtime: Option<WorkloadSpec>. Encodes the two-role model: build step is always transient; SSR companion is optional long-lived. Fidelity knob decision: HostSide = host watcher (dev+sim), InContainer = CI-fidelity (cloud/ha). All three codegen targets updated: export-ts.rs, packages/yah/workload-spec/index.ts, .yah/schema/workload.toml.schema.json. Schema drift tests pass.")
//! @yah:verify("cargo check -p workload-spec --locked")
//! @yah:verify("cargo test -p xtask --locked  # schema_drift tests pass")
//! @yah:verify("cargo test -p cloud --locked --lib  # 165 passed")
//!
//! @yah:ticket(R256-F9, "Almanac as a dependency manifest: orchestrator verifies I/O targets live before run; output invalidates mesofact sources cleanly")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-25T21:28:15Z)
//! @yah:status(review)
//! @yah:parent(R256)
//! @yah:next("almanac is a manifest declaring inputs + outputs + cadence + command — NOT a bash cron; the declared I/O is the contract")
//! @yah:next("before a run the orchestrator verifies declared inputs exist AND output targets (e.g. the mesofact app + its source/object store) are reachable; if not → the run fails or waits/times out rather than producing orphaned output")
//! @yah:next("almanac output invalidates downstream mesofact sources cleanly + deliberately (a declared dependency edge, not a blunt rebuild-everything) — this is the reason it's a named manifest, not a shell cron")
//! @yah:next("decide the not-ready policy knob: fail-fast vs wait-with-timeout vs requeue")
//! @yah:next("generalizes the OpenRouter refresher (spawn_almanac_refresher), which is the degenerate no-dependency case (output = JSON cache, no app target)")
//! @yah:assumes("precondition enforcement lives in the shared scheduler layer (embedded by camp for dev/sim, yubaba for cloud/ha) — it needs the workload registry + xlb-net discovery to answer 'is the target up?', which a bash cron lacks")
//! @arch:see(.yah/docs/architecture/A024-vocabulary.md)
//! @yah:depends_on(R256-F6)
//! @yah:handoff("AlmanacTarget (Http/Tcp probe), NotReadyPolicy (WaitWithTimeout default=5s/FailFast/Requeue), Cadence (Once/Every/Cron), and AlmanacManifest types added to workload-spec. Workload enum gains Almanac(AlmanacManifest) variant (kind='almanac'). NotReadyPolicy::WaitWithTimeout(5s) is the default — matches sim-tier spinup budget. AlmanacManifest.invalidates: Vec<MeshIdent> declares downstream cache-bust targets. export-ts.rs updated; index.ts and workload.toml.schema.json regenerated; drift tests pass. The degenerate case (no inputs, no outputs, Cron, no invalidates) is exactly the OpenRouter refresher pattern. The orchestrator precondition enforcement (xlb-net probing) is left for R276/yubaba integration.")
//! @yah:verify("cargo check -p workload-spec --locked")
//! @yah:verify("cargo test -p xtask --locked  # schema drift tests pass")
//! @yah:verify("cargo test -p cloud --locked --lib  # 165 passed")
//!
//! @yah:relay(R335, "Almanac mirror-binding — scope a feed to the mirror it affects")
//! @yah:at(2026-05-27T02:19:09Z)
//! @yah:status(open)
//! @arch:see(.yah/docs/working/W058-almanac-mirror-binding.md)
//! @yah:depends_on(R256-F9)
//!
//! @yah:ticket(R335-S1, "Decide cross-env pollution mechanism: extend R256-F9 manifest vs add per-mirror capability")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-05-27T02:19:33Z)
//! @yah:kind(spike)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R335)
//! @yah:gotcha("Build ON R256-F9's AlmanacManifest (workload-spec/src/lib.rs) — do NOT invent a parallel manifest. R256-F9 is in review.")
//! @yah:depends_on(R256-F9)
//! @yah:handoff("Decided. Recorded in almanac-mirror-binding.md §11. KEY FINDING: two almanac paths exist; the live R330 feed uses almanac::FeedConfig (on_change=MesofactRebuild{service,route} — a service id, NOT a MeshIdent), so it never touches AlmanacManifest.invalidates. Verdict on the S1 title: NEITHER extend the manifest nor (yet) add capability is the accident fix — dev->cloud is ALREADY blocked by construction (feed path = process locality + per-mirror reconciler + MinIO/R2 backend split; manifest path = no camp-embedded MeshState, mesh resolution is yubaba-raft-only). Residual holes: /revalidate receiver is UNAUTHENTICATED, and same-tier (two clouds on one R2) has no per-mirror key prefix.")
//! @yah:next("FILED: R335-F3 (P1, no yubaba dep) mirror-aware /revalidate receiver — reject feeds not bound to this mirror; satisfies R335-T2; lands with R330-F4.")
//! @yah:next("FILED: R335-F4 (P2) per-mirror artifact key prefix in derive_minio_key/publish_to_r2 — closes same-tier collision.")
//! @yah:next("FILED: R335-F5 (P3, BLOCKED on yubaba control plane) per-mirror capability gate on /revalidate via yubaba/xlb-net node identity.")
//!
//! @yah:ticket(R278-F4, "RolloutPolicy schema in workload-spec (TOML types)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T02:31:25Z)
//! @yah:status(review)
//! @yah:parent(R278)
//! @yah:next("Add src/rollout.rs with RolloutPolicy, RolloutStrategy, RolloutGate, RolloutStep, RolloutOnFailure")
//! @yah:next("Export pub mod rollout from lib.rs")
//! @yah:next("Add TS export via ts-rs in export-ts.rs")
//! @arch:see(.yah/docs/working/W140-yah-yubaba-ci-cd.md)
//! @yah:handoff("RolloutPolicy, RolloutStrategy, RolloutGate, RolloutStep, RolloutOnFailure added to workload-spec/src/rollout.rs. Exported from lib.rs. toml dev-dep added for round-trip test. Tests: rollout::tests::round_trip_toml + on_failure_default both green.")
//!
//! @yah:ticket(R429-T1, "Workload::StaticAsset variant + schema in workload-spec (catalog + aliases)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T23:24:20Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R429)
//! @yah:next("Add Workload::StaticAsset(StaticAssetWorkload) variant alongside the existing MesofactStatic + Container envelopes. Mirror the tagged-enum shape R222-T3 established.")
//! @yah:next("StaticAssetWorkload fields: kind='static-asset' tag, assets: Vec<AssetEntry>, aliases: BTreeMap<String, String>. AssetEntry { filename: String, source: PathBuf, blake3: BlakeHash }.")
//! @yah:next("BlakeHash newtype validates 64-hex-char shape (reuse from existing places if available, else introduce here).")
//! @yah:next("Closed-catalog invariant: aliases values MUST be filenames present in the assets list. Reject at load with a clear error pointing at the offending alias key + bad filename.")
//! @yah:next("Mirror schema extension: optional [asset_aliases] BTreeMap<String, String> on MirrorConfig. Semantic validator (when both workload + mirror are loaded together) rejects mirror aliases whose target filename isn't in the catalog.")
//! @yah:next("Regenerate the workload.toml.schema.json via xtask emit-schemas (R222-B4). Confirm the drift test stays green.")
//! @yah:next("TS mirror: extend packages/yah/workload-spec/index.ts with the StaticAsset variant + AssetEntry. Confirm bun typecheck stays green.")
//! @yah:verify("cargo check -p workload-spec --locked")
//! @yah:verify("cargo test -p workload-spec")
//! @yah:verify("cargo run -p workload-spec --bin export-ts")
//! @yah:verify("cargo test -p xtask")
//! @arch:see(.yah/docs/working/W160-atomic-release-waves.md)
//!
//! @yah:ticket(R429-F2, "static-asset reconciler: BLAKE3 verify + S3 PUT against mirror's object_store + drift")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T23:24:38Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R429)
//! @yah:next("New reconciler that handles kind='static-asset' in the same service-sync loop that already runs mesofact-static + container. Same wave-gate semantics, same drift shape.")
//! @yah:next("For each [[asset]] row: hash source file (BLAKE3) and compare to manifest entry. Mismatch → surface as drift, halt push for that asset until rebuild.")
//! @yah:next("Resolve mirror's object_store provider → R2 bucket + credentials. HEAD cas/filename; if absent or different content-length → PUT. Idempotent on re-run.")
//! @yah:next("Drift detection: list bucket contents under the component's prefix, compare against catalog filenames. Files in bucket ∖ catalog → report as drift (do NOT delete; that's the prune verb's job).")
//! @yah:next("ServicesView's existing matrix consumes the new drift shape automatically. Confirm SyncGlyph/DriftList render correctly for a static-asset row without UI changes.")
//! @yah:next("MockR2 in tests: HashMap<key, bytes> implementing the S3 surface the reconciler hits. Cover: push first-time, push idempotent, drift catches catalog-vs-bucket mismatch, BLAKE3 mismatch halts push.")
//! @yah:next("Real-R2 integration test gated behind YAH_TEST_R2_BUCKET env var — one round-trip against a scratch bucket; skipped otherwise.")
//! @yah:verify("cargo check --workspace --locked")
//! @yah:verify("cargo test -p <reconciler-crate>  # crate TBD by impl agent")
//! @yah:verify("cargo test -p workload-spec")
//! @yah:gotcha("Auto-delete is OFF — reconciler reports drift on bucket∖catalog files but never DELETEs. That's the prune verb (R429-T2). Easy bug to introduce when 'cleaning up drift'; don't.")
//! @yah:gotcha("S3 multipart upload threshold matters — distil-large-v3 is ~270MB which is over the 5MB single-PUT limit on R2's strictest mode. Use aws-sdk-s3's multipart helper for assets >100MB.")
//! @yah:gotcha("Long-running progress MUST surface in QED/task-pane per the long-running-yah-surface rule. Don't silently spin in a tokio task; model as a Task with progress events.")
//! @arch:see(.yah/docs/working/W160-atomic-release-waves.md)
//! @yah:depends_on(R429-T1)
//!
//! @yah:ticket(R429-T3, "yah service prune verb: candidate enumeration + operator-confirm delete")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T23:24:52Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R429)
//! @yah:next("yah service prune <service-name> enumerates files present in the bucket but not referenced by any current mirror's resolved alias graph. Lists candidates + sizes + last-modified, requires explicit operator confirm before DELETE.")
//! @yah:next("Resolution graph: for each mirror, walk [asset_aliases] → catalog [aliases] → catalog [[asset]] rows. Union across all mirrors = live set. Bucket ∖ live set = prune candidates.")
//! @yah:next("MCP tool mcp__yah__service_prune routes through approval gate (write verb). Read counterpart mcp__yah__service_prune_status auto-passes — returns the candidate list without acting.")
//! @yah:next("Camp: Tauri command + a 'Prune candidates' panel in the existing DeployPanel for each service, showing the candidate table with per-row checkboxes + confirm.")
//! @yah:next("Analytics-driven candidate filter (old AND unaccessed-for-N-days) is OUT OF SCOPE for this ticket — needs access logs we don't aggregate yet. The candidate set today is purely catalog-derived.")
//! @yah:next("User-asset TTL is OUT OF SCOPE — different surface, access-pattern-based, separate relay when it lands.")
//! @yah:verify("cargo test -p <prune-crate>")
//! @yah:verify("yah service prune yah-desktop --dry-run lists candidates")
//! @arch:see(.yah/docs/working/W160-atomic-release-waves.md)
//! @yah:depends_on(R429-F2)
//! @yah:handoff("CLI + library + MCP all landed; UI deferred to R429-F4 (filed). Library lives in crates/yah/cloud/src/reconciler/static_asset_prune.rs and exposes compute_live_set (pure resolution graph), compute_prune_candidates (live + LIST + diff), execute_prune (DELETE), and load_service_and_mirror (path helper). CLI verb is `yah cloud service prune <name> --env <env> [--dry-run] [--yes] [--format=table|json]` at app/yah/cli/src/cloud.rs (ServiceCommands::Prune + handle_service_prune). MCP tools cloud.service_prune_status (read, auto-pass, --dry-run --format=json) and cloud.service_prune (write, --yes --format=json) dispatch through build_command(). New S3 helper sign_s3_get_with_query in local-driver covers ListObjectsV2 (the existing s3_sign helpers don't handle canonical query strings); ListObjectsV2 response is parsed with a tiny hand-rolled split_tags helper to avoid a quick-xml workspace dep. Tests: 12 prune-module unit tests (live-set union, kind filtering, list response parse for single/empty/truncated/no-token, candidate filtering including catalog manifest sidecar exclusion) + 1 s3_sign helper test + 2 MCP build_command tests. cargo check --workspace clean. cargo test -p cloud --lib: 279 pass (1 pre-existing failure cloud_init::tests::embedded_template_matches_workspace_canonical unrelated, per R419-F4 docstring). cargo test -p yah --lib: 299 pass.")
//! @yah:next("R429-F4 carries the Tauri + DeployPanel UI work — depends_on R429-T3, status=open.")
//! @yah:verify("cargo check --workspace --locked")
//! @yah:verify("cargo test -p cloud --lib reconciler::static_asset_prune  # 12 pass")
//! @yah:verify("cargo test -p yah --lib mcp::tools::tests::cloud_service_prune  # 2 pass")
//! @yah:verify("yah cloud service prune --help  # renders usage with --env/--dry-run/--yes/--format")
//!
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//!
//! @yah:ticket(R438-T2, "AssetEntry XOR: source vs derive + shape_static_asset rules")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T21:06:51Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R438)
//! @yah:next("AssetEntry.source: PathBuf → Option<PathBuf>")
//! @yah:next("Add AssetEntry.derive: Option<AssetDerive> with fetch + optional transform")
//! @yah:next("Extend shape_static_asset to enforce exactly-one(source, derive) + license closed-set")
//! @yah:verify("Both-set and neither-set fail shape validation with ShapeError::Field")
//! @yah:verify("Legacy TOMLs with only source still parse + serialize identically")
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//! @yah:handoff("AssetEntry now carries Option<PathBuf> source + Option<AssetDerive> derive (both skip_serializing_if). New types AssetDerive {fetch: FetchSource, transform: Option<TransformSpec>} and TransformSpec {recipe, params} added to workload-spec/src/lib.rs. validate.rs grew FieldPath::Asset(usize, &'static str) and shape_static_asset enforces XOR: both-set or neither-set fail with ShapeError::Field { path: Asset(i, \"source\") }. 4 new tests cover derive-mode round-trip, legacy source-only TOML round-trip without leaking a derive field, both-set rejection, neither-set rejection, and both-modes-accepted positive case. Cloud reconciler (static_asset.rs:360) now bails on derive-mode with a pointer to R438-T5 until the materialize step lands. 3 test fixtures updated with source: Some(...) + derive: None. export-ts regenerated (TransformSpec + AssetDerive emitted); xtask emit-schemas regenerated workload.toml.schema.json; schema_drift test green. workload-spec: 24/24, cloud static_asset: 25/25, xtask: 2/2.")
//!
//! @yah:ticket(R438-T3, "ImageRef digest-pin enforcement at deserialize")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T21:06:55Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R438)
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//! @arch:see(.yah/docs/working/W165-mesofact-build-mode-lowering.md)
//! @yah:handoff("ImageRef now accepts either a string form (digest-pinned, W164/W165 path) or the legacy struct form (backwards-compat for WorkloadSpec configs). String form requires @sha256:<hex> suffix: bare-tag, non-sha256, and non-hex digests all reject at serde-deserialize. Single parser compose_import::parse_pinned_image_ref is the rule's one home; T4 (recipes) and T6 (BuildMode::InContainer) will both deserialize images through this string path. Custom Deserialize uses untagged enum (Pinned(String) | Struct(Fields)); Serialize/TS/JsonSchema derives stay on the struct so wire output and TS exports are unchanged. 6 new tests cover: bare-tag reject, pinned accept (docker.io + ghcr.io), non-sha256 algorithm reject, empty/non-hex digest reject, struct-form still works with digest=None, struct-form TOML round-trip. workload-spec: 30/30 lib + 18/18 semantic + 6/6 shape_fixtures. xtask schema_drift green after emit-schemas regen. cargo check --workspace clean.")
//! @yah:next("Tighten ImageRef workspace-wide: digest: Option<String> → digest: String (required). tag stays as the human-readable identifier; digest is the source of truth. Rationale: every image we execute should be reproducible-by-construction; the on-disk shape should make unpinned-image bugs impossible.")
//! @yah:next("Every existing ImageRef construction site updates to pass a digest. Call sites known today (~10): yubaba integration tests (fake digests via a test helper), yubaba/runtime/{containerd,fake}, yubaba/deploy/{mesh_resolve,env_validate}, local-runtime, cloud/config, workload-spec round_trip tests, restart_policy tests, compose_import::parse_image_ref. The break is bounded — single PR, no surprise call sites outside the workspace.")
//! @yah:next("compose_import::parse_image_ref returns Result<ImageRef, ParseImageRefError> with an UnpinnedImage variant. Docker-compose strings without @sha256: become an explicit parse error — callers must pre-resolve tags to digests (most compose imports already happen at yubaba submission time where a pinning pass can run).")
//! @yah:next("Add task::local::test_support::test_digest() (or similar) for test fixtures — a fixed valid-format sha256 string so tests don't have to mint their own.")
//! @yah:next("Recipe TOML loader (T4) and W165 BuildMode::InContainer (T6) inherit the new requirement for free — they consume ImageRef and digest is now structurally required.")
//! @yah:verify("cargo check --workspace --locked passes after the tightening + call-site migration (yubaba, runtime, local-runtime, mesh_resolve, env_validate, cloud/config, compose_import)")
//! @yah:verify("ImageRef without digest no longer constructs — parse-time + type-level enforcement. cargo test -p workload-spec round_trip + restart_policy pass with updated fixtures.")
//! @yah:verify("compose_import::parse_image_ref(\"node:20\") → Err(UnpinnedImage); parse_image_ref(\"node:20@sha256:...\") → Ok.")
//! @yah:verify("cargo test -p yubaba --tests + -p local-driver passes with new test_digest() helper in place of bare tags.")
//! @yah:gotcha("Earlier framing assumed T3 needed a PinnedImageRef newtype to avoid breaking yubaba. Reversed after design discussion 2026-06-04: breaking yubaba in service of reproducibility-by-construction is the right architectural move. Digest is required workspace-wide; tag stays as a human-readable identifier. ~10 call sites migrate in one PR.")
//! @yah:gotcha("MesofactStaticWorkload.build_mode → InContainer { image } today is declared but never executed (build always runs on host — see W165). Once T3 tightens ImageRef, the wired-up build_mode lowering in T6 inherits digest-pinning automatically, closing W165 OQ#1's escape hatch.")
//! @yah:assumes("No production yubaba deployment ships ImageRefs we don't already digest-pin. Spot-check Hetzner/cloud yah-castle workload specs before merging the tightening; if any prod path uses tag-only, it gets pinned in the same PR.")
//! @yah:handoff("Pushed back from review 2026-06-04 — user reaffirmed the workspace-wide tightening direction. What landed (untagged Deserialize accepting string-form OR struct-form-with-digest:Option) ships digest enforcement at the W164/W165 wire surfaces but leaves the struct-form escape hatch (digest: None still constructs). User: 'breaking yubaba in order to improve it architecturally is fine'. Final shape needs both: (a) keep the string-form parser as a recipe-author convenience (image = \"ghcr.io/x@sha256:...\"), AND (b) tighten the struct form's digest: Option<String> → String. Then both paths land at the same digest-required field and unpinned-image bugs become impossible by construction. ~10 call sites still need migration (yubaba/runtime/{containerd,fake}, yubaba/deploy/{mesh_resolve,env_validate}, local-driver/local_runtime, cloud/config, workload-spec tests/round_trip + tests/restart_policy + yubaba integration_* + yubaba/tests/integration_public_ingress + integration_operator_bridge + integration_mesh + integration_single_node). Add task::local::test_support::test_digest() returning a fixed valid-format sha256 string. Pick this up by claiming R438-T3.")
//! @yah:handoff("Workspace-wide ImageRef tightening landed. (a) ImageRef.digest: Option<String> → String at workload-spec/src/lib.rs:923; Deserialize struct arm now requires the field; untagged string-form parser at compose_import::parse_pinned_image_ref untouched. (b) ImageRef::docker_ref() now always emits tag@digest pair (informational tag alongside content-addressed digest). (c) validate.rs ImageTag check tightened: tag must be non-empty (digest presence is type-enforced now). (d) compose_import::parse_image_ref returns Result<ImageRef, String> — alias for parse_pinned_image_ref. import_compose gained ImportError::UnpinnedImage { service, image, reason } variant; only external caller (yah workload import in app/yah/cli/src/workload.rs) propagates the error type. (e) New workload_spec::testing module (doc-hidden) exposes TEST_DIGEST const + test_digest() fn — all-zeros 64-hex sentinel. (f) task::default_image::catalog_image falls back to testing::test_digest() when the per-image env var is unset, preserving the infallible API but making unset-digest visible at runtime via docker pull failure. default_buildkit_image follows the same pattern. (g) Migrated ~22 struct-form construction sites: workload-spec tests (round_trip/semantic/restart_policy + all 15 fixture JSONs + 3 compose YAML fixtures + matching expected.json), task crate (default_image/integration/lib/local/remote), yubaba (runtime/{containerd,fake}, deploy/{mesh_resolve,env_validate}, all 4 integration_*.rs files), cloud/config (3 sites), local-driver (local_runtime + pond_ssr_runtime), scryer/beholders, kamaji/{server,native,containerd}. (h) ImageSource::pull trait signature tightened: digest: Option<&'a str> → digest: &'a str (only one impl in yubaba/env_validate). (i) Read-site cleanup: yubaba::runtime::containerd::image_ref, kamaji::containerd::image_ref, local-driver::pond_ssr_runtime::compose_image_ref, task::local::image_ref_arg — all dropped Option ceremony, always emit tag@digest. cargo check --workspace clean. cargo test -p workload-spec: 82 pass. cargo test -p task --lib: 59 pass. Pre-existing test failures in cloud (5: 1 cloud_init drift, 4 mesofact_static adopt) and yubaba tests (pond_reconciler_smoke missing ssr_runtime/worker_mode/ssr_origin fields) are unrelated to ImageRef — separate ticket. R438-T4 (recipe loader) and R438-T6 (BuildMode::InContainer) inherit digest-required structurally with zero per-consumer work.")
//!
//! @yah:ticket(R438-T7, "Golden tests: recipe→ForgeSpec lowering + BuildMode→ForgeSpec lowering parity")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T21:07:30Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R438)
//! @yah:next("Golden test: sample transform recipe + asset.derive.transform.params lowers to expected ForgeSpec (argv, image digest, TaskPlacement)")
//! @yah:next("Golden test: MesofactStaticWorkload with build_mode=in_container lowers to expected ForgeSpec")
//! @yah:next("Round-trip parity: same Subprocess + Local + Container quadrant for both consumers; regression-guards argv-substitution and image-pin drop-through")
//! @yah:verify("cargo test -p workload-spec lowering_golden_*")
//! @yah:verify("Golden files versioned; updates require explicit --update flag")
//! @arch:see(.yah/docs/working/W164-derived-static-assets.md)
//! @arch:see(.yah/docs/working/W165-mesofact-build-mode-lowering.md)
//! @yah:depends_on(R438-T5)
//! @yah:depends_on(R438-T6)
//! @yah:handoff("T7 landed. (1) Extracted pure lowering helpers exposed at pub(crate):\\n  - mesofact_static::lower_build_to_forge_spec(workload_dir, &BuildConfig, &BuildMode) -> ForgeSpec (run_build now wraps this)\\n  - static_asset::lower_recipe_step_to_forge_spec(&TransformRecipe, &RecipeStep, substituted_argv) -> ForgeSpec (materialize_transform now calls this for each step)\\n(2) New cfg(test) module crates/yah/cloud/src/reconciler/lowering_golden.rs registered from reconciler/mod.rs. Five golden tests:\\n  - golden_recipe_step_lowers_to_pinned_local_container_subprocess (recipe → ForgeSpec shape: argv, image digest, timeout, label, initiator)\\n  - golden_recipe_step_with_zero_timeout_lowers_to_none (regression-guards the timeout=0 → None mapping)\\n  - golden_build_in_container_lowers_to_pinned_local_container_subprocess (BuildMode::InContainer → sh -c shell wrap + pinned image + cwd label)\\n  - golden_build_host_side_lowers_to_native_quadrant_without_image (BuildMode::HostSide → image=None + TaskRuntime::Native)\\n  - parity_recipe_and_build_in_container_share_quadrant (THE architectural invariant: both consumers land in the same Subprocess + Local + Container quadrant with sha256-pinned images and Gnome initiators — lets one ForgeExecutor dispatch handle both)\\n(3) Test artifacts are hand-coded assertions, not insta/snapshot files — workspace has no insta infra and explicit-Pin tests give clearer diff on drift than auto-update snapshots. The W164/W165 lowering shape is now regression-guarded against silent drift in either consumer. cargo test -p cloud --lib reconciler::lowering_golden: 5 pass. Workspace check clean.")
//! @yah:next("Sign off → archive R438-T7")
//! @yah:next("T8 (worked examples) now has tested lowering primitives to reference")
//! @yah:verify("cargo test -p cloud --lib reconciler::lowering_golden — 5 pass")
//! @yah:verify("cargo test -p cloud --lib reconciler:: — 124 pass; 4 pre-existing R441-B4 adopt_only failures (port 4321 dev-box collision) unrelated")
//! @yah:verify("cargo check --workspace --locked — clean (warnings only)")
//! @yah:verify("Parity test asserts both lowerings produce TaskPlacement{Local, Container} + ForgeCommand::Subprocess + sha256-pinned image — the shared executor dispatch invariant")
//! @yah:gotcha("Test location pivot: original ticket said `cargo test -p workload-spec lowering_golden_*` but the lowering primitives don't live in workload-spec — ForgeSpec/TaskPlacement are in task, and the actual lowering helpers are in cloud (both consumers live there). Tests landed in cloud as `reconciler::lowering_golden`. If a future consumer outside cloud needs the BuildMode lowering, lift `lower_build_to_forge_spec` up to task::transforms alongside the existing recipe lowering primitives.")
//! @yah:gotcha("No snapshot/insta infra in workspace — 'Golden files versioned; updates require explicit --update flag' verify line interpreted as hand-coded explicit assertions instead. Drift surfaces as a single-file test diff on the lowering helper, which is more readable than a .snap diff for the small ForgeSpec shape these tests cover.")
//!
//! @yah:ticket(R594-F2, "Ingress workload kind in workload-spec: pinned-per-node appliance on public-ip-tainted machines")
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:at(2026-07-03T06:03:30Z)
//! @yah:phase(P2)
//! @yah:parent(R594)
//! @yah:next("Add the ingress workload kind to the Workload enum (lib.rs:296) as an appliance in the R572 archetype sense: pinned-per-node, non-drainable, placed by yubaba only on machines carrying a public-ip taint, supervised by kamaji. Depends on R572-F1 (lifecycle archetype discriminator) so the archetype field exists to mark it. Breaking change is fine (pre-release house style); update kamaji-bin server.rs InvalidSpec rejection list deliberately — kamaji MUST accept this kind (it supervises the proxy), unlike MesofactStatic/Almanac/StaticAsset.")
//! @yah:verify("cargo test -p yah-workload-spec; cargo check -p yubaba -p kamaji-bin; kamaji admission accepts kind=ingress in a unit fixture")
//! @yah:gotcha("RUNS SOLO: workload-spec is the shared-type DAG sink (yah-base) — every lane (yubaba, kamaji, qed, host app) rebuilds on its change. Pause all other wave-2/3 implementer lanes while this is active, and check R572-T2 (cpu_millis, Handoff) + R572-F1 owner state before claiming — same file.")
//! @yah:depends_on(R572-F1)
//! @yah:tier(Cleric)
//! @yah:handoff("Modeled the W267 public-ingress appliance as a container-shaped workload (Workload::Container(WorkloadSpec)), not a new Workload variant: mark archetype = Some(LifecycleArchetype::Appliance) (R572-F1, pinned/non-drainable) and declare the public-ip placement requirement via a new annotation-based marker on WorkloadSpec (same zero-blast-radius pattern as existing wants_host_network/HOST_NETWORK_ANNOTATION, chosen specifically to avoid the ~26-call-site churn a new plain field forced for R572-F1's archetype field, and to avoid an exhaustive-match update in peer-owned kamaji-proto/codec.rs that a new Workload variant would force). Added: WorkloadSpec::requires_taint() -> Option<&str>, const REQUIRES_TAINT_ANNOTATION = \"yah.placement.requires-taint\", const PUBLIC_IP_TAINT = \"public-ip\", plus doc comments on Workload::Container recording the modeling decision and its rationale, all in oss/yah-base/crates/workload-spec/src/lib.rs (single file changed). This only declares the requirement as inert metadata — matching taint field on machine TOML is R572-F3 (not yet present) and scheduler enforcement is R572-F5; both out of scope here, noted in the doc comments. Verified kamaji needs NO change: deploy_workload's match in kamaji-bin/src/server.rs already dispatches any Workload::Container(_) to the containerd backend regardless of tier/annotations (only MesofactStatic/Almanac/StaticAsset hit the InvalidSpec rejection arm), confirmed by reading the code and by the existing deploy_container_without_feature_says_so / deploy_mesofast_static_is_rejected_as_invalid_spec unit tests both still passing unmodified. 2 new unit tests added (ingress_marked_spec_is_appliance_and_carries_public_ip_placement_requirement, ingress_marked_spec_round_trips_through_json_as_a_container_workload). cargo test -p yah-workload-spec --lib: 38/38 pass. cargo test -p yah-workload-spec --test round_trip: 7 pass, exactly the same pre-existing 2 postcard failures (round_trip_full_spec_through_postcard, workload_container_round_trips_through_postcard — R590-B3, unrelated) as before this change, confirmed not increased. cargo check -p yah-workload-spec / -p yubaba / -p kamaji-bin all clean, plus full cargo check --workspace in both oss/kamaji and oss/yubaba clean (only pre-existing unrelated warnings). No peer-owned file touched or needed.")
//!
//! @yah:ticket(R590-B10, "forge workload 256MB cgroup memory limit SIGKILLs real builds — rusty-v8 checkout OOMs (bumped to 32GB stopgap)")
//! @yah:at(2026-07-12T00:14:52Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R590)
//! @yah:severity(blocks-on-box-green)
//! @yah:next("Proper fix: thread a per-step memory request from the pipeline (QedStep) through ForgeSpec -> WorkloadSpec so a build declares its footprint, instead of a blanket forge default. Also consider: build_oci_spec should treat memory_mb==0 as 'omit the cgroup limit' (unlimited) so dedicated build-workers aren't capped by an arbitrary constant; pair with a node-sized default. Revisit the 32GB stopgap once per-step resources land.")
//! @yah:verify("yah qed run rusty-v8-musl on us-west-002 completes the checkout + gn/ninja compile without an OOM SIGKILL; a small forge task still runs (32GB is a ceiling, not a reservation).")
//! @yah:gotcha("PROVEN live (2026-07-11): with B7 networking fixed, the rusty-v8 build cloned the full V8 tree then `git checkout third_party/icu` DIED OF SIGNAL 9 (OOM). WorkloadSpec::for_forge set resources.memory_mb=256, which build_oci_spec turns into a hard cgroup memory.limit. /tmp is a RAM-backed tmpfs so the multi-GB source checkout counts against that 256MB too. Bumped for_forge to 32768 (32GB) as a CLI-side stopgap; verified the build proceeds past icu.")
//! @yah:handoff("FIXED + PROVEN LIVE (2026-07-11). WorkloadSpec::for_forge memory_mb 256 -> 32768 (oss/yah-base/crates/workload-spec/src/lib.rs). CLI-only change (spec is client-built), no kamaji redeploy. RESULT: with B7 networking, the rusty-v8 build previously OOM'd (SIGKILL/signal 9) at the icu git-checkout under the 256MB cgroup cap; now it clones the full V8 tree AND proceeds past icu into cargo/gn compilation (Compiling icu_locale_data/icu_calendar_data...) with task RUNNING. Stopgap 32GB ceiling; proper per-step memory request from the pipeline is the follow-up in the ticket body.")
//!
//! @yah:ticket(R546-B7, "workload_spec::Workload envelope is externally tagged (missing serde tag=kind) — no flat on-disk workload.toml can parse through it, broke yah cloud apply for EVERY static-asset component")
//! @yah:at(2026-07-20T23:52:55Z)
//! @yah:status(open)
//! @yah:parent(R546)
//! @yah:next("DO NOT simply add `#[serde(tag = \"kind\")]` without checking postcard: `Workload` is also a postcard wire type on the kamaji RPC path (kamaji-proto/src/codec.rs matches on it; round_trip tests exist). postcard is non-self-describing and cannot decode internally-tagged enums, so naive tagging risks breaking the kamaji wire. Decide deliberately: (a) tag it and prove the postcard round-trips still pass, or (b) split the types — an on-disk `WorkloadManifest` with tag=kind, leaving `Workload` as the untagged wire type.")
//! @yah:next("INTERIM FIX ALREADY LANDED (unblocks publishing): static_asset.rs::load_workload no longer routes through the envelope — it deserializes a small `KindProbe { kind }`, validates kind == \"static-asset\", then parses `StaticAssetWorkload` directly. Same approach seed_derivation_for_target already used successfully. This restored `yah cloud apply` and got the x86_64 rusty-v8 artifact published to the CDN (HTTP 200). The ENVELOPE itself is still broken for every other caller/kind.")
//! @yah:next("Fix the test/example disagreement: lib.rs ~L2544 should assert the FLAT `kind = \"...\"` shape that real files use, and examples/parse_whisper_toml.rs should run in CI so this cannot regress silently again.")
//! @yah:gotcha("SEVERITY: this silently broke `yah cloud apply` for EVERY static-asset component, not just rusty-v8. Verified against the long-published whisper catalog via the repo's own examples/parse_whisper_toml.rs, which panics with the identical error — so the breakage is general and pre-existing, not caused by the R546 hash edits.")
//! @yah:gotcha("ROOT CAUSE: `pub enum Workload` (oss/yah-base/crates/workload-spec/src/lib.rs ~L386) derives Deserialize with ONLY `#[serde(rename_all = \"kebab-case\")]` — there is NO `#[serde(tag = \"kind\")]`, despite its own doc comment stating 'the `kind` field on the wire is the serde discriminator'. Without the tag it is EXTERNALLY tagged, so serde wants a map with exactly ONE key (the variant name). Every real workload.toml is FLAT (`kind = \"static-asset\"` + `schema_version` + `[[asset]]` + `[aliases]`), i.e. a multi-key map -> `TomlError: wanted exactly 1 element, more than 1 element`, reported confusingly at line 1 col 1.")
//! @yah:gotcha("WHY THE UNIT TEST DIDN'T CATCH IT: the passing test at lib.rs ~L2544 feeds the EXTERNALLY-tagged shape `[[static-asset.asset]]`, which no on-disk file actually uses. So the test asserts the broken encoding and the example (parse_whisper_toml.rs) asserting the REAL encoding was never run in CI. The test and the example disagree; the example is right.")
//!
//! @yah:ticket(R626-S3, "Where does desired-state live? Durable per-workload replica count that survives reconcile loops and camp restarts (0↔1 vs scale-to-N)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-07-23T17:47:24Z)
//! @yah:kind(spike)
//! @yah:phase(P3)
//! @yah:parent(R626)
//! @yah:handoff("DECIDED + LANDED. Desired state lives in the CAMP DAEMON, in a durable camp-local document at <camp>/.yah/state/desired-state.json, and NEVER crosses the kamaji or yubaba wire. The governing principle, written to survive the tier: desired state belongs to the DECLARER, not the supervisor — whoever re-asserts a deployment owns the record of whether it is wanted, because anything stored below the declarer is overwritten by the declarer's next re-assert. In the pond/dev tier the declarer is camp (ensure_pond_running -> reconcile_pond_deploys -> deploy_pond_mirrors, which runs at every camp start AND every pond.ensure_running RPC). In cloud the same rule points at the CloudConfig reconciler's raft store. Kamaji is never the holder in either tier.")
//! @yah:handoff("REJECTIONS, with the reason each is not a near-miss. kamaji-local: kamaji is deliberately imperative (Deploy/Stop/List, crash-restart delegated to dockerd's policy per R626-F2) — it holds no desired set and runs no reconcile loop, so storing intent there means giving it a SECOND reconciler that can disagree with camp's, and it still loses to camp's POST /pond/deploy from above. yubaba raft: right answer at cloud scale, wrong scope here — the pond yubaba is a container camp starts, its PondRegistry is in-memory (a restart forgets everything), and a single-camp dev tier has no quorum to be consistent about. Git-tracked config: camp.toml/mirror.toml are the DECLARATION (what exists); a stop is per-machine operator intent (systemctl disable, not editing the unit file) and must not propagate to a teammate's checkout — hence .yah/state/ is gitignored, in both the camp's .gitignore and the scaffold_camp_skeleton template.")
//! @yah:handoff("SHAPE: one knob, `replicas`, where 0 = stopped — deliberately the SAME axis as workload_spec::WorkloadSpec.replicas so scale-to-N later lifts a ceiling instead of adding a second concept beside a boolean. MAX_SUPPORTED_REPLICAS = 1 today and set_replicas REJECTS anything higher rather than persisting an intent no supervisor can honour (a clamp would silently record something the operator did not ask for). No record = replicas 1: a declared workload runs unless someone said otherwise. updated_at + reason ride along so a stale intent is legible and the UI can say when/why. Writes are tmp-then-rename; reads FAIL OPEN (missing/unreadable/corrupt/newer-schema all mean 'everything runs', corrupt file preserved as .corrupt-<epoch_ms>) — fail-closed would mass-stop a camp on one bad byte, and a resurrection is the recoverable failure.")
//! @yah:handoff("LANDED: (1) app/yah/cli/src/desired_state.rs — DesiredStateDoc / WorkloadDesire / DesiredStateStore (load, desired_replicas, is_stopped, stopped_keys, set_replicas, stop, start, forget), 10 unit tests incl. survives-a-camp-restart, per-workload isolation, replicas>1 rejected AND not written, corrupt-file quarantine + fail-open, newer-schema fail-open, and an explicit 'a stop is not a failure' guard on the serialized document. (2) camp.rs: deploy_pond_mirrors and reconcile_pond_deploys now consult the store and skip stopped idents — this is THE enforcement point, since camp's re-assert is the only place 'stay stopped' can be honoured. Extracted pond_idents_needing_deploy(declared, registered, stopped) as a pure helper with 5 tests, because the stopped-subtraction is the load-bearing half: a stopped workload is absent from yubaba's registry ON PURPOSE and is indistinguishable from a failed deploy without the intent record. (3) .yah/.gitignore + app/yah/cli/templates/yah-gitignore-default gain /state. (4) .yah/docs/working/W287-desired-state-for-supervised-workloads.md carries the full rationale, the rejected options, the F4 build-on list, and the scale-to-N scoping.")
//! @yah:handoff("DELIBERATE NON-GOAL: writing intent does NOT actuate. The durable record must land even when the stop call fails, or a failed stop comes back on the next reconcile. Actuation is R626-F4's job.")
//! @yah:next("R626-F4 is unblocked and now has a concrete spec — see W287 §5. It needs three things this ticket deliberately did not build: (a) a per-ident teardown on yubaba (PondRegistry has only shutdown_all, which drains everything; /pond/deploy and /pond/state are the only pond routes), (b) camp RPC methods workload.stop / workload.start writing through DesiredStateStore, (c) desired-vs-actual reporting.")
//! @yah:next("DO NOT add a Stopped variant to PondPhase (R626-F2's noted gap). PondPhase is yubaba's observation of REALITY; intent never crosses that wire by this decision. Camp is the one process holding both halves — render the pair instead: desired=stopped + actual=absent reads 'deliberately stopped'; desired=running + actual=absent reads 'down'.")
//! @yah:next("Scale-to-N stays scoped, not committed (W287 §6). WorkloadSpec.replicas makes N look one constant away; it is not. kamaji native.rs:592 rejects replicas>1, and the docker backend names containers by mesh identity (one identity, one container). N needs a placement layer above the single-workload supervisor: per-replica naming (identity==container name is what makes teardown resolve), per-replica host ports (pond publishes fixed ones — two replicas collide), per-replica mesh identity (a load-balanced set is an xlb-net concern), and a placement decision that is yubaba's job on a fleet. Lifting MAX_SUPPORTED_REPLICAS is the entry point once that layer exists.")
//! @yah:next("Wire DesiredStateStore::forget into the undeclare path so the document doesn't accumulate intent for mirrors that no longer exist.")
//! @yah:verify("cargo test -p yah --lib desired_state — 15 pass (10 desired_state::tests + 5 camp::r626_s3_desired_state_gate_tests), 0 fail")
//! @yah:verify("cargo check -p yah — clean (note: this camp's tree is shared and was transiently broken by peers' in-flight edits in oss/qed, yah-party, and yah-almanac during this run; none touched by this ticket)")
//! @yah:verify("BEHAVIOUR BAR (the one that matters): DesiredStateStore::for_camp(root).stop(ident) followed by a FRESH store over the same root still reports is_stopped — that is exactly a camp restart — and pond_idents_needing_deploy then omits that ident from an EMPTY registry, which is exactly a restarted yubaba. Asserted in camp::r626_s3_desired_state_gate_tests::a_stop_survives_a_camp_restart_end_to_end.")
//! @yah:gotcha("The store is camp-local and GITIGNORED on purpose. If a future ticket wants a stop to be shared/durable in the repo, that is a different decision (declaration vs intent) — re-open W287 §2 rather than moving the file into tracked territory.")
//! @yah:gotcha("Reads fail OPEN. Never 'harden' this into fail-closed: an unreadable document would then stop an entire camp, and the failure would be silent (nothing starts) rather than visible (the workload comes back).")
//!

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub mod compose_import;
pub mod control_plane_install;
pub mod rollout;
pub mod secrets;
pub mod validate;
mod version;

pub use version::SchemaVersion;

// ── Duration ──────────────────────────────────────────────────────────────────

/// Duration expressed as an integer millisecond count.
///
/// Used for healthcheck intervals, timeouts, delays, and stop grace periods.
/// Chosen over `std::time::Duration` to keep serde support dependency-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[ts(type = "number")]
pub struct Millis(pub u64);

impl Millis {
    pub fn from_secs(s: u64) -> Self {
        Self(s * 1000)
    }

    pub fn from_ms(ms: u64) -> Self {
        Self(ms)
    }

    pub fn as_ms(self) -> u64 {
        self.0
    }

    pub fn as_secs_f64(self) -> f64 {
        self.0 as f64 / 1000.0
    }
}

// ── Primitive newtypes ────────────────────────────────────────────────────────

/// Opaque identifier for a yubaba-managed machine within the cluster.
///
/// Used by the semantic validation layer for admission-control capacity checks.
/// Yubaba passes its own machine ID when validating a spec before deployment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MachineId(pub String);

/// DNS-segment identity for a workload on the cluster mesh, e.g.
/// `"noisetable-api.pdx"`. Regex constraint: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`,
/// length ≤ 63. Enforced in shape validation (R090-F2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MeshIdent(pub String);

/// Tier classification that governs admission control and mesh `allow_from`
/// filtering. Known values: `"public"`, `"tenant"`, `"private"`, `"infra"`.
/// Custom tiers are allowed per cluster; shape validation warns on unknowns
/// rather than rejecting them (R090-F2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct TierTag(pub String);

/// Default single-tenant identity written to specs that predate the tenant
/// axis (W206). Its concrete string is arbitrary — what matters is that a
/// single-tenant cluster only ever sees this one value, so every per-tenant
/// isolation primitive collapses to a no-op. See [`TenantId::singleton`].
pub const DEFAULT_TENANT: &str = "default";

/// Default single-namespace identity for specs that predate the namespace
/// axis (W206). See [`NamespaceId::singleton`].
pub const DEFAULT_NAMESPACE: &str = "default";

/// Tenant **isolation** axis (W206). Separates one operator's workloads from
/// another's at the network / DB / mesh-identity level. Orthogonal to
/// [`NamespaceId`] (routing/naming) and [`TierTag`] (workload class within a
/// `(tenant, namespace)` pair).
///
/// **Degenerate case:** when a yubaba reconciler sees only one `TenantId`
/// across every workload on a machine, per-tenant Podman networks collapse
/// into the shared tier networks, the tenant prefix on mesh identity is
/// dropped, and PostgreSQL role separation is skipped — isolation primitives
/// become no-ops. You pay only when more than one tenant is present. Specs
/// written before this axis existed deserialize to [`TenantId::singleton`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct TenantId(pub String);

impl TenantId {
    /// The singleton tenant used for back-compat with single-tenant (current)
    /// deployments. Specs written before the tenant axis existed deserialize
    /// to this value via the `#[serde(default)]` on [`WorkloadSpec::tenant`],
    /// keeping the whole cluster single-tenant so every isolation primitive
    /// stays a no-op.
    pub fn singleton() -> Self {
        Self(DEFAULT_TENANT.to_string())
    }

    /// Whether this is the singleton (degenerate single-tenant) identity.
    pub fn is_singleton(&self) -> bool {
        self.0 == DEFAULT_TENANT
    }
}

/// Namespace **routing/naming** axis (W206). A pure naming key that never
/// affects isolation: it selects the config root, disambiguates service DNS
/// names within a tenant, prefixes object-store bucket names within a tenant's
/// bucket scope, and selects the provider zone (e.g. `noisetable.com` vs
/// `yah.dev`). Two namespaces in the same tenant share networks, mesh-identity
/// space, and PG cluster — they simply cannot collide on workload names or
/// external domains. Specs written before this axis existed deserialize to
/// [`NamespaceId::singleton`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct NamespaceId(pub String);

impl NamespaceId {
    /// The singleton namespace used for back-compat with single-namespace
    /// (current) deployments. Specs written before the namespace axis existed
    /// deserialize to this value via the `#[serde(default)]` on
    /// [`WorkloadSpec::namespace`].
    pub fn singleton() -> Self {
        Self(DEFAULT_NAMESPACE.to_string())
    }

    /// Whether this is the singleton (degenerate single-namespace) identity.
    pub fn is_singleton(&self) -> bool {
        self.0 == DEFAULT_NAMESPACE
    }
}

// ── Workload (on-disk envelope) ──────────────────────────────────────────────

/// On-disk `workload.toml` manifest. Each variant matches one
/// `ServiceComponent.kind` value; the `kind` field on the wire is the serde
/// discriminator.
///
/// This is the **on-disk** envelope — distinct from [`WorkloadSpec`], the
/// containerd wire format yubaba receives over RPC. A `kind = "container"`
/// workload deserializes its remaining fields as a `WorkloadSpec`; other
/// kinds carry their own per-reconciler payload shape.
///
/// **Never put `#[serde(skip_serializing_if = "Option::is_none")]` on a field
/// of this enum or any type it reaches.** These types ride the kamaji-proto
/// **postcard** wire, which is non-self-describing and positional:
/// `skip_serializing_if` omits the field's byte on serialize while decode still
/// expects to read it at that offset, so the byte stream misaligns and the
/// round-trip fails. Use `#[serde(default)]` + `#[ts(optional = nullable)]`
/// instead — that still gives TOML/JSON back-compat (missing field → `None`)
/// while the field is always encoded. `MesofactStaticWorkload::ssr_runtime` and
/// `::serve_bundle` are the reference shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Workload {
    /// Static-site build that publishes an artifact directory to the
    /// service's `static` provider slot. Reconciled by the
    /// `mesofact-static` reconciler — does not deploy to yubaba.
    MesofactStatic(MesofactStaticWorkload),

    /// Containerd workload handed to yubaba over RPC. The inline fields
    /// are the full [`WorkloadSpec`] minus the `kind` discriminator.
    ///
    /// This is also the shape of the W267 sovereign-public-ingress appliance
    /// (R594-F2): a container-kind workload with `archetype =
    /// Some(LifecycleArchetype::Appliance)` and
    /// `requires_taint() == Some(PUBLIC_IP_TAINT)`, **not** a dedicated
    /// `Workload::ingress(..)` variant. It runs an ordinary OCI image (the
    /// `passway` proxy, R594-F4) supervised by kamaji exactly like any other
    /// `Container`, so no admission-list or wire-codec change was needed to
    /// let kamaji accept it. A new enum variant would have forced an
    /// exhaustive-match update in every `Workload` consumer, including
    /// peer-owned `kamaji-proto/src/codec.rs` — the archetype + annotation
    /// combination expresses "this is the public ingress appliance" without
    /// that blast radius. See [`WorkloadSpec::requires_taint`] and
    /// [`LifecycleArchetype::Appliance`].
    Container(WorkloadSpec),

    /// Data-pipeline job with declared I/O and a readiness policy. The
    /// orchestrator checks all `inputs` are reachable before each run and
    /// verifies `outputs` afterward. Generalises the OpenRouter JSON-cache
    /// refresher (`spawn_almanac_refresher`) to the full manifest form.
    Almanac(AlmanacManifest),

    /// Content-addressed static files uploaded to the mirror's `object_store`
    /// provider slot. Wave-0 by default — gating mesofact and container waves.
    /// Rollback is a pointer-flip via `mirror.toml [asset_aliases]`; bytes are
    /// append-only and never re-pushed on rollback. See W160.
    StaticAsset(StaticAssetWorkload),
}

/// `kind = "mesofact-static"` payload — static-site build colocated with the
/// frontend it deploys.
///
/// The two-role model (R256-F7): a build/publish step plus an optional
/// SSR/SPA runtime companion. The build step is always transient (runs once,
/// publishes, exits). The companion is long-lived and only present when the
/// app has dynamic/server-rendered pages; pure static sites leave it `None`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MesofactStaticWorkload {
    /// Wire-format version. Always `V1` today.
    pub schema_version: SchemaVersion,

    /// Build command + output directory.
    pub build: BuildConfig,

    /// Path (relative to the manifest) of the routes module the
    /// `mesofact-static` reconciler reads to enumerate routes.
    pub routes: PathBuf,

    /// Where the build command runs. Default: `HostSide` (mesofact-dev on the
    /// host). Set to `InContainer` for cloud/HA where no host watcher is
    /// present and CI-fidelity build environments are required.
    #[serde(default)]
    pub build_mode: BuildMode,

    /// Optional SSR/SPA runtime companion container.
    ///
    /// `None` → pure static site; Caddy (or equivalent CDN) serves all
    /// requests directly from the object store. This is the common case for
    /// dev-yah today.
    ///
    /// `Some` → the workload spec describes a long-lived container that
    /// handles dynamic/SSR requests. Caddy routes static asset paths to
    /// the object store and all other paths to this container. The companion
    /// uses `RestartPolicy::Always`; the orchestrator (camp or yubaba)
    /// ensures it stays up alongside the Caddy edge.
    #[ts(optional = nullable)]
    pub ssr_runtime: Option<WorkloadSpec>,

    /// Serve-time reference to a published W272 bundle (R599-F4).
    ///
    /// `Some` → the built app is deployed as a content-addressed bundle that
    /// kamaji materializes from the bundle store (R599-F1) and serves via its
    /// native backend, instead of (or in addition to) the build reconciler
    /// pushing `dist/` to the object-store/CDN. `None` → legacy
    /// build-and-publish-only workload — kamaji rejects that form as yubaba's
    /// `mesofact-static` reconciler's responsibility.
    ///
    /// No `skip_serializing_if`: like `ssr_runtime`, this field is always
    /// encoded so the postcard wire codec (non-self-describing, positional)
    /// round-trips — `skip_serializing_if` would omit the byte on serialize
    /// while decode still expects it. `#[serde(default)]` keeps every existing
    /// `mesofact-static` TOML/JSON that predates this field parsing to `None`.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub serve_bundle: Option<MesofactServeBundle>,
}

/// Serve-time reference to a published W272 bundle (R599-F4) — the
/// `{bundle_digest, runtime, lifecycle}` triple a `mesofact-static` workload
/// carries when kamaji, not the build reconciler, serves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MesofactServeBundle {
    /// BLAKE3 digest of the published bundle manifest — the content-address
    /// kamaji materializes from the bundle store (`yah_mesofact_bundle`,
    /// R599-F1). Same 64-hex shape the bundle crate's `BundleHash` validates.
    pub digest: BlakeHash,

    /// Runtime that serves the bundle: `"self"` (bundle ships its own
    /// `bins/<triple>/serve`) or `"mesofact/<version>"` (resolve the stock
    /// serve runtime asset from the node cache). Wire-mirrors
    /// `yah_mesofact_bundle::BundleRuntime`; kept as a plain `String` here so
    /// workload-spec stays free of the bundle crate and its non-TS/schema
    /// newtypes.
    pub runtime: String,

    /// How kamaji supervises the served bundle. Default: keep-alive.
    #[serde(default)]
    pub lifecycle: BundleLifecycle,
}

/// Lifecycle mode for a served bundle (W272 §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BundleLifecycle {
    /// Fork at deploy, keep resident, restart per policy — today's server
    /// archetype. Memory is resident for the workload's lifetime.
    KeepAlive,

    /// Kamaji owns the listen socket, forks the runtime on the first connection
    /// (fd-passing), and reaps it after `idle_ttl` with zero connections — the
    /// "serverless" tier (zero memory when idle). The JIT fork/reap mechanics
    /// land in R599-F6; this variant only declares the intent + budget.
    OnDemand {
        /// Idle time with no live connections before kamaji reaps the process.
        idle_ttl: Millis,
    },
}

impl Default for BundleLifecycle {
    /// Keep-alive — the resident server archetype — matches the current
    /// deploy-and-supervise default.
    fn default() -> Self {
        BundleLifecycle::KeepAlive
    }
}

/// Build step that produces the static artifact published by a
/// `mesofact-static` workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct BuildConfig {
    /// Shell command run from the manifest's directory, e.g. `"bun run build"`.
    pub command: String,

    /// Output directory (relative to the manifest) the reconciler uploads.
    pub out_dir: PathBuf,

    /// Data-only re-render command (W225 §3 "revalidate"), run from the
    /// manifest's directory against the **already-built** `out_dir` — no
    /// bundler. `{route}` is substituted with the invalidated route pattern,
    /// e.g. `"cargo run -p mesofact-build -- render . --route {route} --all"`.
    /// Absent → a revalidate dispatch republishes `out_dir` as-is.
    #[serde(default)]
    pub render_command: Option<String>,
}

// ── BuildMode ─────────────────────────────────────────────────────────────────

/// Where the build command runs for a `mesofact-static` workload.
///
/// The two-role split encodes the F7 design decision: build/publish is a
/// **transient job** (runs once, exits, GC'd); SSR/SPA serving is a separate
/// **long-lived companion container** (optional, only for dynamic pages). A
/// single merged "mesofact container" is the trap — in cloud, CI builds the
/// artifact, R2+CDN serve it, and a distinct worker handles any SSR.
///
/// Default: `HostSide` — mesofact-dev runs the build on the host and publishes
/// to the tier's object store. No container overhead; compatible with dev and
/// sim tiers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BuildMode {
    /// Build command runs on the host (mesofact-dev watcher). The watcher
    /// publishes the output to the tier's object store (DistPointer for dev,
    /// MinIO for sim). Compatible with all tiers; zero container overhead.
    #[default]
    HostSide,

    /// Build runs inside a transient container matching the CI image. Higher
    /// fidelity (environment matches CI exactly); costs image pull +
    /// container cold-start. Required for cloud/HA where no mesofact-dev
    /// watcher is running on the host.
    InContainer {
        /// Container image that runs the build (e.g. `"ghcr.io/org/app-build:v1.2"`).
        /// Must have the build toolchain installed. The container is started with
        /// the workspace root bind-mounted, runs `build.command`, uploads
        /// `build.out_dir` to the object store, then exits.
        image: ImageRef,
    },
}

// ── AlmanacManifest ───────────────────────────────────────────────────────────

/// An observable endpoint the almanac scheduler probes to check readiness.
///
/// Used for both inputs (checked before the run) and outputs (verified after
/// a successful run to confirm the job produced something reachable).
/// The probe is intentionally lightweight — no S3 SigV4, no xlb-net discovery
/// required; a simple TCP connect or HTTP GET is enough for the dev/sim tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AlmanacTarget {
    /// Issue an HTTP GET to `url`; ready when the server responds with
    /// `expect_status` (default: any 2xx).
    Http {
        url: String,
        #[ts(optional = nullable)]
        expect_status: Option<u16>,
    },

    /// Establish a TCP connection to `host:port`; ready when the connect
    /// succeeds. Used for non-HTTP services (e.g. MinIO API on port 9000)
    /// and as a lighter probe when an HTTP endpoint isn't stable yet.
    Tcp { host: String, port: u16 },
}

/// What the almanac scheduler does when a precondition check fails.
///
/// The F9 design decision: `WaitWithTimeout` is the default. Fail-fast is
/// too brittle for the sim tier (containers may still be cold-starting);
/// requeue-with-no-ceiling can block the scheduler indefinitely. The
/// recommended timeout for sim is the container spinup budget (~5 s cold,
/// ~1 s warm): set `timeout` to a few seconds, then let the retry cadence
/// handle transient glitches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotReadyPolicy {
    /// Wait up to `timeout` for all preconditions to pass before aborting
    /// the run. The run is skipped (not rescheduled); the next cadence tick
    /// will retry. Suitable when targets occasionally lag at startup.
    WaitWithTimeout {
        /// How long to wait for each precondition to become reachable. The
        /// scheduler polls with a short sleep between attempts.
        timeout: Millis,
    },

    /// Abort immediately if any precondition check fails. Suitable for
    /// integration-test harnesses where a missing dependency is always a
    /// hard error.
    FailFast,

    /// Requeue with exponential backoff up to `max_attempts` times. After
    /// exhaustion the run is marked failed. Suitable for cloud/HA where
    /// transient dependency outages are expected.
    Requeue {
        /// Maximum number of requeue attempts before the run is marked failed.
        max_attempts: u32,
        /// Initial backoff between attempts, in milliseconds.
        backoff: Millis,
    },
}

impl Default for NotReadyPolicy {
    /// Default is `WaitWithTimeout { timeout: 5 seconds }` — matches the
    /// container spinup budget for the sim tier (few-second cold, sub-second warm).
    fn default() -> Self {
        Self::WaitWithTimeout { timeout: Millis::from_secs(5) }
    }
}

/// When the almanac scheduler triggers a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Cadence {
    /// Run once at first opportunity, then never again.
    Once,

    /// Run repeatedly with a fixed interval between the end of one run and
    /// the start of the next. Equivalent to `sleep N && run` in a loop.
    Every {
        /// Minimum time between consecutive run completions.
        interval: Millis,
    },

    /// Run on a UTC cron schedule (standard 5-field expression, e.g.
    /// `"0 */6 * * *"` for every 6 hours). The scheduler evaluates the
    /// expression relative to UTC midnight.
    Cron { expression: String },
}

/// `kind = "almanac"` manifest — a declared data-pipeline job.
///
/// An almanac job is the generalisation of the OpenRouter refresher
/// (`spawn_almanac_refresher`): it declares its I/O contract explicitly so
/// the orchestrator can enforce preconditions before each run and verify
/// outputs afterward. The degenerate case (no inputs, no app target, cron
/// schedule) is exactly the OpenRouter JSON-cache refresher.
///
/// Lifecycle:
/// 1. Cadence tick fires.
/// 2. Scheduler probes every `inputs` target. If any fail → apply
///    `not_ready_policy`.
/// 3. Command runs (`sh -c command` from the workload directory).
/// 4. Scheduler probes every `outputs` target. Failure → mark run as
///    failed but do not retry.
/// 5. Any workloads listed in `invalidates` receive a cache-bust signal
///    (implementation detail of the orchestrator; in camp this is a
///    rebuild trigger on the mesofact-dev watcher).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct AlmanacManifest {
    /// Wire-format version. Always `V1` today.
    pub schema_version: SchemaVersion,

    /// Shell command executed via `sh -c` from the workload directory.
    pub command: String,

    /// When to run.
    pub cadence: Cadence,

    /// Input targets that must be reachable before the command runs.
    /// Empty list → no precondition checks (degenerate case).
    #[serde(default)]
    pub inputs: Vec<AlmanacTarget>,

    /// Output targets verified after a successful run.
    /// Empty list → no post-run verification.
    #[serde(default)]
    pub outputs: Vec<AlmanacTarget>,

    /// What to do when a precondition check fails.
    /// Default: `WaitWithTimeout { timeout: 5000ms }`.
    #[serde(default)]
    pub not_ready_policy: NotReadyPolicy,

    /// Mesh identities of workloads to notify after a successful run.
    /// The orchestrator sends a cache-bust signal to each entry so
    /// downstream consumers can reload their data (e.g. mesofact-dev
    /// triggers a rebuild when the OpenRouter cache refreshes).
    /// Empty list → no downstream invalidation.
    #[serde(default)]
    pub invalidates: Vec<MeshIdent>,
}

// ── StaticAssetWorkload ───────────────────────────────────────────────────────

/// BLAKE3 content hash expressed as exactly 64 ASCII hex digits.
///
/// This is the content-address key for every file in the static-asset catalog.
/// Deserialization rejects values that do not conform — 64 hex chars, case
/// insensitive. Mismatch between the recorded hash and the source file halts
/// the upload step in the reconciler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[ts(type = "string")]
pub struct BlakeHash(pub String);

impl<'de> Deserialize<'de> for BlakeHash {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(de)?;
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom(format!(
                "blake3 hash must be exactly 64 hex digits, got {:?}",
                s
            )));
        }
        Ok(BlakeHash(s))
    }
}

// ── License & FetchSource (W164) ──────────────────────────────────────────────

/// Closed-set, parse-time-enforced license tag. Mirrors the workspace
/// permissive-license rule (MIT / Apache-2.0 / BSD-2/3-Clause / ISC). Adding a
/// variant is an explicit schema change — non-permissive strings
/// (`"GPL-3.0"`, `"AGPL"`, etc.) fail at serde-deserialize before any shape
/// validator runs.
///
/// Shared between `asset.derive.fetch.license` (W164, required) and a future
/// `almanac::ReleaseSource.license` migration (R438-F10, optional).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum License {
    Mit,
    Apache2,
    Bsd2Clause,
    Bsd3Clause,
    Isc,
}

/// Shared fetch primitive — usable by `asset.derive` today, and by Almanac's
/// `ReleaseSource` after a follow-up migration (R438-F10). Defined once in
/// workload-spec so both consumers reject the same set of non-permissive
/// licenses.
///
/// The `blake3` hash pins the upstream bytes; mismatch at fetch time is a hard
/// error in the reconciler. The `license` field is **required** here — every
/// derived asset must declare its upstream license. If/when Almanac adopts
/// `FetchSource`, the Almanac side may wrap this in a struct with
/// `Option<License>` since release manifests have no distribution license per
/// se.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct FetchSource {
    /// Upstream URL fetched verbatim. Reconciler retry policy is configured
    /// elsewhere (R438-F11); the URL itself is opaque to workload-spec.
    pub url: String,

    /// Expected BLAKE3 hash of the fetched bytes (64 hex characters). The
    /// reconciler verifies this after download and aborts on mismatch.
    pub blake3: BlakeHash,

    /// Upstream license. Closed-set, parse-time enforced.
    pub license: License,
}

/// Optional transform applied after a [`FetchSource`] download, lowering to a
/// `ForgeCommand::Subprocess` via the recipe loader (R438-T4). The transform's
/// output is content-addressed by the entry's `blake3` (the recipe runs only
/// when the cache misses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct TransformSpec {
    /// Named recipe under `.yah/qed/transforms/<recipe>.toml`. Loader rejects
    /// missing recipes at materialize time.
    pub recipe: String,

    /// `{{key}}` substitutions passed to the recipe argv at element
    /// granularity (no shell, no string concat). Empty when the recipe is
    /// fully parameterless.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

/// W212/R518: the committed derivation lock — the in-tree action-cache
/// receipt. `input_hash` is the input-addressed derivation key computed over
/// the complete declared input set (fetched-input pin ⊕ recipe-file bytes ⊕
/// invocation params ⊕ schema version); `output_blake3` is what those inputs
/// produced (== the entry's `blake3`). The reconciler skips the entire build
/// (no fetch, no transform, no PUT) when the lock matches the inputs recomputed
/// from the current pins and the bucket already holds the output — the
/// Nix-substituter / Bazel-remote-cache behaviour. Written by the R510 bind
/// path from the reconciler's `discovered_input_hash:<filename>` output; the
/// `git diff` on this block is the receipt that the derivation rolled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DeriveLock {
    /// Input-addressed derivation key (BLAKE3 hex). A change to any declared
    /// input flips this, so a stale lock never produces a false skip.
    pub input_hash: String,
    /// Output the locked inputs produced (BLAKE3 hex; equals the entry's
    /// `blake3`). Carried so the lock is a self-contained action-cache entry.
    pub output_blake3: String,
}

/// Provenance chain for a derived asset: required `fetch` step, optional
/// `transform` step. Materialized bytes replace `AssetEntry.source` for the
/// rest of the static-asset reconcile loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct AssetDerive {
    /// Upstream fetch — URL + content-pin + license.
    pub fetch: FetchSource,

    /// Post-fetch transform. `None` → the fetched bytes ARE the asset
    /// (entry `blake3` must match fetch `blake3`).
    #[serde(default)]
    #[ts(optional = nullable)]
    pub transform: Option<TransformSpec>,

    /// W212/R518: committed derivation lock (input-addressed action-cache
    /// receipt). Absent until the first successful build writes it via the
    /// bind path. When present and current, enables the substituter-style
    /// build skip.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub lock: Option<DeriveLock>,
}

/// A single file entry in the static-asset catalog.
///
/// One `[[asset]]` row per bucket object. Multiple rows for different variants
/// (e.g. q5 and q4 whisper models) are fine — each declares its own filename
/// and hash. The reconciler treats the catalog as exhaustive and append-only:
/// new rows trigger a PUT; removed rows surface as drift (never a DELETE).
///
/// **Source-vs-derive XOR.** Exactly one of `source` or `derive` must be set.
/// Legacy local-bytes assets keep `source = "..."`; W164 derived assets set
/// `[asset.derive]` instead. [`validate::shape_static_asset`] enforces the
/// XOR; both-set and neither-set are hard `ShapeError::Field`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct AssetEntry {
    /// Destination path within the bucket, e.g.
    /// `"whisper/distil-large-v3-q5_1.bin"`. Must be unique in the catalog.
    /// Used as the S3 object key by the reconciler.
    pub filename: String,

    /// Path to a local source file, relative to the `workload.toml` directory.
    /// Mutually exclusive with `derive`.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub source: Option<PathBuf>,

    /// Declared fetch (+ optional transform) provenance chain. The reconciler
    /// materializes the bytes into a content-addressed cache; the cache path
    /// then replaces `source` for the rest of the upload pipeline. Mutually
    /// exclusive with `source`.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub derive: Option<AssetDerive>,

    /// Expected BLAKE3 hash of the *final* asset bytes (64 hex characters).
    /// For `source` mode, this is hashed before upload. For `derive` mode,
    /// it's the post-transform (or post-fetch when no transform) output.
    /// Mismatch aborts the upload.
    pub blake3: BlakeHash,
}

/// `kind = "static-asset"` payload — content-addressed bucket catalog.
///
/// The reconciler makes the bucket match the `[[asset]]` list exactly
/// (append-only: new rows → PUT; removed rows → drift report, not DELETE).
/// Rollback is pointer-flip via `mirror.toml [asset_aliases]` — bytes never
/// move during rollback.
///
/// **Closed-catalog invariant**: every value in `[aliases]` must be a
/// `filename` that exists in `[[asset]]`. Enforced by
/// [`validate::shape_static_asset`]. Mirror overrides (`[asset_aliases]` in
/// `mirror.toml`) are bound by the same rule — the alias graph can only
/// resolve to filenames already in the catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct StaticAssetWorkload {
    /// Wire-format version. Always `V1` today.
    pub schema_version: SchemaVersion,

    /// Exhaustive catalog of files this component manages in the bucket.
    ///
    /// Named `asset` on disk (TOML `[[asset]]` array-of-tables) to follow TOML
    /// convention; accessed as `.assets` in Rust code.
    #[serde(rename = "asset", default)]
    pub assets: Vec<AssetEntry>,

    /// Canonical logical-name → filename mappings for this component.
    ///
    /// Values must be filenames present in `assets` — validated by
    /// [`validate::shape_static_asset`]. Mirror files may override individual
    /// entries via `[asset_aliases]` but may never reference filenames absent
    /// from this catalog.
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
}

// ── Lifecycle archetype (R572-F1 / W244) ───────────────────────────────────────

/// Explicit lifecycle archetype for a `kind = "container"` workload (W244).
///
/// The question that actually matters to a scheduler: *"can I kill this and
/// recreate it somewhere else?"* Before this field existed, the answer was
/// inferred per-spec from `volumes.is_empty()` + `restart_policy` — fragile
/// absence-as-policy, the same trap W243 calls out on the node-taint side.
/// This type makes the answer structural instead of guessed.
///
/// This ticket (R572-F1) adds the discriminator only. The reconciler does not
/// yet branch on it (R572-F4) and neither does the scheduler (R572-F5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleArchetype {
    /// k8s analogue: Deployment. Stateless and fungible — the scheduler may
    /// move it, scale it to N replicas, or restart it on a different node
    /// with zero consequence. Drainable.
    Server,

    /// k8s analogue: StatefulSet. Stable identity + a volume that must
    /// follow it; at most one live instance. Not drainable — the reconciler
    /// must not schedule it onto a different node. Example: a postgres peer,
    /// headscale (W267/R591).
    Appliance,

    /// k8s analogue: Job. Runs to completion with declared inputs/outputs,
    /// then is gone — no steady-state identity. `almanac` is the first
    /// job-family member; forge runs (`WorkloadSpec::for_forge`, used by QED)
    /// are the `container`-kind instance of this archetype.
    Job,
}

impl LifecycleArchetype {
    /// The repel-taint key for this archetype (R572-F5). A node carrying the
    /// taint `"no-<key>"` repels workloads of this class unless they
    /// explicitly tolerate it.
    ///
    /// Examples: `Server` → `"server"` (repelled by `"no-server"`);
    /// `Appliance` → `"appliance"` (repelled by `"no-appliance"`).
    pub fn taint_key(&self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Appliance => "appliance",
            Self::Job => "job",
        }
    }

    /// The pre-R572 inference this field replaces, kept only to give
    /// `WorkloadSpec::effective_archetype` a behavior-preserving fallback for
    /// specs written before this field existed (`archetype: None`).
    ///
    /// A volume that must follow the workload is the strongest signal of
    /// durable state → [`Self::Appliance`]. Absent that, `RestartPolicy::Never`
    /// is the existing forge/run-once convention (see
    /// [`RestartPolicy::Never`]'s doc comment) → [`Self::Job`]. Everything
    /// else defaults to the common case, [`Self::Server`].
    fn infer(volumes: &[VolumeMount], restart_policy: &RestartPolicy) -> Self {
        if !volumes.is_empty() {
            LifecycleArchetype::Appliance
        } else if matches!(restart_policy, RestartPolicy::Never) {
            LifecycleArchetype::Job
        } else {
            LifecycleArchetype::Server
        }
    }
}

// ── WorkloadSpec ──────────────────────────────────────────────────────────────

/// Complete typed description of a containerd workload handed to yubaba over
/// RPC. This is also the payload of the `kind = "container"` variant of
/// [`Workload`] on disk.
///
/// Yubaba never accepts compose YAML on its RPC surface — agents, the desktop,
/// and operator CLIs all hand yubaba `WorkloadSpec` values. See the arch doc
/// for the validation layers and evolution rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct WorkloadSpec {
    /// Wire-format version; always `V1` today. Present at the top level so
    /// rolling clusters can detect and migrate across schema generations.
    pub schema_version: SchemaVersion,

    /// DNS-friendly workload name, e.g. `"noisetable-api"`. Regex:
    /// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, length ≤ 63.
    pub name: String,

    /// Container image to pull.
    pub image: ImageRef,

    /// Tier tag controlling admission control and mesh filtering.
    pub tier: TierTag,

    /// Tenant **isolation** axis (W206). Separates operators' workloads at the
    /// network / DB / mesh-identity level. Defaults to [`TenantId::singleton`]
    /// for specs that predate the axis, so single-tenant clusters keep every
    /// isolation primitive a no-op. Orthogonal to [`Self::tier`] (class) and
    /// [`Self::namespace`] (routing).
    #[serde(default = "TenantId::singleton")]
    pub tenant: TenantId,

    /// Namespace **routing/naming** axis (W206). A pure naming key — never
    /// affects isolation; disambiguates DNS names and selects config root /
    /// provider zone within a tenant. Defaults to [`NamespaceId::singleton`].
    #[serde(default = "NamespaceId::singleton")]
    pub namespace: NamespaceId,

    /// Target replica count. `0` registers the workload without deploying it.
    /// Range: 0–100 (cluster-wide cap; operator can raise it).
    pub replicas: u32,

    /// Override the image's `CMD`. `None` leaves the image default.
    #[ts(optional = nullable)]
    pub command: Option<Vec<String>>,

    /// Override the image's `ENTRYPOINT`. `None` leaves the image default.
    #[ts(optional = nullable)]
    pub entrypoint: Option<Vec<String>>,

    /// Working directory inside the container.
    #[ts(optional = nullable)]
    pub workdir: Option<PathBuf>,

    /// User to run as, e.g. `"1000:1000"` or `"appuser"`.
    #[ts(optional = nullable)]
    pub user: Option<String>,

    /// Environment variables. Values may be literals, secret refs, or
    /// mesh-address references resolved by yubaba at deploy time.
    #[serde(default)]
    pub env: Vec<EnvVar>,

    /// Secret mounts. Values never appear in the spec JSON — only references.
    #[serde(default)]
    pub secrets: Vec<SecretMount>,

    /// Volume mounts.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,

    /// Hard resource caps enforced by containerd/cgroups.
    pub resources: ResourceLimits,

    /// Mesh idents that must reach `Ready` before this workload starts.
    #[serde(default)]
    pub depends_on: Vec<MeshIdent>,

    /// Container liveness/readiness probe.
    #[ts(optional = nullable)]
    pub healthcheck: Option<Healthcheck>,

    /// What yubaba does when the container exits.
    pub restart_policy: RestartPolicy,

    /// Explicit lifecycle archetype (R572-F1 / W244): `server`, `appliance`,
    /// or `job`. `None` means the spec predates this field (or the author
    /// didn't set it) — callers MUST NOT read this directly to decide
    /// drainability; use [`WorkloadSpec::effective_archetype`], which falls
    /// back to the pre-R572 `volumes`/`restart_policy` inference so no
    /// existing spec's effective meaning changes.
    ///
    /// Additive: this field did not exist before R572-F1. Reconciler (F4)
    /// and scheduler (F5) branching on the resolved archetype are separate,
    /// later tickets — this field alone changes no runtime behavior.
    #[serde(default)]
    #[ts(optional = nullable)]
    pub archetype: Option<LifecycleArchetype>,

    /// Graceful shutdown configuration.
    pub stop_policy: StopPolicy,

    /// Network exposure configuration — mesh, public, and operator channels
    /// are independent and can be set in any combination.
    pub expose: ExposeSpec,

    /// OCI-style labels, passed through to the container. Opaque to yubaba.
    #[serde(default)]
    pub labels: HashMap<String, String>,

    /// Yah-specific metadata, conventionally prefixed `yah.*`. Opaque to
    /// yubaba beyond `yah.forge=true` which suppresses the Never-restart guard.
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

impl WorkloadSpec {
    /// Build a `WorkloadSpec` for a forge run.
    ///
    /// Sets the conventional forge fields in one place so callers cannot
    /// forget any of them:
    ///
    /// - `restart_policy = Never`
    /// - `archetype = Some(LifecycleArchetype::Job)` — a forge run is
    ///   exactly the `container`-kind instance of the job archetype (W244);
    ///   set explicitly rather than left to infer since this constructor
    ///   knows its own shape
    /// - `expose.public = None`, `expose.operator = None`
    /// - `expose.mesh.identity = "forge.<forge_id>"`
    /// - `annotations["yah.forge"] = "true"` (suppresses the shape warning)
    /// - `tier` and `image` come from the caller; `ports` becomes the mesh
    ///   port list (empty is valid — forge jobs often don't expose ports)
    ///
    /// All other fields are set to safe defaults. Callers can mutate the
    /// returned value to fill in `command`, `env`, `resources`, etc.
    pub fn for_forge(
        forge_id: &str,
        image: ImageRef,
        tier: TierTag,
        ports: Vec<u16>,
    ) -> Self {
        let mut annotations = HashMap::new();
        annotations.insert("yah.forge".into(), "true".into());

        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            // NB: DNS-label safe (no dots) — `check_name` validation rejects
            // dots here. The container_id derives from this; the state-poll
            // keys off `expose.mesh.identity` (`forge.<id>`) instead, so those
            // two must be reconciled at the read path, NOT by dotting the name
            // (see R590-B9).
            name: format!("forge-{forge_id}"),
            image,
            tier,
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            replicas: 1,
            command: None,
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                // R590-B10: forge workloads are BUILDS (cargo, buildkit, a
                // from-source V8 checkout+compile), not tiny services. The old
                // 256 MB placeholder became a hard cgroup memory.limit in
                // build_oci_spec and SIGKILL'd the rusty-v8 build mid-checkout
                // (git checkout of third_party/icu died of signal 9) — the
                // more so because /tmp is a RAM-backed tmpfs, so the source
                // tree counts against this limit too. 32 GiB is a bounded
                // ceiling that fits the V8 build's >12 GB peak with headroom,
                // protects the host from a runaway (vs truly unlimited), and is
                // above physical RAM on smaller build-workers (⇒ effectively
                // unlimited there). A per-step memory request threaded from the
                // pipeline is the eventual right model (see R590-B10).
                memory_mb: 32768,
                cpu_millis: 512,
                ephemeral_storage_mb: 512,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Never,
            archetype: Some(LifecycleArchetype::Job),
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(30),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(format!("forge.{forge_id}")),
                    ports,
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: HashMap::new(),
            annotations,
        }
    }

    /// Whether this workload requests the **host network namespace** rather
    /// than an isolated one.
    ///
    /// Opt-in via `annotations["yah.network"] == "host"` (see
    /// [`HOST_NETWORK_ANNOTATION`] / [`HOST_NETWORK_VALUE`]). Default is the
    /// isolated netns every other workload gets — host networking is a
    /// privileged escape hatch for the few infra workloads that must bind a
    /// host port so an on-host ingress (e.g. a Cloudflare tunnel reaching
    /// `127.0.0.1:<port>`) can route to them without CNI/bridge plumbing.
    ///
    /// The backend (kamaji) is responsible for **guarding** this: host
    /// networking is only honoured for `tier == "infra"` workloads; a
    /// non-infra workload that sets the annotation is rejected at deploy. See
    /// `validate_spec_for_constable`.
    pub fn wants_host_network(&self) -> bool {
        self.annotations
            .get(HOST_NETWORK_ANNOTATION)
            .map(|v| v == HOST_NETWORK_VALUE)
            .unwrap_or(false)
    }

    /// Resolve the lifecycle archetype (R572-F1 / W244): the explicit
    /// [`Self::archetype`] if set, otherwise the pre-R572 inference from
    /// `volumes`/`restart_policy` this field replaces.
    ///
    /// This is the one seam callers should use to ask "can I kill and
    /// reschedule this?" — it is intentionally the *only* place that
    /// implements the fallback, so behavior for pre-existing specs (no
    /// `archetype` on disk) is identical to what it was before this field
    /// existed. Consumers (reconciler R572-F4, scheduler R572-F5) branch on
    /// the return value; this crate does not itself change any reconciler or
    /// scheduler behavior.
    pub fn effective_archetype(&self) -> LifecycleArchetype {
        self.archetype
            .unwrap_or_else(|| LifecycleArchetype::infer(&self.volumes, &self.restart_policy))
    }

    /// Fully-qualified mesh identity `<tenant>/<namespace>/<name>` (W206 /
    /// R558-F3), where `<name>` is this workload's [`MeshExpose::identity`].
    ///
    /// Within a tenant, workloads still address each other by the short
    /// identity (namespace disambiguates only on collision); the FQN is what
    /// makes the identity unambiguous across tenants and is exactly what a
    /// [`MeshPeer::CrossTenant`] grant names.
    pub fn fq_mesh_identity(&self) -> String {
        format!(
            "{}/{}/{}",
            self.tenant.0, self.namespace.0, self.expose.mesh.identity.0
        )
    }

    /// The taint this workload requires its node to carry, if any (R594-F2 /
    /// W267 sovereign public ingress).
    ///
    /// Opt-in via `annotations["yah.placement.requires-taint"] = "<taint
    /// name>"` (see [`REQUIRES_TAINT_ANNOTATION`]) — same annotation-based,
    /// zero-blast-radius shape as [`Self::wants_host_network`], chosen so
    /// declaring this requirement does not force a struct-literal edit at
    /// every existing `WorkloadSpec { .. }` construction site the way a new
    /// plain field would (see R572-F1's handoff: ~26 sites for one field).
    ///
    /// **This only declares the requirement — nothing matches it yet.** The
    /// taint itself doesn't exist on the machine-TOML side until
    /// [R572-F3](yah://arch/symbol/R572) adds a `taints` list there, and
    /// nothing enforces repel-unless-tolerate placement until
    /// [R572-F5](yah://arch/symbol/R572)'s scheduler lands. Until then this
    /// is inert metadata a future scheduler can read.
    ///
    /// The public-ingress appliance (W267) is the first user: a
    /// `kind = "container"` workload with `archetype =
    /// Some(LifecycleArchetype::Appliance)` and
    /// `requires_taint() == Some(PUBLIC_IP_TAINT)`, so yubaba may one day
    /// place it only on machines carrying the `"public-ip"` taint and kamaji
    /// supervises it like any other container (no new `Workload` variant —
    /// see [`Workload::Container`]'s doc comment).
    pub fn requires_taint(&self) -> Option<&str> {
        self.annotations
            .get(REQUIRES_TAINT_ANNOTATION)
            .map(String::as_str)
    }
}

/// Annotation key requesting a workload share the host network namespace.
/// See [`WorkloadSpec::wants_host_network`].
pub const HOST_NETWORK_ANNOTATION: &str = "yah.network";

/// Annotation value (for [`HOST_NETWORK_ANNOTATION`]) selecting host
/// networking. Any other value leaves the workload in an isolated netns.
pub const HOST_NETWORK_VALUE: &str = "host";

/// Annotation key declaring that a workload must land only on a node
/// carrying a specific taint. See [`WorkloadSpec::requires_taint`].
pub const REQUIRES_TAINT_ANNOTATION: &str = "yah.placement.requires-taint";

/// Taint name (for [`REQUIRES_TAINT_ANNOTATION`]) identifying machines with
/// a publicly-routable IP — the W267 sovereign-ingress placement
/// requirement. The corresponding taint field on the machine TOML doesn't
/// exist yet (R572-F3); this constant is the agreed-upon name both sides
/// will use once it does.
pub const PUBLIC_IP_TAINT: &str = "public-ip";

// ── ImageRef ─────────────────────────────────────────────────────────────────

/// Container image reference identifying a specific image to pull.
///
/// **Digest is required.** Every executable image reference in the workspace
/// is content-addressed by `sha256:<hex>`. The `tag` is preserved as a
/// human-readable identifier but is not the source of truth — registries
/// return mutable `tag → digest` mappings and we don't trust them for
/// reproducibility. R438-T3 tightened `digest: Option<String> → String` to
/// make unpinned-image bugs impossible by construction.
///
/// **Two deserialize shapes.** The struct form
/// (`registry`/`repository`/`tag`/`digest` fields) is the on-disk envelope.
/// A **string form** (`image = "ghcr.io/foo/bar:v1@sha256:<hex>"`) is also
/// accepted and is the shape W164 transform recipes (R438-T4) and W165
/// `BuildMode::InContainer` (R438-T6) use. Both shapes go through a single
/// parser ([`compose_import::parse_pinned_image_ref`]) that rejects
/// bare-tag references at serde-deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ImageRef {
    /// Registry hostname, e.g. `"ghcr.io"` or `"localhost:5000"`.
    pub registry: String,

    /// Repository path, e.g. `"noisetable/api"`.
    pub repository: String,

    /// Tag, e.g. `"v1.4.2"` or `"latest"`. Informational — the digest is
    /// the source of truth for image identity.
    pub tag: String,

    /// Content-addressed pinned identity, e.g. `"sha256:abc..."`. Required.
    pub digest: String,
}

impl<'de> Deserialize<'de> for ImageRef {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            registry: String,
            repository: String,
            tag: String,
            digest: String,
        }

        // The string-or-struct `untagged` probe requires `deserialize_any`,
        // which only self-describing formats support. Postcard — the binary
        // wire behind the kamaji UDS — returns `WontImplement` for it, so a
        // `Workload::Container(WorkloadSpec)` carrying a nested `ImageRef`
        // failed to decode and every container deploy 500'd (R590-B3).
        //
        // The string form is purely an authoring convenience in human-readable
        // configs (`image = "ghcr.io/…@sha256:…"` in recipe/workload TOML and
        // JSON); the binary wire only ever carries the derived struct form
        // (Serialize is a plain struct derive). So branch on the format: text
        // keeps the string-or-struct convenience via `untagged`; binary decodes
        // the plain positional struct with no `deserialize_any`.
        if de.is_human_readable() {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Repr {
                // Order matters for `untagged`: try the string form first so
                // explicit strings don't get coerced into a struct error.
                Pinned(String),
                Struct(Fields),
            }

            match Repr::deserialize(de)? {
                Repr::Pinned(s) => {
                    compose_import::parse_pinned_image_ref(&s).map_err(serde::de::Error::custom)
                }
                Repr::Struct(f) => Ok(ImageRef {
                    registry: f.registry,
                    repository: f.repository,
                    tag: f.tag,
                    digest: f.digest,
                }),
            }
        } else {
            let f = Fields::deserialize(de)?;
            Ok(ImageRef {
                registry: f.registry,
                repository: f.repository,
                tag: f.tag,
                digest: f.digest,
            })
        }
    }
}

// ── testing helpers ───────────────────────────────────────────────────────────

/// Fixture helpers for test code that needs to construct types whose schemas
/// would otherwise demand operator-pinned values (digests, hashes). Doc-hidden
/// to discourage misuse from non-test code — production paths must source
/// digests from registry resolution or compile-time injection.
#[doc(hidden)]
pub mod testing {
    /// Fixed valid-format sha256 digest for test fixtures. All-zeros marker
    /// is impossible for any real image, so a leaked test fixture in a
    /// production code-path surfaces obviously.
    ///
    /// Aliases [`super::ImageRef::UNPINNED_DIGEST`] — the two are deliberately
    /// the same value: the fixture sentinel and the production "unpinned"
    /// marker must agree so [`super::ImageRef::pull_ref`]'s tag-fallback fires
    /// on exactly the digest `catalog_image` writes.
    pub const TEST_DIGEST: &str = super::ImageRef::UNPINNED_DIGEST;

    /// Owned `String` form of [`TEST_DIGEST`] for fixture constructors.
    pub fn test_digest() -> String {
        TEST_DIGEST.to_string()
    }
}

// ── EnvVar ────────────────────────────────────────────────────────────────────

/// A single environment variable injected into the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct EnvVar {
    /// Variable name, conventionally `SCREAMING_SNAKE_CASE`.
    pub name: String,

    /// Value source.
    pub value: EnvValue,
}

/// Value source for an environment variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum EnvValue {
    /// Static string baked into the spec.
    Literal { value: String },

    /// Resolved from a yubaba secret at deploy time; the secret value never
    /// appears in the spec JSON.
    FromSecret { secret: String, key: String },

    /// Resolved from another workload's mesh address at deploy time by yubaba.
    /// Lets workloads reference each other symbolically without IP pinning.
    FromMesh { ident: MeshIdent, kind: MeshLookup },
}

/// Which aspect of a mesh peer's address to inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum MeshLookup {
    /// Full URL, e.g. `"http://noisetable-db.pdx:5432"`.
    Url,
    /// Hostname only, e.g. `"noisetable-db.pdx"`.
    Host,
    /// Port only, e.g. `"5432"`.
    Port,
}

// ── Secrets ───────────────────────────────────────────────────────────────────

/// A secret value mounted into the container as an env var or file.
///
/// The secret value never appears in the spec JSON — only the reference.
/// Yubaba audits secret access per workload from these references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct SecretMount {
    /// Where yubaba reads the secret value from.
    pub source: SecretRef,

    /// How the secret is surfaced inside the container.
    pub target: SecretTarget,
}

/// Where yubaba resolves the secret value from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SecretRef {
    /// Per-machine yubaba secret store at `/var/lib/yah/yubaba/secrets/`.
    LocalFile { path: PathBuf },

    /// Raft-replicated cluster secret spanning all machines (planned; not in
    /// V1 deployment). Sketch preserved for wire compatibility.
    Cluster { name: String },
}

/// How the secret is surfaced inside the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SecretTarget {
    /// Injected as an environment variable. Value never appears in spec JSON.
    /// Prefer `File` — env vars leak through subprocess env and log dumps.
    EnvVar { name: String },

    /// Mounted as a file inside the container at `path` with `mode` (octal).
    File { path: PathBuf, mode: u32 },
}

// ── Volumes ───────────────────────────────────────────────────────────────────

/// A volume mount inside the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct VolumeMount {
    /// Backing volume source.
    pub source: VolumeSource,

    /// Absolute path inside the container.
    pub target: PathBuf,

    /// Whether the container sees the volume as read-only.
    pub read_only: bool,
}

/// Backing source for a volume mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum VolumeSource {
    /// Yubaba-managed named volume; created on first use.
    Named { name: String },

    /// Operator-managed host path. Yubaba rejects bind mounts unless
    /// `WorkloadSpec.tier == "infra"`; shape validation enforces this.
    Bind { host_path: PathBuf },

    /// In-memory tmpfs; discarded on container stop. `size_mb` caps space
    /// consumed by the writable layer.
    Tmpfs { size_mb: u32 },
}

// ── Durable forge produced-artifact convention (R603-T5) ──────────────────────

/// Convention for a remote forge step's durable produced artifacts.
///
/// A remote build (e.g. the rusty_v8 musl build on a build-worker) writes its
/// output tarball to a path *inside* the container. The container's rootfs is
/// destroyed when kamaji reaps the EXITED container — so if the camp daemon is
/// down when the build finishes, the artifact is gone before boot-reconcile can
/// retrieve it (R603-T4 surfaced this as `Success`-but-`UNPUBLISHED`).
///
/// The fix (R603-T5) is a **host-persistent bind mount**: forge Subprocess
/// workloads mount [`HOST_ROOT`]`/<forge_id>` onto [`CONTAINER_DIR`], so a
/// build that writes its `produces` under `/yah/produced` lands the bytes on
/// the worker's host filesystem. yubaba then reads them back from the host path
/// ([`host_path`]) — which outlives container reaping — instead of the
/// unreachable container rootfs.
///
/// The container-side path and the host root are a shared convention between
/// three crates: the qed `build_workload_spec` that adds the mount, kamaji that
/// binds it, and the yubaba handler that reads + reaps it. Keeping it here (the
/// crate all three already depend on) is the single source of truth.
pub mod forge_produced {
    use std::path::{Path, PathBuf};

    /// Conventional container-side directory a remote forge step writes its
    /// durable produced artifacts to. Bind-mounted onto a host-persistent dir.
    pub const CONTAINER_DIR: &str = "/yah/produced";

    /// Host root under which each forge's durable produced dir lives, one
    /// subdir per run: `<HOST_ROOT>/<forge_id>/`. yubaba owns this directory —
    /// it creates the per-forge subdir at deploy, serves reads from it, and
    /// reaps it on teardown / TTL sweep.
    pub const HOST_ROOT: &str = "/var/lib/yah/qed/produced";

    /// Forge mesh idents are `forge.<id>` (see [`WorkloadSpec::for_forge`]).
    /// Extract the bare `<id>`, or `None` for a non-forge ident.
    ///
    /// [`WorkloadSpec::for_forge`]: super::WorkloadSpec::for_forge
    pub fn forge_id_from_ident(ident: &str) -> Option<&str> {
        ident.strip_prefix("forge.")
    }

    /// The host-persistent produced directory for one forge run.
    pub fn host_dir(forge_id: &str) -> PathBuf {
        PathBuf::from(HOST_ROOT).join(forge_id)
    }

    /// Translate a container-side produced path to its durable host path for a
    /// given forge run. Returns `None` when `container_path` is not under
    /// [`CONTAINER_DIR`] (the caller then knows the artifact was not written to
    /// the durable location and won't survive reaping), or when the relative
    /// path contains a `..` component (a traversal attempt that could escape the
    /// per-forge dir — the reader must never serve a file outside it).
    pub fn host_path(forge_id: &str, container_path: &Path) -> Option<PathBuf> {
        let rel = container_path.strip_prefix(CONTAINER_DIR).ok()?;
        if rel
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return None;
        }
        Some(host_dir(forge_id).join(rel))
    }

    /// The durable produced-dir bind mount for a forge run: host
    /// `<HOST_ROOT>/<forge_id>` → container [`CONTAINER_DIR`], writable.
    pub fn durable_mount(forge_id: &str) -> super::VolumeMount {
        super::VolumeMount {
            source: super::VolumeSource::Bind {
                host_path: host_dir(forge_id),
            },
            target: PathBuf::from(CONTAINER_DIR),
            read_only: false,
        }
    }

    /// True when `path` is (or is under) the conventional durable produced dir
    /// — the guard qed uses to enforce that declared `produces` land somewhere
    /// reap-durable.
    pub fn is_durable_path(path: &Path) -> bool {
        path.starts_with(CONTAINER_DIR)
    }
}

// ── Resources ─────────────────────────────────────────────────────────────────

/// Hard resource caps enforced by containerd/cgroups at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ResourceLimits {
    /// Maximum RAM the container may allocate, in MiB. The container is OOM-
    /// killed if it exceeds this.
    pub memory_mb: u32,

    /// CPU **request** in millicores (k8s convention): `1000` = one full core,
    /// `250` = `.25 CPU`. Unlike a Docker relative weight this is an
    /// allocatable quantity a bin-packer can subtract from a node's budget.
    /// `0` means "no CPU limit". Backends that speak a relative weight derive
    /// it via [`ResourceLimits::cpu_shares`].
    pub cpu_millis: u32,

    /// Cap on the writable layer + tmpfs footprint, in MiB.
    pub ephemeral_storage_mb: u32,
}

impl ResourceLimits {
    /// The Docker/OCI relative CPU weight (`cpu.shares`, where `1024` ≈ one
    /// core) equivalent to this millicore request. The containerd and docker
    /// backends express CPU as a weight rather than a millicore request, so
    /// they derive it here instead of storing shares: `1000m` ⇒ `1024`.
    pub fn cpu_shares(&self) -> u64 {
        (u64::from(self.cpu_millis) * 1024) / 1000
    }
}

// ── Healthcheck ───────────────────────────────────────────────────────────────

/// Container health probe configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct Healthcheck {
    /// The probe executed to determine container health.
    pub probe: HealthProbe,

    /// How often the probe runs.
    pub interval: Millis,

    /// Per-probe timeout; a slow response counts as failure.
    pub timeout: Millis,

    /// Time to wait after container start before the first probe. Shape
    /// validation warns (not errors) if this is less than
    /// `stop_policy.grace_period * 2`.
    pub initial_delay: Millis,

    /// Number of consecutive failures before the container is marked
    /// `Unhealthy`.
    pub failure_threshold: u32,
}

/// Mechanism used to check container health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HealthProbe {
    /// HTTP GET to `path` on `port`. A 2xx (or `expect_status` if set)
    /// response counts as healthy.
    HttpGet {
        path: String,
        port: u16,
        #[ts(optional = nullable)]
        expect_status: Option<u16>,
    },

    /// Run `argv` inside the container; exit-0 counts as healthy.
    Exec { argv: Vec<String> },

    /// TCP connection to `port`; a successful connect counts as healthy.
    TcpConnect { port: u16 },
}

// ── Restart / Stop ────────────────────────────────────────────────────────────

/// What yubaba does when the container exits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Restart unconditionally on any exit.
    Always,

    /// Restart on non-zero exit, up to `max_attempts` times with exponential
    /// backoff. After exhaustion, the workload is marked `Failed`.
    OnFailure {
        max_attempts: u32,
        backoff: BackoffPolicy,
    },

    /// Do not restart. The container runs once and exits.
    ///
    /// **Forge convention.** Forge runs (R094) synthesize a `WorkloadSpec`
    /// using [`WorkloadSpec::for_forge`] which sets all the conventional fields
    /// together:
    ///
    /// - `restart_policy = Never`
    /// - `expose.public = None`, `expose.operator = None`
    /// - `expose.mesh.identity = "forge.<forge_id>"` — distinguishable from
    ///   persistent mirror identities at the mesh layer
    /// - `tier = "infra"` (or the forge-spec's effective tier)
    /// - `annotations["yah.forge"] = "true"` — suppresses the shape warning
    ///
    /// Using `Never` on a persistent mirror (not a forge run) means the mirror
    /// stays dead after any exit — a likely misconfiguration. Shape validation
    /// emits a soft warning unless `annotations["yah.forge"] == "true"` is
    /// present. See R094 forge.
    Never,
}

/// Exponential backoff parameters for `RestartPolicy::OnFailure`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct BackoffPolicy {
    /// Initial delay before the first restart, in milliseconds.
    pub initial_ms: u32,

    /// Maximum delay between retries, in milliseconds.
    pub max_ms: u32,

    /// Backoff multiplier applied to each successive delay.
    pub multiplier: f32,
}

/// Graceful shutdown configuration for yubaba's stop sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct StopPolicy {
    /// Signal number sent first, e.g. `15` (SIGTERM) or `2` (SIGINT).
    pub signal: i32,

    /// Time yubaba waits after sending `signal` before issuing SIGKILL.
    pub grace_period: Millis,
}

// ── Expose ────────────────────────────────────────────────────────────────────

/// Network exposure configuration. The three channels are independent; any
/// combination is valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ExposeSpec {
    /// Mesh-internal exposure. Required; every workload must have a mesh
    /// identity even if no other workload currently reaches it.
    pub mesh: MeshExpose,

    /// Public internet exposure via a Cloudflare tunnel route. `None` means
    /// the workload is not internet-reachable.
    #[ts(optional = nullable)]
    pub public: Option<PublicExpose>,

    /// Operator-facing exposure via a Tailscale ACL tag. `None` means the
    /// workload is not operator-reachable via Tailscale.
    #[ts(optional = nullable)]
    pub operator: Option<OperatorExpose>,
}

/// A peer permitted to initiate mesh connections to a workload (W206 / R558-F3).
///
/// Cross-tenant access is **deny-by-default**: a workload accepts inter-tenant
/// traffic only from peers it lists explicitly as [`MeshPeer::CrossTenant`].
/// Same-tenant access stays tier-based ([`MeshPeer::Tier`]) — the pre-R558
/// model — and an `allow_from` with no `Tier` entries still admits every
/// same-tenant peer (the historical "empty = allow all" default).
///
/// External serde tagging keeps this postcard-safe (R590-B3): no internal tag,
/// no untagged, no `skip_serializing_if`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum MeshPeer {
    /// Any **same-tenant** workload whose `tier` matches this tag. This is the
    /// pre-R558 `allow_from` semantics.
    Tier(TierTag),

    /// A specific workload in **another tenant**, addressed by its fully
    /// qualified mesh identity `<tenant>/<namespace>/<name>`. There is no
    /// cross-tenant tier wildcard — each cross-tenant peer is granted
    /// individually, so a shared fleet stays isolated unless an operator opts
    /// in here.
    CrossTenant {
        tenant: TenantId,
        namespace: NamespaceId,
        /// Peer's mesh identity (its [`MeshExpose::identity`]).
        name: MeshIdent,
    },
}

/// Mesh-internal port exposure and peer access control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct MeshExpose {
    /// DNS-segment mesh identity for this workload. Must be unique in the
    /// cluster. Regex: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, length ≤ 63.
    pub identity: MeshIdent,

    /// Container-side ports this workload listens on. Other workloads reach
    /// it at `<identity>:<port>` on the mesh.
    pub ports: Vec<u16>,

    /// Peers permitted to initiate connections to this workload on the mesh
    /// (W206 / R558-F3). Same-tenant tier rules and explicit cross-tenant
    /// grants share this one list. With **no** [`MeshPeer::Tier`] entries every
    /// same-tenant peer is admitted (the historical "empty = allow all"
    /// default); cross-tenant peers are always denied unless named by a
    /// [`MeshPeer::CrossTenant`] entry. See [`MeshExpose::admits_peer`].
    #[serde(default)]
    pub allow_from: Vec<MeshPeer>,
}

impl MeshExpose {
    /// Whether a peer may initiate a mesh connection to a workload whose mesh
    /// exposure is `self`. `own_tenant` is the tenant of the workload being
    /// protected; the remaining arguments identify the connecting peer.
    ///
    /// Deny-by-default across tenants (W206 / R558-F3):
    /// - **Same tenant** (`own_tenant == peer_tenant`): admitted when the
    ///   peer's tier matches a [`MeshPeer::Tier`] rule, or when there are no
    ///   `Tier` rules at all (historical "empty `allow_from` = allow all
    ///   same-tenant").
    /// - **Cross tenant**: admitted only when an explicit
    ///   [`MeshPeer::CrossTenant`] entry matches the peer's
    ///   `(tenant, namespace, name)`.
    pub fn admits_peer(
        &self,
        own_tenant: &TenantId,
        peer_tenant: &TenantId,
        peer_namespace: &NamespaceId,
        peer_name: &MeshIdent,
        peer_tier: &TierTag,
    ) -> bool {
        if own_tenant == peer_tenant {
            let mut has_tier_rule = false;
            for peer in &self.allow_from {
                if let MeshPeer::Tier(t) = peer {
                    has_tier_rule = true;
                    if t == peer_tier {
                        return true;
                    }
                }
            }
            // No same-tenant tier restriction declared → admit all same-tenant.
            !has_tier_rule
        } else {
            self.allow_from.iter().any(|peer| {
                matches!(
                    peer,
                    MeshPeer::CrossTenant { tenant, namespace, name }
                        if tenant == peer_tenant
                            && namespace == peer_namespace
                            && name == peer_name
                )
            })
        }
    }
}

/// The name by which a workload is addressed **within its own tenant** (W206 /
/// R558-F3), given every `(namespace, identity)` pair present in that tenant.
///
/// Within a tenant, a workload is reached by its short mesh `identity` when that
/// identity is unique across the tenant's namespaces. When two namespaces
/// expose the same identity, the name is ambiguous, so both are disambiguated
/// by a namespace prefix — `<namespace>.<identity>` (e.g. `yah.runner` vs
/// `noisetable.runner`). Cross-tenant addressing always uses the full FQN
/// ([`WorkloadSpec::fq_mesh_identity`]) and is out of scope here.
pub fn intra_tenant_address(
    namespace: &NamespaceId,
    identity: &MeshIdent,
    tenant_workloads: &[(NamespaceId, MeshIdent)],
) -> String {
    let collides = tenant_workloads
        .iter()
        .any(|(ns, id)| id == identity && ns != namespace);
    if collides {
        format!("{}.{}", namespace.0, identity.0)
    } else {
        identity.0.clone()
    }
}

/// Public internet exposure via a Cloudflare tunnel route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PublicExpose {
    /// Public hostname to route, e.g. `"api.noisetable.io"`. Semantic
    /// validation checks that this hostname is owned by a configured CF zone.
    pub hostname: String,

    /// Container-side port to route traffic to. Shape validation requires this
    /// port to appear in `expose.mesh.ports`.
    pub port: u16,

    /// TLS configuration for the public endpoint.
    pub tls: PublicTls,
}

/// TLS mode for a public endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PublicTls {
    /// Cloudflare manages the TLS certificate (default; requires a proxied DNS
    /// record in the configured zone).
    CfManaged,

    /// User-supplied certificate referenced by name in the yubaba secret store.
    UserCertRef { name: String },
}

/// Operator-facing exposure via a Tailscale ACL tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct OperatorExpose {
    /// Tailscale ACL tag granting access, e.g. `"tag:noisetable-ops"`. Semantic
    /// validation checks that this tag exists in the cluster's Tailscale ACL.
    pub tailscale_tag: String,

    /// Container-side port to expose to Tailscale-authorized operators.
    pub port: u16,
}

// ── ImageRef helpers ──────────────────────────────────────────────────────────

impl ImageRef {
    /// The all-zeros sha256 digest that marks an image reference as **not
    /// content-pinned**. No real image can carry it, so a build that never
    /// injected a compile-time digest (dev builds) or a catalog image that
    /// isn't published-and-pinned yet lands on this sentinel. This is the
    /// single source of truth both the catalog emitter
    /// (`task::default_image::catalog_image`, which writes it) and the
    /// container-runtime resolvers ([`Self::pull_ref`], via kamaji) agree on —
    /// keeping them here means they cannot drift. [`testing::TEST_DIGEST`] is
    /// the same value re-exported for fixtures.
    pub const UNPINNED_DIGEST: &'static str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    /// Parse a full digest-pinned image reference —
    /// `[registry/]repo[:tag]@sha256:<hex>` — into its parts.
    ///
    /// This is the public door onto the same parser the `ImageRef` string-form
    /// `Deserialize` arm uses, so a config that spells an image as one string
    /// (a qed `step.image`, a transform recipe) and a config that spells it as
    /// a struct land on identical semantics. A bare tag is rejected: the whole
    /// point of the string form is that it carries the digest.
    pub fn parse_pinned(s: &str) -> Result<Self, String> {
        compose_import::parse_pinned_image_ref(s)
    }

    /// Format this reference as a Docker-compatible image string,
    /// `{registry}/{repository}:{tag}@{digest}`. Tag is included for human
    /// readability; the digest is what the pull resolves against. Always emits
    /// the digest — this is the display/logging form; use [`Self::pull_ref`]
    /// for the string handed to a container runtime.
    pub fn docker_ref(&self) -> String {
        format!("{}/{}:{}@{}", self.registry, self.repository, self.tag, self.digest)
    }

    /// True when this reference carries a real content-addressed digest, i.e.
    /// its digest is not the all-zeros [`Self::UNPINNED_DIGEST`] sentinel.
    pub fn is_pinned(&self) -> bool {
        self.digest != Self::UNPINNED_DIGEST
    }

    /// The reference string to hand a container runtime for pull/resolve.
    ///
    /// - **Pinned** (real digest): `{registry}/{repository}:{tag}@{digest}` —
    ///   content-addressed, the reproducible path.
    /// - **Unpinned** (all-zeros [`Self::UNPINNED_DIGEST`]): `{registry}/{repository}:{tag}`
    ///   — tag-only. No registry or local store holds an image under the
    ///   sentinel digest, so `…@sha256:0000…` can never resolve; a
    ///   tag-pulled or locally-built image is keyed by `registry/repo:tag`.
    ///   This is the tag-fallback path that lets a not-yet-published catalog
    ///   image (e.g. a from-source build-worker image) still pull by tag.
    pub fn pull_ref(&self) -> String {
        if self.is_pinned() {
            format!("{}/{}:{}@{}", self.registry, self.repository, self.tag, self.digest)
        } else {
            format!("{}/{}:{}", self.registry, self.repository, self.tag)
        }
    }
}

// ── WorkloadRuntime trait ─────────────────────────────────────────────────────

/// Shared interface for deploying and managing `WorkloadSpec` containers.
///
/// This is the keystone abstraction (R256-F10) that makes sim and cloud
/// literally interchangeable at the container level:
///
/// - **Camp/sim tier**: `LocalDockerRuntime` in `cloud` implements this trait
///   via the docker CLI pointed at OrbStack (or any Docker-compatible socket).
///   No mesh — containers communicate over OrbStack's bridge network.
///
/// - **Yubaba/cloud-HA tier**: `yubaba::runtime::ContainerRuntime` (gRPC to
///   containerd) will implement this trait. Mesh assignment is a separate
///   orchestration step on top (handled by yubaba's raft layer), not part
///   of the shared deploy/supervise interface.
///
/// Callers that type against `WorkloadRuntime` automatically work with both
/// backends. Reconcilers in `cloud` use it today; yubaba wires its own impl
/// when R276 Tier-3 lands.
#[async_trait::async_trait]
pub trait WorkloadRuntime: Send + Sync {
    /// Deploy a workload described by `spec`. Pulls the image if needed,
    /// creates and starts the container, and returns an opaque workload ID
    /// (typically the container name derived from `spec.name`).
    ///
    /// Idempotent: re-deploying a running workload replaces it cleanly.
    async fn deploy_workload(&self, spec: &WorkloadSpec) -> anyhow::Result<String>;

    /// Tear down a deployed workload — stop the process and remove all
    /// associated state. No-op when the workload is already gone.
    async fn teardown_workload(&self, name: &str) -> anyhow::Result<()>;

    /// Returns `true` when the named workload is currently running (i.e.
    /// the container process is alive and has not exited).
    async fn is_running(&self, name: &str) -> anyhow::Result<bool>;

    /// Probe the runtime backend. Returns `true` when the backend socket is
    /// reachable and healthy (e.g. docker daemon up, containerd gRPC up).
    /// Used by health endpoints and startup checks.
    async fn runtime_health(&self) -> anyhow::Result<bool>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── R603-T5 durable forge produced convention ──────────────────────────────

    #[test]
    fn forge_produced_ident_parse() {
        assert_eq!(forge_produced::forge_id_from_ident("forge.abc123"), Some("abc123"));
        assert_eq!(forge_produced::forge_id_from_ident("svc.web"), None);
        assert_eq!(forge_produced::forge_id_from_ident("abc123"), None);
    }

    #[test]
    fn forge_produced_host_path_translates_under_convention_dir() {
        let hp = forge_produced::host_path(
            "fid",
            std::path::Path::new("/yah/produced/librusty_v8.tar.gz"),
        )
        .expect("path under the convention dir translates");
        assert_eq!(
            hp,
            PathBuf::from("/var/lib/yah/qed/produced/fid/librusty_v8.tar.gz")
        );
    }

    #[test]
    fn forge_produced_host_path_rejects_paths_outside_convention_dir() {
        assert_eq!(
            forge_produced::host_path("fid", std::path::Path::new("/tmp/x.tar.gz")),
            None,
            "a path outside /yah/produced has no durable host mapping"
        );
    }

    #[test]
    fn forge_produced_host_path_rejects_traversal() {
        // A `..` component must never let a read escape the per-forge dir.
        assert_eq!(
            forge_produced::host_path(
                "fid",
                std::path::Path::new("/yah/produced/../../etc/passwd")
            ),
            None,
            "traversal out of the per-forge dir must be refused"
        );
    }

    #[test]
    fn forge_produced_durable_mount_shape() {
        let m = forge_produced::durable_mount("fid");
        assert_eq!(m.target, PathBuf::from("/yah/produced"));
        assert!(!m.read_only, "the build must be able to write to it");
        assert_eq!(
            m.source,
            VolumeSource::Bind {
                host_path: PathBuf::from("/var/lib/yah/qed/produced/fid"),
            }
        );
    }

    const HASH_64: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    #[test]
    fn blake_hash_accepts_64_hex() {
        let h: BlakeHash = toml::from_str(&format!("x = \"{HASH_64}\""))
            .map(|t: toml::Table| t["x"].as_str().unwrap().to_owned())
            .map(|s| serde_json::from_value(serde_json::Value::String(s)).unwrap())
            .unwrap();
        assert_eq!(h.0, HASH_64);
    }

    #[test]
    fn blake_hash_rejects_wrong_length() {
        let short = "abcdef";
        let res: Result<BlakeHash, _> =
            serde_json::from_value(serde_json::Value::String(short.into()));
        assert!(res.is_err());
    }

    #[test]
    fn blake_hash_rejects_non_hex() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let res: Result<BlakeHash, _> =
            serde_json::from_value(serde_json::Value::String(bad.into()));
        assert!(res.is_err());
    }

    fn image_ref(digest: &str) -> ImageRef {
        ImageRef {
            registry: "ghcr.io".into(),
            repository: "yah-ai/rusty-v8-musl-builder".into(),
            tag: "latest".into(),
            digest: digest.into(),
        }
    }

    #[test]
    fn is_pinned_distinguishes_real_digest_from_sentinel() {
        assert!(!image_ref(ImageRef::UNPINNED_DIGEST).is_pinned());
        assert!(!image_ref(&testing::test_digest()).is_pinned());
        assert!(image_ref("sha256:deadbeef").is_pinned());
    }

    #[test]
    fn pull_ref_pinned_carries_tag_and_digest() {
        assert_eq!(
            image_ref("sha256:deadbeef").pull_ref(),
            "ghcr.io/yah-ai/rusty-v8-musl-builder:latest@sha256:deadbeef",
        );
    }

    #[test]
    fn pull_ref_unpinned_falls_back_to_tag_only() {
        // An unpinned catalog image (all-zeros sentinel) resolves by tag —
        // no store holds `…@sha256:0000…`, so the tag is the only usable key.
        assert_eq!(
            image_ref(ImageRef::UNPINNED_DIGEST).pull_ref(),
            "ghcr.io/yah-ai/rusty-v8-musl-builder:latest",
        );
    }

    #[test]
    fn test_digest_alias_is_the_unpinned_sentinel() {
        assert_eq!(testing::TEST_DIGEST, ImageRef::UNPINNED_DIGEST);
    }

    #[test]
    fn static_asset_workload_round_trips() {
        let src = format!(
            r#"
schema_version = "V1"

[[asset]]
filename = "whisper/distil-large-v3-q5_1.bin"
source   = "sources/distil-large-v3-q5_1.bin"
blake3   = "{HASH_64}"

[[asset]]
filename = "whisper/distil-large-v3-q4_0.bin"
source   = "sources/distil-large-v3-q4_0.bin"
blake3   = "{HASH_64}"

[aliases]
"whisper-default" = "whisper/distil-large-v3-q5_1.bin"
"#
        );
        let w: StaticAssetWorkload = toml::from_str(&src).expect("parse");
        assert_eq!(w.assets.len(), 2);
        assert_eq!(w.assets[0].filename, "whisper/distil-large-v3-q5_1.bin");
        assert_eq!(w.assets[0].blake3.0, HASH_64);
        assert_eq!(w.aliases["whisper-default"], "whisper/distil-large-v3-q5_1.bin");

        let back = toml::to_string(&w).expect("serialize");
        let w2: StaticAssetWorkload = toml::from_str(&back).expect("re-parse");
        assert_eq!(w, w2);
    }

    #[test]
    fn license_round_trip_each_variant() {
        // Wire format is whatever serde's `rename_all = "kebab-case"` emits.
        // heck's kebab-case keeps letter→digit attached but splits digit→uppercase,
        // so `Apache2 → "apache2"` and `Bsd2Clause → "bsd2-clause"`.
        for (variant, on_wire) in [
            (License::Mit, "mit"),
            (License::Apache2, "apache2"),
            (License::Bsd2Clause, "bsd2-clause"),
            (License::Bsd3Clause, "bsd3-clause"),
            (License::Isc, "isc"),
        ] {
            let ser = serde_json::to_value(variant).expect("serialize");
            assert_eq!(ser, serde_json::Value::String(on_wire.into()));
            let back: License = serde_json::from_value(ser).expect("deserialize");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn license_rejects_non_permissive_variants() {
        for unknown in ["GPL-3.0", "AGPL", "lgpl-2.1", "unknown", "MIT"] {
            let res: Result<License, _> =
                serde_json::from_value(serde_json::Value::String(unknown.into()));
            assert!(res.is_err(), "expected rejection for {unknown:?}");
        }
    }

    #[test]
    fn fetch_source_round_trips() {
        let src = format!(
            r#"
url     = "https://example.invalid/upstream.bin"
blake3  = "{HASH_64}"
license = "mit"
"#
        );
        let fs: FetchSource = toml::from_str(&src).expect("parse");
        assert_eq!(fs.url, "https://example.invalid/upstream.bin");
        assert_eq!(fs.blake3.0, HASH_64);
        assert_eq!(fs.license, License::Mit);

        let back = toml::to_string(&fs).expect("serialize");
        let fs2: FetchSource = toml::from_str(&back).expect("re-parse");
        assert_eq!(fs, fs2);
    }

    #[test]
    fn fetch_source_rejects_unknown_license() {
        let src = format!(
            r#"
url     = "https://example.invalid/upstream.bin"
blake3  = "{HASH_64}"
license = "GPL-3.0"
"#
        );
        let res: Result<FetchSource, _> = toml::from_str(&src);
        assert!(res.is_err(), "expected non-permissive license to reject");
    }

    #[test]
    fn asset_entry_derive_mode_round_trips() {
        let src = format!(
            r#"
schema_version = "V1"

[[asset]]
filename = "whisper/distil-large-v3-q5_1.bin"
blake3   = "{HASH_64}"

[asset.derive.fetch]
url     = "https://example.invalid/ggml-distil-large-v3.bin"
blake3  = "{HASH_64}"
license = "mit"

[asset.derive.transform]
recipe = "whisper-quantize"
params = {{ quant = "q5_1" }}
"#
        );
        let w: StaticAssetWorkload = toml::from_str(&src).expect("parse");
        assert_eq!(w.assets.len(), 1);
        let entry = &w.assets[0];
        assert!(entry.source.is_none());
        let derive = entry.derive.as_ref().expect("derive present");
        assert_eq!(derive.fetch.url, "https://example.invalid/ggml-distil-large-v3.bin");
        assert_eq!(derive.fetch.license, License::Mit);
        let transform = derive.transform.as_ref().expect("transform present");
        assert_eq!(transform.recipe, "whisper-quantize");
        assert_eq!(transform.params.get("quant").map(String::as_str), Some("q5_1"));

        let back = toml::to_string(&w).expect("serialize");
        let w2: StaticAssetWorkload = toml::from_str(&back).expect("re-parse");
        assert_eq!(w, w2);
    }

    #[test]
    fn legacy_source_only_asset_serializes_without_derive_field() {
        // Verify the skip_serializing_if guards keep legacy TOMLs round-tripping
        // without ever emitting an empty `derive = ...` line.
        let src = format!(
            r#"
schema_version = "V1"

[[asset]]
filename = "operator-curated.bin"
source   = "sources/operator-curated.bin"
blake3   = "{HASH_64}"
"#
        );
        let w: StaticAssetWorkload = toml::from_str(&src).expect("parse");
        let back = toml::to_string(&w).expect("serialize");
        assert!(!back.contains("derive"), "serialized output leaked a derive field: {back}");
        let w2: StaticAssetWorkload = toml::from_str(&back).expect("re-parse");
        assert_eq!(w, w2);
    }

    /// W212/R518: the `[asset.derive.lock]` block round-trips through TOML, and
    /// is omitted from output when absent (so non-derive / unlocked assets stay
    /// clean).
    #[test]
    fn derive_lock_round_trips_through_toml() {
        let toml = r#"
url     = "https://example.invalid/config.json"
blake3  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
license = "mit"
"#;
        let fetch: FetchSource = ::toml::from_str(toml).unwrap();
        let derive = AssetDerive {
            fetch,
            transform: Some(TransformSpec {
                recipe: "whisper-bundle-tar".into(),
                params: BTreeMap::new(),
            }),
            lock: Some(DeriveLock {
                input_hash: "1111111111111111111111111111111111111111111111111111111111111111".into(),
                output_blake3: "2222222222222222222222222222222222222222222222222222222222222222".into(),
            }),
        };
        let s = ::toml::to_string(&derive).unwrap();
        assert!(s.contains("[lock]"), "lock serialized: {s}");
        let back: AssetDerive = ::toml::from_str(&s).unwrap();
        assert_eq!(derive, back);

        // Absent lock → no `[lock]` table in the output.
        let unlocked = AssetDerive { lock: None, ..derive };
        let s2 = ::toml::to_string(&unlocked).unwrap();
        assert!(!s2.contains("[lock]"), "unlocked must omit lock: {s2}");
    }

    #[test]
    fn shape_static_asset_rejects_both_source_and_derive() {
        use crate::validate::{shape_static_asset, FieldPath, ShapeError};

        let entry = AssetEntry {
            filename: "ambiguous.bin".into(),
            source: Some("sources/ambiguous.bin".into()),
            derive: Some(AssetDerive {
                fetch: FetchSource {
                    url: "https://example.invalid/x".into(),
                    blake3: BlakeHash(HASH_64.into()),
                    license: License::Mit,
                },
                transform: None,
                lock: None,
            }),
            blake3: BlakeHash(HASH_64.into()),
        };
        let w = StaticAssetWorkload {
            schema_version: SchemaVersion::V1,
            assets: vec![entry],
            aliases: BTreeMap::new(),
        };
        let err = shape_static_asset(&w).expect_err("XOR violated");
        match err {
            ShapeError::Field { path: FieldPath::Asset(0, "source"), .. } => {}
            other => panic!("expected Asset(0, \"source\") shape error, got {other:?}"),
        }
    }

    #[test]
    fn shape_static_asset_rejects_neither_source_nor_derive() {
        use crate::validate::{shape_static_asset, FieldPath, ShapeError};

        let entry = AssetEntry {
            filename: "empty.bin".into(),
            source: None,
            derive: None,
            blake3: BlakeHash(HASH_64.into()),
        };
        let w = StaticAssetWorkload {
            schema_version: SchemaVersion::V1,
            assets: vec![entry],
            aliases: BTreeMap::new(),
        };
        let err = shape_static_asset(&w).expect_err("XOR violated");
        match err {
            ShapeError::Field { path: FieldPath::Asset(0, "source"), .. } => {}
            other => panic!("expected Asset(0, \"source\") shape error, got {other:?}"),
        }
    }

    #[test]
    fn shape_static_asset_accepts_either_mode() {
        use crate::validate::shape_static_asset;

        let legacy = AssetEntry {
            filename: "a.bin".into(),
            source: Some("sources/a.bin".into()),
            derive: None,
            blake3: BlakeHash(HASH_64.into()),
        };
        let derived = AssetEntry {
            filename: "b.bin".into(),
            source: None,
            derive: Some(AssetDerive {
                fetch: FetchSource {
                    url: "https://example.invalid/b".into(),
                    blake3: BlakeHash(HASH_64.into()),
                    license: License::Apache2,
                },
                transform: None,
                lock: None,
            }),
            blake3: BlakeHash(HASH_64.into()),
        };
        let w = StaticAssetWorkload {
            schema_version: SchemaVersion::V1,
            assets: vec![legacy, derived],
            aliases: BTreeMap::new(),
        };
        shape_static_asset(&w).expect("both modes accepted");
    }

    #[test]
    fn image_ref_string_form_rejects_bare_tag() {
        let res: Result<ImageRef, _> =
            serde_json::from_value(serde_json::Value::String("node:20".into()));
        let err = res.expect_err("bare-tag must reject");
        let msg = format!("{err}");
        assert!(msg.contains("digest"), "error should mention digest: {msg}");
    }

    #[test]
    fn image_ref_string_form_accepts_digest_pinned() {
        let pinned = format!("node:20@sha256:{HASH_64}");
        let img: ImageRef =
            serde_json::from_value(serde_json::Value::String(pinned.clone())).expect("parse");
        assert_eq!(img.registry, "docker.io");
        assert_eq!(img.repository, "library/node");
        assert_eq!(img.tag, "20");
        assert_eq!(img.digest, format!("sha256:{HASH_64}"));
    }

    #[test]
    fn image_ref_string_form_accepts_ghcr_with_pin() {
        let pinned = format!("ghcr.io/foo/bar:v1.7.4@sha256:{HASH_64}");
        let img: ImageRef =
            serde_json::from_value(serde_json::Value::String(pinned)).expect("parse");
        assert_eq!(img.registry, "ghcr.io");
        assert_eq!(img.repository, "foo/bar");
        assert_eq!(img.tag, "v1.7.4");
        assert!(img.digest.starts_with("sha256:"));
    }

    #[test]
    fn image_ref_string_form_rejects_non_sha256_digest() {
        for bad in [
            "node:20@md5:abcdef",
            "node:20@sha1:abcdef",
            "node:20@sha256:",
            "node:20@sha256:zzznothex",
        ] {
            let res: Result<ImageRef, _> =
                serde_json::from_value(serde_json::Value::String(bad.into()));
            assert!(res.is_err(), "expected reject for {bad:?}");
        }
    }

    #[test]
    fn image_ref_struct_form_rejects_missing_digest() {
        // Digest is now structurally required (R438-T3). Struct-form payloads
        // without `digest` must fail at serde-deserialize.
        let v = serde_json::json!({
            "registry": "ghcr.io",
            "repository": "noisetable/api",
            "tag": "v1.4.2",
        });
        let res: Result<ImageRef, _> = serde_json::from_value(v);
        assert!(res.is_err(), "missing digest must reject");
    }

    #[test]
    fn image_ref_struct_form_round_trips_through_toml() {
        let img = ImageRef {
            registry: "ghcr.io".into(),
            repository: "ggerganov/whisper.cpp".into(),
            tag: "v1.7.4".into(),
            digest: format!("sha256:{HASH_64}"),
        };
        let toml_doc = toml::to_string(&img).expect("serialize");
        let back: ImageRef = toml::from_str(&toml_doc).expect("re-parse");
        assert_eq!(img, back);
    }

    #[test]
    fn workload_envelope_dispatches_static_asset() {
        // Externally-tagged: the `static-asset` variant is a wrapping table
        // (R590-B3 flipped the Workload graph off internal `kind =` tags so the
        // whole spec is postcard-decodable over the kamaji UDS).
        let src = format!(
            r#"
[static-asset]
schema_version = "V1"

[[static-asset.asset]]
filename = "foo/bar.bin"
source   = "sources/bar.bin"
blake3   = "{HASH_64}"
"#
        );
        let w: Workload = toml::from_str(&src).expect("parse");
        assert!(matches!(w, Workload::StaticAsset(_)));
    }

    // ── R572-F1: lifecycle archetype discriminator ─────────────────────────

    fn archetype_test_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec::for_forge(
            name,
            ImageRef {
                registry: "ghcr.io".into(),
                repository: "yah/test".into(),
                tag: "latest".into(),
                digest: testing::test_digest(),
            },
            TierTag("infra".into()),
            vec![],
        )
    }

    #[test]
    fn explicit_archetype_round_trips_through_json_and_wins_over_inference() {
        for archetype in [
            LifecycleArchetype::Server,
            LifecycleArchetype::Appliance,
            LifecycleArchetype::Job,
        ] {
            let mut spec = archetype_test_spec("explicit");
            // Volumes present + restart_policy Always would infer Appliance
            // (see effective_archetype_infers_* below) — deliberately
            // mismatched against every archetype under test so the
            // assertion actually proves the explicit field wins, not that
            // it happens to agree with inference.
            spec.volumes = vec![VolumeMount {
                source: VolumeSource::Named { name: "data".into() },
                target: PathBuf::from("/data"),
                read_only: false,
            }];
            spec.restart_policy = RestartPolicy::Always;
            spec.archetype = Some(archetype);

            let json = serde_json::to_string(&spec).expect("serialize");
            assert!(
                json.contains("\"archetype\""),
                "explicit archetype must be present on the wire"
            );
            let back: WorkloadSpec = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(spec, back, "spec did not survive JSON round-trip");
            assert_eq!(back.archetype, Some(archetype));
            assert_eq!(
                back.effective_archetype(),
                archetype,
                "explicit archetype must win over the volumes/restart_policy inference"
            );
        }
    }

    #[test]
    fn archetype_serializes_as_null_when_none() {
        let mut spec = archetype_test_spec("omitted");
        spec.archetype = None;
        let json = serde_json::to_value(&spec).expect("to_value");
        // Postcard-native (R590-B3): no `skip_serializing_if` anywhere on the
        // graph, so every field is always on the wire — a None Option is an
        // explicit `null`, not an absent key. The binary UDS wire is positional
        // and requires the slot to be present.
        assert_eq!(json.get("archetype"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn spec_without_archetype_field_deserializes_to_none() {
        // Simulates an on-disk spec written before R572-F1: no `archetype`
        // key at all. Omitting the key must still parse to None (the additive-
        // default contract) even though we now always *emit* the field.
        let mut spec = archetype_test_spec("pre-existing");
        spec.archetype = None;
        let mut json = serde_json::to_value(&spec).expect("to_value");
        json.as_object_mut().unwrap().remove("archetype");
        let back: WorkloadSpec = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back.archetype, None);
    }

    #[test]
    fn effective_archetype_infers_appliance_from_volumes_when_field_absent() {
        // Pre-R572 behavior: a workload with a volume was understood (by
        // convention, never a type) to be stateful/pinned. Confirm that
        // meaning is preserved bit-for-bit through effective_archetype().
        let mut spec = archetype_test_spec("appliance-inferred");
        spec.volumes = vec![VolumeMount {
            source: VolumeSource::Named { name: "pgdata".into() },
            target: PathBuf::from("/var/lib/postgresql/data"),
            read_only: false,
        }];
        spec.restart_policy = RestartPolicy::Always;
        spec.archetype = None;
        assert_eq!(spec.effective_archetype(), LifecycleArchetype::Appliance);
    }

    #[test]
    fn effective_archetype_infers_job_from_restart_never_when_field_absent() {
        // Pre-R572 behavior: RestartPolicy::Never + no volumes is the forge
        // run-once convention (see RestartPolicy::Never's own doc comment) —
        // structurally a job. WorkloadSpec::for_forge already produces
        // exactly this shape; isolate the pure-inference path by clearing
        // the explicit archetype for_forge now sets.
        let mut spec = archetype_test_spec("job-inferred");
        assert!(spec.volumes.is_empty());
        assert!(matches!(spec.restart_policy, RestartPolicy::Never));
        spec.archetype = None;
        assert_eq!(spec.effective_archetype(), LifecycleArchetype::Job);
    }

    #[test]
    fn effective_archetype_defaults_to_server_as_the_common_case_when_field_absent() {
        // Pre-R572 behavior: no volumes + a restartable policy (the common
        // stateless-web-server shape) inferred as movable/fungible.
        let mut spec = archetype_test_spec("server-inferred");
        spec.restart_policy = RestartPolicy::Always;
        spec.archetype = None;
        assert_eq!(spec.effective_archetype(), LifecycleArchetype::Server);
    }

    // ── R594-F2: public-ingress appliance (container-shaped, not a new
    // Workload variant — see Workload::Container's doc comment) ───────────

    #[test]
    fn ingress_marked_spec_is_appliance_and_carries_public_ip_placement_requirement() {
        let mut spec = archetype_test_spec("public-ingress");
        spec.archetype = Some(LifecycleArchetype::Appliance);
        spec.annotations.insert(
            REQUIRES_TAINT_ANNOTATION.to_string(),
            PUBLIC_IP_TAINT.to_string(),
        );

        assert_eq!(
            spec.effective_archetype(),
            LifecycleArchetype::Appliance,
            "ingress must be pinned-per-node/non-drainable, the R572 appliance sense"
        );
        assert_eq!(
            spec.requires_taint(),
            Some(PUBLIC_IP_TAINT),
            "ingress must declare it can only land on a public-ip-tainted node"
        );

        // No taint exists to match against yet (R572-F3) and nothing
        // enforces placement yet (R572-F5) — confirm this ticket stays
        // declarative-only by checking a spec with no requirement stays
        // unaffected.
        let unrelated = archetype_test_spec("unrelated");
        assert_eq!(unrelated.requires_taint(), None);
    }

    #[test]
    fn ingress_marked_spec_round_trips_through_json_as_a_container_workload() {
        // Mirrors the on-disk envelope: the externally-tagged `container`
        // variant wrapping the WorkloadSpec, exactly like every other
        // container-shaped workload. No new Workload variant, no new
        // discriminator.
        let mut inner = archetype_test_spec("public-ingress");
        inner.archetype = Some(LifecycleArchetype::Appliance);
        inner.annotations.insert(
            REQUIRES_TAINT_ANNOTATION.to_string(),
            PUBLIC_IP_TAINT.to_string(),
        );
        let workload = Workload::Container(inner.clone());

        let json = serde_json::to_string(&workload).expect("serialize");
        assert!(json.contains("\"container\""));
        assert!(json.contains(REQUIRES_TAINT_ANNOTATION));
        assert!(json.contains(PUBLIC_IP_TAINT));

        let back: Workload = serde_json::from_str(&json).expect("deserialize");
        match back {
            Workload::Container(spec) => {
                assert_eq!(spec, inner);
                assert_eq!(spec.effective_archetype(), LifecycleArchetype::Appliance);
                assert_eq!(spec.requires_taint(), Some(PUBLIC_IP_TAINT));
            }
            other => panic!("expected Workload::Container, got {other:?}"),
        }
    }
}
