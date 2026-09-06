use std::collections::HashMap;
use std::path::Path;

use workload_spec::validate::{self, FieldPath};
use workload_spec::WorkloadSpec;

fn load(path: &Path) -> WorkloadSpec {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

/// Map from fixture file stem to the expected failing field path.
fn expected_errors() -> HashMap<&'static str, FieldPath> {
    let mut m = HashMap::new();
    m.insert("name_empty", FieldPath::Name);
    m.insert("name_too_long", FieldPath::Name);
    m.insert("name_invalid_chars", FieldPath::Name);
    m.insert("mesh_identity_starts_dash", FieldPath::MeshIdentity);
    m.insert("tailscale_tag_no_prefix", FieldPath::TailscaleTag);
    m.insert("replicas_too_high", FieldPath::Replicas);
    m.insert("image_tag_empty", FieldPath::ImageTag);
    m.insert("bind_volume_non_infra", FieldPath::Volume(0, "source"));
    m.insert("public_port_not_in_mesh", FieldPath::ExposeMeshPort(9000));
    m.insert("secret_target_relative_path", FieldPath::Secret(0, "target.path"));
    m.insert("secret_env_var_lowercase", FieldPath::Secret(0, "target.name"));
    m
}

#[test]
fn bad_fixtures_produce_expected_shape_error() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bad");
    let expected = expected_errors();
    let mut checked = 0u32;

    for entry in std::fs::read_dir(&fixtures).expect("read fixtures/bad") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("stem")
            .to_owned();

        let spec = load(&path);
        let result = validate::shape(&spec);

        assert!(
            result.is_err(),
            "expected ShapeError for fixture {stem} but got Ok({:?})",
            result.as_ref().unwrap()
        );

        if let Some(expected_path) = expected.get(stem.as_str()) {
            let err = result.unwrap_err();
            let validate::ShapeError::Field { path: actual_path, .. } = &err;
            assert_eq!(
                actual_path, expected_path,
                "fixture {stem}: wrong field path — got {actual_path:?}, expected {expected_path:?}"
            );
        } else {
            panic!("fixture {stem} has no entry in expected_errors(); add one");
        }

        checked += 1;
    }

    assert!(checked > 0, "no .json files found in fixtures/bad — check the path");
    assert_eq!(
        checked as usize,
        expected.len(),
        "expected_errors() has {} entries but found {} .json fixtures",
        expected.len(),
        checked
    );
}

#[test]
fn valid_fixtures_pass_shape() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/valid");
    let mut checked = 0u32;

    for entry in std::fs::read_dir(&fixtures).expect("read fixtures/valid") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("stem")
            .to_owned();

        let spec = load(&path);
        let result = validate::shape(&spec);

        assert!(
            result.is_ok(),
            "expected shape to pass for fixture {stem} but got Err({:?})",
            result.unwrap_err()
        );
        checked += 1;
    }

    assert!(checked > 0, "no .json files found in fixtures/valid — check the path");
}

#[test]
fn restart_never_without_forge_annotation_warns() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/valid/warn_restart_never.json");
    let spec = load(&path);
    let warnings = validate::shape(&spec).expect("should pass shape");
    assert!(
        warnings
            .iter()
            .any(|w| w.path == FieldPath::RestartPolicy),
        "expected RestartPolicy warning for Never without yah.forge=true; got {:?}",
        warnings
    );
}

#[test]
fn restart_never_with_forge_annotation_no_warning() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/valid/warn_restart_never.json");
    let mut spec = load(&path);
    spec.annotations.insert("yah.forge".into(), "true".into());
    let warnings = validate::shape(&spec).expect("should pass shape");
    assert!(
        !warnings.iter().any(|w| w.path == FieldPath::RestartPolicy),
        "expected no RestartPolicy warning when yah.forge=true is set; got {:?}",
        warnings
    );
}

#[test]
fn healthcheck_short_delay_warns() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/valid/warn_healthcheck_delay.json");
    let spec = load(&path);
    let warnings = validate::shape(&spec).expect("should pass shape");
    assert!(
        warnings
            .iter()
            .any(|w| w.path == FieldPath::Healthcheck("initial_delay")),
        "expected Healthcheck(initial_delay) warning; got {:?}",
        warnings
    );
}

#[test]
fn unknown_tier_warns() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/valid/warn_unknown_tier.json");
    let spec = load(&path);
    let warnings = validate::shape(&spec).expect("should pass shape");
    assert!(
        warnings.iter().any(|w| w.path == FieldPath::Tier),
        "expected Tier warning for unknown tier; got {:?}",
        warnings
    );
}

// ── R850-P4: durability declaration ─────────────────────────────────────────

/// Mutate the minimal valid fixture into the shape the whole survivability
/// question is about: an appliance whose only copy of its state is a
/// yubaba-managed named volume.
fn stateful_appliance() -> WorkloadSpec {
    let mut spec = load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/valid/minimal.json"),
    );
    spec.archetype = Some(workload_spec::LifecycleArchetype::Appliance);
    spec.volumes = vec![workload_spec::VolumeMount {
        source: workload_spec::VolumeSource::Named {
            name: "accounts".into(),
        },
        target: "/var/lib/app".into(),
        read_only: false,
    }];
    spec
}

/// The soft half. Every spec in the tree predates the annotation, so an
/// undeclared tier cannot be a hard failure — but a stateful appliance with no
/// second copy of its bytes has to say so at the point the spec is loaded, not
/// only when someone thinks to run the analyzer.
#[test]
fn a_stateful_appliance_with_no_durability_tier_warns() {
    let warnings = validate::shape(&stateful_appliance()).expect("undeclared must stay soft");
    assert!(
        warnings
            .iter()
            .any(|w| w.path == FieldPath::Annotation("yah.durability.tier")),
        "expected a durability warning; got {warnings:?}"
    );
}

#[test]
fn declaring_the_tier_silences_the_warning_even_when_it_is_none() {
    let mut spec = stateful_appliance();
    spec.annotations
        .insert("yah.durability.tier".into(), "none".into());
    let warnings = validate::shape(&spec).expect("tier = none is valid");
    assert!(
        !warnings
            .iter()
            .any(|w| w.path == FieldPath::Annotation("yah.durability.tier")),
        "a deliberate `none` is an answer, not a finding; got {warnings:?}"
    );
}

/// The hard half, and the asymmetry's whole point: a *malformed* declaration
/// must fail the load rather than degrade into the "undeclared" warning above,
/// because `tier = "streem"` would otherwise mean "no backups" silently.
#[test]
fn a_malformed_durability_tier_fails_shape_validation() {
    let mut spec = stateful_appliance();
    spec.annotations
        .insert("yah.durability.tier".into(), "streem".into());
    let err = validate::shape(&spec).expect_err("a misspelled tier must not load");
    let validate::ShapeError::Field { path, reason } = &err;
    assert_eq!(*path, FieldPath::Annotation("yah.durability.tier"));
    assert!(reason.contains("streem"), "{reason}");
}

/// A stateless workload is not nagged — the warning is about state with no
/// second copy, and firing it on every server in the fleet would train the
/// operator to ignore it.
#[test]
fn a_stateless_workload_is_not_asked_to_declare_durability() {
    let spec = load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/valid/minimal.json"),
    );
    let warnings = validate::shape(&spec).expect("minimal fixture is valid");
    assert!(
        !warnings
            .iter()
            .any(|w| w.path == FieldPath::Annotation("yah.durability.tier")),
        "got {warnings:?}"
    );
}

// ── R850-F1: subjects are relative to exactly one named volume ──────────────

/// Give `spec` a complete bytes-shipping declaration over `subjects`.
fn declare_stream(spec: &mut WorkloadSpec, subjects: &str) {
    for (k, v) in [
        ("yah.durability.tier", "stream"),
        ("yah.durability.engine", "turso"),
        ("yah.durability.store", "s3://yah-backups/acct"),
        ("yah.durability.subjects", subjects),
    ] {
        spec.annotations.insert(k.into(), v.into());
    }
}

#[test]
fn a_complete_stream_declaration_over_one_named_volume_is_valid_and_unwarned() {
    let mut spec = stateful_appliance();
    declare_stream(&mut spec, "accounts.db,sessions.db");
    let warnings = validate::shape(&spec).expect("a complete declaration must load");
    assert!(
        !warnings
            .iter()
            .any(|w| matches!(w.path, FieldPath::Annotation(k) if k.starts_with("yah.durability"))),
        "got {warnings:?}"
    );
}

/// Subjects are volume-relative, so zero or two named volumes leaves the
/// hydrate helper with no host directory to resolve them against — or a choice
/// between two, where a wrong pick restores one database over another.
#[test]
fn a_stream_tier_needs_exactly_one_named_volume_to_be_relative_to() {
    let mut none = stateful_appliance();
    none.volumes.clear();
    declare_stream(&mut none, "accounts.db");
    let validate::ShapeError::Field { path, reason } =
        &validate::shape(&none).expect_err("no named volume must not load");
    assert_eq!(*path, FieldPath::Annotation("yah.durability.subjects"));
    assert!(reason.contains("0 named volumes"), "{reason}");

    let mut two = stateful_appliance();
    two.volumes.push(workload_spec::VolumeMount {
        source: workload_spec::VolumeSource::Named {
            name: "sessions".into(),
        },
        target: "/var/lib/sessions".into(),
        read_only: false,
    });
    declare_stream(&mut two, "accounts.db");
    let validate::ShapeError::Field { path, reason } =
        &validate::shape(&two).expect_err("two named volumes must not load");
    assert_eq!(*path, FieldPath::Annotation("yah.durability.subjects"));
    // The refusal names the candidates — an operator fixing this needs to know
    // which two it could not choose between.
    assert!(reason.contains("accounts, sessions"), "{reason}");
}

/// The rule is scoped to tiers that ship bytes. `tier = "none"` has no
/// subjects to place, so a deliberately-ephemeral workload with two volumes (or
/// none) must still load.
#[test]
fn tier_none_is_not_subject_to_the_one_volume_rule() {
    let mut spec = stateful_appliance();
    spec.volumes.clear();
    spec.annotations
        .insert("yah.durability.tier".into(), "none".into());
    validate::shape(&spec).expect("tier = none places no subjects");
}
