use workload_spec::{
    testing::test_digest, validate, ImageRef, RestartPolicy, TierTag, WorkloadSpec,
};

fn forge_image() -> ImageRef {
    ImageRef {
        registry: "docker.io".into(),
        repository: "library/alpine".into(),
        tag: "3.19".into(),
        digest: test_digest(),
    }
}

#[test]
fn never_round_trip() {
    let cases = vec![
        RestartPolicy::Always,
        RestartPolicy::Never,
        RestartPolicy::OnFailure {
            max_attempts: 3,
            backoff: workload_spec::BackoffPolicy {
                initial_ms: 100,
                max_ms: 5000,
                multiplier: 1.5,
            },
        },
    ];
    for policy in cases {
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: RestartPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, back, "round-trip failed for {json}");
    }
}

#[test]
fn semantic_warns_without_forge_annotation() {
    let spec = WorkloadSpec::for_forge("test-run-1", forge_image(), TierTag("infra".into()), vec![]);
    // for_forge sets yah.forge=true, so no warning
    let warnings = validate::shape(&spec).expect("shape");
    assert!(
        !warnings
            .iter()
            .any(|w| w.path == validate::FieldPath::RestartPolicy),
        "for_forge should suppress the Never warning; got {:?}",
        warnings
    );

    // Remove the annotation — warning should appear
    let mut spec_no_ann = spec.clone();
    spec_no_ann.annotations.remove("yah.forge");
    let warnings = validate::shape(&spec_no_ann).expect("shape");
    assert!(
        warnings
            .iter()
            .any(|w| w.path == validate::FieldPath::RestartPolicy),
        "expected RestartPolicy warning when yah.forge annotation absent; got {:?}",
        warnings
    );
}

#[test]
fn for_forge_sets_conventional_fields() {
    let spec = WorkloadSpec::for_forge(
        "build-42",
        forge_image(),
        TierTag("infra".into()),
        vec![8080],
    );

    assert!(
        matches!(spec.restart_policy, RestartPolicy::Never),
        "for_forge must set restart_policy=Never"
    );
    assert!(spec.expose.public.is_none(), "for_forge must leave expose.public=None");
    assert!(spec.expose.operator.is_none(), "for_forge must leave expose.operator=None");
    assert_eq!(
        spec.expose.mesh.identity.0, "forge.build-42",
        "mesh identity must be forge.<forge_id>"
    );
    assert_eq!(
        spec.annotations.get("yah.forge").map(String::as_str),
        Some("true"),
        "for_forge must set annotations[yah.forge]=true"
    );
    assert_eq!(spec.expose.mesh.numbers(), vec![8080]);
}

/// A forge run's cgroup ceiling is deliberately roomy; its placement request
/// must stay small, or a scheduler reading the ceiling refuses every node
/// smaller than it (the fleet's 8 GiB build-workers, in practice).
#[test]
fn for_forge_memory_request_is_a_floor_not_the_cgroup_ceiling() {
    let spec = WorkloadSpec::for_forge("build-42", forge_image(), TierTag("infra".into()), vec![]);

    assert_eq!(
        spec.resources.memory_mb,
        workload_spec::FORGE_MEMORY_LIMIT_MB
    );
    assert_eq!(
        spec.memory_request_mb(),
        workload_spec::FORGE_MEMORY_REQUEST_MB
    );
    assert!(
        spec.memory_request_mb() < spec.resources.memory_mb,
        "request must be strictly below the ceiling"
    );
    // The concrete regression: an 8 GiB build-worker must be a legal target.
    assert!(
        spec.memory_request_mb() <= 8192,
        "a forge run must fit the fleet's 8 GiB Pi-5 build-workers"
    );
}

/// Absent annotation ⇒ the request is the ceiling, i.e. exactly the pre-split
/// behaviour. Every spec in the tree that never declares a request is admitted
/// on the same number it always was.
#[test]
fn memory_request_falls_back_to_the_limit_when_undeclared() {
    let mut spec = WorkloadSpec::for_forge("b", forge_image(), TierTag("infra".into()), vec![]);
    spec.annotations
        .remove(workload_spec::MEMORY_REQUEST_ANNOTATION);
    assert_eq!(spec.memory_request_mb(), spec.resources.memory_mb);

    // A garbage value falls back too rather than admitting on 0 — an
    // unparseable request must not silently become "fits anywhere".
    spec.annotations.insert(
        workload_spec::MEMORY_REQUEST_ANNOTATION.into(),
        "not-a-number".into(),
    );
    assert_eq!(spec.memory_request_mb(), spec.resources.memory_mb);
}
