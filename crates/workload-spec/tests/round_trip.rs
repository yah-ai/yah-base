use std::collections::HashMap;
use std::path::PathBuf;

use workload_spec::*;

/// Representative spec with every field family populated.
fn full_spec() -> WorkloadSpec {
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: "noisetable-api".into(),
        image: ImageRef {
            registry: "ghcr.io".into(),
            repository: "noisetable/api".into(),
            tag: "v1.4.2".into(),
            digest: "sha256:abc123def456".into(),
        },
        tier: TierTag("private".into()),
        tenant: TenantId("ss".into()),
        namespace: NamespaceId("noisetable".into()),
        replicas: 2,
        command: Some(vec!["./server".into()]),
        entrypoint: Some(vec!["/bin/sh".into(), "-c".into()]),
        workdir: Some(PathBuf::from("/app")),
        user: Some("1000:1000".into()),
        env: vec![
            EnvVar {
                name: "APP_ENV".into(),
                value: EnvValue::Literal { value: "production".into() },
            },
            EnvVar {
                name: "DB_PASSWORD".into(),
                value: EnvValue::FromSecret {
                    secret: "db-creds".into(),
                    key: "password".into(),
                },
            },
            EnvVar {
                name: "DATABASE_URL".into(),
                value: EnvValue::FromMesh {
                    ident: MeshIdent("noisetable-db.pdx".into()),
                    kind: MeshLookup::Url,
                },
            },
        ],
        secrets: vec![
            SecretMount {
                source: SecretRef::LocalFile {
                    path: PathBuf::from("/var/lib/yah/yubaba/secrets/tls.crt"),
                },
                target: SecretTarget::File {
                    path: PathBuf::from("/etc/tls/cert.crt"),
                    mode: 0o400,
                },
            },
            SecretMount {
                source: SecretRef::Cluster { name: "stripe-key".into() },
                target: SecretTarget::EnvVar { name: "STRIPE_SECRET_KEY".into() },
            },
        ],
        volumes: vec![
            VolumeMount {
                source: VolumeSource::Named { name: "api-data".into() },
                target: PathBuf::from("/data"),
                read_only: false,
            },
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/opt/yah/config"),
                },
                target: PathBuf::from("/config"),
                read_only: true,
            },
            VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 128 },
                target: PathBuf::from("/tmp"),
                read_only: false,
            },
        ],
        resources: ResourceLimits {
            memory_mb: 512,
            cpu_millis: 1024,
            ephemeral_storage_mb: 256,
        },
        depends_on: vec![MeshIdent("noisetable-db.pdx".into())],
        healthcheck: Some(Healthcheck {
            probe: HealthProbe::HttpGet {
                path: "/healthz".into(),
                port: 8080,
                expect_status: Some(200),
            },
            interval: Millis::from_secs(10),
            timeout: Millis::from_secs(5),
            initial_delay: Millis::from_secs(30),
            failure_threshold: 3,
        }),
        restart_policy: RestartPolicy::OnFailure {
            max_attempts: 5,
            backoff: BackoffPolicy {
                initial_ms: 500,
                max_ms: 30_000,
                multiplier: 2.0,
            },
        },
        // "Every field family populated" — this spec also has a volume, so
        // Appliance is the archetype an operator would actually pick.
        archetype: Some(LifecycleArchetype::Appliance),
        stop_policy: StopPolicy {
            signal: 15,
            grace_period: Millis::from_secs(30),
        },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent("noisetable-api.pdx".into()),
                ports: vec![8080, 9090],
                allow_from: vec![
                    MeshPeer::Tier(TierTag("private".into())),
                    MeshPeer::Tier(TierTag("tenant".into())),
                ],
            },
            public: Some(PublicExpose {
                hostname: "api.noisetable.io".into(),
                port: 8080,
                tls: PublicTls::CfManaged,
            }),
            operator: Some(OperatorExpose {
                tailscale_tag: "tag:noisetable-ops".into(),
                port: 9090,
            }),
        },
        labels: {
            let mut m = HashMap::new();
            m.insert("org.opencontainers.image.source".into(), "https://github.com/noisetable/api".into());
            m
        },
        annotations: {
            let mut m = HashMap::new();
            m.insert("yah.created-by".into(), "agent:claude".into());
            m
        },
    }
}

#[test]
fn round_trip_full_spec() {
    let original = full_spec();
    let json = serde_json::to_string_pretty(&original).expect("serialize");
    let decoded: WorkloadSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, decoded, "spec did not survive JSON round-trip");
}

/// The exact R590-B3 failure: a `WorkloadSpec` (carrying a nested `ImageRef`)
/// crossing the kamaji UDS, which is postcard — a binary, non-self-describing
/// format. `ImageRef`'s Deserialize used to probe string-or-struct via
/// `#[serde(untagged)]`, which needs `deserialize_any`; postcard returns
/// `WontImplement` for that, so every container deploy 500'd on decode. The
/// original "smoke" only ever exercised JSON, so this stayed latent. Guard the
/// binary path explicitly.
#[test]
fn round_trip_full_spec_through_postcard() {
    let original = full_spec();
    let bytes = postcard::to_stdvec(&original).expect("postcard serialize");
    let decoded: WorkloadSpec =
        postcard::from_bytes(&bytes).expect("postcard deserialize (R590-B3 regression)");
    assert_eq!(original, decoded, "spec did not survive postcard round-trip");
}

/// The real wire payload is `Workload::Container(spec)` inside
/// `WardenToConstable::Deploy`, so round-trip that enum shape through postcard
/// too — this is byte-for-byte what yubaba sends kamaji over the UDS.
#[test]
fn workload_container_round_trips_through_postcard() {
    let original = Workload::Container(full_spec());
    let bytes = postcard::to_stdvec(&original).expect("postcard serialize");
    let decoded: Workload =
        postcard::from_bytes(&bytes).expect("postcard deserialize (R590-B3 regression)");
    assert_eq!(original, decoded, "Workload::Container did not survive postcard");
}

/// The narrowest unit: the untagged Deserialize itself, exercised directly on
/// the binary format so a regression points straight at `ImageRef`.
#[test]
fn image_ref_round_trips_through_postcard() {
    let original = ImageRef {
        registry: "ghcr.io".into(),
        repository: "noisetable/api".into(),
        tag: "v1.4.2".into(),
        digest: "sha256:abc123def456".into(),
    };
    let bytes = postcard::to_stdvec(&original).expect("postcard serialize");
    let decoded: ImageRef =
        postcard::from_bytes(&bytes).expect("postcard deserialize (R590-B3 regression)");
    assert_eq!(original, decoded);
}

#[test]
fn schema_version_serializes_as_v1() {
    let spec = full_spec();
    let json = serde_json::to_value(&spec).expect("to_value");
    assert_eq!(json["schema_version"], "V1");
}

#[test]
fn env_value_variants_round_trip() {
    let cases = vec![
        EnvValue::Literal { value: "hello".into() },
        EnvValue::FromSecret { secret: "my-secret".into(), key: "key".into() },
        EnvValue::FromMesh {
            ident: MeshIdent("svc.cluster".into()),
            kind: MeshLookup::Host,
        },
    ];
    for v in cases {
        let json = serde_json::to_string(&v).expect("serialize");
        let back: EnvValue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, back);
    }
}

#[test]
fn restart_policy_variants_round_trip() {
    let cases = vec![
        RestartPolicy::Always,
        RestartPolicy::Never,
        RestartPolicy::OnFailure {
            max_attempts: 3,
            backoff: BackoffPolicy { initial_ms: 100, max_ms: 5000, multiplier: 1.5 },
        },
    ];
    for p in cases {
        let json = serde_json::to_string(&p).expect("serialize");
        let back: RestartPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
    }
}

#[test]
fn health_probe_variants_round_trip() {
    let cases = vec![
        HealthProbe::HttpGet { path: "/".into(), port: 80, expect_status: None },
        HealthProbe::HttpGet { path: "/ready".into(), port: 8080, expect_status: Some(204) },
        HealthProbe::Exec { argv: vec!["pg_isready".into()] },
        HealthProbe::TcpConnect { port: 5432 },
    ];
    for p in cases {
        let json = serde_json::to_string(&p).expect("serialize");
        let back: HealthProbe = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
    }
}

#[test]
fn minimal_spec_round_trips_through_json_and_postcard() {
    let spec = WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: "minimal".into(),
        image: ImageRef {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
            tag: "3.19".into(),
            digest: workload_spec::testing::test_digest(),
        },
        tier: TierTag("private".into()),
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
        resources: ResourceLimits { memory_mb: 64, cpu_millis: 256, ephemeral_storage_mb: 64 },
        depends_on: vec![],
        healthcheck: None,
        restart_policy: RestartPolicy::Always,
        archetype: None,
        stop_policy: StopPolicy { signal: 15, grace_period: Millis::from_secs(5) },
        expose: ExposeSpec {
            mesh: MeshExpose {
                identity: MeshIdent("minimal.local".into()),
                ports: vec![80],
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: HashMap::new(),
        annotations: HashMap::new(),
    };

    // Postcard-native (R590-B3): no `skip_serializing_if` anywhere, so None /
    // empty fields are always on the wire as explicit null / [] — not absent.
    let json = serde_json::to_value(&spec).expect("to_value");
    assert_eq!(json.get("command"), Some(&serde_json::Value::Null));
    assert_eq!(json.get("healthcheck"), Some(&serde_json::Value::Null));

    // JSON round-trip.
    let text = serde_json::to_string(&spec).expect("serialize");
    let back: WorkloadSpec = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(spec, back);

    // Postcard round-trip — the second half of R590-B3. With
    // `skip_serializing_if`, these None/empty fields were dropped from the
    // positional byte stream, so decode misaligned and died with
    // `DeserializeBadOption`. `full_spec()` hid it by populating every optional;
    // this spec leaves them all empty, which is exactly what `for_forge` (a
    // real forge deploy) produces.
    let bytes = postcard::to_stdvec(&spec).expect("postcard serialize");
    let decoded: WorkloadSpec =
        postcard::from_bytes(&bytes).expect("postcard deserialize (R590-B3 skip-strip regression)");
    assert_eq!(spec, decoded);
}

/// W206 / R558-F1: a spec whose on-disk form predates the tenant/namespace
/// axes (both keys absent) deserializes to the operator singleton, so existing
/// single-tenant clusters keep every isolation primitive a no-op. Explicit
/// non-singleton values survive the round trip unchanged.
#[test]
fn tenant_namespace_default_to_singleton_when_absent() {
    // full_spec() carries explicit non-singleton tenant/namespace; drop both
    // keys to simulate a pre-axis, single-tenant on-disk spec.
    let mut json = serde_json::to_value(full_spec()).expect("to_value");
    let obj = json.as_object_mut().expect("spec serializes as a JSON object");
    obj.remove("tenant");
    obj.remove("namespace");

    let back: WorkloadSpec = serde_json::from_value(json).expect("deserialize without axes");
    assert_eq!(back.tenant, TenantId::singleton());
    assert_eq!(back.namespace, NamespaceId::singleton());
    assert!(back.tenant.is_singleton());
    assert!(back.namespace.is_singleton());

    // Explicit non-singleton values (full_spec sets tenant=ss, namespace=noisetable)
    // survive JSON round-trip untouched.
    let full = full_spec();
    let text = serde_json::to_string(&full).expect("serialize");
    let decoded: WorkloadSpec = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(decoded.tenant, TenantId("ss".into()));
    assert_eq!(decoded.namespace, NamespaceId("noisetable".into()));
    assert!(!decoded.tenant.is_singleton());
    assert!(!decoded.namespace.is_singleton());
}

/// W206 / R558-F3: both `MeshPeer` variants survive JSON **and** postcard
/// (external serde tag, no `skip_serializing_if` — the R590-B3 invariant that
/// keeps the workload wire postcard-decodable).
#[test]
fn mesh_peer_variants_round_trip() {
    for p in [
        MeshPeer::Tier(TierTag("private".into())),
        MeshPeer::CrossTenant {
            tenant: TenantId("ss".into()),
            namespace: NamespaceId("noisetable".into()),
            name: MeshIdent("runner".into()),
        },
    ] {
        let json = serde_json::to_string(&p).expect("json serialize");
        let back: MeshPeer = serde_json::from_str(&json).expect("json deserialize");
        assert_eq!(p, back, "JSON round-trip");

        let bytes = postcard::to_stdvec(&p).expect("postcard serialize");
        let dec: MeshPeer = postcard::from_bytes(&bytes).expect("postcard deserialize");
        assert_eq!(p, dec, "postcard round-trip");
    }
}

/// W206 / R558-F3: the fully-qualified mesh identity is `<tenant>/<namespace>/<name>`.
#[test]
fn fq_mesh_identity_is_tenant_namespace_name() {
    let spec = full_spec(); // tenant=ss, namespace=noisetable
    assert_eq!(
        spec.fq_mesh_identity(),
        format!("ss/noisetable/{}", spec.expose.mesh.identity.0),
    );
    assert!(spec.fq_mesh_identity().starts_with("ss/noisetable/"));
}

/// W206 / R558-F3: within a tenant a workload keeps its short mesh identity
/// until two namespaces collide on the same one, then both gain a namespace
/// prefix (`yah.runner` vs `noisetable.runner`).
#[test]
fn intra_tenant_address_prefixes_only_on_collision() {
    let yah = NamespaceId("yah".into());
    let nt = NamespaceId("noisetable".into());
    let runner = MeshIdent("runner".into());
    let api = MeshIdent("api".into());

    // yah.runner collides with noisetable.runner; yah.api is unique.
    let all = vec![
        (yah.clone(), runner.clone()),
        (nt.clone(), runner.clone()),
        (yah.clone(), api.clone()),
    ];

    // Colliding identity → namespace-prefixed on both sides.
    assert_eq!(intra_tenant_address(&yah, &runner, &all), "yah.runner");
    assert_eq!(intra_tenant_address(&nt, &runner, &all), "noisetable.runner");
    // Unique identity → bare short name.
    assert_eq!(intra_tenant_address(&yah, &api, &all), "api");
    // A lone workload is always addressed by its short name.
    assert_eq!(
        intra_tenant_address(&yah, &api, &[(yah.clone(), api.clone())]),
        "api"
    );
}

/// W206 / R558-F3: `MeshExpose::admits_peer` is deny-by-default across tenants.
#[test]
fn admits_peer_enforces_deny_by_default_across_tenants() {
    let ss = TenantId("ss".into());
    let nt = TenantId("noisetable".into());
    let ns = NamespaceId("default".into());
    let runner = MeshIdent("runner".into());
    let private = TierTag("private".into());
    let public = TierTag("public".into());
    let expose = |allow_from| MeshExpose {
        identity: MeshIdent("api".into()),
        ports: vec![8080],
        allow_from,
    };

    // Empty allow_from → all same-tenant peers admitted, cross-tenant denied.
    let open = expose(vec![]);
    assert!(open.admits_peer(&ss, &ss, &ns, &runner, &private), "same-tenant allow-all");
    assert!(
        !open.admits_peer(&ss, &nt, &ns, &runner, &private),
        "cross-tenant denied by default even with empty allow_from"
    );

    // Same-tenant tier restriction.
    let tiered = expose(vec![MeshPeer::Tier(private.clone())]);
    assert!(tiered.admits_peer(&ss, &ss, &ns, &runner, &private), "matching tier admitted");
    assert!(!tiered.admits_peer(&ss, &ss, &ns, &runner, &public), "non-matching tier denied");
    assert!(!tiered.admits_peer(&ss, &nt, &ns, &runner, &private), "cross-tenant still denied");

    // Explicit cross-tenant grant.
    let granted = expose(vec![MeshPeer::CrossTenant {
        tenant: nt.clone(),
        namespace: ns.clone(),
        name: runner.clone(),
    }]);
    assert!(
        granted.admits_peer(&ss, &nt, &ns, &runner, &public),
        "explicitly granted cross-tenant peer admitted (tier irrelevant)"
    );
    assert!(
        !granted.admits_peer(&ss, &nt, &ns, &MeshIdent("other".into()), &public),
        "unlisted cross-tenant peer denied"
    );
    assert!(
        granted.admits_peer(&ss, &ss, &ns, &runner, &private),
        "a CrossTenant-only allow_from still admits all same-tenant peers"
    );
}
