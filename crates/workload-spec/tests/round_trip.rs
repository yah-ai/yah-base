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
                ports: MeshExpose::anonymous_ports([8080, 9090]),
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
    let original = Workload::container(full_spec());
    let bytes = postcard::to_stdvec(&original).expect("postcard serialize");
    let decoded: Workload =
        postcard::from_bytes(&bytes).expect("postcard deserialize (R590-B3 regression)");
    assert_eq!(original, decoded, "Workload::Container did not survive postcard");
}

/// R783-F1 wire-compat gate: splitting `Workload::Container`'s payload into
/// [`ContainerManifest`] must not move a single byte on the kamaji UDS.
///
/// A round-trip alone cannot prove that — it would still pass if both halves
/// changed together. So assert the encoding directly: postcard writes an
/// external tag as the varint variant index (`Container` is index 1) followed
/// by the payload, so the frame must be exactly `[1] ++ postcard(WorkloadSpec)`
/// — which is what it was before the manifest enum existed.
#[test]
fn container_postcard_frame_is_the_variant_index_then_the_bare_spec() {
    let spec = full_spec();
    let enveloped = postcard::to_stdvec(&Workload::container(spec.clone())).expect("envelope");
    let bare = postcard::to_stdvec(&spec).expect("bare spec");

    let mut expected = vec![1u8];
    expected.extend_from_slice(&bare);
    assert_eq!(
        enveloped, expected,
        "the container wire frame moved — kamaji decodes this positionally"
    );
}

/// The other half of the split (W324 §5): a build recipe names an image tag,
/// not a digest, so it must be *refused* on the way to kamaji rather than
/// encoded as something the far side cannot pull.
#[test]
fn container_recipe_is_refused_by_postcard_rather_than_encoded() {
    let recipe = Workload::Container(ContainerManifest::Recipe(ContainerBuild {
        schema_version: SchemaVersion::V1,
        name: "yah-cloud-admin".into(),
        build: ContainerBuildStep {
            dockerfile: "Dockerfile".into(),
            context: Some(".".into()),
            image: Some("yah-local/yah-cloud-admin:dev".into()),
        },
        run: ContainerRunConfig::default(),
    }));

    // postcard's `Error` discards the custom message, so the assertion is on
    // the refusal itself; the human-readable half below is where the *reason*
    // is legible.
    postcard::to_stdvec(&recipe).expect_err("a recipe must not reach the wire");

    let json = serde_json::to_string(&recipe).expect("a recipe is still valid on disk");
    assert!(json.contains("\"kind\":\"container\""), "{json}");
    assert!(json.contains("yah-local/yah-cloud-admin:dev"), "{json}");
}

// ── Per-tenant passway (R852-F1) ─────────────────────────────────────────────

fn tenant_passway() -> TenantPasswayWorkload {
    TenantPasswayWorkload::cold("shop.tenant.io", "127.0.0.1:8443")
        .with_upstreams(["100.64.0.9:8080", "100.64.0.10:8080"])
}

/// The wire-compat half of appending a variant. `TenantPassway` is index 4, so
/// every pre-existing variant keeps the index a deployed node already decodes
/// — the failure a mid-enum insertion would cause is silent (a node reads
/// `StaticAsset` bytes as `Almanac`), so it gets an explicit frame assertion
/// rather than only a round-trip.
#[test]
fn tenant_passway_postcard_frame_is_index_four_then_the_bare_payload() {
    let w = tenant_passway();
    let enveloped =
        postcard::to_stdvec(&Workload::TenantPassway(w.clone())).expect("envelope encodes");
    let bare = postcard::to_stdvec(&w).expect("bare payload");

    let mut expected = vec![4u8];
    expected.extend_from_slice(&bare);
    assert_eq!(
        enveloped, expected,
        "the tenant-passway wire frame is not [4] ++ payload — kamaji decodes this positionally"
    );

    let decoded: Workload = postcard::from_bytes(&enveloped).expect("postcard decode");
    assert_eq!(decoded, Workload::TenantPassway(w));
}

/// The human-readable half: flat, internally tagged on `kind`, so a
/// hand-written manifest is a normal TOML/JSON document.
#[test]
fn tenant_passway_round_trips_through_json_as_a_flat_kind_tagged_object() {
    let original = Workload::TenantPassway(tenant_passway());
    let json = serde_json::to_string(&original).expect("serialize");
    assert!(json.contains("\"kind\":\"tenant-passway\""), "{json}");
    let decoded: Workload = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, original);
    assert_eq!(decoded.kind_str(), "tenant-passway");
    assert!(decoded.tenant_passway().is_some());
}

/// The invariant the whole kind exists to hold: `PASSWAY_LISTEN` is *derived*
/// from the one declared `listen`, never restated by a caller. passway's
/// socket-activation path panics rather than binding fresh when `LISTEN_FDS`
/// is set and the seed does not take, so a drift here is a workload that forks
/// and dies on every connection.
#[test]
fn jit_spec_derives_the_bind_string_and_the_env_escape_hatch_cannot_override_it() {
    let mut w = tenant_passway();
    // A caller trying to set the load-bearing keys by hand.
    w.env.insert("PASSWAY_LISTEN".into(), "0.0.0.0:443".into());
    w.env.insert("LISTEN_FDS".into(), "0".into());
    w.env.insert("PASSWAY_TLS_MODE".into(), "acme".into());
    w.env
        .insert("PASSWAY_HEALTH_PATH".into(), "/healthz".into());

    let spec = w.jit_spec("passway-shop-tenant-io");
    let get = |k: &str| -> Option<String> {
        spec.env.iter().find(|e| e.name == k).map(|e| match &e.value {
            EnvValue::Literal { value } => value.clone(),
            other => panic!("{k} must be a literal, got {other:?}"),
        })
    };

    assert_eq!(get("PASSWAY_LISTEN").as_deref(), Some("127.0.0.1:8443"));
    assert_eq!(get("LISTEN_FDS").as_deref(), Some("1"));
    assert_eq!(get("PASSWAY_TLS_MODE").as_deref(), Some("manual"));
    // The non-load-bearing key the caller set survives — this is an escape
    // hatch, not a whitelist.
    assert_eq!(get("PASSWAY_HEALTH_PATH").as_deref(), Some("/healthz"));

    // Upstreams carry the domain prefix, one entry per backend (R844-F3
    // load-balances repeats), and the port the mesh declares is parsed back off
    // `listen` rather than carried twice.
    assert_eq!(
        get("PASSWAY_UPSTREAMS").as_deref(),
        Some("shop.tenant.io=100.64.0.9:8080,shop.tenant.io=100.64.0.10:8080")
    );
    assert_eq!(spec.expose.mesh.numbers(), vec![8443]);
    assert_eq!(spec.expose.mesh.identity.0, "passway-shop-tenant-io");
    // The JIT supervisor owns re-forking; an idle self-reap is not a crash.
    assert!(matches!(spec.restart_policy, RestartPolicy::Never));
    assert_eq!(
        spec.entrypoint.as_deref(),
        Some(["/usr/local/bin/passway".to_string()].as_slice())
    );
}

/// `idle_ttl` rounds UP, and `None` means the variable is absent rather than
/// zero — passway reads an absent `PASSWAY_IDLE_TTL_SECS` as "never reap" and
/// a `0` as a timer, so truncating 500ms to 0 would turn a declared-cold
/// workload resident with nothing to read in any log.
#[test]
fn idle_ttl_rounds_up_and_never_reap_omits_the_variable() {
    let has_ttl = |w: &TenantPasswayWorkload| -> Option<String> {
        w.jit_spec("x")
            .env
            .iter()
            .find(|e| e.name == "PASSWAY_IDLE_TTL_SECS")
            .map(|e| match &e.value {
                EnvValue::Literal { value } => value.clone(),
                other => panic!("unexpected {other:?}"),
            })
    };

    let mut w = tenant_passway();
    w.idle_ttl = Some(Millis::from_ms(500));
    assert_eq!(w.idle_ttl_secs(), Some(1));
    assert_eq!(has_ttl(&w).as_deref(), Some("1"));

    w.idle_ttl = Some(Millis::from_ms(1500));
    assert_eq!(has_ttl(&w).as_deref(), Some("2"));

    w.idle_ttl = None;
    assert_eq!(w.idle_ttl_secs(), None);
    assert_eq!(has_ttl(&w), None, "never-reap must OMIT the variable, not zero it");

    // Even when the escape hatch tries to reintroduce it.
    w.env
        .insert("PASSWAY_IDLE_TTL_SECS".into(), "30".into());
    assert_eq!(has_ttl(&w), None);
}

/// A passway with no backend yet is legal — a domain is enrolled and issued
/// before the tenant's app is placed — and renders an empty upstream list,
/// which passway answers 503 on rather than refusing to start.
#[test]
fn a_tenant_passway_with_no_upstreams_renders_an_empty_list() {
    let w = TenantPasswayWorkload::cold("new.tenant.io", "127.0.0.1:9443");
    assert_eq!(w.passway_upstreams(), "");
    assert_eq!(
        w.tls.cert,
        "/run/yah/passway/tenants/new.tenant.io/tls.crt",
        "cert paths are per-domain: a shared path is a shared certificate"
    );
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
                ports: MeshExpose::anonymous_ports([80]),
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
        ports: MeshExpose::anonymous_ports([8080]),
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

/// R838-B1: a `mesofact-static` manifest that declares `[build]` with an
/// `out_dir` but no `command` must load.
///
/// This is the shape `mesofact new` scaffolds (its template's own header says
/// the omission is deliberate: the in-process pipeline builds `out_dir` with
/// no third binary, no package manager and no Node). While `BuildConfig.
/// command` was a required `String`, every scaffolded project shipped a
/// manifest the envelope could not read — which is what
/// `xtask::workload_envelope` caught.
#[test]
fn mesofact_static_build_table_without_a_command_parses_as_none() {
    let src = r#"
schema_version = 1
kind = "mesofact-static"
routes = "./mesofact.routes.ts"

[build]
out_dir = "dist"
"#;
    let workload: Workload = toml::from_str(src).expect("scaffold manifest must load");
    let Workload::MesofactStatic(ms) = workload else {
        panic!("expected MesofactStatic");
    };
    assert_eq!(ms.build.command, None, "absent command is None, not empty");
    assert_eq!(ms.build.out_dir, PathBuf::from("dist"));
    assert_eq!(ms.routes, PathBuf::from("./mesofact.routes.ts"));
}

/// The `deny_unknown_fields` guard on `BuildConfig` (R658-B1) still bites —
/// making `command` optional must not have made the table permissive.
#[test]
fn an_unknown_build_key_is_still_refused_now_that_command_is_optional() {
    let src = r#"
schema_version = 1
kind = "mesofact-static"

[build]
out_dir = "dist"
routes = "./mesofact.routes.ts"
"#;
    let err = toml::from_str::<Workload>(src).expect_err("build.routes must not be swallowed");
    let msg = err.to_string();
    assert!(msg.contains("routes"), "error must name the stray key; got: {msg}");
}

/// Both arms of the now-optional `command` survive the postcard kamaji wire.
/// `Option<String>` writes a leading tag byte the bare `String` did not have,
/// so this pins that both the present and absent forms decode back to
/// themselves rather than one of them shifting into the next field.
#[test]
fn mesofact_static_build_command_round_trips_through_postcard_both_ways() {
    let build = |command: Option<&str>| MesofactStaticWorkload {
        schema_version: SchemaVersion::V1,
        build: BuildConfig {
            command: command.map(str::to_string),
            out_dir: PathBuf::from("dist"),
            render_command: None,
        },
        routes: PathBuf::from("./mesofact.routes.ts"),
        build_mode: BuildMode::default(),
        ssr_runtime: None,
        serve_bundle: None,
        revalidate_receiver: None,
    };

    for command in [None, Some("bun run build")] {
        let original = Workload::MesofactStatic(build(command));
        let bytes = postcard::to_allocvec(&original).expect("encode");
        let decoded: Workload = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, original, "command = {command:?}");
    }
}
