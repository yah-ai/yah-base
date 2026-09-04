//! R844-F17 — the manifest declaration surface for *named* ports.
//!
//! Ports were named at every tier below the manifest before this — kamaji's
//! allocator resolves `name -> port`, a service record publishes `{"http":
//! 8080}`, `PORT_<NAME>` reaches the process — and unwritable at the top, so
//! every name downstream was synthesised rather than stated. These tests pin
//! the three accepted spellings, the shape rules, and the one property that
//! makes the change safe to land under existing manifests: a bare number array
//! still parses to exactly what it always did.

use workload_spec::validate::{shape, FieldPath, ShapeError};
use workload_spec::{MeshExpose, MeshIdent, MeshPeer, MeshPort, TierTag, WorkloadSpec};

/// Parse just the `[expose.mesh]` table, which is where the three spellings
/// live. Going through the whole `WorkloadSpec` would drag in an image digest
/// and a tier for no gain — the field's deserializer is the unit under test.
fn mesh(toml_src: &str) -> MeshExpose {
    toml::from_str(toml_src).expect("mesh expose parses")
}

#[test]
fn a_bare_number_array_parses_exactly_as_it_did_before_names_existed() {
    let m = mesh(
        r#"
identity = "api"
ports = [8080, 9090]
"#,
    );
    assert_eq!(m.numbers(), vec![8080, 9090]);
    assert!(m.names().is_empty(), "nothing was named: {:?}", m.names());
    assert!(m.named_numbers().is_empty());
}

#[test]
fn a_string_array_declares_names_whose_numbers_the_supervisor_picks() {
    let m = mesh(
        r#"
identity = "api"
ports = ["http", "wss"]
"#,
    );
    assert_eq!(m.names(), vec!["http", "wss"]);
    // The point of the assertion: a name-only port has NO number yet, and
    // `numbers()` says so rather than inventing one.
    assert!(m.numbers().is_empty(), "{:?}", m.numbers());
    assert!(m.named_numbers().is_empty());
}

#[test]
fn a_table_entry_states_both_halves() {
    let m = mesh(
        r#"
identity = "api"
ports = [{ name = "http", port = 8080 }, { name = "metrics", port = 9090 }]
"#,
    );
    assert_eq!(m.numbers(), vec![8080, 9090]);
    assert_eq!(
        m.named_numbers(),
        [
            ("http".to_string(), 8080u16),
            ("metrics".to_string(), 9090u16)
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn the_three_spellings_mix_in_one_array() {
    // The mix is the real case: a container's ports are fixed by its image and
    // still want names, while a listener the supervisor allocates has only a
    // name to give.
    let m = mesh(
        r#"
identity = "api"
ports = [{ name = "http", port = 8080 }, "wss", 9090]
"#,
    );
    assert_eq!(m.numbers(), vec![8080, 9090]);
    assert_eq!(m.names(), vec!["http", "wss"]);
    assert_eq!(
        m.named_numbers(),
        [("http".to_string(), 8080u16)].into_iter().collect()
    );
}

#[test]
fn a_table_entry_may_omit_the_port_which_is_the_bare_name_form() {
    let m = mesh(
        r#"
identity = "api"
ports = [{ name = "http" }]
"#,
    );
    assert_eq!(m, mesh("identity = \"api\"\nports = [\"http\"]"));
}

#[test]
fn every_spelling_round_trips_through_toml() {
    // Serialize picks the most compact faithful form, so a re-parse has to land
    // on the same value rather than merely a similar one.
    for src in [
        "identity = \"api\"\nports = [8080]",
        "identity = \"api\"\nports = [\"http\", \"wss\"]",
        "identity = \"api\"\nports = [{ name = \"http\", port = 8080 }]",
        "identity = \"api\"\nports = [{ name = \"http\", port = 8080 }, \"wss\", 9090]",
    ] {
        let first = mesh(src);
        let rendered = toml::to_string(&first).expect("mesh expose renders");
        let second: MeshExpose = toml::from_str(&rendered).expect("re-parses");
        assert_eq!(first, second, "round trip lost something for {src:?}");
    }
}

#[test]
fn the_binary_wire_carries_both_halves_of_every_spelling() {
    // Postcard is the kamaji UDS wire and is not self-describing, so `MeshPort`
    // takes a different serialize path there (the plain two-`Option` struct).
    // That path is what `ProtocolVersion::V7` exists for; if it stopped
    // round-tripping, a deploy would decode a port list that is not the one
    // sent — silently, because postcard has no field names to disagree about.
    let m = mesh(
        r#"
identity = "api"
ports = [{ name = "http", port = 8080 }, "wss", 9090]
"#,
    );
    let bytes = postcard::to_allocvec(&m).expect("postcard encodes");
    let back: MeshExpose = postcard::from_bytes(&bytes).expect("postcard decodes");
    assert_eq!(m, back);
}

// ── shape validation ─────────────────────────────────────────────────────────

fn spec_with(ports: Vec<MeshPort>) -> WorkloadSpec {
    let image = workload_spec::ImageRef {
        registry: "docker.io".into(),
        repository: "library/alpine".into(),
        tag: "3.19".into(),
        digest: workload_spec::testing::test_digest(),
    };
    let mut spec = WorkloadSpec::for_forge("f1", image, TierTag("private".into()), vec![]);
    spec.expose.mesh.identity = MeshIdent("api".into());
    spec.expose.mesh.allow_from = Vec::<MeshPeer>::new();
    spec.expose.mesh.ports = ports;
    spec
}

fn field_of(err: ShapeError) -> FieldPath {
    let ShapeError::Field { path, .. } = err;
    path
}

#[test]
fn a_repeated_port_name_is_rejected_because_a_consumer_selects_by_it() {
    let err = shape(&spec_with(vec![
        MeshPort::pinned("http", 8080),
        MeshPort::pinned("http", 9090),
    ]))
    .expect_err("a duplicate name must not validate");
    assert_eq!(field_of(err), FieldPath::MeshPort(1));
}

#[test]
fn a_repeated_port_number_is_rejected_because_one_socket_binds_once() {
    let err = shape(&spec_with(vec![
        MeshPort::pinned("http", 8080),
        MeshPort::pinned("alt", 8080),
    ]))
    .expect_err("a duplicate number must not validate");
    assert_eq!(field_of(err), FieldPath::MeshPort(1));
}

#[test]
fn a_port_name_that_is_not_a_dns_label_is_rejected() {
    // `PORT_<NAME>` folds non-alphanumerics to `_`, so `ws control` and
    // `ws-control` would reach the workload as one variable. Rejecting the
    // shape is how the two cannot collide in the first place.
    let err = shape(&spec_with(vec![MeshPort::named("WS Control")]))
        .expect_err("a non-label name must not validate");
    assert_eq!(field_of(err), FieldPath::MeshPort(0));
}

#[test]
fn a_port_name_longer_than_a_service_name_is_rejected() {
    let err = shape(&spec_with(vec![MeshPort::named("aaaaaaaaaaaaaaaa")]))
        .expect_err("16 characters is one too many");
    assert_eq!(field_of(err), FieldPath::MeshPort(0));
}

#[test]
fn an_entry_that_states_neither_a_name_nor_a_number_is_rejected() {
    let empty = MeshPort {
        name: None,
        number: None,
    };
    let err = shape(&spec_with(vec![empty])).expect_err("an empty declaration must not validate");
    assert_eq!(field_of(err), FieldPath::MeshPort(0));
}

#[test]
fn a_name_only_port_validates_and_warns_that_only_the_native_tier_binds_it() {
    // R844-F21 changed what this warning has to say, and the rename is the
    // point: a name-only port IS allocated now, by the native backend, which
    // owns the workload's network namespace. It is still unbindable on a
    // container backend, where the ports are the image's — so the spelling is
    // neither inert (the pre-F21 reading) nor universally fine.
    //
    // A warning rather than an error because shape validation cannot tell which
    // backend a spec will land on; placement decides that later. Naming the
    // split is the most this layer can honestly say.
    let warnings = shape(&spec_with(vec![MeshPort::named("wss")]))
        .expect("a name-only port is not a hard error");
    let warning = warnings
        .iter()
        .find(|w| w.path == FieldPath::MeshPort(0))
        .unwrap_or_else(|| panic!("no warning for the name-only port: {warnings:?}"));
    assert!(
        warning.message.contains("declares no number"),
        "{warning}"
    );
    assert!(
        warning.message.contains("PORT_WSS"),
        "the warning must name the variable the allocated number arrives in, \
         since that is what makes the spelling usable rather than inert: {warning}"
    );
    assert!(
        warning.message.contains("container"),
        "the warning must name the tier that still refuses it: {warning}"
    );

    // Stating the number is the fix the warning asks for, and it is silent.
    let quiet = shape(&spec_with(vec![MeshPort::pinned("wss", 8443)]))
        .expect("a named, numbered port validates");
    assert!(
        !quiet.iter().any(|w| w.path == FieldPath::MeshPort(0)),
        "{quiet:?}"
    );
}

#[test]
fn the_public_port_rule_reads_declared_numbers_not_declared_names() {
    // `expose.public.port` must appear in `expose.mesh.ports`. A name-only
    // entry has no number, so it cannot satisfy that rule — and the failure has
    // to name the public port rather than the port list, because the port list
    // is not what is wrong.
    let mut spec = spec_with(vec![MeshPort::named("http")]);
    spec.expose.public = Some(workload_spec::PublicExpose {
        hostname: "api.example.com".into(),
        port: 8080,
        tls: workload_spec::PublicTls::CfManaged,
    });
    let err = shape(&spec).expect_err("a name cannot stand in for a number here");
    assert_eq!(field_of(err), FieldPath::ExposeMeshPort(8080));

    spec.expose.mesh.ports = vec![MeshPort::pinned("http", 8080)];
    shape(&spec).expect("stating the number satisfies it");
}
