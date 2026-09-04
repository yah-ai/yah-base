//! R090-F6 — `MeshResolver` trait contract tests.
//!
//! Round-trips `EnvValue::FromMesh` through serde and exercises the trait's
//! happy + missing-ident error paths against a `FakeMeshResolver`. Yubaba's
//! own resolver lives in `yubaba::deploy::mesh_resolve` and has its own
//! integration tests (Url/Host/Port + waiting-for-dep + timeout).

use std::collections::{BTreeMap, HashMap};

use workload_spec::validate::{
    resolve_env_from_mesh, select_mesh_port, MeshError, MeshResolver,
};
use workload_spec::*;

// ── Fake resolver ─────────────────────────────────────────────────────────────

/// Test resolver backed by an in-memory `ident -> (name -> port)` map.
///
/// It routes port selection through
/// [`workload_spec::validate::select_mesh_port`] rather than re-deriving it,
/// which is the same discipline the doc now requires of every implementation:
/// this fake used to carry its own copy of "the first entry", so it agreed with
/// the production resolver about a rule that was wrong in both (R844-B22).
struct FakeMeshResolver {
    by_ident: HashMap<String, BTreeMap<String, u16>>,
}

impl FakeMeshResolver {
    fn new() -> Self {
        Self {
            by_ident: HashMap::new(),
        }
    }

    /// Register a peer whose ports are named — the R844-F17 spelling.
    fn with_named(mut self, ident: &str, ports: &[(&str, u16)]) -> Self {
        self.by_ident.insert(
            ident.into(),
            ports
                .iter()
                .map(|(n, p)| ((*n).to_string(), *p))
                .collect(),
        );
        self
    }

    /// Register a peer that named nothing, using the same synthesis the
    /// supervisor applies to bare numbers: a sole port is `http`; several are
    /// their own numbers and none is `http`.
    fn with(self, ident: &str, ports: Vec<u16>) -> Self {
        let named: Vec<(String, u16)> = match ports.as_slice() {
            [one] => vec![("http".to_string(), *one)],
            many => many.iter().map(|p| (p.to_string(), *p)).collect(),
        };
        let borrowed: Vec<(&str, u16)> =
            named.iter().map(|(n, p)| (n.as_str(), *p)).collect();
        self.with_named(ident, &borrowed)
    }
}

impl MeshResolver for FakeMeshResolver {
    fn resolve(&self, ident: &MeshIdent, kind: MeshLookup) -> Result<String, MeshError> {
        let ports = self
            .by_ident
            .get(&ident.0)
            .ok_or_else(|| MeshError::NotDeployed {
                ident: ident.0.clone(),
            })?;
        if !kind.needs_port() {
            return Ok(ident.0.clone());
        }
        let port = select_mesh_port(&ident.0, ports, &kind)?;
        match kind {
            MeshLookup::Host => unreachable!("Host needs no port"),
            MeshLookup::Port | MeshLookup::PortNamed { .. } => Ok(port.to_string()),
            MeshLookup::Url | MeshLookup::UrlNamed { .. } => {
                Ok(format!("http://{}:{}", ident.0, port))
            }
        }
    }
}

// ── Round-trip ────────────────────────────────────────────────────────────────

#[test]
fn from_mesh_round_trips_through_serde() {
    let original = EnvValue::FromMesh {
        ident: MeshIdent("noisetable-db.pdx".into()),
        kind: MeshLookup::Url,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: EnvValue = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, back);
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[test]
fn url_renders_the_sole_port_with_http_prefix() {
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432]);
    let value = resolver
        .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Url)
        .expect("resolve");
    assert_eq!(value, "http://noisetable-db.pdx:5432");
}

/// R844-B22: this case used to render `http://…:5432` — the first entry —
/// which is a coin flip dressed as an answer. A peer with several listeners and
/// no `http` among them has not said which one a dependent should dial, so the
/// resolver says so instead of picking.
#[test]
fn several_unnamed_ports_is_an_error_not_the_first_one() {
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432, 9100]);
    for kind in [MeshLookup::Url, MeshLookup::Port] {
        let err = resolver
            .resolve(&MeshIdent("noisetable-db.pdx".into()), kind.clone())
            .unwrap_err();
        match err {
            MeshError::AmbiguousPort { ident, names, .. } => {
                assert_eq!(ident, "noisetable-db.pdx");
                assert_eq!(names, vec!["5432".to_string(), "9100".to_string()]);
            }
            other => panic!("expected AmbiguousPort for {kind:?}, got {other:?}"),
        }
    }
}

/// Naming one of them `http` is the author answering the question, and it is
/// the answer the rest of the workspace already assumes (`ServiceRecord::port`,
/// the `PORT` env alias).
#[test]
fn several_ports_resolve_through_http_when_one_is_named_that() {
    let resolver =
        FakeMeshResolver::new().with_named("api.pdx", &[("http", 8080), ("metrics", 9100)]);
    let url = resolver
        .resolve(&MeshIdent("api.pdx".into()), MeshLookup::Url)
        .expect("resolve");
    assert_eq!(url, "http://api.pdx:8080");
    let port = resolver
        .resolve(&MeshIdent("api.pdx".into()), MeshLookup::Port)
        .expect("resolve");
    assert_eq!(port, "8080");
}

/// The spelling that removes the guess entirely.
#[test]
fn a_named_lookup_selects_that_port_and_nothing_else() {
    let resolver =
        FakeMeshResolver::new().with_named("api.pdx", &[("http", 8080), ("wss", 8443)]);
    let url = resolver
        .resolve(
            &MeshIdent("api.pdx".into()),
            MeshLookup::UrlNamed {
                name: "wss".into(),
            },
        )
        .expect("resolve");
    assert_eq!(url, "http://api.pdx:8443");
    let port = resolver
        .resolve(
            &MeshIdent("api.pdx".into()),
            MeshLookup::PortNamed {
                name: "wss".into(),
            },
        )
        .expect("resolve");
    assert_eq!(port, "8443");
}

/// A named lookup must NOT fall back to `http` — that would be the positional
/// guess wearing a name, and it is the failure the named spelling exists to
/// remove.
#[test]
fn a_named_lookup_for_an_absent_port_errors_rather_than_falling_back() {
    let resolver =
        FakeMeshResolver::new().with_named("api.pdx", &[("http", 8080), ("wss", 8443)]);
    let err = resolver
        .resolve(
            &MeshIdent("api.pdx".into()),
            MeshLookup::PortNamed {
                name: "grpc".into(),
            },
        )
        .unwrap_err();
    match err {
        MeshError::NoSuchPort {
            ident,
            name,
            available,
        } => {
            assert_eq!(ident, "api.pdx");
            assert_eq!(name, "grpc");
            assert_eq!(available, vec!["http".to_string(), "wss".to_string()]);
        }
        other => panic!("expected NoSuchPort, got {other:?}"),
    }
}

/// The rule itself, exercised directly rather than through a resolver.
///
/// The case worth naming: a peer with ONE port that is not called `http` still
/// resolves to it. "Sole port" is checked before the `http` rule on purpose —
/// there is no ambiguity to resolve when there is only one listener, and
/// demanding the name there would break every single-port peer whose author
/// called it something else.
#[test]
fn a_sole_port_resolves_whatever_it_is_called() {
    let ports: BTreeMap<String, u16> = [("grpc".to_string(), 50051)].into_iter().collect();
    assert_eq!(
        select_mesh_port("api.pdx", &ports, &MeshLookup::Port).expect("sole port"),
        50051
    );
}

#[test]
fn an_empty_port_map_is_no_ports_not_ambiguous() {
    let ports: BTreeMap<String, u16> = BTreeMap::new();
    let err = select_mesh_port("api.pdx", &ports, &MeshLookup::Url).unwrap_err();
    assert!(
        matches!(err, MeshError::NoPorts { .. }),
        "expected NoPorts, got {err:?}"
    );
}

/// `Host` needs no port, so it must keep answering for a peer that exposes
/// none — the one lookup a portless dependency can still satisfy.
#[test]
fn host_resolves_for_a_portless_peer() {
    let resolver = FakeMeshResolver::new().with("portless.pdx", vec![]);
    let value = resolver
        .resolve(&MeshIdent("portless.pdx".into()), MeshLookup::Host)
        .expect("Host needs no port");
    assert_eq!(value, "portless.pdx");
}

#[test]
fn host_renders_bare_ident() {
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432]);
    let value = resolver
        .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Host)
        .expect("resolve");
    assert_eq!(value, "noisetable-db.pdx");
}

#[test]
fn port_renders_the_sole_port_as_string() {
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432]);
    let value = resolver
        .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Port)
        .expect("resolve");
    assert_eq!(value, "5432");
}

// ── Error paths ───────────────────────────────────────────────────────────────

#[test]
fn missing_ident_returns_not_deployed_error() {
    let resolver = FakeMeshResolver::new(); // empty map
    let err = resolver
        .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Url)
        .unwrap_err();
    assert_eq!(
        err,
        MeshError::NotDeployed {
            ident: "noisetable-db.pdx".into(),
        }
    );
}

#[test]
fn deployed_but_no_ports_returns_no_ports_error() {
    let resolver = FakeMeshResolver::new().with("portless.pdx", vec![]);
    let err = resolver
        .resolve(&MeshIdent("portless.pdx".into()), MeshLookup::Url)
        .unwrap_err();
    assert_eq!(
        err,
        MeshError::NoPorts {
            ident: "portless.pdx".into(),
            lookup: MeshLookup::Url,
        }
    );
}

// ── resolve_env_from_mesh helper ──────────────────────────────────────────────

#[test]
fn resolve_env_from_mesh_renders_only_from_mesh_entries() {
    let env = vec![
        EnvVar {
            name: "APP_ENV".into(),
            value: EnvValue::Literal {
                value: "production".into(),
            },
        },
        EnvVar {
            name: "DB_PASSWORD".into(),
            value: EnvValue::FromSecret {
                secret: "creds".into(),
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
        EnvVar {
            name: "DATABASE_HOST".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("noisetable-db.pdx".into()),
                kind: MeshLookup::Host,
            },
        },
    ];
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432]);

    let resolved = resolve_env_from_mesh(&env, &resolver).expect("resolve env");

    assert_eq!(resolved.len(), 4);
    // Literal pass-through
    assert_eq!(
        resolved[0].value,
        EnvValue::Literal {
            value: "production".into()
        }
    );
    // FromSecret untouched — secrets layer (R090-F5) handles those
    assert!(matches!(resolved[1].value, EnvValue::FromSecret { .. }));
    // FromMesh now Literal
    assert_eq!(
        resolved[2].value,
        EnvValue::Literal {
            value: "http://noisetable-db.pdx:5432".into()
        }
    );
    assert_eq!(
        resolved[3].value,
        EnvValue::Literal {
            value: "noisetable-db.pdx".into()
        }
    );
}

#[test]
fn resolve_env_from_mesh_propagates_missing_ident_error() {
    let env = vec![EnvVar {
        name: "DATABASE_URL".into(),
        value: EnvValue::FromMesh {
            ident: MeshIdent("missing.pdx".into()),
            kind: MeshLookup::Url,
        },
    }];
    let resolver = FakeMeshResolver::new(); // no idents registered

    let err = resolve_env_from_mesh(&env, &resolver).unwrap_err();
    assert_eq!(
        err,
        MeshError::NotDeployed {
            ident: "missing.pdx".into(),
        }
    );
}
