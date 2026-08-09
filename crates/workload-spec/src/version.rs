use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Wire-format schema version envelope.
///
/// Single variant today. When a breaking field rename or removal requires a
/// migration path, a new variant is added. The `schema_version` field on
/// `WorkloadSpec` uses this as a tag so rolling clusters can decode multiple
/// versions simultaneously. See arch doc §Evolution for the versioning rules.
/// **Reads liberally, writes canonically (R546-B7).** Serialization always
/// emits the variant name (`"V1"`), but deserialization also accepts the bare
/// integer `1` and lowercase `"v1"`. Most on-disk `workload.toml` files in the
/// camp — every `mesofact-static` and `container` component, plus the
/// `cloudflare-worker` ones whose reconciler-local struct types this field as a
/// plain integer — were authored as `schema_version = 1`. Rejecting that form
/// meant `workload_spec::Workload` could not load them even once the envelope's
/// tagging was fixed, and `mesofact_static::read_mesofact_build` had to
/// hand-extract raw `toml::Value` subtrees to work around it (R438-T6's gotcha).
/// A version envelope is exactly the field that should tolerate both spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum SchemaVersion {
    V1,
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Untagged needs `deserialize_any`, which postcard refuses — and this
        // type rides the kamaji wire inside `WorkloadSpec`. Same branch as
        // `Workload` and `ImageRef`: convenience in text, plain variant index
        // in binary.
        if de.is_human_readable() {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Repr {
                Num(u64),
                Name(String),
            }
            match Repr::deserialize(de)? {
                Repr::Num(1) => Ok(SchemaVersion::V1),
                Repr::Num(n) => Err(serde::de::Error::custom(format!(
                    "unknown schema_version {n} (known versions: 1)"
                ))),
                Repr::Name(s) if s.eq_ignore_ascii_case("v1") => Ok(SchemaVersion::V1),
                Repr::Name(s) => Err(serde::de::Error::custom(format!(
                    "unknown schema_version {s:?} (known versions: \"V1\")"
                ))),
            }
        } else {
            #[derive(Deserialize)]
            enum Wire {
                V1,
            }
            match Wire::deserialize(de)? {
                Wire::V1 => Ok(SchemaVersion::V1),
            }
        }
    }
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self::V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R546-B7: both spellings load; output stays canonical.
    #[test]
    fn accepts_integer_and_string_forms_and_writes_the_name() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Doc {
            schema_version: SchemaVersion,
        }

        for src in [
            "schema_version = 1",
            r#"schema_version = "V1""#,
            r#"schema_version = "v1""#,
        ] {
            let doc: Doc = toml::from_str(src).unwrap_or_else(|e| panic!("{src}: {e}"));
            assert_eq!(doc.schema_version, SchemaVersion::V1);
        }

        let out = toml::to_string(&Doc {
            schema_version: SchemaVersion::V1,
        })
        .expect("serialize");
        assert!(out.contains("\"V1\""), "canonical output, got {out}");
    }

    #[test]
    fn rejects_unknown_versions() {
        #[derive(Deserialize, Debug)]
        struct Doc {
            #[allow(dead_code)]
            schema_version: SchemaVersion,
        }
        assert!(toml::from_str::<Doc>("schema_version = 2").is_err());
        assert!(toml::from_str::<Doc>(r#"schema_version = "V2""#).is_err());
    }

    /// The binary branch must not reach `deserialize_any` — postcard refuses
    /// it, and this type rides the kamaji UDS inside every `WorkloadSpec`.
    #[test]
    fn round_trips_through_postcard() {
        let bytes = postcard::to_allocvec(&SchemaVersion::V1).expect("encode");
        assert_eq!(
            postcard::from_bytes::<SchemaVersion>(&bytes).expect("decode"),
            SchemaVersion::V1
        );
    }
}
