use crate::errors::{Result, error};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt};

/// Duplicate-checking JSON parser. Errors never include document values.
pub fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(error(
            "DOCUMENT_TOO_LARGE",
            "structure",
            "Document exceeds 4 MiB",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer).map_err(|_| {
        error(
            "INVALID_JSON",
            "structure",
            "Invalid JSON or duplicate property",
        )
    })?;
    deserializer
        .end()
        .map_err(|_| error("INVALID_JSON", "structure", "Trailing JSON content"))?;
    Ok(value.0)
}
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictValue(n.into()))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element::<StrictValue>()? {
                    out.push(v.0);
                }
                Ok(StrictValue(out.into()))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate property"));
                    }
                    out.insert(k, a.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(out.into()))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Source {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Evidence {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default)]
    pub claim_paths: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Relationship {
    pub id: String,
    pub relation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Holon {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub schema_version: String,
    pub claims: BTreeMap<String, Value>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub related_holons: Vec<Relationship>,
}
pub fn absolute_uri(s: &str) -> bool {
    iref::Iri::new(s).is_ok()
}
pub fn date(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.to_utc())
        .map_err(|_| {
            error(
                "INVALID_DATE",
                "structure",
                "An RFC3339 timestamp is required",
            )
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Reveal {
    pub version: String,
    pub selective_pointers: Vec<String>,
}
impl Reveal {
    pub fn validate(&self) -> Result<()> {
        if self.version != "1.0"
            || self.selective_pointers.iter().any(|p| {
                p.is_empty()
                    || p.parse::<ssi_core::JsonPointerBuf>().is_err()
                    || p.starts_with("/proof")
                    || p.starts_with("/@context")
            })
        {
            Err(error(
                "INVALID_REVEAL",
                "disclosure",
                "Unsupported reveal version or protected/invalid pointer",
            ))
        } else {
            Ok(())
        }
    }
}
