use crate::errors::{Result, error};
use serde_json::Value;
pub const HOLON_SCHEMA: &str = include_str!("../schemas/holon-v1.schema.json");
pub const DISCLOSURE_SCHEMA: &str = include_str!("../schemas/holon-v1.disclosure.schema.json");

pub fn validate(schema: &Value, instance: &Value) -> Result<()> {
    // Only self-contained schema profiles are admitted; never fetch arbitrary $refs.
    fn refs(v: &Value) -> bool {
        match v {
            Value::Object(o) => o.iter().all(|(k, v)| {
                if ["$ref", "$dynamicRef", "$recursiveRef"].contains(&k.as_str()) {
                    v.as_str().is_some_and(|s| s.starts_with('#'))
                } else {
                    refs(v)
                }
            }),
            Value::Array(a) => a.iter().all(refs),
            _ => true,
        }
    }
    if !refs(schema) {
        return Err(error(
            "SCHEMA_REFERENCE_DENIED",
            "schema",
            "External schema references must be bundled locally",
        ));
    }
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(schema)
        .map_err(|_| {
            error(
                "INVALID_SCHEMA",
                "schema",
                "Invalid or unsupported JSON Schema",
            )
        })?;
    if validator.is_valid(instance) {
        Ok(())
    } else {
        Err(error(
            "SCHEMA_MISMATCH",
            "schema",
            "Document does not satisfy its schema",
        ))
    }
}
