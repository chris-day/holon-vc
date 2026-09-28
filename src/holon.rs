use crate::{
    errors::{Result, error},
    models::{Holon, absolute_uri, date},
};
use serde_json::Value;

pub fn validate(value: &Value) -> Result<Holon> {
    let h: Holon = serde_json::from_value(value.clone())
        .map_err(|_| error("INVALID_HOLON", "schema", "Holon structure is invalid"))?;
    if h.schema_version != "1.0" || !absolute_uri(&h.id) || h.type_.is_empty() {
        return Err(error(
            "INVALID_HOLON",
            "schema",
            "Unsupported schema version or missing identifier/type",
        ));
    }
    date(&h.created_at)?;
    if let Some(d) = &h.observed_at {
        date(d)?;
    }
    if let Some(s) = &h.source
        && (!absolute_uri(&s.id)
            || s.kind.is_empty()
            || s.uri.as_ref().is_some_and(|u| !absolute_uri(u)))
    {
        return Err(error(
            "INVALID_SOURCE",
            "schema",
            "Malformed source reference",
        ));
    }
    for e in &h.evidence {
        if !absolute_uri(&e.id)
            || !absolute_uri(&e.source)
            || e.type_.is_empty()
            || e.digest
                .as_ref()
                .is_some_and(|d| d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()))
            || e.claim_paths
                .iter()
                .any(|p| p.parse::<ssi_core::JsonPointerBuf>().is_err())
        {
            return Err(error(
                "INVALID_EVIDENCE",
                "schema",
                "Malformed evidence reference",
            ));
        }
    }
    for r in &h.related_holons {
        if !absolute_uri(&r.id) || !absolute_uri(&r.relation) {
            return Err(error(
                "INVALID_RELATION",
                "schema",
                "Malformed relationship",
            ));
        }
    }
    Ok(h)
}
