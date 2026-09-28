use crate::{
    app::App,
    errors::{Result, error},
    models, storage,
};
use serde_json::Value;
use ssi_json_ld::ContextLoader;
use std::collections::HashMap;
pub const HOLON_CONTEXT: &str = "urn:holon:context:1.0";
pub fn loader(app: &App) -> Result<ContextLoader> {
    let mut contexts = HashMap::from([
        (
            "https://www.w3.org/ns/credentials/v2".into(),
            include_str!("../contexts/w3c-ns-credentials-v2.jsonld").into(),
        ),
        (
            "https://w3id.org/security/data-integrity/v2".into(),
            include_str!("../contexts/w3id-data-integrity-v2.jsonld").into(),
        ),
        (
            "https://w3id.org/security/multikey/v1".into(),
            include_str!("../contexts/w3id-multikey-v1.jsonld").into(),
        ),
        (
            "https://w3id.org/security/suites/ed25519-2020/v1".into(),
            include_str!("../contexts/w3id-ed25519-signature-2020-v1.jsonld").into(),
        ),
        (
            HOLON_CONTEXT.into(),
            include_str!("../contexts/holon-v1.jsonld").into(),
        ),
    ]);
    for (url, pin) in &app.config.contexts {
        if contexts.contains_key(url) {
            return Err(error(
                "CONTEXT_OVERRIDE",
                "jsonld",
                "Built-in contexts cannot be overridden",
            ));
        }
        let bytes = storage::read(&pin.path, false)?;
        models::parse(&bytes)?;
        if storage::digest(&bytes) != pin.sha256
            || models::date(&pin.expires)? <= chrono::Utc::now()
        {
            return Err(error(
                "CONTEXT_PIN_FAILED",
                "jsonld",
                "Context digest mismatch or expired pin",
            ));
        }
        contexts.insert(
            url.clone(),
            String::from_utf8(bytes)
                .map_err(|_| error("INVALID_CONTEXT", "jsonld", "Context must be UTF-8"))?,
        );
    }
    ContextLoader::empty()
        .with_context_map_from(contexts)
        .map_err(|_| error("INVALID_CONTEXT", "jsonld", "Invalid pinned context"))
}
pub fn policy(value: &Value, app: &App) -> Result<()> {
    fn allowed(v: &Value, app: &App) -> bool {
        match v {
            Value::String(s) => {
                [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://w3id.org/security/data-integrity/v2",
                    "https://w3id.org/security/multikey/v1",
                    "https://w3id.org/security/suites/ed25519-2020/v1",
                    HOLON_CONTEXT,
                ]
                .contains(&s.as_str())
                    || app.config.contexts.contains_key(s)
            }
            Value::Array(a) => a.iter().all(|v| allowed(v, app)),
            _ => false,
        }
    }
    fn walk(v: &Value, app: &App) -> bool {
        match v {
            Value::Object(o) => o.iter().all(|(k, v)| {
                if k == "@context" {
                    allowed(v, app)
                } else {
                    walk(v, app)
                }
            }),
            Value::Array(a) => a.iter().all(|v| walk(v, app)),
            _ => true,
        }
    }
    if !walk(value, app) {
        return Err(error(
            "CONTEXT_DENIED",
            "jsonld",
            "Inline or unapproved JSON-LD contexts are forbidden",
        ));
    }
    Ok(())
}
