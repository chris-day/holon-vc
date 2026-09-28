use crate::{
    app::App,
    errors::{Result, error},
    keys::PublicKey,
    resolvers,
};
use serde_json::Value;
pub fn web_url(did: &str) -> Result<String> {
    let bad = || {
        error(
            "INVALID_DID",
            "did",
            "Malformed or unsupported did:web identifier",
        )
    };
    if !crate::models::absolute_uri(did) {
        return Err(bad());
    }
    let specific = did.strip_prefix("did:web:").ok_or_else(bad)?;
    if specific.contains(['#', '?', '/', '\\', '@']) {
        return Err(bad());
    }
    let mut parts = specific.split(':');
    let host = parts
        .next()
        .ok_or_else(bad)?
        .replace("%3A", ":")
        .replace("%3a", ":");
    if host.is_empty() || host.contains('%') {
        return Err(bad());
    }
    let path: Vec<_> = parts.collect();
    if path
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == ".." || p.contains('%'))
    {
        return Err(bad());
    }
    let value = if path.is_empty() {
        format!("https://{host}/.well-known/did.json")
    } else {
        format!("https://{host}/{}/did.json", path.join("/"))
    };
    let url = url::Url::parse(&value).map_err(|_| bad())?;
    if url.username() != "" || url.password().is_some() || url.host_str().is_none() {
        return Err(bad());
    }
    Ok(url.to_string())
}
pub fn authorized(
    document: &Value,
    controller: &str,
    method: &str,
    purpose: &str,
) -> Result<PublicKey> {
    let fail = || {
        error(
            "METHOD_UNAUTHORIZED",
            "authorization",
            "Verification method is not authorized by the claimed controller",
        )
    };
    if document["id"] != controller
        || !method.starts_with(&format!("{controller}#"))
        || !["assertionMethod", "authentication"].contains(&purpose)
    {
        return Err(fail());
    }
    let relations = document[purpose].as_array().ok_or_else(fail)?;
    let matches = |id: &str| {
        id == method
            || id
                .strip_prefix('#')
                .is_some_and(|fragment| format!("{controller}#{fragment}") == method)
    };
    let relationships: Vec<_> = relations
        .iter()
        .filter(|r| r.as_str().is_some_and(matches) || r["id"].as_str().is_some_and(matches))
        .collect();
    if relationships.len() != 1 {
        return Err(fail());
    }
    let relationship = relationships[0];
    let definitions = document["verificationMethod"].as_array();
    let vm = if relationship.is_object() {
        if definitions.is_some_and(|a| {
            a.iter()
                .any(|v| v["id"].as_str().is_some_and(matches) && v != relationship)
        }) {
            return Err(fail());
        }
        relationship
    } else {
        let candidates: Vec<_> = definitions
            .ok_or_else(fail)?
            .iter()
            .filter(|v| v["id"].as_str().is_some_and(matches))
            .collect();
        if candidates.len() != 1 {
            return Err(fail());
        }
        candidates[0]
    };
    if vm["controller"] != controller
        || !matches!(
            vm["type"].as_str(),
            Some("Multikey" | "Ed25519VerificationKey2020")
        )
    {
        return Err(fail());
    }
    let key = PublicKey::from_multibase(vm["publicKeyMultibase"].as_str().ok_or_else(fail)?)?;
    if vm["type"] == "Ed25519VerificationKey2020"
        && key.algorithm != crate::keys::Algorithm::Ed25519
    {
        return Err(fail());
    }
    Ok(key)
}
pub async fn resolve(
    app: &App,
    controller: &str,
    method: &str,
    purpose: &str,
) -> Result<PublicKey> {
    let doc = resolvers::json(app, &web_url(controller)?).await?;
    authorized(&doc, controller, method, purpose)
}
