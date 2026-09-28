//! Evidence integrity and explicit comparisons. Digests alone never corroborate claims.
use crate::{
    app::App,
    errors::{Result, error},
    trust::Policy,
    verification,
};
use serde_json::Value;
use std::collections::BTreeSet;
#[derive(Default)]
pub struct Assessment {
    pub verified: bool,
    pub contradicted: bool,
    pub independent: usize,
}
pub fn instruction_like(v: &Value) -> bool {
    match v {
        Value::String(s) => {
            let s = s.to_ascii_lowercase();
            [
                "ignore previous instructions",
                "ignore all previous",
                "system prompt",
                "execute this command",
                "<|system|>",
                "[inst]",
            ]
            .iter()
            .any(|p| s.contains(p))
        }
        Value::Array(a) => a.iter().any(instruction_like),
        Value::Object(o) => o.values().any(instruction_like),
        _ => false,
    }
}
pub async fn assess(app: &App, v: &Value, p: &Policy) -> Result<Assessment> {
    let evidence = v["credentialSubject"]["evidence"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if evidence.len() > 32 {
        return Err(error(
            "EVIDENCE_LIMIT",
            "evidence",
            "Too many evidence references",
        ));
    }
    let mut found = BTreeSet::new();
    let mut groups = BTreeSet::new();
    let mut a = Assessment::default();
    for e in &evidence {
        let kind = verification::string(e, "type")?;
        found.insert(kind.to_owned());
        let source = verification::string(e, "source")?;
        let bytes = crate::resolvers::retrieve(
            app,
            verification::string(e, "id")?,
            &["application/json", "application/ld+json", "application/vc"],
        )
        .await?;
        if let Some(d) = e["digest"].as_str() {
            if crate::storage::digest(&bytes) != d {
                return Err(error(
                    "EVIDENCE_DIGEST",
                    "evidence",
                    "Evidence digest mismatch",
                ));
            }
        } else if kind == "DigestEvidence" {
            return Err(error(
                "EVIDENCE_DIGEST",
                "evidence",
                "Digest evidence requires a digest",
            ));
        }
        let data = crate::models::parse(&bytes)?;
        if kind == "CredentialEvidence" {
            if data["issuer"] != source {
                return Err(error(
                    "EVIDENCE_SOURCE",
                    "evidence",
                    "Evidence source and credential issuer differ",
                ));
            }
            verification::structure(&data)?;
            verification::schema(app, &data)?;
            verification::dates(&data, false)?;
            verification::authenticate(app, &data, "assertionMethod").await?;
            if crate::status::check(app, &data).await? != "active" {
                return Err(error(
                    "EVIDENCE_STATUS",
                    "evidence",
                    "Supporting credential is not active",
                ));
            }
            let group = p.independent_sources.get(source);
            let issuer_group = p
                .independent_sources
                .get(verification::string(v, "issuer")?);
            let comparable = group.is_some()
                && source != verification::string(v, "issuer")?
                && group != issuer_group
                && !p.comparisons.is_empty();
            let mut complete = true;
            for rule in p.comparisons.iter().filter(|_| comparable) {
                let left = v.pointer(&rule.claim_path);
                let right = data.pointer(&rule.evidence_path);
                if left.is_none() || right.is_none() {
                    complete = false;
                } else if left != right {
                    a.contradicted = true;
                    complete = false;
                }
            }
            if comparable && complete {
                groups.insert(group.expect("checked group").clone());
            }
        } else if kind != "DigestEvidence" {
            return Err(error(
                "UNSUPPORTED_EVIDENCE",
                "evidence",
                "Unsupported evidence type",
            ));
        }
    }
    if p.required_evidence_types.iter().any(|t| !found.contains(t)) {
        return Err(error(
            "EVIDENCE_REQUIRED",
            "evidence",
            "Required evidence type is missing",
        ));
    }
    a.verified = !evidence.is_empty();
    a.independent = groups.len();
    Ok(a)
}

/// Compare overlapping properties only; undisclosed claims are not contradictions.
pub fn conflicts(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => a
            .iter()
            .any(|(k, v)| b.get(k).is_some_and(|w| conflicts(v, w))),
        _ => a != b,
    }
}
