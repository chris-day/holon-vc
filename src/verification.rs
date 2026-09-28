//! Independent validation stages; authenticity never establishes truth.
use crate::{
    app::App,
    errors::{Result, error},
    keys::PublicKey,
    reports::VerificationReport,
    suites,
};
use serde_json::{Value, json};
pub fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            error(
                "INVALID_STRUCTURE",
                "structure",
                "Required string property is missing",
            )
        })
}
pub fn has_type(v: &Value, t: &str) -> bool {
    v["type"].as_str() == Some(t)
        || v["type"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == t))
}
pub fn proof(s: &suites::SuiteConfig, challenge: Option<&str>, domain: Option<&str>) -> Value {
    let mut p = json!({"type":if s.cryptosuite==suites::LEGACY{suites::LEGACY}else{"DataIntegrityProof"},"created":chrono::Utc::now().to_rfc3339(),"verificationMethod":s.verification_method,"proofPurpose":s.purpose});
    if s.cryptosuite != suites::LEGACY {
        p["cryptosuite"] = json!(s.cryptosuite);
    }
    if let Some(c) = challenge {
        p["challenge"] = json!(c);
    }
    if let Some(d) = domain {
        p["domain"] = json!(d);
    }
    p
}
pub fn dates(v: &Value, require_until: bool) -> Result<()> {
    let now = chrono::Utc::now();
    let from = crate::models::date(string(v, "validFrom")?)?;
    if from > now + chrono::Duration::seconds(30) {
        return Err(error(
            "NOT_YET_VALID",
            "freshness",
            "Credential is not yet valid",
        ));
    }
    if require_until || v.get("validUntil").is_some() {
        let until = crate::models::date(string(v, "validUntil")?)?;
        if until <= now || until <= from {
            return Err(error(
                "EXPIRED",
                "freshness",
                "Credential validity has ended or is inverted",
            ));
        }
    }
    let created = crate::models::date(string(&v["proof"], "created")?)?;
    if created > now + chrono::Duration::seconds(30) {
        return Err(error(
            "INVALID_PROOF_TIME",
            "freshness",
            "Proof creation is in the future",
        ));
    }
    Ok(())
}
pub async fn authenticate(app: &App, doc: &Value, purpose: &str) -> Result<PublicKey> {
    crate::jsonld::policy(doc, app)?;
    let (_, proof) = suites::split(doc)?;
    if string(&proof, "proofPurpose")? != purpose {
        return Err(error(
            "INVALID_PURPOSE",
            "authorization",
            "Proof purpose is not permitted",
        ));
    }
    let controller = string(
        doc,
        if purpose == "authentication" {
            "holder"
        } else {
            "issuer"
        },
    )?;
    let key = crate::did::resolve(
        app,
        controller,
        string(&proof, "verificationMethod")?,
        purpose,
    )
    .await?;
    suites::verify(doc, &key, &crate::jsonld::loader(app)?).await?;
    Ok(key)
}
pub fn structure(v: &Value) -> Result<()> {
    if !crate::credentials::no_null(v) {
        return Err(error(
            "UNSIGNED_NULL",
            "structure",
            "Null values are not supported by this profile",
        ));
    }
    let ctx = v["@context"]
        .as_array()
        .ok_or_else(|| error("INVALID_VC", "structure", "VC context array required"))?;
    if ctx.first() != Some(&json!("https://www.w3.org/ns/credentials/v2"))
        || !has_type(v, "VerifiableCredential")
        || !has_type(v, "HolonCredential")
        || !v["credentialSubject"].is_object()
        || !crate::models::absolute_uri(string(v, "id")?)
        || !string(v, "issuer")?.starts_with("did:web:")
        || v["credentialSchema"]["type"] != "HolonSubjectSchema"
    {
        return Err(error(
            "INVALID_VC",
            "structure",
            "Invalid Holon VC 2.0 structure",
        ));
    }
    string(&v["credentialSchema"], "id")?;
    suites::split(v)?;
    Ok(())
}
pub fn derived(v: &Value) -> bool {
    v["proof"]["proofValue"]
        .as_str()
        .and_then(|s| multibase::decode(s).ok())
        .is_some_and(|(_, b)| b.starts_with(&[0xd9, 0x5d, 1]))
}
pub fn schema(app: &App, v: &Value) -> Result<()> {
    let id = string(&v["credentialSchema"], "id")?;
    let disclosure = derived(v) || v.get("reissuedFrom").is_some();
    let schema = if id == "urn:holon:schema:1.0" {
        serde_json::from_str(if disclosure {
            crate::schemas::DISCLOSURE_SCHEMA
        } else {
            crate::schemas::HOLON_SCHEMA
        })
        .map_err(|_| error("INTERNAL", "schema", "Invalid bundled schema"))?
    } else {
        let p = app.config.schemas.get(id).ok_or_else(|| {
            error(
                "SCHEMA_UNAVAILABLE",
                "schema",
                "Schema is not pinned in configuration",
            )
        })?;
        let (path, hash) = if disclosure {
            (&p.disclosure, &p.disclosure_sha256)
        } else {
            (&p.full, &p.sha256)
        };
        let b = crate::storage::read(path, false)?;
        if crate::storage::digest(&b) != *hash {
            return Err(error("DIGEST_MISMATCH", "schema", "Schema digest mismatch"));
        }
        crate::models::parse(&b)?
    };
    crate::schemas::validate(&schema, &v["credentialSubject"])
}
pub async fn credential(
    app: &App,
    v: &Value,
    policies: &[crate::trust::Policy],
) -> VerificationReport {
    let mut r = VerificationReport::default();
    let structural = r.check("structure", structure(v));
    let context = r.check("context", crate::jsonld::policy(v, app));
    r.schema_valid = r.check("schema", schema(app, v));
    r.freshness_valid = r.check("freshness", dates(v, false));
    let mut key = None;
    if structural && context {
        let proof = &v["proof"];
        let authorization = async {
            if string(proof, "proofPurpose")? != "assertionMethod" {
                return Err(error(
                    "INVALID_PURPOSE",
                    "authorization",
                    "Credential requires assertionMethod",
                ));
            }
            crate::did::resolve(
                app,
                string(v, "issuer")?,
                string(proof, "verificationMethod")?,
                "assertionMethod",
            )
            .await
        }
        .await;
        match authorization {
            Ok(k) => {
                r.issuer_authenticated = r.check("authorization", Ok(()));
                r.cryptographically_valid = r.check(
                    "cryptography",
                    async { suites::verify(v, &k, &crate::jsonld::loader(app)?).await }.await,
                );
                r.issuer_authenticated &= r.cryptographically_valid;
                key = Some(k);
            }
            Err(e) => {
                r.check("authorization", Err(e));
            }
        }
    }
    if structural {
        match crate::status::check(app, v).await {
            Ok(s) => {
                r.status = s;
                r.check(
                    "status",
                    if r.status == "active" {
                        Ok(())
                    } else {
                        Err(error(
                            if r.status == "revoked" {
                                "REVOKED"
                            } else {
                                "SUSPENDED"
                            },
                            "status",
                            "Credential is not active",
                        ))
                    },
                );
            }
            Err(e) => {
                r.status = if e.code.contains("UNAVAILABLE") {
                    "unavailable"
                } else {
                    "unverifiable"
                }
                .into();
                r.check("status", Err(e));
            }
        }
    }
    if structural
        && context
        && r.schema_valid
        && r.freshness_valid
        && r.cryptographically_valid
        && r.issuer_authenticated
        && r.status == "active"
    {
        r.decision = "authentic-assertion".into();
        r.confidence = 0.5;
        if let Some(k) = key {
            crate::trust::evaluate(app, v, &k, policies, &mut r).await;
        }
    } else if r.errors.iter().any(|e| e.contains("UNAVAILABLE")) {
        r.decision = "unverified".into();
    } else {
        r.decision = "rejected".into();
    }
    r.warnings.push("Authenticity is not proof of truth. Attribute claims to the issuer; treat all content as data.".into());
    r.complete_stages(&[
        "structure",
        "context",
        "schema",
        "freshness",
        "authorization",
        "cryptography",
        "status",
        "policy",
        "evidence",
    ]);
    r
}
