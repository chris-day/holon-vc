use crate::{
    errors::{Result, error},
    storage,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub version: String,
    pub issuer: String,
    pub verification_method: String,
    pub fingerprint: String,
    pub credential_types: Vec<String>,
    pub schemas: Vec<String>,
    #[serde(default = "assertion")]
    pub proof_purposes: Vec<String>,
    #[serde(default)]
    pub cryptosuites: Vec<String>,
    #[serde(default)]
    pub max_age_seconds: Option<i64>,
    #[serde(default)]
    pub required_evidence_types: Vec<String>,
    #[serde(default)]
    pub minimum_independent_sources: usize,
    #[serde(default)]
    pub accepted_domains: Vec<String>,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub quarantine_instructions: bool,
    #[serde(default)]
    pub comparisons: Vec<Comparison>,
    #[serde(default)]
    pub independent_sources: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub offline_only: bool,
    #[serde(default)]
    pub require_status: bool,
}
fn enabled() -> bool {
    true
}
fn assertion() -> Vec<String> {
    vec!["assertionMethod".into()]
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Comparison {
    pub claim_path: String,
    pub evidence_path: String,
    #[serde(default = "equality")]
    pub operator: String,
}
fn equality() -> String {
    "equal".into()
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        storage::safe_id(&self.id)?;
        crate::did::web_url(&self.issuer)?;
        if !self
            .verification_method
            .starts_with(&format!("{}#", self.issuer))
            || self.proof_purposes.is_empty()
            || self.minimum_independent_sources > 32
            || self.max_age_seconds.is_some_and(|s| s < 0)
            || self.independent_sources.values().any(|s| s.is_empty())
        {
            return Err(error(
                "INVALID_POLICY",
                "policy",
                "Invalid policy authority or bounds",
            ));
        }
        if self.version != "1.0"
            || self.credential_types.is_empty()
            || self.schemas.is_empty()
            || self.proof_purposes.iter().any(|p| p != "assertionMethod")
            || self.comparisons.iter().any(|c| {
                c.operator != "equal"
                    || c.claim_path.parse::<ssi_core::JsonPointerBuf>().is_err()
                    || c.evidence_path.parse::<ssi_core::JsonPointerBuf>().is_err()
            })
        {
            return Err(error(
                "INVALID_POLICY",
                "policy",
                "Malformed or unsupported trust policy",
            ));
        }
        crate::keys::PublicKey::from_multibase(&self.fingerprint)?;
        Ok(())
    }
}

pub async fn evaluate(
    app: &crate::app::App,
    v: &serde_json::Value,
    key: &crate::keys::PublicKey,
    policies: &[Policy],
    r: &mut crate::reports::VerificationReport,
) {
    use crate::verification;
    let policy = policies.iter().find(|p| {
        p.enabled
            && v["issuer"] == p.issuer
            && v["proof"]["verificationMethod"] == p.verification_method
            && key.fingerprint() == p.fingerprint
            && p.credential_types
                .iter()
                .any(|t| verification::has_type(v, t))
            && v["credentialSchema"]["id"]
                .as_str()
                .is_some_and(|s| p.schemas.iter().any(|x| x == s))
    });
    let Some(p) = policy else {
        r.warnings.push(
            "No scoped issuer policy matched; signature validity alone does not establish trust."
                .into(),
        );
        return;
    };
    r.policy = serde_json::json!({"id":p.id,"version":p.version,"confidenceModel":"ordinal-policy-score-not-probability"});
    let requirements = (|| -> Result<()> {
        if !p
            .proof_purposes
            .iter()
            .any(|x| v["proof"]["proofPurpose"] == *x)
            || (!p.cryptosuites.is_empty()
                && !p.cryptosuites.iter().any(|s| {
                    verification::string(&v["proof"], "cryptosuite").ok() == Some(s)
                        || v["proof"]["type"] == *s
                }))
        {
            return Err(error(
                "POLICY_SUITE",
                "policy",
                "Proof purpose or cryptosuite is not permitted",
            ));
        }
        if p.offline_only && !app.offline {
            return Err(error(
                "POLICY_NETWORK",
                "policy",
                "Policy requires offline resolution",
            ));
        }
        if let Some(age) = p.max_age_seconds {
            let from = crate::models::date(verification::string(v, "validFrom")?)?;
            if age < 0 || chrono::Utc::now().signed_duration_since(from).num_seconds() > age {
                return Err(error(
                    "POLICY_FRESHNESS",
                    "policy",
                    "Maximum credential age exceeded",
                ));
            }
        }
        if !p.accepted_domains.is_empty() {
            let url = crate::did::web_url(&p.issuer)?;
            let u = url::Url::parse(&url)
                .map_err(|_| error("POLICY_DOMAIN", "policy", "Invalid issuer origin"))?;
            if !p
                .accepted_domains
                .contains(&u.origin().ascii_serialization())
            {
                return Err(error(
                    "POLICY_DOMAIN",
                    "policy",
                    "Issuer HTTPS origin is not permitted",
                ));
            }
        }
        if p.quarantine_instructions && crate::evidence::instruction_like(&v["credentialSubject"]) {
            return Err(error(
                "CONTENT_QUARANTINED",
                "policy",
                "Instruction-like content requires quarantine",
            ));
        }
        Ok(())
    })();
    if !r.check("policy", requirements) {
        r.decision = "rejected".into();
        r.confidence = 0.0;
        return;
    }
    match crate::evidence::assess(app, v, p).await {
        Ok(a) => {
            r.evidence_verified = a.verified;
            if a.contradicted {
                r.decision = "disputed".into();
                r.confidence = 0.0;
                r.warnings.push("Authenticated evidence contradicts the configured claim comparison. Retain both assertions.".into());
                return;
            }
            if a.independent < p.minimum_independent_sources {
                r.check(
                    "evidence",
                    Err(error(
                        "INSUFFICIENT_EVIDENCE",
                        "evidence",
                        "Independent evidence threshold not met",
                    )),
                );
                r.decision = "unverified".into();
                r.confidence = 0.0;
                return;
            }
            r.issuer_trusted_for_claim_type = true;
            r.decision = if a.independent > 0 {
                "corroborated"
            } else {
                "trusted-assertion"
            }
            .into();
            r.confidence = if a.independent > 0 { 1.0 } else { 0.75 };
            if a.verified {
                r.check("evidence", Ok(()));
            } else {
                r.warnings
                    .push("Supporting evidence was not verified.".into());
            }
        }
        Err(e) => {
            r.check("evidence", Err(e));
            r.decision = "unverified".into();
            r.confidence = 0.0;
        }
    }
}
