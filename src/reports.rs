use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Passed,
    Failed,
    Unavailable,
    NotEvaluated,
    NotApplicable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub stage: String,
    pub outcome: Outcome,
    pub code: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub report_version: String,
    pub cryptographically_valid: bool,
    pub issuer_authenticated: bool,
    pub issuer_trusted_for_claim_type: bool,
    pub schema_valid: bool,
    pub status: String,
    pub freshness_valid: bool,
    pub evidence_verified: bool,
    pub holder_authenticated: bool,
    pub decision: String,
    pub confidence: f64,
    pub policy: serde_json::Value,
    pub checks: Vec<Check>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<VerificationReport>,
}
impl Default for VerificationReport {
    fn default() -> Self {
        Self {
            report_version: "1.0".into(),
            cryptographically_valid: false,
            issuer_authenticated: false,
            issuer_trusted_for_claim_type: false,
            schema_valid: false,
            status: "unavailable".into(),
            freshness_valid: false,
            evidence_verified: false,
            holder_authenticated: false,
            decision: "unverified".into(),
            confidence: 0.0,
            policy: serde_json::json!({"id":"holon-default","version":"1.0","confidenceModel":"ordinal-policy-score-not-probability"}),
            checks: vec![],
            warnings: vec![],
            errors: vec![],
            credentials: vec![],
        }
    }
}
impl VerificationReport {
    pub fn check(&mut self, stage: &str, result: crate::errors::Result<()>) -> bool {
        match result {
            Ok(()) => {
                self.checks.push(Check {
                    stage: stage.into(),
                    outcome: Outcome::Passed,
                    code: "OK".into(),
                });
                true
            }
            Err(e) => {
                self.checks.push(Check {
                    stage: stage.into(),
                    outcome: if e.code.contains("UNAVAILABLE") {
                        Outcome::Unavailable
                    } else {
                        Outcome::Failed
                    },
                    code: e.code.into(),
                });
                self.errors.push(e.code.into());
                false
            }
        }
    }
    pub fn complete_stages(&mut self, stages: &[&str]) {
        for stage in stages {
            if !self.checks.iter().any(|c| c.stage == *stage) {
                self.checks.push(Check {
                    stage: (*stage).into(),
                    outcome: Outcome::NotEvaluated,
                    code: "NOT_EVALUATED".into(),
                });
            }
        }
    }
    pub fn accepted(&self, threshold: &str) -> bool {
        let rank = |d: &str| match d {
            "authentic-assertion" => 1,
            "trusted-assertion" => 2,
            "corroborated" => 3,
            _ => 0,
        };
        rank(threshold) > 0 && rank(&self.decision) > 0 && rank(&self.decision) >= rank(threshold)
    }
}
