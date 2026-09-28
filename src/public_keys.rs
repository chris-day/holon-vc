use crate::{
    errors::{Result, error},
    keys::{Algorithm, PrivateKey, PublicKey},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub controller: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub public_key_multibase: String,
    pub fingerprint: String,
    pub created: String,
    pub status: String,
    #[serde(default)]
    pub rotation_history: Vec<String>,
}
impl PublicDocument {
    pub fn new(key: &PrivateKey, id: &str, controller: &str) -> Self {
        let f = key.public().fingerprint();
        Self {
            context: vec!["https://w3id.org/security/multikey/v1".into()],
            id: format!("{controller}#{id}"),
            controller: controller.into(),
            type_: "Multikey".into(),
            public_key_multibase: f.clone(),
            fingerprint: f,
            created: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            status: "active".into(),
            rotation_history: vec![],
        }
    }
    pub fn key(&self) -> Result<PublicKey> {
        crate::did::web_url(&self.controller)?;
        crate::models::date(&self.created)?;
        if !["active", "retired"].contains(&self.status.as_str())
            || self.context != ["https://w3id.org/security/multikey/v1"]
        {
            return Err(error("INVALID_KEY", "key", "Invalid key metadata"));
        }
        let key = PublicKey::from_multibase(&self.public_key_multibase)?;
        if key.fingerprint() != self.fingerprint
            || !self.id.starts_with(&format!("{}#", self.controller))
            || self.type_ != "Multikey"
        {
            return Err(error(
                "KEY_SUBSTITUTION",
                "key",
                "Public-key identity or fingerprint mismatch",
            ));
        }
        Ok(key)
    }
    pub fn method(&self, legacy: bool) -> Result<serde_json::Value> {
        self.key()?;
        Ok(
            serde_json::json!({"id":self.id,"controller":self.controller,"type":if legacy{"Ed25519VerificationKey2020"}else{"Multikey"},"publicKeyMultibase":self.public_key_multibase}),
        )
    }
    pub fn algorithm(&self) -> Result<Algorithm> {
        Ok(self.key()?.algorithm)
    }
}
