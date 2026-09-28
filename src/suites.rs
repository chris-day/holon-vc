//! Data Integrity proof construction. No implicit algorithm selection or fallback.
use crate::{
    canonicalization,
    errors::{Result, crypto_error, error},
    keys::{Algorithm, PrivateKey, PublicKey},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ssi_json_ld::Loader;

pub const MODERN: &str = "eddsa-rdfc-2022";
pub const SELECTIVE: &str = "ecdsa-sd-2023";
pub const LEGACY: &str = "Ed25519Signature2020";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuiteConfig {
    pub name: String,
    pub cryptosuite: String,
    pub key: std::path::PathBuf,
    pub verification_method: String,
    pub controller: String,
    pub fingerprint: String,
    pub purpose: String,
}
impl SuiteConfig {
    pub fn validate(
        &self,
        public: &crate::public_keys::PublicDocument,
        legacy: bool,
    ) -> Result<()> {
        crate::storage::safe_id(&self.name)?;
        let alg = public.algorithm()?;
        if self.controller != public.controller
            || self.verification_method != public.id
            || self.fingerprint != public.fingerprint
            || public.status != "active"
        {
            return Err(error(
                "KEY_SUBSTITUTION",
                "suite",
                "Suite key/controller/fingerprint mismatch or inactive key",
            ));
        }
        if !["assertionMethod", "authentication"].contains(&self.purpose.as_str()) {
            return Err(error(
                "INVALID_PURPOSE",
                "suite",
                "Unsupported proof purpose",
            ));
        }
        match self.cryptosuite.as_str() {
            MODERN if alg == Algorithm::Ed25519 => Ok(()),
            SELECTIVE if alg == Algorithm::P256 && self.purpose == "assertionMethod" => Ok(()),
            LEGACY if alg == Algorithm::Ed25519 && legacy => Ok(()),
            _ => Err(error(
                "KEY_SUITE_MISMATCH",
                "suite",
                "Unsupported suite/key/purpose combination or missing --legacy",
            )),
        }
    }
}

pub fn suite(proof: &Value) -> Result<&str> {
    match proof.get("type").and_then(Value::as_str) {
        Some(LEGACY) if proof.get("cryptosuite").is_none() => Ok(LEGACY),
        Some("DataIntegrityProof") => match proof.get("cryptosuite").and_then(Value::as_str) {
            Some(MODERN) => Ok(MODERN),
            Some(SELECTIVE) => Ok(SELECTIVE),
            _ => Err(error(
                "UNSUPPORTED_SUITE",
                "cryptosuite",
                "Unsupported Data Integrity cryptosuite",
            )),
        },
        _ => Err(error(
            "UNSUPPORTED_SUITE",
            "cryptosuite",
            "Unsupported proof type",
        )),
    }
}

pub fn split(document: &Value) -> Result<(Value, Value)> {
    let mut unsigned = document.clone();
    let proof = unsigned
        .as_object_mut()
        .ok_or_else(crypto_error)?
        .remove("proof")
        .ok_or_else(crypto_error)?;
    if !proof.is_object() {
        return Err(error(
            "PROOF_STRUCTURE",
            "structure",
            "Exactly one proof object is required by this profile",
        ));
    }
    suite(&proof)?;
    Ok((unsigned, proof))
}

pub async fn proof_hash(
    document: &Value,
    proof: &Value,
    loader: &impl Loader,
    legacy: bool,
) -> Result<[u8; 32]> {
    let mut config = proof.clone();
    let object = config.as_object_mut().ok_or_else(crypto_error)?;
    object.remove("proofValue");
    // Context is inherited from the unsecured document, not supplied by the attacker.
    object.insert(
        "@context".into(),
        document.get("@context").ok_or_else(crypto_error)?.clone(),
    );
    Ok(Sha256::digest(
        canonicalization::canonicalize(&config, loader, legacy)
            .await?
            .as_bytes(),
    )
    .into())
}

pub async fn sign(
    document: &Value,
    key: &PrivateKey,
    proof: &Value,
    mandatory: &[String],
    loader: &impl Loader,
) -> Result<Value> {
    if document.get("proof").is_some() {
        return Err(crypto_error());
    }
    let kind = suite(proof)?;
    if kind == SELECTIVE {
        return crate::disclosure::issue(document, key, proof, mandatory, loader).await;
    }
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(error(
            "KEY_SUITE_MISMATCH",
            "cryptosuite",
            "Ed25519 is required for this suite",
        ));
    }
    let mut input = proof_hash(document, proof, loader, kind == LEGACY)
        .await?
        .to_vec();
    input.extend_from_slice(&Sha256::digest(
        canonicalization::canonicalize(document, loader, kind == LEGACY)
            .await?
            .as_bytes(),
    ));
    let mut result = document.clone();
    let mut proof = proof.clone();
    proof["proofValue"] = Value::String(multibase::encode(
        multibase::Base::Base58Btc,
        key.sign(&input),
    ));
    result["proof"] = proof;
    Ok(result)
}

/// Cryptography only. Authorization, status, schema, dates and trust are independent stages.
pub async fn verify(document: &Value, key: &PublicKey, loader: &impl Loader) -> Result<()> {
    let (unsigned, proof) = split(document)?;
    let kind = suite(&proof)?;
    if kind == SELECTIVE {
        return crate::disclosure::verify(document, key, loader).await;
    }
    if key.algorithm != Algorithm::Ed25519 {
        return Err(crypto_error());
    }
    let mut input = proof_hash(&unsigned, &proof, loader, kind == LEGACY)
        .await?
        .to_vec();
    input.extend_from_slice(&Sha256::digest(
        canonicalization::canonicalize(&unsigned, loader, kind == LEGACY)
            .await?
            .as_bytes(),
    ));
    let (base, bytes) = multibase::decode(proof["proofValue"].as_str().ok_or_else(crypto_error)?)
        .map_err(|_| crypto_error())?;
    if base != multibase::Base::Base58Btc {
        return Err(crypto_error());
    }
    key.verify(&input, &bytes)
}
