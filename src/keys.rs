//! Signature primitives and public encodings; key persistence is separate.
use crate::errors::{Result, crypto_error, error};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use p256::{ecdsa, elliptic_curve::sec1::ToEncodedPoint};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    Ed25519,
    P256,
}

pub enum PrivateKey {
    Ed25519(SigningKey),
    P256(ecdsa::SigningKey),
}

impl PrivateKey {
    pub fn generate(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Ed25519 => Self::Ed25519(SigningKey::generate(&mut OsRng)),
            Algorithm::P256 => Self::P256(ecdsa::SigningKey::random(&mut OsRng)),
        }
    }
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        match algorithm {
            Algorithm::Ed25519 => Ok(Self::Ed25519(SigningKey::from_bytes(
                bytes.try_into().map_err(|_| crypto_error())?,
            ))),
            Algorithm::P256 => Ok(Self::P256(
                ecdsa::SigningKey::from_slice(bytes).map_err(|_| crypto_error())?,
            )),
        }
    }
    pub fn secret_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(match self {
            Self::Ed25519(k) => k.to_bytes().to_vec(),
            Self::P256(k) => k.to_bytes().to_vec(),
        })
    }
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::P256(_) => Algorithm::P256,
        }
    }
    pub fn public(&self) -> PublicKey {
        match self {
            Self::Ed25519(k) => PublicKey {
                algorithm: Algorithm::Ed25519,
                bytes: k.verifying_key().to_bytes().to_vec(),
            },
            Self::P256(k) => PublicKey {
                algorithm: Algorithm::P256,
                bytes: k.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
            },
        }
    }
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(k) => k.sign(message).to_bytes().to_vec(),
            Self::P256(k) => {
                let s: ecdsa::Signature = k.sign(message);
                s.to_bytes().to_vec()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub algorithm: Algorithm,
    pub bytes: Vec<u8>,
}

impl PublicKey {
    pub fn multicodec(&self) -> Vec<u8> {
        let mut bytes = match self.algorithm {
            Algorithm::Ed25519 => vec![0xed, 0x01],
            Algorithm::P256 => vec![0x80, 0x24],
        };
        bytes.extend_from_slice(&self.bytes);
        bytes
    }
    pub fn fingerprint(&self) -> String {
        multibase::encode(multibase::Base::Base58Btc, self.multicodec())
    }
    pub fn from_multicodec(bytes: &[u8]) -> Result<Self> {
        let (algorithm, key) = if bytes.starts_with(&[0xed, 1]) && bytes.len() == 34 {
            (Algorithm::Ed25519, &bytes[2..])
        } else if bytes.starts_with(&[0x80, 0x24]) && bytes.len() == 35 {
            (Algorithm::P256, &bytes[2..])
        } else {
            return Err(error(
                "INVALID_KEY",
                "key",
                "Unsupported or invalid public key encoding",
            ));
        };
        match algorithm {
            Algorithm::Ed25519 => {
                ed25519_dalek::VerifyingKey::from_bytes(
                    key.try_into().map_err(|_| crypto_error())?,
                )
                .map_err(|_| crypto_error())?;
            }
            Algorithm::P256 => {
                p256::PublicKey::from_sec1_bytes(key).map_err(|_| crypto_error())?;
            }
        }
        Ok(Self {
            algorithm,
            bytes: key.to_vec(),
        })
    }
    pub fn from_multibase(s: &str) -> Result<Self> {
        let (base, bytes) = multibase::decode(s).map_err(|_| crypto_error())?;
        if base != multibase::Base::Base58Btc {
            return Err(crypto_error());
        }
        Self::from_multicodec(&bytes)
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self.algorithm {
            Algorithm::Ed25519 => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(
                    self.bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| crypto_error())?,
                )
                .map_err(|_| crypto_error())?;
                let sig =
                    ed25519_dalek::Signature::from_slice(signature).map_err(|_| crypto_error())?;
                key.verify_strict(message, &sig).map_err(|_| crypto_error())
            }
            Algorithm::P256 => {
                use p256::ecdsa::signature::Verifier;
                let key = ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes)
                    .map_err(|_| crypto_error())?;
                let sig = ecdsa::Signature::from_slice(signature).map_err(|_| crypto_error())?;
                key.verify(message, &sig).map_err(|_| crypto_error())
            }
        }
    }
    pub fn jwk(&self, id: &str) -> Result<serde_json::Value> {
        use serde_json::json;
        match self.algorithm {
            Algorithm::Ed25519 => Ok(
                json!({"kid":id,"kty":"OKP","crv":"Ed25519","x":BASE64_URL_SAFE_NO_PAD.encode(&self.bytes),"use":"sig","alg":"EdDSA"}),
            ),
            Algorithm::P256 => {
                let point = p256::PublicKey::from_sec1_bytes(&self.bytes)
                    .map_err(|_| crypto_error())?
                    .to_encoded_point(false);
                Ok(
                    json!({"kid":id,"kty":"EC","crv":"P-256","x":BASE64_URL_SAFE_NO_PAD.encode(point.x().ok_or_else(crypto_error)?),"y":BASE64_URL_SAFE_NO_PAD.encode(point.y().ok_or_else(crypto_error)?),"use":"sig","alg":"ES256"}),
                )
            }
        }
    }
}
