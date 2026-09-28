//! Test-only bridge; ephemeral test secrets are accepted on stdin, never arguments.
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use holon_vc::{
    disclosure,
    keys::{Algorithm, PrivateKey, PublicKey},
    suites,
};
use serde_json::{Value, json};
use std::io::Read;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let v: Value = serde_json::from_str(&input)?;
    let loader = ssi_json_ld::ContextLoader::default();
    let result = match v["operation"].as_str().unwrap_or("") {
        "sign" => {
            let alg = if v["algorithm"] == "p256" {
                Algorithm::P256
            } else {
                Algorithm::Ed25519
            };
            let secret =
                BASE64_URL_SAFE_NO_PAD.decode(v["secret"].as_str().ok_or("missing secret")?)?;
            let key = PrivateKey::from_bytes(alg, &secret)?;
            let pointers: Vec<String> = serde_json::from_value(v["pointers"].clone())?;
            suites::sign(&v["document"], &key, &v["proof"], &pointers, &loader).await?
        }
        "verify" => {
            let key = PublicKey::from_multibase(v["public"].as_str().ok_or("public")?)?;
            suites::verify(&v["document"], &key, &loader).await?;
            json!({"cryptographicallyValid":true})
        }
        "derive" => {
            let key = PublicKey::from_multibase(v["public"].as_str().ok_or("public")?)?;
            let pointers: Vec<String> = serde_json::from_value(v["pointers"].clone())?;
            disclosure::derive(&v["document"], &key, &pointers, &loader).await?
        }
        _ => return Err("unknown operation".into()),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
