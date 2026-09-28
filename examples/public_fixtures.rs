//! Generates public-only example artefacts from a disposable key held only in memory.
use holon_vc::{
    app::App,
    config::Config,
    keys::{Algorithm, PrivateKey},
    public_keys::PublicDocument,
    storage,
    suites::{MODERN, SuiteConfig},
    well_known::{self, Generate},
};
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let root = std::env::args().nth(1).expect("output root");
    let key = PrivateKey::generate(Algorithm::Ed25519);
    let issuer = "did:web:issuer.example";
    let public = PublicDocument::new(&key, "example-key", issuer);
    let suite = SuiteConfig {
        name: "example".into(),
        cryptosuite: MODERN.into(),
        key: "unused".into(),
        verification_method: public.id.clone(),
        controller: issuer.into(),
        fingerprint: public.fingerprint.clone(),
        purpose: "assertionMethod".into(),
    };
    let openid = serde_json::json!({"credential_issuer":"https://issuer.example","credential_endpoint":"https://issuer.example/external-service/credential","credential_configurations_supported":{"Holon":{"format":"ldp_vc","cryptographic_binding_methods_supported":["did:web"],"credential_signing_alg_values_supported":[MODERN],"credential_definition":{"@context":["https://www.w3.org/ns/credentials/v2","urn:holon:context:1.0"],"type":["VerifiableCredential","HolonCredential"]}}}});
    let app = App {
        root: std::path::PathBuf::from(&root),
        config: Config {
            openid: Some(openid),
            ..Default::default()
        },
        offline: true,
        development: false,
    };
    let docs = well_known::build(
        &app,
        Generate {
            origin: "https://issuer.example",
            issuer,
            suite: &suite,
            key: &key,
            public_keys: vec![public.clone()],
            policy: None,
            display_name: "Disposable public example (no live issuance service)",
            jwks: true,
            openid: true,
        },
    )
    .await
    .expect("valid example set");
    for (path, value) in docs {
        storage::write_json(&app.root.join("site").join(path), &value, false, false).unwrap();
    }
    storage::write_json(&app.root.join("public-key.json"), &public, false, false).unwrap();
}
