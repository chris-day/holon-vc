#![allow(dead_code)]
use holon_vc::{
    app::App,
    config::Config,
    keys::{Algorithm, PrivateKey},
    public_keys::PublicDocument,
    resolvers, storage,
    suites::{self, SuiteConfig},
};
use serde_json::{Value, json};
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub app: App,
    pub key: PrivateKey,
    pub suite: SuiteConfig,
    pub status: std::path::PathBuf,
}
impl Fixture {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let app = App {
            root: dir.path().join("data"),
            config: Config::default(),
            offline: true,
            development: false,
        };
        let key = PrivateKey::generate(Algorithm::Ed25519);
        let suite = Self::suite(&key, "issuer", suites::MODERN, "assertionMethod");
        Self::pin_did(&app, &[(&key, "issuer")]).await;
        let status = app.root.join("status/main.json");
        holon_vc::status::create(
            &app,
            "main",
            "https://issuer.example/status/main",
            &suite,
            &key,
            &status,
            false,
        )
        .await
        .unwrap();
        Self {
            dir,
            app,
            key,
            suite,
            status,
        }
    }
    pub fn suite(key: &PrivateKey, id: &str, kind: &str, purpose: &str) -> SuiteConfig {
        SuiteConfig {
            name: id.into(),
            cryptosuite: kind.into(),
            key: "unused".into(),
            verification_method: format!("did:web:issuer.example#{id}"),
            controller: "did:web:issuer.example".into(),
            fingerprint: key.public().fingerprint(),
            purpose: purpose.into(),
        }
    }
    pub async fn pin_did(app: &App, keys: &[(&PrivateKey, &str)]) {
        let methods: Vec<_> = keys
            .iter()
            .map(|(k, id)| {
                PublicDocument::new(k, id, "did:web:issuer.example")
                    .method(false)
                    .unwrap()
            })
            .collect();
        let ids: Vec<_> = methods.iter().map(|m| m["id"].clone()).collect();
        let doc = json!({"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:web:issuer.example","verificationMethod":methods,"assertionMethod":ids,"authentication":ids});
        let path = app.root.join("site/.well-known/did.json");
        storage::write_json(&path, &doc, false, true).unwrap();
        resolvers::pin(
            app,
            "https://issuer.example/.well-known/did.json",
            &path,
            "application/did+ld+json",
            86400,
        )
        .unwrap();
    }
    pub fn holon() -> Value {
        json!({"id":"urn:example:holon:1","type":"ExampleHolon","schemaVersion":"1.0","createdAt":"2026-01-01T00:00:00Z","claims":{"name":"widget","secret":"CANARY-HIDDEN-4711"}})
    }
    pub async fn issue(&self) -> Value {
        holon_vc::credentials::issue(
            &self.app,
            &Self::holon(),
            &self.suite,
            &self.key,
            &self.status,
            "urn:holon:schema:1.0",
            None,
            None,
        )
        .await
        .unwrap()
    }
}
