use holon_vc::{
    keys::{Algorithm, PrivateKey},
    public_keys::PublicDocument,
    suites::{LEGACY, MODERN, SuiteConfig},
    trust::Policy,
};
#[test]
fn suite_binding_and_legacy_opt_in() {
    let key = PrivateKey::generate(Algorithm::Ed25519);
    let public = PublicDocument::new(&key, "key", "did:web:issuer.example");
    let mut suite = SuiteConfig {
        name: "default".into(),
        cryptosuite: MODERN.into(),
        key: "key.json".into(),
        verification_method: public.id.clone(),
        controller: public.controller.clone(),
        fingerprint: public.fingerprint.clone(),
        purpose: "assertionMethod".into(),
    };
    suite.validate(&public, false).unwrap();
    suite.cryptosuite = LEGACY.into();
    assert!(suite.validate(&public, false).is_err());
    suite.validate(&public, true).unwrap();
    suite.fingerprint = "wrong".into();
    assert!(suite.validate(&public, true).is_err());
}
#[test]
fn trust_requires_scopes() {
    let key = PrivateKey::generate(Algorithm::Ed25519);
    let p:Policy=serde_json::from_value(serde_json::json!({"id":"test","version":"1.0","issuer":"did:web:issuer.example","verificationMethod":"did:web:issuer.example#key","fingerprint":key.public().fingerprint(),"credentialTypes":[],"schemas":[]})).unwrap();
    assert!(p.validate().is_err());
}
