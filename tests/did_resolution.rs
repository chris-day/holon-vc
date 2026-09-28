use holon_vc::{
    did,
    keys::{Algorithm, PrivateKey},
    public_keys::PublicDocument,
};
use serde_json::json;
#[test]
fn translations_and_path_attacks() {
    assert_eq!(
        did::web_url("did:web:issuer.example").unwrap(),
        "https://issuer.example/.well-known/did.json"
    );
    assert_eq!(
        did::web_url("did:web:issuer.example:departments:quality").unwrap(),
        "https://issuer.example/departments/quality/did.json"
    );
    assert_eq!(
        did::web_url("did:web:issuer.example%3A8443").unwrap(),
        "https://issuer.example:8443/.well-known/did.json"
    );
    for d in [
        "did:web:issuer.example:..:secrets",
        "did:web:issuer.example:%2fsecrets",
        "did:web:user@issuer.example",
        "did:web:issuer.example#key",
    ] {
        assert!(did::web_url(d).is_err());
    }
}
#[test]
fn authorization_is_not_key_presence() {
    let key = PrivateKey::generate(Algorithm::Ed25519);
    let public = PublicDocument::new(&key, "key", "did:web:issuer.example");
    let mut doc = json!({"id":public.controller,"verificationMethod":[public.method(false).unwrap()],"authentication":[public.id]});
    assert!(did::authorized(&doc, &public.controller, &public.id, "assertionMethod").is_err());
    doc["assertionMethod"] = json!([public.id]);
    assert_eq!(
        did::authorized(&doc, &public.controller, &public.id, "assertionMethod").unwrap(),
        key.public()
    );
    doc["verificationMethod"][0]["controller"] = "did:web:other.example".into();
    assert!(did::authorized(&doc, &public.controller, &public.id, "assertionMethod").is_err());
}
