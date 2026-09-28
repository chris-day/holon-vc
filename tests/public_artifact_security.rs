mod common;
use common::Fixture;
use holon_vc::{
    public_keys::PublicDocument,
    well_known::{self, Generate},
};
use serde_json::json;
#[tokio::test]
async fn tampered_artifacts_and_private_material_rejected() {
    let f = Fixture::new().await;
    let docs = well_known::build(
        &f.app,
        Generate {
            origin: "https://issuer.example",
            issuer: &f.suite.controller,
            suite: &f.suite,
            key: &f.key,
            public_keys: vec![PublicDocument::new(&f.key, "issuer", &f.suite.controller)],
            policy: None,
            display_name: "Example",
            jwks: true,
            openid: false,
        },
    )
    .await
    .unwrap();
    for (path, k, v) in [
        (".well-known/jwks.json", "keys", json!([])),
        (
            ".well-known/holon-issuer.json",
            "expires",
            json!("2020-01-01T00:00:00Z"),
        ),
        (".well-known/did.json", "privateKey", json!("canary")),
    ] {
        let mut bad = docs.clone();
        bad.get_mut(path).unwrap()[k] = v;
        assert!(
            well_known::validate_set(
                &f.app,
                "https://issuer.example",
                &f.suite.controller,
                &f.suite.fingerprint,
                &bad
            )
            .await
            .is_err()
        );
    }
    for name in ["d", "seed", "privateKeyMultibase", "ciphertext"] {
        assert!(well_known::public_only(&json!({"nested":[{name:"canary"}]})).is_err());
    }
}
