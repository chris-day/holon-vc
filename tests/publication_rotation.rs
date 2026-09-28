mod common;
use common::Fixture;
use holon_vc::{
    keys::{Algorithm, PrivateKey},
    public_keys::PublicDocument,
    suites,
    well_known::{self, Generate},
};
#[tokio::test]
async fn retired_keys_leave_did_and_jwks_and_old_pin_fails() {
    let f = Fixture::new().await;
    let next = PrivateKey::generate(Algorithm::Ed25519);
    let s = Fixture::suite(&next, "successor", suites::MODERN, "assertionMethod");
    let mut old = PublicDocument::new(&f.key, "issuer", &s.controller);
    old.status = "retired".into();
    let docs = well_known::build(
        &f.app,
        Generate {
            origin: "https://issuer.example",
            issuer: &s.controller,
            suite: &s,
            key: &next,
            public_keys: vec![old, PublicDocument::new(&next, "successor", &s.controller)],
            policy: None,
            display_name: "Example",
            jwks: true,
            openid: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        docs[".well-known/jwks.json"]["keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        well_known::validate_set(
            &f.app,
            "https://issuer.example",
            &s.controller,
            &f.suite.fingerprint,
            &docs
        )
        .await
        .is_err()
    );
}
