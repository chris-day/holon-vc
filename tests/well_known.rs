mod common;
use common::Fixture;
use holon_vc::{
    public_keys::PublicDocument,
    well_known::{self, Generate},
};
#[tokio::test]
async fn origin_and_path_publications_validate() {
    for did in [
        "did:web:issuer.example",
        "did:web:issuer.example:departments:quality",
    ] {
        let f = Fixture::new().await;
        let mut s = f.suite.clone();
        s.controller = did.into();
        s.verification_method = format!("{did}#issuer");
        let docs = well_known::build(
            &f.app,
            Generate {
                origin: "https://issuer.example",
                issuer: did,
                suite: &s,
                key: &f.key,
                public_keys: vec![PublicDocument::new(&f.key, "issuer", did)],
                policy: None,
                display_name: "Example",
                jwks: true,
                openid: false,
            },
        )
        .await
        .unwrap();
        let dir = f.app.root.join("publication/.well-known");
        well_known::publish(&f.app, &dir, &docs, false).unwrap();
        let loaded = well_known::load_set(&f.app, "https://issuer.example", did, Some(&dir))
            .await
            .unwrap();
        well_known::validate_set(
            &f.app,
            "https://issuer.example",
            did,
            &s.fingerprint,
            &loaded,
        )
        .await
        .unwrap();
        if did.contains("departments") {
            assert!(
                dir.parent()
                    .unwrap()
                    .join("departments/quality/did.json")
                    .exists()
            );
            assert!(!dir.join("did.json").exists());
        }
        assert!(well_known::publish(&f.app, &dir, &docs, false).is_err());
    }
}
