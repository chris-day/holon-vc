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
        let manifest = &docs[".well-known/manifest.json"];
        let from = holon_vc::models::date(manifest["generatedAt"].as_str().unwrap()).unwrap();
        let until = holon_vc::models::date(manifest["expires"].as_str().unwrap()).unwrap();
        assert_eq!(until - from, chrono::Duration::days(365));
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

#[tokio::test]
async fn static_host_json_did_preserves_digest_and_media_checks() {
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
            display_name: "Static host",
            jwks: true,
            openid: false,
        },
    )
    .await
    .unwrap();
    let dir = f.app.root.join("publication/.well-known");
    well_known::publish(&f.app, &dir, &docs, false).unwrap();
    let did_url = "https://issuer.example/.well-known/did.json";
    let did_path = dir.join("did.json");
    holon_vc::resolvers::pin(&f.app, did_url, &did_path, "application/json", 300).unwrap();
    let loaded = well_known::load_set(&f.app, "https://issuer.example", &f.suite.controller, None)
        .await
        .unwrap();
    well_known::validate_set(
        &f.app,
        "https://issuer.example",
        &f.suite.controller,
        &f.suite.fingerprint,
        &loaded,
    )
    .await
    .unwrap();

    holon_vc::resolvers::pin(&f.app, did_url, &did_path, "text/html", 300).unwrap();
    let error = well_known::load_set(&f.app, "https://issuer.example", &f.suite.controller, None)
        .await
        .unwrap_err();
    assert_eq!(error.code, "MEDIA_TYPE");

    let mut altered = docs[".well-known/did.json"].clone();
    altered["id"] = "did:web:other.example".into();
    holon_vc::storage::write_json(&did_path, &altered, false, true).unwrap();
    holon_vc::resolvers::pin(&f.app, did_url, &did_path, "application/json", 300).unwrap();
    let error = well_known::load_set(&f.app, "https://issuer.example", &f.suite.controller, None)
        .await
        .unwrap_err();
    assert_eq!(error.code, "DIGEST_MISMATCH");
}
