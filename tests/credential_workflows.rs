mod common;
use common::Fixture;
use holon_vc::{credentials, suites, verification};
use serde_json::json;
#[tokio::test]
async fn modern_legacy_tampering_and_dates() {
    let f = Fixture::new().await;
    let v = f.issue().await;
    let r = verification::credential(&f.app, &v, &[]).await;
    assert_eq!(r.decision, "authentic-assertion", "{r:?}");
    let mut bad = v.clone();
    bad["credentialSubject"]["claims"]["name"] = json!("changed");
    assert!(
        !verification::credential(&f.app, &bad, &[])
            .await
            .cryptographically_valid
    );
    bad = v.clone();
    bad["validUntil"] = json!("2020-01-01T00:00:00Z");
    assert!(
        !verification::credential(&f.app, &bad, &[])
            .await
            .freshness_valid
    );
    bad = v.clone();
    bad["proof"]["proofPurpose"] = json!("authentication");
    assert!(
        !verification::credential(&f.app, &bad, &[])
            .await
            .issuer_authenticated
    );
    let mut legacy = f.suite.clone();
    legacy.cryptosuite = suites::LEGACY.into();
    let v = credentials::issue(
        &f.app,
        &Fixture::holon(),
        &legacy,
        &f.key,
        &f.status,
        "urn:holon:schema:1.0",
        None,
        None,
    )
    .await
    .unwrap();
    assert!(
        verification::credential(&f.app, &v, &[])
            .await
            .cryptographically_valid
    );
}
#[tokio::test]
async fn undefined_and_null_claims_rejected() {
    let f = Fixture::new().await;
    for (k, value) in [("secret", json!(null)), ("unmapped", json!("silent loss"))] {
        let mut h = Fixture::holon();
        h["claims"][k] = value;
        assert!(
            credentials::issue(
                &f.app,
                &h,
                &f.suite,
                &f.key,
                &f.status,
                "urn:holon:schema:1.0",
                None,
                None
            )
            .await
            .is_err()
        );
    }
}
#[tokio::test]
async fn documented_holon_expands() {
    let f = Fixture::new().await;
    let full: serde_json::Value =
        serde_json::from_str(include_str!("../examples/holon.json")).unwrap();
    for k in ["claims", "source", "evidence", "relatedHolons"] {
        let mut h = Fixture::holon();
        h[k] = full[k].clone();
        let result = credentials::issue(
            &f.app,
            &h,
            &f.suite,
            &f.key,
            &f.status,
            "urn:holon:schema:1.0",
            None,
            None,
        )
        .await;
        assert!(result.is_ok(), "Field {k}: {result:?}");
    }
}
