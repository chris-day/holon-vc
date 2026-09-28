mod common;
use common::Fixture;
use holon_vc::{
    credentials,
    keys::{Algorithm, PrivateKey},
    models::Reveal,
    suites, verification,
};
#[tokio::test]
async fn genuine_disclosure_preserves_metadata_and_hides_claims() {
    let f = Fixture::new().await;
    let key = PrivateKey::generate(Algorithm::P256);
    Fixture::pin_did(&f.app, &[(&f.key, "issuer"), (&key, "sd")]).await;
    let s = Fixture::suite(&key, "sd", suites::SELECTIVE, "assertionMethod");
    let v = credentials::issue(
        &f.app,
        &Fixture::holon(),
        &s,
        &key,
        &f.status,
        "urn:holon:schema:1.0",
        None,
        None,
    )
    .await
    .unwrap();
    let reveal = Reveal {
        version: "1.0".into(),
        selective_pointers: vec!["/credentialSubject/claims/name".into()],
    };
    let d = credentials::derive(&f.app, &v, &reveal).await.unwrap();
    assert!(!d.to_string().contains("CANARY-HIDDEN"));
    assert_eq!(d["credentialStatus"], v["credentialStatus"]);
    assert!(
        verification::credential(&f.app, &d, &[])
            .await
            .accepted("authentic-assertion")
    );
    assert!(
        credentials::derive(&f.app, &f.issue().await, &reveal)
            .await
            .is_err()
    );
}
