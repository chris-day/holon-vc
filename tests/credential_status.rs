mod common;
use base64::Engine;
use common::Fixture;
use holon_vc::{status, verification};
use std::io::Read;
#[tokio::test]
async fn status_transitions_and_bit_order() {
    let f = Fixture::new().await;
    let v = f.issue().await;
    for (op, want) in [
        ("suspend", "suspended"),
        ("restore", "active"),
        ("revoke", "revoked"),
    ] {
        status::update(&f.app, &f.status, &v, op, &f.suite, &f.key)
            .await
            .unwrap();
        assert_eq!(verification::credential(&f.app, &v, &[]).await.status, want);
    }
    assert!(
        status::update(&f.app, &f.status, &v, "restore", &f.suite, &f.key)
            .await
            .is_err()
    );
    status::create(
        &f.app,
        "main",
        "https://issuer.example/status/main",
        &f.suite,
        &f.key,
        &f.status,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        verification::credential(&f.app, &v, &[]).await.status,
        "revoked"
    );
    let r = status::load(&f.status).unwrap();
    for list in r.lists.values() {
        let from = holon_vc::models::date(list["validFrom"].as_str().unwrap()).unwrap();
        let until = holon_vc::models::date(list["validUntil"].as_str().unwrap()).unwrap();
        assert_eq!(until - from, chrono::Duration::days(365));
    }
    let s = r.lists["revocation"]["credentialSubject"]["encodedList"]
        .as_str()
        .unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&s[1..])
        .unwrap();
    let mut bits = vec![];
    flate2::read::GzDecoder::new(bytes.as_slice())
        .read_to_end(&mut bits)
        .unwrap();
    assert_eq!(bits.len(), 16384);
    assert_eq!(bits[0], 0x80);
}
#[tokio::test]
async fn missing_status_is_never_active() {
    let f = Fixture::new().await;
    let mut v = f.issue().await;
    v["credentialStatus"][0]["statusListCredential"] = "https://missing.example/list".into();
    v["credentialStatus"][0]["id"] = "https://missing.example/list#0".into();
    let r = verification::credential(&f.app, &v, &[]).await;
    assert_eq!(r.status, "unavailable");
    assert!(!r.accepted("authentic-assertion"));
}
#[tokio::test]
async fn status_ttl_is_not_overridden_by_long_pin_expiry() {
    let f = Fixture::new().await;
    let v = f.issue().await;
    let mut pins = holon_vc::resolvers::generated_pins(&f.app).unwrap();
    for (url, pin) in &mut pins {
        if url.contains("/status/") {
            pin.retrieved_at =
                Some((chrono::Utc::now() - chrono::Duration::minutes(6)).to_rfc3339());
            pin.expires = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        }
    }
    holon_vc::storage::write_json(&f.app.root.join("config/resources.json"), &pins, true, true)
        .unwrap();
    let r = verification::credential(&f.app, &v, &[]).await;
    assert_eq!(r.status, "unavailable");
    assert!(!r.accepted("authentic-assertion"));
}
