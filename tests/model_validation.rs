use holon_vc::{holon, models, schemas};
use serde_json::json;
#[test]
fn duplicates_and_trailing_json() {
    for v in [
        r#"{"a":1,"a":2}"#,
        r#"{"nested":{"x":1,"x":2}}"#,
        r#"{} {}"#,
    ] {
        assert!(models::parse(v.as_bytes()).is_err());
    }
}
#[test]
fn valid_and_invalid_holons() {
    let v = json!({"id":"urn:uuid:0480d807-84d1-432e-9038-ac83ce73e7c2","type":"ExampleHolon","schemaVersion":"1.0","claims":{"name":"test"},"createdAt":"2026-09-27T12:00:00Z"});
    holon::validate(&v).unwrap();
    schemas::validate(&serde_json::from_str(schemas::HOLON_SCHEMA).unwrap(), &v).unwrap();
    for (k, val) in [
        ("createdAt", json!("bad")),
        ("schemaVersion", json!("2.0")),
        ("unknownCritical", json!(true)),
    ] {
        let mut bad = v.clone();
        bad[k] = val;
        assert!(holon::validate(&bad).is_err());
    }
}
#[test]
fn no_remote_schema_resolution() {
    assert!(
        schemas::validate(
            &json!({"$ref":"https://internal.example/schema"}),
            &json!({})
        )
        .is_err()
    );
}
