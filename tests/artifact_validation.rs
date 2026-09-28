mod common;
use common::Fixture;
use holon_vc::{
    jsonld,
    public_keys::PublicDocument,
    schemas, storage, suites,
    well_known::{self, Generate},
};
use serde_json::{Value, json};
fn shape(v: &Value, key: &str) -> Value {
    if [
        "id",
        "issuer",
        "controller",
        "verificationMethod",
        "fingerprint",
        "publicKeyMultibase",
        "kid",
        "x",
        "y",
        "proofValue",
        "created",
        "generatedAt",
        "expires",
        "validFrom",
        "validUntil",
        "sha256",
        "displayName",
    ]
    .contains(&key)
        && v.is_string()
    {
        return json!("DYNAMIC");
    }
    match v {
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, v)| (k.clone(), shape(v, k))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| shape(v, key)).collect()),
        _ => v.clone(),
    }
}
#[tokio::test]
async fn golden_publication_shapes_schemas_and_real_fixture_signature() {
    let mut f = Fixture::new().await;
    let dir = std::path::Path::new("examples/public/site/.well-known");
    let oid = storage::read_json(&dir.join("openid-credential-issuer")).unwrap();
    f.app.config.openid = Some(oid);
    let mut s = f.suite.clone();
    s.verification_method = "did:web:issuer.example#example-key".into();
    let docs = well_known::build(
        &f.app,
        Generate {
            origin: "https://issuer.example",
            issuer: &s.controller,
            suite: &s,
            key: &f.key,
            public_keys: vec![PublicDocument::new(&f.key, "example-key", &s.controller)],
            policy: None,
            display_name: "Golden test",
            jwks: true,
            openid: true,
        },
    )
    .await
    .unwrap();
    for (path, value) in &docs {
        let fixture =
            storage::read_json(&std::path::Path::new("examples/public/site").join(path)).unwrap();
        assert_eq!(
            shape(value, ""),
            shape(&fixture, ""),
            "golden mismatch: {path}"
        );
        well_known::public_only(&fixture).unwrap();
    }
    let did = storage::read_json(&dir.join("did.json")).unwrap();
    let link = storage::read_json(&dir.join("did-configuration.json")).unwrap();
    let vc = &link["linked_dids"][0];
    let key = holon_vc::did::authorized(
        &did,
        "did:web:issuer.example",
        vc["proof"]["verificationMethod"].as_str().unwrap(),
        "assertionMethod",
    )
    .unwrap();
    suites::verify(vc, &key, &jsonld::loader(&f.app).unwrap())
        .await
        .unwrap();
    for entry in std::fs::read_dir("schemas").unwrap() {
        let p = entry.unwrap().path();
        let schema = storage::read_json(&p).unwrap();
        jsonschema::draft202012::meta::validate(&schema).unwrap();
    }
    let h = storage::read_json(std::path::Path::new("examples/holon.json")).unwrap();
    schemas::validate(&serde_json::from_str(schemas::HOLON_SCHEMA).unwrap(), &h).unwrap();
}
