use holon_vc::{app::App, canonicalization, config::Config, jsonld};
use serde_json::json;
#[tokio::test]
async fn unknown_context_and_undefined_claims_fail() {
    let dir = tempfile::tempdir().unwrap();
    let app = App {
        root: dir.path().into(),
        config: Config::default(),
        offline: true,
        development: false,
    };
    assert!(
        jsonld::policy(
            &json!({"@context":"https://attacker.example/context"}),
            &app
        )
        .is_err()
    );
    assert!(
        jsonld::policy(
            &json!({"@context":{"x":"https://attacker.example/x"}}),
            &app
        )
        .is_err()
    );
    let loader = jsonld::loader(&app).unwrap();
    let doc = json!({"@context":["https://www.w3.org/ns/credentials/v2",jsonld::HOLON_CONTEXT],"type":"VerifiableCredential","credentialSubject":{"unmappedSecret":"must not disappear"}});
    assert!(
        canonicalization::canonicalize(&doc, &loader, false)
            .await
            .is_err()
    );
}
