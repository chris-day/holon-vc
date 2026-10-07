mod common;
use common::Fixture;
use holon_vc::{canonicalization, config, credentials, schemas, storage, verification};
use serde_json::{Value, json};
use std::path::Path;

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn pin(path: &Path) -> config::PinnedResource {
    config::PinnedResource {
        path: path.to_path_buf(),
        sha256: storage::digest(&std::fs::read(path).unwrap()),
        expires: (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
        media_type: "application/ld+json".into(),
        retrieved_at: None,
    }
}

#[tokio::test]
async fn generated_profile_preserves_rdf_and_issues_each_product() {
    let mut f = Fixture::new().await;
    let synthetic = f.dir.path().join("docs/products");
    for (index, extra) in [
        json!({"additionalProperty":[{"@type":"PropertyValue","name":"Net content","value":"411 g"}]}),
        json!({"model":"Phone", "color":"White", "mpn":"ABC", "weight":{"@type":"QuantitativeValue","value":177,"unitCode":"GRM"}, "height":{"@type":"QuantitativeValue","value":149.6,"unitCode":"MMT"}, "width":{"@type":"QuantitativeValue","value":71.5,"unitCode":"MMT"},"depth":{"@type":"QuantitativeValue","value":7.9,"unitCode":"MMT"}}),
        json!({"offers":{"@type":"Offer","price":4.49,"priceCurrency":"GBP"}}),
        json!({"offers":{"@type":"Offer","price":"3.45","priceCurrency":"GBP"}}),
    ].into_iter().enumerate() {
        let mut product=json!({"@context":"https://schema.org","@id":format!("https://example.org/product/{index}"),"@type":"Product","gtin14":format!("{index:014}"),"name":"Test product","category":"Examples","image":["https://example.org/image.png"]});
        product.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let dir=synthetic.join(index.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("product.jsonld"),serde_json::to_vec(&product).unwrap()).unwrap();
    }
    // Optional read-only validation of the operator's actual product directory.
    let source = std::env::var_os("GS1_PRODUCT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or(synthetic);
    let output = f.dir.path().join("profile");
    assert!(
        std::process::Command::new("python3")
            .arg("scripts/product_profile.py")
            .arg("--products-dir")
            .arg(&source)
            .arg("--output")
            .arg(&output)
            .status()
            .unwrap()
            .success()
    );
    let report = read(&output.join("profile.json"));
    let schema_id = report["profileId"].as_str().unwrap();
    let context = read(&output.join("context.jsonld"));
    let full = read(&output.join("schema.json"));
    let inputs = f.dir.path().join("inputs");
    assert!(
        std::process::Command::new("python3")
            .arg("scripts/prepare_product_issuance.py")
            .arg("--products-dir")
            .arg(&source)
            .arg("--profile-dir")
            .arg(&output)
            .arg("--output")
            .arg(&inputs)
            .status()
            .unwrap()
            .success()
    );
    let prepared: config::Config =
        toml::from_str(&std::fs::read_to_string(inputs.join("product-config.toml")).unwrap())
            .unwrap();
    f.app.config.contexts.extend(prepared.contexts);
    f.app.config.schemas.extend(prepared.schemas);
    f.app.config.contexts.insert(
        "https://schema.org".into(),
        pin(Path::new("contexts/vendor/schemaorg-2026-10-07.jsonld")),
    );
    let loader = holon_vc::jsonld::loader(&f.app).unwrap();
    for item in report["products"].as_array().unwrap() {
        let path = source.join(item["path"].as_str().unwrap());
        let original = read(&path);
        let mut scoped = original.clone();
        scoped["@context"] = context["@context"][1]["product"]["@context"].clone();
        assert_eq!(
            canonicalization::canonicalize(&original, &loader, false)
                .await
                .unwrap(),
            canonicalization::canonicalize(&scoped, &loader, false)
                .await
                .unwrap(),
            "RDF meanings must be preserved"
        );
        let mut product = original.clone();
        product.as_object_mut().unwrap().remove("@context");
        let holon = read(
            &inputs
                .join("holons")
                .join(format!("{}.json", item["gtin14"].as_str().unwrap())),
        );
        assert_eq!(holon["claims"]["product"], product);
        schemas::validate(&full, &holon).unwrap();
        for field in ["@id", "@type", "name", "gtin14"] {
            let mut bad = holon.clone();
            bad["claims"]["product"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(schemas::validate(&full, &bad).is_err(), "missing {field}");
        }
        let mut bad = holon.clone();
        bad["claims"]["product"]["inventedClaim"] = json!("not in profile");
        assert!(schemas::validate(&full, &bad).is_err());
        let signed = credentials::issue(
            &f.app, &holon, &f.suite, &f.key, &f.status, schema_id, None, None,
        )
        .await
        .unwrap();
        assert_eq!(signed["credentialSubject"]["claims"]["product"], product);
        let result = verification::credential(&f.app, &signed, &[]).await;
        assert!(
            result.cryptographically_valid && result.schema_valid,
            "{result:?}"
        );
        let mut reduced = holon.clone();
        reduced["claims"]["product"]
            .as_object_mut()
            .unwrap()
            .retain(|k, _| ["@id", "@type", "name", "gtin14"].contains(&k.as_str()));
        schemas::validate(&full, &reduced).unwrap();
        assert_eq!(
            storage::digest(&std::fs::read(path).unwrap()),
            item["sha256"].as_str().unwrap()
        );
    }
}
