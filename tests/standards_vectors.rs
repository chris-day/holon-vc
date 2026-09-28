use holon_vc::{
    canonicalization::rdfc_nquads,
    disclosure,
    keys::{Algorithm, PrivateKey},
    suites,
};
use serde_json::{Value, json};
use ssi_json_ld::ContextLoader;

fn document() -> Value {
    json!({"@context":["https://www.w3.org/ns/credentials/v2",{"name":"https://schema.org/name","secret":"https://schema.org/description"}],"type":["VerifiableCredential"],"id":"urn:uuid:8764226a-441c-45cd-85d1-3d838e808036","issuer":"did:web:issuer.example","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"urn:uuid:97c796de-2b35-4cb3-86a4-b9d77e88e0da","name":"Public","secret":"hidden-canary"}})
}
fn proof(suite: &str) -> Value {
    json!({"type":"DataIntegrityProof","cryptosuite":suite,"verificationMethod":"did:web:issuer.example#key-1","proofPurpose":"assertionMethod","created":"2026-01-01T00:00:00Z"})
}

#[tokio::test]
async fn eddsa_tamper_and_key_substitution() {
    let key = PrivateKey::generate(Algorithm::Ed25519);
    let loader = ContextLoader::default();
    let vc = suites::sign(&document(), &key, &proof(suites::MODERN), &[], &loader)
        .await
        .unwrap();
    suites::verify(&vc, &key.public(), &loader).await.unwrap();
    assert!(
        suites::verify(
            &vc,
            &PrivateKey::generate(Algorithm::Ed25519).public(),
            &loader
        )
        .await
        .is_err()
    );
    let mut tampered = vc.clone();
    tampered["credentialSubject"]["secret"] = "changed".into();
    assert!(
        suites::verify(&tampered, &key.public(), &loader)
            .await
            .is_err()
    );
    assert!(
        disclosure::derive(&vc, &key.public(), &[], &loader)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn genuine_selective_disclosure_and_base_validation() {
    let key = PrivateKey::generate(Algorithm::P256);
    let loader = ContextLoader::default();
    let mandatory = [
        "/issuer",
        "/type",
        "/id",
        "/validFrom",
        "/credentialSubject/id",
    ]
    .map(String::from);
    let vc = suites::sign(
        &document(),
        &key,
        &proof(suites::SELECTIVE),
        &mandatory,
        &loader,
    )
    .await
    .unwrap();
    suites::verify(&vc, &key.public(), &loader).await.unwrap();
    let mut tampered = vc.clone();
    tampered["credentialSubject"]["secret"] = "changed".into();
    assert!(
        suites::verify(&tampered, &key.public(), &loader)
            .await
            .is_err()
    );
    assert!(
        disclosure::derive(
            &tampered,
            &key.public(),
            &["/credentialSubject/name".into()],
            &loader
        )
        .await
        .is_err()
    );
    let derived = disclosure::derive(
        &vc,
        &key.public(),
        &["/credentialSubject/name".into()],
        &loader,
    )
    .await
    .unwrap();
    assert_eq!(derived["credentialSubject"]["name"], "Public");
    assert!(derived["credentialSubject"].get("secret").is_none());
    assert!(!derived.to_string().contains("hidden-canary"));
    suites::verify(&derived, &key.public(), &loader)
        .await
        .unwrap();
    let mut tampered = derived.clone();
    tampered["credentialSubject"]["name"] = "changed".into();
    assert!(
        suites::verify(&tampered, &key.public(), &loader)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn legacy_signature() {
    let key = PrivateKey::generate(Algorithm::Ed25519);
    let loader = ContextLoader::default();
    let mut doc = document();
    doc["@context"]
        .as_array_mut()
        .unwrap()
        .push(json!("https://w3id.org/security/suites/ed25519-2020/v1"));
    let proof = json!({"type":"Ed25519Signature2020","verificationMethod":"did:web:issuer.example#key-1","proofPurpose":"assertionMethod","created":"2026-01-01T00:00:00Z"});
    let vc = suites::sign(&doc, &key, &proof, &[], &loader)
        .await
        .unwrap();
    suites::verify(&vc, &key.public(), &loader).await.unwrap();
}

#[test]
fn canonical_labels_are_stable() {
    let a = rdfc_nquads("_:a <https://example.org/p> _:b .\n_:b <https://example.org/p> \"v\" .\n")
        .unwrap()
        .0;
    let b = rdfc_nquads("_:z <https://example.org/p> \"v\" .\n_:y <https://example.org/p> _:z .\n")
        .unwrap()
        .0;
    assert_eq!(a, b);
}

#[test]
fn official_rdfc_sha256_vectors() {
    let root = std::path::Path::new("tests/fixtures/rdf-canon");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.jsonld")).unwrap()).unwrap();
    let mut count = 0;
    for test in manifest["entries"].as_array().unwrap() {
        if test.get("hashAlgorithm").is_some() {
            continue;
        } // SHA384 is not an enabled profile.
        let input = std::fs::read_to_string(root.join(test["action"].as_str().unwrap())).unwrap();
        let result = rdfc_nquads(&input);
        if test["type"] == "rdfc:RDFC10NegativeEvalTest" {
            assert!(result.is_err());
            count += 1;
            continue;
        }
        if test["computationalComplexity"] == "high" && result.is_err() {
            count += 1;
            continue;
        } // Explicit configured resource limit.
        let (canonical, map) = result.unwrap_or_else(|e| panic!("{}: {e}", test["id"]));
        let expected =
            std::fs::read_to_string(root.join(test["result"].as_str().unwrap())).unwrap();
        if test["type"] == "rdfc:RDFC10EvalTest" {
            assert_eq!(canonical, expected, "{}", test["id"]);
        } else {
            let actual: std::collections::BTreeMap<_, _> = map
                .into_iter()
                .map(|(a, b)| (a.suffix().to_string(), b.suffix().to_string()))
                .collect();
            let expected: std::collections::BTreeMap<String, String> =
                serde_json::from_str(&expected).unwrap();
            assert_eq!(actual, expected, "{}", test["id"]);
        }
        count += 1;
    }
    assert_eq!(count, 84);
}

#[tokio::test]
async fn official_eddsa_and_legacy_signatures() {
    let root = std::path::Path::new("tests/fixtures/eddsa");
    let pair: Value =
        serde_json::from_slice(&std::fs::read(root.join("keyPair.json")).unwrap()).unwrap();
    let public =
        holon_vc::keys::PublicKey::from_multibase(pair["publicKeyMultibase"].as_str().unwrap())
            .unwrap();
    let (_, secret) = multibase::decode(pair["privateKeyMultibase"].as_str().unwrap()).unwrap();
    let key = PrivateKey::from_bytes(Algorithm::Ed25519, &secret[2..]).unwrap();
    for file in [
        "eddsa-rdfc-2022/signedDataInt.json",
        "Ed25519Signature2020/signedEdSig.json",
    ] {
        let signed: Value =
            serde_json::from_slice(&std::fs::read(root.join(file)).unwrap()).unwrap();
        suites::verify(&signed, &public, &ContextLoader::default())
            .await
            .unwrap();
        let (unsigned, mut proof) = suites::split(&signed).unwrap();
        proof.as_object_mut().unwrap().remove("proofValue");
        let ours = suites::sign(&unsigned, &key, &proof, &[], &ContextLoader::default())
            .await
            .unwrap();
        assert_eq!(ours["proof"]["proofValue"], signed["proof"]["proofValue"]);
    }
}
