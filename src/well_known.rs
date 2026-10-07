//! Public discovery artefacts. Domain linkage is explicitly a Holon VC 2.0 profile.
use crate::{
    app::{App, required},
    cli::{get, yes},
    errors::{Result, error},
    keys::PrivateKey,
    public_keys::PublicDocument,
    storage, suites, verification,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
pub const META_SCHEMA: &str = include_str!("../schemas/holon-issuer.schema.json");
pub fn public_only(v: &Value) -> Result<()> {
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                let k = k.to_ascii_lowercase();
                if [
                    "d",
                    "seed",
                    "privatekey",
                    "privatekeymultibase",
                    "privatekeyjwk",
                    "secretkey",
                    "ciphertext",
                    "password",
                    "nonce",
                    "salt",
                ]
                .contains(&k.as_str())
                    || k.starts_with("private")
                {
                    return Err(error(
                        "PRIVATE_MATERIAL",
                        "publication",
                        "Forbidden private property in public artefact",
                    ));
                }
                public_only(v)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                public_only(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn origin(app: &App, s: &str, did: &str) -> Result<String> {
    let u = crate::resolvers::checked_url(app, s)?;
    let origin = u.origin().ascii_serialization();
    if s.trim_end_matches('/') != origin || u.query().is_some() {
        return Err(error(
            "INVALID_ORIGIN",
            "publication",
            "An HTTPS origin without a path is required",
        ));
    }
    let d = url::Url::parse(&crate::did::web_url(did)?)
        .map_err(|_| error("INVALID_DID", "publication", "Invalid DID URL"))?;
    if d.origin().ascii_serialization() != origin {
        return Err(error(
            "ORIGIN_MISMATCH",
            "publication",
            "Issuer DID and origin differ",
        ));
    }
    Ok(origin)
}
fn encode(v: &Value) -> Result<Vec<u8>> {
    let mut b = serde_json::to_vec_pretty(v)
        .map_err(|_| error("INTERNAL", "publication", "Serialization failed"))?;
    b.push(b'\n');
    Ok(b)
}
fn public_docs(app: &App, extra: Option<&Path>) -> Result<Vec<PublicDocument>> {
    let mut docs: Vec<PublicDocument> = Vec::new();
    let dir = app.root.join("keys/public");
    if dir.exists() {
        storage::directory(&dir, false)?;
        for e in std::fs::read_dir(&dir).map_err(|_| {
            error(
                "STORAGE_UNAVAILABLE",
                "publication",
                "Public key directory unavailable",
            )
        })? {
            let p = e
                .map_err(|_| {
                    error(
                        "STORAGE_UNAVAILABLE",
                        "publication",
                        "Public key unavailable",
                    )
                })?
                .path();
            if p.extension().is_some_and(|e| e == "json") {
                docs.push(
                    serde_json::from_value(storage::read_json(&p)?).map_err(|_| {
                        error("INVALID_KEY", "publication", "Invalid public key document")
                    })?,
                );
            }
        }
    }
    if let Some(path) = extra {
        let d: PublicDocument = serde_json::from_value(storage::read_json(path)?)
            .map_err(|_| error("INVALID_KEY", "publication", "Invalid public key document"))?;
        docs.retain(|old| old.id != d.id);
        docs.push(d);
    }
    docs.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(docs)
}
fn openid_check(app: &App, v: &Value, origin: &str, algorithms: &BTreeSet<String>) -> Result<()> {
    if v["credential_issuer"] != origin {
        return Err(error(
            "OPENID_ISSUER",
            "publication",
            "OpenID issuer must match origin",
        ));
    }
    for key in [
        "credential_endpoint",
        "nonce_endpoint",
        "deferred_credential_endpoint",
    ] {
        if key == "credential_endpoint" || v.get(key).is_some() {
            crate::resolvers::checked_url(app, verification::string(v, key)?)?;
        }
    }
    let configs = v["credential_configurations_supported"]
        .as_object()
        .filter(|o| !o.is_empty())
        .ok_or_else(|| {
            error(
                "OPENID_CAPABILITIES",
                "publication",
                "Explicit externally implemented credential configurations required",
            )
        })?;
    for c in configs.values() {
        if c["format"] != "ldp_vc"
            || c["credential_definition"]["@context"]
                != json!([
                    "https://www.w3.org/ns/credentials/v2",
                    crate::jsonld::HOLON_CONTEXT
                ])
            || c["credential_definition"]["type"]
                != json!(["VerifiableCredential", "HolonCredential"])
            || c["cryptographic_binding_methods_supported"] != json!(["did:web"])
        {
            return Err(error(
                "OPENID_CAPABILITIES",
                "publication",
                "Unsupported OpenID credential profile",
            ));
        }
        let algs = c["credential_signing_alg_values_supported"]
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or_else(|| {
                error(
                    "OPENID_CAPABILITIES",
                    "publication",
                    "Signing suites must be explicit",
                )
            })?;
        if algs
            .iter()
            .any(|a| a.as_str().is_none_or(|a| !algorithms.contains(a)))
        {
            return Err(error(
                "OPENID_CAPABILITIES",
                "publication",
                "OpenID advertises unavailable signing suite",
            ));
        }
    }
    public_only(v)
}
pub struct Generate<'a> {
    pub origin: &'a str,
    pub issuer: &'a str,
    pub suite: &'a suites::SuiteConfig,
    pub key: &'a PrivateKey,
    pub public_keys: Vec<PublicDocument>,
    pub policy: Option<crate::trust::Policy>,
    pub display_name: &'a str,
    pub jwks: bool,
    pub openid: bool,
}
pub async fn build(app: &App, g: Generate<'_>) -> Result<BTreeMap<String, Value>> {
    let base = origin(app, g.origin, g.issuer)?;
    if g.suite.controller != g.issuer
        || g.suite.cryptosuite != suites::MODERN
        || g.suite.purpose != "assertionMethod"
        || g.key.public().fingerprint() != g.suite.fingerprint
    {
        return Err(error(
            "LINKAGE_SUITE",
            "publication",
            "Modern Ed25519 issuer assertion suite is required",
        ));
    }
    let docs: Vec<_> = g
        .public_keys
        .into_iter()
        .filter(|d| d.controller == g.issuer && d.status == "active")
        .collect();
    let mut ids = BTreeSet::new();
    let mut methods = vec![];
    let mut auth = vec![];
    let mut jwks = vec![];
    let mut algorithms = BTreeSet::new();
    for d in &docs {
        if !ids.insert(d.id.clone()) {
            return Err(error(
                "DUPLICATE_KEY",
                "publication",
                "Duplicate verification method",
            ));
        }
        let key = d.key()?;
        methods.push(d.method(false)?);
        if key.algorithm == crate::keys::Algorithm::Ed25519 {
            auth.push(d.id.clone());
            algorithms.insert(suites::MODERN.to_string());
        } else {
            algorithms.insert(suites::SELECTIVE.to_string());
        }
        jwks.push(key.jwk(&d.id)?);
    }
    let did = json!({"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":g.issuer,"verificationMethod":methods,"assertionMethod":ids,"authentication":auth,"service":[{"id":format!("{}#holon-metadata",g.issuer),"type":"HolonIssuerMetadata","serviceEndpoint":format!("{base}/.well-known/holon-issuer.json")}]});
    let authorized = crate::did::authorized(
        &did,
        g.issuer,
        &g.suite.verification_method,
        "assertionMethod",
    )?;
    if authorized != g.key.public() {
        return Err(error(
            "KEY_SUBSTITUTION",
            "publication",
            "Publication does not authorize the signing key",
        ));
    }
    let now = chrono::Utc::now();
    let until = now + chrono::Duration::days(365);
    let linkage = json!({"@context":["https://www.w3.org/ns/credentials/v2",crate::jsonld::HOLON_CONTEXT],"id":format!("urn:uuid:{}",uuid::Uuid::new_v4()),"type":["VerifiableCredential","HolonDomainLinkageCredential"],"issuer":g.issuer,"validFrom":now.to_rfc3339(),"validUntil":until.to_rfc3339(),"credentialSubject":{"id":g.issuer,"origin":base}});
    let signed = suites::sign(
        &linkage,
        g.key,
        &verification::proof(g.suite, None, None),
        &[],
        &crate::jsonld::loader(app)?,
    )
    .await?;
    let did_url = crate::did::web_url(g.issuer)?;
    let did_path = url::Url::parse(&did_url)
        .map_err(|_| error("INVALID_DID", "publication", "Invalid DID URL"))?
        .path()
        .trim_start_matches('/')
        .to_owned();
    let policy = if let Some(p) = g.policy {
        p.validate()?;
        if p.issuer != g.issuer
            || p.fingerprint != g.suite.fingerprint
            || p.verification_method != g.suite.verification_method
        {
            return Err(error(
                "POLICY_MISMATCH",
                "publication",
                "Publication trust policy does not match signer",
            ));
        }
        json!({"id":p.id,"version":p.version,"requiredEvidenceTypes":p.required_evidence_types,"minimumIndependentSources":p.minimum_independent_sources})
    } else {
        json!({"id":"unconfigured","version":"1.0","requiredEvidenceTypes":[],"minimumIndependentSources":0})
    };
    let mut meta = json!({"profile":"holon-issuer-v1","issuer":g.issuer,"displayName":g.display_name,"credentialTypes":["HolonCredential"],"schemas":[{"id":"urn:holon:schema:1.0","version":"1.0","disclosure":"urn:holon:schema:1.0:disclosure"}],"cryptosuites":algorithms,"statusMechanisms":["BitstringStatusListEntry"],"trustPolicy":policy,"didDocument":did_url,"generatedAt":now.to_rfc3339(),"expires":until.to_rfc3339(),"domainLinkageProfile":"holon-vc2-domain-linkage-v1"});
    if g.jwks {
        meta["jwks"] = json!(format!("{base}/.well-known/jwks.json"));
    }
    if g.openid {
        meta["openidCredentialIssuer"] =
            json!(format!("{base}/.well-known/openid-credential-issuer"));
    }
    let mut out = BTreeMap::from([
        (did_path, did),
        (
            ".well-known/did-configuration.json".into(),
            json!({"profile":"holon-vc2-domain-linkage-v1","linked_dids":[signed]}),
        ),
        (".well-known/holon-issuer.json".into(), meta),
    ]);
    if g.jwks {
        out.insert(".well-known/jwks.json".into(), json!({"keys":jwks}));
    }
    if g.openid {
        let v = app.config.openid.clone().ok_or_else(|| {
            error(
                "OPENID_ENDPOINTS_REQUIRED",
                "publication",
                "Configure explicit externally hosted OpenID metadata first",
            )
        })?;
        openid_check(app, &v, &base, &algorithms)?;
        out.insert(".well-known/openid-credential-issuer".into(), v);
    }
    let entries=out.iter().map(|(p,v)|Ok(json!({"path":p,"url":format!("{base}/{p}"),"mediaType":if p.ends_with("did.json"){"application/did+ld+json"}else{"application/json"},"sha256":storage::digest(&encode(v)?),"generatedAt":now.to_rfc3339(),"fingerprint":g.suite.fingerprint,"cacheControl":"public, max-age=300, must-revalidate"}))).collect::<Result<Vec<_>>>()?;
    out.insert(".well-known/manifest.json".into(),json!({"profile":"holon-manifest-v1","issuer":g.issuer,"origin":base,"generatedAt":now.to_rfc3339(),"expires":until.to_rfc3339(),"fingerprint":g.suite.fingerprint,"artifacts":entries}));
    validate_set(app, &base, g.issuer, &g.suite.fingerprint, &out).await?;
    Ok(out)
}
pub async fn validate_set(
    app: &App,
    base: &str,
    issuer: &str,
    fingerprint: &str,
    docs: &BTreeMap<String, Value>,
) -> Result<()> {
    let base = origin(app, base, issuer)?;
    let fail = || {
        error(
            "ARTIFACT_MISMATCH",
            "publication",
            "Missing or inconsistent public artefact",
        )
    };
    for v in docs.values() {
        public_only(v)?;
    }
    let manifest = docs.get(".well-known/manifest.json").ok_or_else(fail)?;
    if manifest["profile"] != "holon-manifest-v1"
        || manifest["issuer"] != issuer
        || manifest["origin"] != base
        || manifest["fingerprint"] != fingerprint
    {
        return Err(fail());
    }
    fresh(manifest)?;
    for (path, value) in docs {
        let schema = match path.as_str() {
            ".well-known/manifest.json" => include_str!("../schemas/manifest.schema.json"),
            ".well-known/did-configuration.json" => {
                include_str!("../schemas/did-configuration.schema.json")
            }
            ".well-known/holon-issuer.json" => META_SCHEMA,
            ".well-known/jwks.json" => include_str!("../schemas/jwks.schema.json"),
            ".well-known/openid-credential-issuer" => {
                include_str!("../schemas/openid-credential-issuer.schema.json")
            }
            p if p
                == url::Url::parse(&crate::did::web_url(issuer)?)
                    .map_err(|_| fail())?
                    .path()
                    .trim_start_matches('/') =>
            {
                include_str!("../schemas/did-document.schema.json")
            }
            _ => {
                return Err(error(
                    "UNSUPPORTED_ARTIFACT",
                    "publication",
                    "Manifest contains an unsupported artifact",
                ));
            }
        };
        crate::schemas::validate(&serde_json::from_str(schema).map_err(|_| fail())?, value)?;
    }

    let entries = manifest["artifacts"].as_array().ok_or_else(fail)?;
    if entries.len() + 1 != docs.len() || entries.len() > 16 {
        return Err(fail());
    }
    let mut paths = BTreeSet::new();
    for e in entries {
        let p = verification::string(e, "path")?;
        safe_path(p)?;
        if !paths.insert(p)
            || e["url"] != format!("{base}/{p}")
            || e["fingerprint"] != fingerprint
            || e["generatedAt"] != manifest["generatedAt"]
            || e["mediaType"]
                != if p.ends_with("did.json") {
                    "application/did+ld+json"
                } else {
                    "application/json"
                }
        {
            return Err(fail());
        }
        let v = docs.get(p).ok_or_else(fail)?;
        if e["sha256"] != storage::digest(&encode(v)?) {
            return Err(error(
                "DIGEST_MISMATCH",
                "publication",
                "Manifest digest mismatch",
            ));
        }
    }
    let did_url = crate::did::web_url(issuer)?;
    let parsed = url::Url::parse(&did_url).map_err(|_| fail())?;
    let did = docs
        .get(parsed.path().trim_start_matches('/'))
        .ok_or_else(fail)?;
    let methods = did["verificationMethod"]
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(fail)?;
    let mut authorized = BTreeMap::new();
    let mut suites = BTreeSet::new();
    for m in methods {
        let id = verification::string(m, "id")?;
        let k = crate::did::authorized(did, issuer, id, "assertionMethod")?;
        if authorized.insert(id.to_string(), k.clone()).is_some() {
            return Err(fail());
        }
        suites.insert(
            if k.algorithm == crate::keys::Algorithm::Ed25519 {
                crate::suites::MODERN
            } else {
                crate::suites::SELECTIVE
            }
            .to_string(),
        );
    }
    for relation in did["authentication"].as_array().ok_or_else(fail)? {
        let id = relation.as_str().ok_or_else(fail)?;
        let key = crate::did::authorized(did, issuer, id, "authentication")?;
        if !authorized.contains_key(id) || key.algorithm != crate::keys::Algorithm::Ed25519 {
            return Err(fail());
        }
    }
    for relation in did["assertionMethod"].as_array().ok_or_else(fail)? {
        if !authorized.contains_key(relation.as_str().ok_or_else(fail)?) {
            return Err(fail());
        }
    }
    if !authorized.values().any(|k| k.fingerprint() == fingerprint) {
        return Err(error(
            "KEY_SUBSTITUTION",
            "publication",
            "Expected public fingerprint is absent",
        ));
    }
    let config = docs
        .get(".well-known/did-configuration.json")
        .ok_or_else(fail)?;
    if config["profile"] != "holon-vc2-domain-linkage-v1" {
        return Err(fail());
    }
    let links = config["linked_dids"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or_else(fail)?;
    let link = &links[0];
    if !verification::has_type(link, "HolonDomainLinkageCredential")
        || link["issuer"] != issuer
        || link["credentialSubject"]["id"] != issuer
        || link["credentialSubject"]["origin"] != base
        || link["proof"]["proofPurpose"] != "assertionMethod"
        || crate::suites::suite(&link["proof"])? != crate::suites::MODERN
    {
        return Err(fail());
    }
    let key = crate::did::authorized(
        did,
        issuer,
        verification::string(&link["proof"], "verificationMethod")?,
        "assertionMethod",
    )?;
    if key.fingerprint() != fingerprint {
        return Err(error(
            "KEY_SUBSTITUTION",
            "publication",
            "Domain linkage signer does not match expected fingerprint",
        ));
    }
    crate::jsonld::policy(link, app)?;
    crate::suites::verify(link, &key, &crate::jsonld::loader(app)?).await?;
    verification::dates(link, true)?;
    let meta = docs.get(".well-known/holon-issuer.json").ok_or_else(fail)?;
    crate::schemas::validate(
        &serde_json::from_str(META_SCHEMA).map_err(|_| fail())?,
        meta,
    )?;
    fresh(meta)?;
    if meta["generatedAt"] != manifest["generatedAt"]
        || meta["expires"] != manifest["expires"]
        || link["validFrom"] != manifest["generatedAt"]
        || link["validUntil"] != manifest["expires"]
    {
        return Err(fail());
    }
    if did["service"]
        != json!([{"id":format!("{issuer}#holon-metadata"),"type":"HolonIssuerMetadata","serviceEndpoint":format!("{base}/.well-known/holon-issuer.json")}])
    {
        return Err(fail());
    }

    if meta["issuer"] != issuer
        || meta["didDocument"] != did_url
        || meta["cryptosuites"] != json!(suites)
        || meta["domainLinkageProfile"] != "holon-vc2-domain-linkage-v1"
    {
        return Err(fail());
    }
    if let Some(jwks) = docs.get(".well-known/jwks.json") {
        if meta["jwks"] != format!("{base}/.well-known/jwks.json") {
            return Err(fail());
        }
        let keys = jwks["keys"].as_array().ok_or_else(fail)?;
        if keys.len() != authorized.len() {
            return Err(fail());
        }
        let mut seen = BTreeSet::new();
        for jwk in keys {
            let kid = verification::string(jwk, "kid")?;
            if !seen.insert(kid) || *jwk != authorized.get(kid).ok_or_else(fail)?.jwk(kid)? {
                return Err(error(
                    "JWKS_MISMATCH",
                    "publication",
                    "JWKS and authorized DID keys differ",
                ));
            }
        }
    } else if meta.get("jwks").is_some() {
        return Err(fail());
    }
    if let Some(oid) = docs.get(".well-known/openid-credential-issuer") {
        if meta["openidCredentialIssuer"] != format!("{base}/.well-known/openid-credential-issuer")
        {
            return Err(fail());
        }
        openid_check(app, oid, &base, &suites)?;
    } else if meta.get("openidCredentialIssuer").is_some() {
        return Err(fail());
    }
    Ok(())
}
fn fresh(v: &Value) -> Result<()> {
    let from = crate::models::date(verification::string(v, "generatedAt")?)?;
    let until = crate::models::date(verification::string(v, "expires")?)?;
    let now = chrono::Utc::now();
    if from > now + chrono::Duration::seconds(30)
        || until <= now
        || until <= from
        || until > from + chrono::Duration::days(365)
    {
        return Err(error(
            "STALE_METADATA",
            "publication",
            "Metadata is stale or has an invalid validity window",
        ));
    }
    Ok(())
}
fn safe_path(p: &str) -> Result<()> {
    if p.is_empty()
        || p.starts_with('/')
        || p.contains(['\\', '?', '#', '%'])
        || p.split('/').any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(error("UNSAFE_PATH", "publication", "Invalid manifest path"));
    }
    Ok(())
}
pub fn publish(
    app: &App,
    output_dir: &Path,
    docs: &BTreeMap<String, Value>,
    force: bool,
) -> Result<()> {
    if output_dir.file_name().is_none_or(|n| n != ".well-known") {
        return Err(error(
            "OUTPUT_DIRECTORY",
            "publication",
            "Output directory must end in .well-known; parent is the site root",
        ));
    }
    let site = output_dir
        .parent()
        .ok_or_else(|| error("OUTPUT_DIRECTORY", "publication", "Site root required"))?;
    for p in docs.keys() {
        safe_path(p)?;
        if site.join(p).exists() && !force {
            return Err(error(
                "OUTPUT_EXISTS",
                "publication",
                "Public artefact exists; use --force",
            ));
        }
    }
    for (p, v) in docs
        .iter()
        .filter(|(p, _)| p.as_str() != ".well-known/manifest.json")
    {
        storage::write(&site.join(p), &encode(v)?, false, force)?;
    }
    storage::write(
        &site.join(".well-known/manifest.json"),
        &encode(&docs[".well-known/manifest.json"])?,
        false,
        force,
    )?;
    for e in docs[".well-known/manifest.json"]["artifacts"]
        .as_array()
        .ok_or_else(|| error("INVALID_MANIFEST", "publication", "Invalid manifest"))?
    {
        crate::resolvers::pin(
            app,
            verification::string(e, "url")?,
            &site.join(verification::string(e, "path")?),
            verification::string(e, "mediaType")?,
            300,
        )?;
    }
    let base = verification::string(&docs[".well-known/manifest.json"], "origin")?;
    crate::resolvers::pin(
        app,
        &format!("{base}/.well-known/manifest.json"),
        &site.join(".well-known/manifest.json"),
        "application/json",
        300,
    )
}
pub async fn load_set(
    app: &App,
    base: &str,
    issuer: &str,
    dir: Option<&Path>,
) -> Result<BTreeMap<String, Value>> {
    let base = origin(app, base, issuer)?;
    let manifest = if let Some(d) = dir {
        storage::read_json(&d.join("manifest.json"))?
    } else {
        crate::resolvers::json(app, &format!("{base}/.well-known/manifest.json")).await?
    };
    let mut out = BTreeMap::new();
    let entries = manifest["artifacts"]
        .as_array()
        .filter(|a| a.len() <= 16)
        .ok_or_else(|| {
            error(
                "INVALID_MANIFEST",
                "publication",
                "Invalid manifest entries",
            )
        })?;
    for e in entries {
        let p = verification::string(e, "path")?;
        safe_path(p)?;
        if e["url"] != format!("{base}/{p}") {
            return Err(error(
                "ORIGIN_MISMATCH",
                "publication",
                "Manifest URL is outside expected origin",
            ));
        }
        let bytes = if let Some(d) = dir {
            storage::read(
                &d.parent()
                    .ok_or_else(|| error("OUTPUT_DIRECTORY", "publication", "Site root required"))?
                    .join(p),
                false,
            )?
        } else {
            crate::resolvers::retrieve(
                app,
                verification::string(e, "url")?,
                &[verification::string(e, "mediaType")?],
            )
            .await?
        };
        if storage::digest(&bytes) != verification::string(e, "sha256")? {
            return Err(error(
                "DIGEST_MISMATCH",
                "publication",
                "Published bytes differ from manifest digest",
            ));
        }
        let v = crate::models::parse(&bytes)?;
        if out.insert(p.into(), v).is_some() {
            return Err(error(
                "INVALID_MANIFEST",
                "publication",
                "Duplicate manifest path",
            ));
        }
    }
    out.insert(".well-known/manifest.json".into(), manifest);
    Ok(out)
}
pub async fn run(app: &mut App, action: &str, m: &clap::ArgMatches) -> Result<Value> {
    app.development = yes(m, "local-development");
    match action {
        "inspect" => Ok(
            json!({"verified":false,"manifest":storage::read_json(&Path::new(required(m,"output-dir")?).join("manifest.json"))?}),
        ),
        "generate" => {
            let s = app.suite(get(m, "suite"))?;
            let p = crate::key_storage::password(yes(m, "password-stdin"), false)?;
            let key = app.signing_key(&s, &p, false)?;
            let policy = get(m, "trust-policy")
                .map(|p| storage::read_json(Path::new(p)))
                .transpose()?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| error("INVALID_POLICY", "publication", "Invalid policy document"))?;
            let docs = build(
                app,
                Generate {
                    origin: required(m, "origin")?,
                    issuer: required(m, "issuer-did")?,
                    suite: &s,
                    key: &key,
                    public_keys: public_docs(app, get(m, "public-key").map(Path::new))?,
                    policy,
                    display_name: get(m, "display-name").unwrap_or("Holon issuer"),
                    jwks: yes(m, "jwks"),
                    openid: yes(m, "openid"),
                },
            )
            .await?;
            let dir = get(m, "output-dir")
                .map(PathBuf::from)
                .unwrap_or(app.root.join("site/.well-known"));
            publish(app, &dir, &docs, yes(m, "force"))?;
            Ok(json!({"outputDirectory":dir,"manifest":docs[".well-known/manifest.json"]}))
        }
        "validate" => {
            let base = required(m, "origin")?;
            let issuer = required(m, "issuer-did")?;
            let fingerprint = required(m, "expected-fingerprint")?;
            let mut r = crate::reports::VerificationReport::default();
            let result = async {
                let docs = load_set(app, base, issuer, get(m, "output-dir").map(Path::new)).await?;
                validate_set(app, base, issuer, fingerprint, &docs).await
            }
            .await;
            if r.check("publication", result) {
                r.cryptographically_valid = true;
                r.issuer_authenticated = true;
                r.freshness_valid = true;
                r.schema_valid = true;
                r.decision = "authentic-assertion".into();
                r.confidence = 0.5;
            } else {
                r.decision = "rejected".into();
            }
            r.warnings.push("Holon VC 2.0 domain linkage is an application profile, not the DIF VC 1.x linkage profile; it does not establish claim truth.".into());
            Ok(json!(r))
        }
        _ => Err(error(
            "UNSUPPORTED_COMMAND",
            "cli",
            "Unknown publication command",
        )),
    }
}

#[cfg(test)]
mod validity_tests {
    #[test]
    fn metadata_accepts_one_year_but_rejects_longer_or_expired_windows() {
        let now = chrono::Utc::now();
        let document = |from: chrono::DateTime<chrono::Utc>,
                        until: chrono::DateTime<chrono::Utc>| {
            serde_json::json!({"generatedAt": from.to_rfc3339(), "expires": until.to_rfc3339()})
        };
        assert!(super::fresh(&document(now, now + chrono::Duration::days(365))).is_ok());
        assert!(super::fresh(&document(now, now + chrono::Duration::days(366))).is_err());
        assert!(
            super::fresh(&document(
                now - chrono::Duration::days(365),
                now - chrono::Duration::seconds(1)
            ))
            .is_err()
        );
    }
}
