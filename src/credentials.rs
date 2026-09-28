use crate::{
    app::{App, required},
    cli::{get, yes},
    errors::{Result, error},
    keys::PrivateKey,
    storage, suites, verification,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
pub fn mandatory(v: &Value) -> Vec<String> {
    let mut p: Vec<String> = [
        "/id",
        "/type",
        "/issuer",
        "/validFrom",
        "/credentialSchema",
        "/credentialStatus",
        "/credentialSubject/id",
        "/credentialSubject/type",
        "/credentialSubject/schemaVersion",
    ]
    .map(String::from)
    .into();
    if v.get("validUntil").is_some() {
        p.push("/validUntil".into());
    }
    p
}
pub fn no_null(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Array(a) => a.iter().all(no_null),
        Value::Object(o) => o.values().all(no_null),
        _ => true,
    }
}
pub fn status_path(app: &App, m: &clap::ArgMatches) -> Result<PathBuf> {
    get(m, "status-list")
        .map(PathBuf::from)
        .or(app.config.default_status_list.clone())
        .ok_or_else(|| {
            error(
                "STATUS_REQUIRED",
                "status",
                "Supply --status-list or configured default_status_list",
            )
        })
}
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit application-boundary parameters keep signing authority and output options visible"
)]
pub async fn issue(
    app: &App,
    holon: &Value,
    s: &suites::SuiteConfig,
    key: &PrivateKey,
    status: &Path,
    schema_id: &str,
    expires: Option<&str>,
    reissued: Option<&str>,
) -> Result<Value> {
    if s.purpose != "assertionMethod" || key.public().fingerprint() != s.fingerprint {
        return Err(error(
            "INVALID_PURPOSE",
            "authorization",
            "Authorized assertion suite required",
        ));
    }
    if !no_null(holon) {
        return Err(error(
            "UNSIGNED_NULL",
            "schema",
            "Null values are not supported by this JSON-LD profile",
        ));
    }
    if reissued.is_none() {
        crate::holon::validate(holon)?;
    }
    let context = if schema_id == "urn:holon:schema:1.0" {
        crate::jsonld::HOLON_CONTEXT
    } else {
        &app.config
            .schemas
            .get(schema_id)
            .ok_or_else(|| {
                error(
                    "SCHEMA_UNAVAILABLE",
                    "schema",
                    "Schema profile is not configured",
                )
            })?
            .context
    };
    let mut contexts = vec!["https://www.w3.org/ns/credentials/v2", context];
    if s.cryptosuite == suites::LEGACY {
        contexts.push("https://w3id.org/security/suites/ed25519-2020/v1");
    }
    let mut v = json!({"@context":contexts,"id":format!("urn:uuid:{}",uuid::Uuid::new_v4()),"type":["VerifiableCredential","HolonCredential"],"issuer":s.controller,"validFrom":chrono::Utc::now().to_rfc3339(),"credentialSubject":holon,"credentialSchema":{"id":schema_id,"type":"HolonSubjectSchema"}});
    if let Some(e) = expires {
        if crate::models::date(e)? <= chrono::Utc::now() {
            return Err(error(
                "EXPIRED",
                "freshness",
                "Expiration must be in the future",
            ));
        }
        v["validUntil"] = json!(e);
    }
    if let Some(id) = reissued {
        v["reissuedFrom"] = json!(id);
    }
    verification::schema(app, &v)?;
    crate::jsonld::policy(&v, app)?;
    let authorized = crate::did::resolve(
        app,
        &s.controller,
        &s.verification_method,
        "assertionMethod",
    )
    .await?;
    if authorized != key.public() {
        return Err(error(
            "KEY_SUBSTITUTION",
            "authorization",
            "DID key does not match the signing suite",
        ));
    }
    let loader = crate::jsonld::loader(app)?;
    crate::canonicalization::quads(&v, &loader).await?;
    v["credentialStatus"] =
        crate::status::allocate(status, verification::string(&v, "id")?, &s.controller)?;
    let result = suites::sign(
        &v,
        key,
        &verification::proof(s, None, None),
        &mandatory(&v),
        &loader,
    )
    .await?;
    let r = verification::credential(app, &result, &[]).await;
    if !r.accepted("authentic-assertion") {
        return Err(error(
            "ISSUANCE_VERIFICATION",
            "issuance",
            "Self-verification failed; reserved status index is retained",
        ));
    }
    Ok(result)
}
pub fn reveal(path: &Path) -> Result<crate::models::Reveal> {
    let r: crate::models::Reveal = serde_json::from_value(storage::read_json(path)?)
        .map_err(|_| error("INVALID_REVEAL", "disclosure", "Malformed reveal document"))?;
    r.validate()?;
    if r.selective_pointers
        .iter()
        .any(|p| !p.starts_with("/credentialSubject/"))
    {
        return Err(error(
            "INVALID_REVEAL",
            "disclosure",
            "Only subject claims can be selected",
        ));
    }
    Ok(r)
}
pub async fn derive(app: &App, v: &Value, reveal: &crate::models::Reveal) -> Result<Value> {
    reveal.validate()?;
    let r = verification::credential(app, v, &[]).await;
    if !r.accepted("authentic-assertion") {
        return Err(error(
            "INVALID_BASE_CREDENTIAL",
            "disclosure",
            "Original credential failed validation",
        ));
    }
    let key = verification::authenticate(app, v, "assertionMethod").await?;
    let result = crate::disclosure::derive(
        v,
        &key,
        &reveal.selective_pointers,
        &crate::jsonld::loader(app)?,
    )
    .await?;
    if !verification::credential(app, &result, &[])
        .await
        .accepted("authentic-assertion")
    {
        return Err(error(
            "INVALID_DERIVED_CREDENTIAL",
            "disclosure",
            "Derived credential failed validation",
        ));
    }
    Ok(result)
}
pub async fn run(app: &mut App, action: &str, m: &clap::ArgMatches) -> Result<Value> {
    app.development = yes(m, "local-development");
    match action {
        "issue" => {
            let holon = storage::read_json(Path::new(required(m, "holon")?))?;
            if let Some(schema) = get(m, "schema") {
                crate::schemas::validate(&storage::read_json(Path::new(schema))?, &holon)?;
            }
            let s = app.suite(get(m, "suite"))?;
            let p = crate::key_storage::password(yes(m, "password-stdin"), false)?;
            let key = app.signing_key(&s, &p, yes(m, "legacy"))?;
            issue(
                app,
                &holon,
                &s,
                &key,
                &status_path(app, m)?,
                get(m, "schema-id").unwrap_or("urn:holon:schema:1.0"),
                get(m, "expires"),
                None,
            )
            .await
        }
        "inspect" => Ok(
            json!({"verified":false,"credential":storage::read_json(Path::new(required(m,"credential")?))?}),
        ),
        "verify" => {
            let v = storage::read_json(Path::new(required(m, "credential")?))?;
            let policies = app.policies(get(m, "trust-store"))?;
            let mut report = verification::credential(app, &v, &policies).await;
            if let Some(path) = get(m, "conflicting-credential") {
                let other = storage::read_json(Path::new(path))?;
                let r = verification::credential(app, &other, &policies).await;
                if report.accepted("authentic-assertion")
                    && r.accepted("authentic-assertion")
                    && v["credentialSubject"]["id"] == other["credentialSubject"]["id"]
                    && crate::evidence::conflicts(
                        &v["credentialSubject"]["claims"],
                        &other["credentialSubject"]["claims"],
                    )
                {
                    report.decision = "disputed".into();
                    report.confidence = 0.0;
                    report.warnings.push("A separately authenticated assertion reports different claims for this subject.".into());
                }
                report.credentials.push(r);
            }
            Ok(json!(report))
        }
        "derive" => {
            let v = storage::read_json(Path::new(required(m, "credential")?))?;
            if let Some(directory) = get(m, "trust-store") {
                let policies = app.policies(Some(directory))?;
                if !verification::credential(app, &v, &policies)
                    .await
                    .accepted("trusted-assertion")
                {
                    return Err(error(
                        "UNTRUSTED_BASE",
                        "disclosure",
                        "Original credential does not satisfy the selected trust store",
                    ));
                }
            }
            derive(app, &v, &reveal(Path::new(required(m, "reveal")?))?).await
        }
        "reissue-redacted" => {
            let v = storage::read_json(Path::new(required(m, "credential")?))?;
            if !verification::credential(app, &v, &[])
                .await
                .accepted("authentic-assertion")
            {
                return Err(error(
                    "INVALID_BASE_CREDENTIAL",
                    "issuance",
                    "Original credential failed validation",
                ));
            }
            let r = reveal(Path::new(required(m, "reveal")?))?;
            let s = app.suite(get(m, "suite"))?;
            if v["issuer"] != s.controller || s.cryptosuite != suites::MODERN {
                return Err(error(
                    "ISSUER_MISMATCH",
                    "issuance",
                    "Modern original-issuer suite required for reissuance",
                ));
            }
            let mut paths = mandatory(&v);
            paths.extend(r.selective_pointers);
            let paths = paths
                .iter()
                .map(|s| {
                    s.parse::<ssi_core::JsonPointerBuf>()
                        .map_err(|_| error("INVALID_REVEAL", "disclosure", "Invalid pointer"))
                })
                .collect::<Result<Vec<_>>>()?;
            let object = json_syntax::to_value(&v)
                .map_err(|_| error("INVALID_REVEAL", "disclosure", "Invalid document"))?
                .into_object()
                .ok_or_else(|| error("INVALID_REVEAL", "disclosure", "Invalid document"))?;
            let selected = ssi_di_sd_primitives::select::select_json_ld(&paths, &object)
                .map_err(|_| error("INVALID_REVEAL", "disclosure", "Invalid selection"))?
                .ok_or_else(|| error("INVALID_REVEAL", "disclosure", "Empty selection"))?;
            let selected: Value = serde_json::to_value(selected)
                .map_err(|_| error("INVALID_REVEAL", "disclosure", "Invalid selection"))?;
            let p = crate::key_storage::password(yes(m, "password-stdin"), false)?;
            let key = app.signing_key(&s, &p, false)?;
            issue(
                app,
                &selected["credentialSubject"],
                &s,
                &key,
                &status_path(app, m)?,
                verification::string(&v["credentialSchema"], "id")?,
                v["validUntil"].as_str(),
                Some(verification::string(&v, "id")?),
            )
            .await
        }
        _ => Err(error(
            "UNSUPPORTED_COMMAND",
            "cli",
            "Unknown credential command",
        )),
    }
}
