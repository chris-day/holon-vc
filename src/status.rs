//! Signed W3C Bitstring Status List v1.0, one-bit revocation and suspension.
use crate::{
    app::App,
    errors::{Result, error},
    keys::PrivateKey,
    storage, suites, verification,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::Path,
};
const BITS: usize = 131072;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registry {
    pub version: String,
    pub id: String,
    pub url: String,
    pub issuer: String,
    pub suite: String,
    pub allocations: BTreeMap<String, usize>,
    pub revoked: BTreeSet<usize>,
    pub suspended: BTreeSet<usize>,
    pub lists: BTreeMap<String, Value>,
}
pub fn load(path: &Path) -> Result<Registry> {
    let r: Registry = serde_json::from_value(crate::models::parse(&storage::read(path, true)?)?)
        .map_err(|_| error("INVALID_STATUS", "status", "Invalid status registry"))?;
    if r.version != "1.0"
        || r.allocations.len() > BITS
        || r.allocations.values().any(|i| *i >= BITS)
    {
        return Err(error(
            "INVALID_STATUS",
            "status",
            "Invalid status allocation",
        ));
    }
    Ok(r)
}
pub fn entries(r: &Registry, id: &str) -> Result<Value> {
    let i = r
        .allocations
        .get(id)
        .ok_or_else(|| error("INVALID_STATUS", "status", "Credential is not allocated"))?;
    Ok(json!(["revocation","suspension"].map(|p|{let url=format!("{}/{}.json",r.url,p);json!({"id":format!("{url}#{i}"),"type":"BitstringStatusListEntry","statusPurpose":p,"statusListIndex":i.to_string(),"statusListCredential":url})})))
}
pub fn allocate(path: &Path, id: &str, issuer: &str) -> Result<Value> {
    let mut r = load(path)?;
    if r.issuer != issuer || r.allocations.contains_key(id) || r.allocations.len() >= BITS {
        return Err(error(
            "INVALID_STATUS",
            "status",
            "Status issuer mismatch, duplicate or exhausted list",
        ));
    }
    r.allocations.insert(id.into(), r.allocations.len());
    let e = entries(&r, id)?;
    storage::write_json(path, &r, true, true)?;
    Ok(e)
}
async fn refresh(
    app: &App,
    r: &mut Registry,
    s: &suites::SuiteConfig,
    key: &PrivateKey,
) -> Result<()> {
    if s.cryptosuite != suites::MODERN || s.purpose != "assertionMethod" || s.controller != r.issuer
    {
        return Err(error(
            "STATUS_SUITE",
            "status",
            "Status requires authorized modern Ed25519 assertion suite",
        ));
    }
    let loader = crate::jsonld::loader(app)?;
    let now = chrono::Utc::now();
    for (purpose, set) in [("revocation", &r.revoked), ("suspension", &r.suspended)] {
        let mut bits = vec![0u8; BITS / 8];
        for i in set {
            if *i >= BITS {
                return Err(error("INVALID_STATUS", "status", "Invalid bit index"));
            }
            bits[i / 8] |= 1 << (7 - i % 8);
        }
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&bits)
            .map_err(|_| error("INTERNAL", "status", "Compression failed"))?;
        let encoded = format!(
            "u{}",
            URL_SAFE_NO_PAD.encode(gzip.finish().map_err(|_| error(
                "INTERNAL",
                "status",
                "Compression failed"
            ))?)
        );
        let url = format!("{}/{}.json", r.url, purpose);
        let doc = json!({"@context":["https://www.w3.org/ns/credentials/v2"],"id":url,"type":["VerifiableCredential","BitstringStatusListCredential"],"issuer":r.issuer,"validFrom":now.to_rfc3339(),"validUntil":(now+chrono::Duration::days(1)).to_rfc3339(),"credentialSubject":{"id":format!("{url}#list"),"type":"BitstringStatusList","statusPurpose":purpose,"encodedList":encoded}});
        let signed =
            suites::sign(&doc, key, &verification::proof(s, None, None), &[], &loader).await?;
        suites::verify(&signed, &key.public(), &loader).await?;
        r.lists.insert(purpose.into(), signed);
    }
    Ok(())
}
pub fn publish(app: &App, r: &Registry) -> Result<()> {
    for (p, list) in &r.lists {
        let path = app
            .root
            .join("site/status")
            .join(&r.id)
            .join(format!("{p}.json"));
        storage::write_json(&path, list, false, true)?;
        crate::resolvers::pin(
            app,
            &format!("{}/{}.json", r.url, p),
            &path,
            "application/vc",
            300,
        )?;
    }
    Ok(())
}
pub async fn create(
    app: &App,
    id: &str,
    url: &str,
    s: &suites::SuiteConfig,
    key: &PrivateKey,
    path: &Path,
    force: bool,
) -> Result<Registry> {
    storage::safe_id(id)?;
    crate::resolvers::checked_url(app, url)?;
    if url.ends_with('/') || url.contains('?') {
        return Err(error(
            "INVALID_URL",
            "status",
            "Status base URL must not have a query or trailing slash",
        ));
    }
    if path.exists() {
        if !force {
            return Err(error(
                "OUTPUT_EXISTS",
                "status",
                "Status registry already exists",
            ));
        }
        let mut existing = load(path)?;
        if existing.id != id || existing.url != url || existing.issuer != s.controller {
            return Err(error(
                "STATUS_BINDING",
                "status",
                "Cannot replace an existing status registry identity",
            ));
        }
        refresh(app, &mut existing, s, key).await?;
        storage::write_json(path, &existing, true, true)?;
        publish(app, &existing)?;
        return Ok(existing);
    }
    let mut r = Registry {
        version: "1.0".into(),
        id: id.into(),
        url: url.into(),
        issuer: s.controller.clone(),
        suite: s.name.clone(),
        allocations: BTreeMap::new(),
        revoked: BTreeSet::new(),
        suspended: BTreeSet::new(),
        lists: BTreeMap::new(),
    };
    refresh(app, &mut r, s, key).await?;
    storage::write_json(path, &r, true, force)?;
    publish(app, &r)?;
    Ok(r)
}
pub async fn update(
    app: &App,
    path: &Path,
    credential: &Value,
    op: &str,
    s: &suites::SuiteConfig,
    key: &PrivateKey,
) -> Result<Value> {
    let mut r = load(path)?;
    let id = verification::string(credential, "id")?;
    if credential.get("credentialStatus") != Some(&entries(&r, id)?) {
        return Err(error(
            "INVALID_STATUS",
            "status",
            "Credential status does not match registry",
        ));
    }
    let i = *r
        .allocations
        .get(id)
        .ok_or_else(|| error("INVALID_STATUS", "status", "Unallocated credential"))?;
    match op {
        "revoke" => {
            r.revoked.insert(i);
        }
        "suspend" => {
            if r.revoked.contains(&i) {
                return Err(error("REVOKED", "status", "Revocation is permanent"));
            }
            r.suspended.insert(i);
        }
        "restore" => {
            if r.revoked.contains(&i) {
                return Err(error("REVOKED", "status", "Revocation is permanent"));
            }
            r.suspended.remove(&i);
        }
        _ => {
            return Err(error(
                "INVALID_STATUS",
                "status",
                "Unknown status operation",
            ));
        }
    };
    refresh(app, &mut r, s, key).await?;
    storage::write_json(path, &r, true, true)?;
    publish(app, &r)?;
    Ok(
        json!({"credential":id,"status":if r.revoked.contains(&i){"revoked"}else if r.suspended.contains(&i){"suspended"}else{"active"}}),
    )
}
pub async fn check(app: &App, vc: &Value) -> Result<String> {
    let entries = vc["credentialStatus"].as_array().ok_or_else(|| {
        error(
            "STATUS_UNAVAILABLE",
            "status",
            "Both status entries are required",
        )
    })?;
    if entries.len() != 2 {
        return Err(error(
            "INVALID_STATUS",
            "status",
            "Exactly two status purposes required",
        ));
    }
    let mut state = "active";
    let mut purposes = BTreeSet::new();
    for e in entries {
        let p = verification::string(e, "statusPurpose")?;
        if !["revocation", "suspension"].contains(&p)
            || !purposes.insert(p)
            || e["type"] != "BitstringStatusListEntry"
        {
            return Err(error(
                "INVALID_STATUS",
                "status",
                "Invalid status purpose or type",
            ));
        }
        let url = verification::string(e, "statusListCredential")?;
        let i = verification::string(e, "statusListIndex")?
            .parse::<usize>()
            .map_err(|_| error("INVALID_STATUS", "status", "Invalid status index"))?;
        if e["id"] != format!("{url}#{i}") {
            return Err(error(
                "INVALID_STATUS",
                "status",
                "Status entry identifier does not match list and index",
            ));
        }
        let list = crate::resolvers::json(app, url).await?;
        if list["id"] != url
            || list["issuer"] != vc["issuer"]
            || !verification::has_type(&list, "BitstringStatusListCredential")
            || list["credentialSubject"]["type"] != "BitstringStatusList"
            || list["credentialSubject"]["statusPurpose"] != p
            || list.get("credentialStatus").is_some()
            || list["credentialSubject"]
                .get("statusSize")
                .is_some_and(|v| v != 1)
        {
            return Err(error(
                "INVALID_STATUS",
                "status",
                "Status credential binding or profile is invalid",
            ));
        }
        verification::authenticate(app, &list, "assertionMethod").await?;
        verification::dates(&list, true)?;
        let ttl = match list["credentialSubject"].get("ttl") {
            Some(v) => v.as_u64().ok_or_else(|| {
                error(
                    "INVALID_STATUS_TTL",
                    "status",
                    "TTL must be a positive integer",
                )
            })?,
            None => 300_000,
        };
        crate::resolvers::status_cache_age(app, url, ttl)?;
        let encoded = verification::string(&list["credentialSubject"], "encodedList")?;
        let encoded = encoded.strip_prefix('u').ok_or_else(|| {
            error(
                "INVALID_STATUS",
                "status",
                "Base64url multibase status encoding required",
            )
        })?;
        let compressed = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| error("INVALID_STATUS", "status", "Invalid status encoding"))?;
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("INVALID_STATUS", "status", "Invalid gzip list"))?;
        if bytes.len() < BITS / 8 || bytes.len() > 16 * 1024 * 1024 || i / 8 >= bytes.len() {
            return Err(error(
                "INVALID_STATUS",
                "status",
                "Invalid bitstring size or index",
            ));
        }
        if bytes[i / 8] & (1 << (7 - i % 8)) != 0 {
            if p == "revocation" {
                state = "revoked";
            } else if state != "revoked" {
                state = "suspended";
            }
        }
    }
    Ok(state.into())
}
