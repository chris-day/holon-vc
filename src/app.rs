use crate::{
    cli::{get, yes},
    config::Config,
    errors::{Result, error},
    key_storage,
    keys::{Algorithm, PrivateKey},
    public_keys::PublicDocument,
    storage,
    suites::SuiteConfig,
    trust::Policy,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub struct App {
    pub root: PathBuf,
    pub config: Config,
    pub offline: bool,
    pub development: bool,
}
impl App {
    pub fn new(matches: &clap::ArgMatches) -> Result<Self> {
        let root = PathBuf::from(get(matches, "data-dir").unwrap_or("holon-vc-data"));
        let config_path = get(matches, "config")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("config/config.toml"));
        let config = if config_path.exists() {
            toml::from_str::<Config>(
                std::str::from_utf8(&storage::read(&config_path, false)?)
                    .map_err(|_| error("INVALID_CONFIG", "config", "Configuration is not UTF-8"))?,
            )
            .map_err(|_| error("INVALID_CONFIG", "config", "Invalid TOML configuration"))?
        } else if get(matches, "config").is_some() {
            return Err(error(
                "INVALID_CONFIG",
                "config",
                "Selected configuration does not exist",
            ));
        } else {
            Config::default()
        };
        Ok(Self {
            root,
            config,
            offline: yes(matches, "offline"),
            development: false,
        })
    }
    pub fn named(&self, folder: &str, id: &str) -> Result<PathBuf> {
        storage::safe_id(id)?;
        Ok(self.root.join(folder).join(format!("{id}.json")))
    }
    pub fn suite(&self, name: Option<&str>) -> Result<SuiteConfig> {
        let name = name
            .or(self.config.default_suite.as_deref())
            .ok_or_else(|| {
                error(
                    "SUITE_REQUIRED",
                    "suite",
                    "Supply --suite or default_suite in config",
                )
            })?;
        let path = if name.contains('/') {
            PathBuf::from(name)
        } else {
            self.named("suites", name)?
        };
        serde_json::from_value(storage::read_json(&path)?)
            .map_err(|_| error("INVALID_SUITE", "suite", "Malformed suite configuration"))
    }
    pub fn signing_key(
        &self,
        suite: &SuiteConfig,
        password: &[u8],
        legacy: bool,
    ) -> Result<PrivateKey> {
        let (key, public) = key_storage::load(&suite.key, password)?;
        suite.validate(&public, legacy)?;
        Ok(key)
    }
    pub fn policies(&self, directory: Option<&str>) -> Result<Vec<Policy>> {
        let path = directory
            .map(PathBuf::from)
            .unwrap_or_else(|| self.root.join("trust"));
        if !path.exists() {
            return Ok(vec![]);
        }
        storage::directory(&path, false)?;
        let mut policies = Vec::new();
        for e in std::fs::read_dir(path)
            .map_err(|_| error("POLICY_UNAVAILABLE", "policy", "Cannot read policy store"))?
        {
            let path = e
                .map_err(|_| error("POLICY_UNAVAILABLE", "policy", "Cannot read policy store"))?
                .path();
            if path.extension().is_some_and(|s| s == "json") {
                let p: Policy = serde_json::from_value(storage::read_json(&path)?)
                    .map_err(|_| error("INVALID_POLICY", "policy", "Malformed policy"))?;
                p.validate()?;
                if p.enabled {
                    policies.push(p);
                }
            }
        }
        policies.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(policies)
    }
}
pub fn required<'a>(m: &'a clap::ArgMatches, k: &str) -> Result<&'a str> {
    get(m, k).ok_or_else(|| error("MISSING_ARGUMENT", "cli", "Required argument is missing"))
}
pub fn output(m: &clap::ArgMatches, value: &Value) -> Result<()> {
    if let Some(path) = get(m, "output") {
        storage::write_json(Path::new(path), value, false, yes(m, "force"))?;
    }
    Ok(())
}
fn list(app: &App, folder: &str) -> Result<Value> {
    let path = app.root.join(folder);
    if !path.exists() {
        return Ok(json!([]));
    }
    storage::directory(&path, false)?;
    let mut files = std::fs::read_dir(path)
        .map_err(|_| error("STORAGE_UNAVAILABLE", "storage", "Directory unavailable"))?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| error("STORAGE_UNAVAILABLE", "storage", "Directory unavailable"))?;
    files.sort();
    let mut values = vec![];
    for f in files {
        if f.extension().is_some_and(|s| s == "json") {
            values.push(storage::read_json(&f)?);
        }
    }
    Ok(values.into())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Explicit application-boundary parameters keep signing authority and output options visible"
)]
pub fn generate_key(
    app: &App,
    id: &str,
    controller: &str,
    algorithm: Algorithm,
    private: Option<&str>,
    public: Option<&str>,
    password: &[u8],
    force: bool,
) -> Result<PublicDocument> {
    crate::did::web_url(controller)?;
    storage::safe_id(id)?;
    if !controller.starts_with("did:web:")
        || !crate::models::absolute_uri(controller)
        || controller.contains('#')
    {
        return Err(error(
            "INVALID_CONTROLLER",
            "key",
            "A did:web controller is required",
        ));
    }
    let private = private
        .map(PathBuf::from)
        .unwrap_or(app.named("keys/private", id)?);
    let public = public
        .map(PathBuf::from)
        .unwrap_or(app.named("keys/public", id)?);
    if private == public {
        return Err(error(
            "UNSAFE_STORAGE",
            "key",
            "Private and public paths must differ",
        ));
    }
    if !force && (private.exists() || public.exists()) {
        return Err(error("OUTPUT_EXISTS", "storage", "Key already exists"));
    }
    let key = PrivateKey::generate(algorithm);
    let doc = PublicDocument::new(&key, id, controller);
    key_storage::save(&private, &key, doc.clone(), password, force)?;
    storage::write_json(&public, &doc, false, force)?;
    Ok(doc)
}
pub fn rotate_key(app: &App, old_path: &Path, id: &str, password: &[u8]) -> Result<PublicDocument> {
    let (old, mut doc) = key_storage::load(old_path, password)?;
    let mut next = generate_key(
        app,
        id,
        &doc.controller,
        old.algorithm(),
        None,
        None,
        password,
        false,
    )?;
    next.rotation_history = doc.rotation_history.clone();
    next.rotation_history.push(doc.id.clone());
    let next_private = app.named("keys/private", id)?;
    let (key, _) = key_storage::load(&next_private, password)?;
    key_storage::save(&next_private, &key, next.clone(), password, true)?;
    storage::write_json(&app.named("keys/public", id)?, &next, false, true)?;
    doc.status = "retired".into();
    doc.rotation_history.push(next.id.clone());
    key_storage::save(old_path, &old, doc.clone(), password, true)?;
    let old_id = doc
        .id
        .rsplit_once('#')
        .ok_or_else(|| error("INVALID_KEY", "key", "Invalid key identifier"))?
        .1;
    storage::write_json(&app.named("keys/public", old_id)?, &doc, false, true)?;
    Ok(next)
}
pub async fn run(app: &mut App, group: &str, action: &str, m: &clap::ArgMatches) -> Result<Value> {
    match (group, action) {
        ("key", "setup") => {
            let alg = match get(m, "algorithm").unwrap_or("ed25519") {
                "ed25519" => Algorithm::Ed25519,
                "p256" => Algorithm::P256,
                _ => return Err(error("UNSUPPORTED_KEY", "key", "Use ed25519 or p256")),
            };
            let password = key_storage::password(yes(m, "password-stdin"), true)?;
            Ok(serde_json::to_value(generate_key(
                app,
                required(m, "id")?,
                required(m, "controller")?,
                alg,
                get(m, "private-key"),
                get(m, "public-key"),
                &password,
                yes(m, "force"),
            )?)
            .map_err(|_| error("INTERNAL", "key", "Serialization failed"))?)
        }
        ("key", "inspect") => {
            let value = storage::read_json(Path::new(required(m, "key")?))?;
            let public: PublicDocument =
                serde_json::from_value(value.get("public").cloned().unwrap_or(value))
                    .map_err(|_| error("INVALID_KEY", "key", "Malformed public key metadata"))?;
            public.key()?;
            Ok(json!({"authenticated":false,"public":public}))
        }
        ("key", "export-public") => {
            let path = Path::new(required(m, "key")?);
            let value = storage::read_json(path)?;
            let doc: PublicDocument = if value.get("ciphertext").is_some() {
                let p = key_storage::password(yes(m, "password-stdin"), false)?;
                key_storage::load(path, &p)?.1
            } else {
                serde_json::from_value(value)
                    .map_err(|_| error("INVALID_KEY", "key", "Malformed public key"))?
            };
            doc.key()?;
            Ok(serde_json::to_value(doc)
                .map_err(|_| error("INTERNAL", "key", "Serialization failed"))?)
        }
        ("key", "rotate") => {
            let p = key_storage::password(yes(m, "password-stdin"), false)?;
            Ok(serde_json::to_value(rotate_key(
                app,
                Path::new(required(m, "key")?),
                required(m, "id")?,
                &p,
            )?)
            .map_err(|_| error("INTERNAL", "key", "Serialization failed"))?)
        }
        ("key", "list") => {
            let values = list(app, "keys/public")?;
            let mut output = Vec::new();
            for value in values
                .as_array()
                .ok_or_else(|| error("INVALID_KEY", "key", "Invalid public key collection"))?
            {
                let public: PublicDocument = serde_json::from_value(value.clone())
                    .map_err(|_| error("INVALID_KEY", "key", "Malformed public key metadata"))?;
                public.key()?;
                output.push(public);
            }
            Ok(json!(output))
        }
        ("suite", "setup") => {
            let path = PathBuf::from(required(m, "key")?);
            let public = key_storage::public(&path)?;
            let absolute = if path.is_absolute() {
                path
            } else {
                std::env::current_dir()
                    .map_err(|_| error("UNSAFE_STORAGE", "suite", "Working directory unavailable"))?
                    .join(path)
            };
            let s = SuiteConfig {
                name: required(m, "name")?.into(),
                cryptosuite: get(m, "cryptosuite")
                    .unwrap_or(crate::suites::MODERN)
                    .into(),
                key: absolute,
                verification_method: required(m, "verification-method")?.into(),
                controller: public.controller.clone(),
                fingerprint: public.fingerprint.clone(),
                purpose: get(m, "purpose").unwrap_or("assertionMethod").into(),
            };
            s.validate(&public, yes(m, "legacy"))?;
            storage::write_json(&app.named("suites", &s.name)?, &s, true, yes(m, "force"))?;
            Ok(json!(s))
        }
        ("suite", "inspect") => Ok(json!(app.suite(get(m, "name"))?)),
        ("suite", "list") => list(app, "suites"),
        ("trust", "add") => {
            let p: Policy = if let Some(file) = get(m, "policy") {
                serde_json::from_value(storage::read_json(Path::new(file))?)
                    .map_err(|_| error("INVALID_POLICY", "policy", "Malformed policy"))?
            } else {
                serde_json::from_value(json!({"id":get(m,"id").unwrap_or("issuer-policy"),"version":"1.0","issuer":required(m,"issuer")?,"verificationMethod":required(m,"verification-method")?,"fingerprint":required(m,"fingerprint")?,"credentialTypes":[required(m,"credential-type")?],"schemas":[required(m,"schema")?]})).map_err(|_|error("INVALID_POLICY","policy","Malformed policy"))?
            };
            if get(m, "purpose").is_some_and(|p| p != "holon-assertion") {
                return Err(error(
                    "INVALID_POLICY",
                    "policy",
                    "Unsupported application purpose",
                ));
            }
            p.validate()?;
            storage::write_json(&app.named("trust", &p.id)?, &p, true, yes(m, "force"))?;
            Ok(json!(p))
        }
        ("trust", "list") => list(app, "trust"),
        ("trust", op @ ("inspect" | "remove" | "enable" | "disable")) => {
            let path = app.named("trust", required(m, "id")?)?;
            let mut value = storage::read_json(&path)?;
            match op {
                "remove" => {
                    storage::remove(&path)?;
                    Ok(json!({"removed":required(m,"id")?}))
                }
                "enable" | "disable" => {
                    value["enabled"] = json!(op == "enable");
                    storage::write_json(&path, &value, true, true)?;
                    Ok(value)
                }
                _ => Ok(value),
            }
        }
        ("well-known", op) => crate::well_known::run(app, op, m).await,
        ("presentation", op) => crate::presentations::run(app, op, m).await,
        ("credential", op) => crate::credentials::run(app, op, m).await,
        ("status", "inspect") => Ok(json!(crate::status::load(Path::new(required(
            m,
            "status-list"
        )?))?)),
        ("status", op) => {
            let s = app.suite(get(m, "suite"))?;
            let p = key_storage::password(yes(m, "password-stdin"), false)?;
            let key = app.signing_key(&s, &p, false)?;
            if op == "create" {
                let id = required(m, "id")?;
                let path = app.named("status", id)?;
                let r = crate::status::create(
                    app,
                    id,
                    required(m, "url")?,
                    &s,
                    &key,
                    &path,
                    yes(m, "force"),
                )
                .await?;
                Ok(json!({"registry":path,"url":r.url,"issuer":r.issuer}))
            } else {
                crate::status::update(
                    app,
                    Path::new(required(m, "status-list")?),
                    &storage::read_json(Path::new(required(m, "credential")?))?,
                    op,
                    &s,
                    &key,
                )
                .await
            }
        }
        _ => Err(error("UNSUPPORTED_COMMAND", "cli", "Unknown command")),
    }
}
