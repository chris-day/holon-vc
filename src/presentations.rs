use crate::{
    app::{App, required},
    cli::{get, yes},
    errors::{Result, error},
    reports::VerificationReport,
    storage, suites, verification,
};
use serde_json::{Value, json};
use std::path::Path;
/// Implementations MUST atomically reject duplicate domain/challenge pairs.
pub trait ReplayStore {
    fn consume(&mut self, domain: &str, challenge: &str, expires: i64) -> Result<()>;
}
pub struct SqliteReplay {
    connection: rusqlite::Connection,
}
impl SqliteReplay {
    pub fn open(root: &Path) -> Result<Self> {
        let path = root.join("replay/challenges.sqlite");
        if !path.exists() {
            storage::write(&path, &[], true, false)?;
        }
        storage::read(&path, true)?;
        let c = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| {
            error(
                "REPLAY_UNAVAILABLE",
                "replay",
                "Replay store cannot be opened",
            )
        })?;
        c.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| error("REPLAY_UNAVAILABLE", "replay", "Replay store unavailable"))?;
        c.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS challenges (digest TEXT PRIMARY KEY, expires INTEGER NOT NULL);").map_err(|_|error("REPLAY_UNAVAILABLE","replay","Replay store initialization failed"))?;
        Ok(Self { connection: c })
    }
}
impl ReplayStore for SqliteReplay {
    fn consume(&mut self, domain: &str, challenge: &str, expires: i64) -> Result<()> {
        let bytes = serde_json::to_vec(&(domain, challenge))
            .map_err(|_| error("INTERNAL", "replay", "Serialization failed"))?;
        let digest = storage::digest(&bytes);
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| error("REPLAY_UNAVAILABLE", "replay", "Replay transaction failed"))?;
        let now = chrono::Utc::now().timestamp();
        if expires <= now {
            return Err(error("EXPIRED", "replay", "Presentation expired"));
        }
        tx.execute("DELETE FROM challenges WHERE expires < ?1", [now])
            .map_err(|_| error("REPLAY_UNAVAILABLE", "replay", "Replay cleanup failed"))?;
        match tx.execute(
            "INSERT INTO challenges(digest, expires) VALUES (?1,?2)",
            rusqlite::params![digest, expires],
        ) {
            Ok(_) => tx
                .commit()
                .map_err(|_| error("REPLAY_UNAVAILABLE", "replay", "Replay commit failed")),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(error(
                    "REPLAYED",
                    "replay",
                    "Challenge was already consumed",
                ))
            }
            Err(_) => Err(error("REPLAY_UNAVAILABLE", "replay", "Replay write failed")),
        }
    }
}
pub async fn create(
    app: &App,
    credentials: Vec<Value>,
    holder: Option<&str>,
    signer: Option<(&suites::SuiteConfig, &crate::keys::PrivateKey)>,
    challenge: Option<&str>,
    domain: Option<&str>,
    expires: Option<&str>,
) -> Result<Value> {
    if credentials.is_empty() || credentials.len() > 32 {
        return Err(error(
            "INVALID_VP",
            "presentation",
            "Between one and 32 credentials are required",
        ));
    }
    for c in &credentials {
        if !verification::credential(app, c, &[])
            .await
            .accepted("authentic-assertion")
        {
            return Err(error(
                "INVALID_CREDENTIAL",
                "presentation",
                "Embedded credential failed validation",
            ));
        }
    }
    let mut vp = json!({"@context":["https://www.w3.org/ns/credentials/v2"],"id":format!("urn:uuid:{}",uuid::Uuid::new_v4()),"type":["VerifiablePresentation"],"verifiableCredential":credentials});
    if let Some(h) = holder {
        vp["holder"] = json!(h);
    }
    if let Some((s, key)) = signer {
        let c = challenge
            .filter(|c| (16..=512).contains(&c.len()))
            .ok_or_else(|| {
                error(
                    "CHALLENGE_REQUIRED",
                    "presentation",
                    "A verifier-generated nonce of 16–512 bytes is required",
                )
            })?;
        let d = domain
            .filter(|d| !d.is_empty() && d.len() <= 2048)
            .ok_or_else(|| {
                error(
                    "DOMAIN_REQUIRED",
                    "presentation",
                    "Verifier domain is required",
                )
            })?;
        if s.purpose != "authentication"
            || s.cryptosuite != suites::MODERN
            || holder != Some(&s.controller)
        {
            return Err(error(
                "HOLDER_MISMATCH",
                "presentation",
                "Modern holder authentication suite required",
            ));
        }
        let public =
            crate::did::resolve(app, &s.controller, &s.verification_method, "authentication")
                .await?;
        if public != key.public() {
            return Err(error(
                "KEY_SUBSTITUTION",
                "presentation",
                "Holder key mismatch",
            ));
        }
        let until = expires
            .map(crate::models::date)
            .transpose()?
            .unwrap_or(chrono::Utc::now() + chrono::Duration::minutes(5));
        if until <= chrono::Utc::now() || until > chrono::Utc::now() + chrono::Duration::minutes(5)
        {
            return Err(error(
                "INVALID_EXPIRATION",
                "presentation",
                "Presentation expiration must be within five minutes",
            ));
        }
        let mut proof = verification::proof(s, Some(c), Some(d));
        proof["expires"] = json!(until.to_rfc3339());
        vp = suites::sign(&vp, key, &proof, &[], &crate::jsonld::loader(app)?).await?;
        verification::authenticate(app, &vp, "authentication").await?;
    } else if challenge.is_some() || domain.is_some() || expires.is_some() {
        return Err(error(
            "SIGN_REQUIRED",
            "presentation",
            "Challenge, domain and expiry require --sign",
        ));
    }
    Ok(vp)
}
pub async fn verify(
    app: &App,
    vp: &Value,
    challenge: Option<&str>,
    domain: Option<&str>,
    policies: &[crate::trust::Policy],
    replay: &mut impl ReplayStore,
) -> VerificationReport {
    let mut r = VerificationReport::default();
    let structure = if verification::has_type(vp, "VerifiablePresentation")
        && vp["@context"]
            .as_array()
            .is_some_and(|a| a.first() == Some(&json!("https://www.w3.org/ns/credentials/v2")))
        && vp["verifiableCredential"]
            .as_array()
            .is_some_and(|a| !a.is_empty() && a.len() <= 32)
    {
        Ok(())
    } else {
        Err(error(
            "INVALID_VP",
            "structure",
            "Invalid presentation structure",
        ))
    };
    if !r.check("structure", structure) {
        r.decision = "rejected".into();
        return r;
    }
    let context = r.check("context", crate::jsonld::policy(vp, app));
    for c in vp["verifiableCredential"]
        .as_array()
        .expect("checked array")
    {
        r.credentials
            .push(verification::credential(app, c, policies).await);
    }
    let mut expires = None;
    let signed = vp.get("proof").is_some();
    let mut valid = context;
    if signed {
        let binding = (|| -> Result<()> {
            let p = &vp["proof"];
            if challenge.is_none()
                || domain.is_none()
                || p["challenge"].as_str() != challenge
                || p["domain"].as_str() != domain
            {
                return Err(error(
                    "CHALLENGE_DOMAIN_MISMATCH",
                    "presentation",
                    "Expected challenge and domain must match exactly",
                ));
            }
            let now = chrono::Utc::now();
            let created = crate::models::date(verification::string(p, "created")?)?;
            let until = crate::models::date(verification::string(p, "expires")?)?;
            if created > now + chrono::Duration::seconds(30)
                || until <= now
                || until <= created
                || until > created + chrono::Duration::minutes(5)
            {
                return Err(error(
                    "EXPIRED",
                    "presentation",
                    "Presentation is expired or outside its five-minute window",
                ));
            }
            expires = Some(until.timestamp());
            Ok(())
        })();
        let binding_valid = r.check("holder-binding", binding);
        valid &= binding_valid;
        let auth = verification::authenticate(app, vp, "authentication")
            .await
            .map(|_| ());
        r.cryptographically_valid = r.check("holder-authentication", auth);
        r.holder_authenticated = r.cryptographically_valid && binding_valid;
        valid &= r.holder_authenticated;
        r.freshness_valid = expires.is_some();
    } else {
        r.warnings.push(
            "Unsigned presentation is a transport container; holder control is not authenticated."
                .into(),
        );
        if challenge.is_some() || domain.is_some() {
            valid &= r.check(
                "holder-binding",
                Err(error(
                    "UNSIGNED_PRESENTATION",
                    "presentation",
                    "An unsigned container cannot answer a challenge",
                )),
            );
        }
    }
    valid &= r
        .credentials
        .iter()
        .all(|c| c.accepted("authentic-assertion"));
    if valid && signed {
        let replay_valid = r.check(
            "replay",
            replay.consume(
                domain.expect("checked domain"),
                challenge.expect("checked challenge"),
                expires.expect("checked expiry"),
            ),
        );
        r.holder_authenticated &= replay_valid;
        valid &= replay_valid;
    }
    if valid {
        let rank = |s: &str| match s {
            "corroborated" => 3,
            "trusted-assertion" => 2,
            _ => 1,
        };
        let weakest = r
            .credentials
            .iter()
            .min_by_key(|c| rank(&c.decision))
            .expect("nonempty");
        r.decision = weakest.decision.clone();
        r.confidence = weakest.confidence;
        r.issuer_authenticated = r.credentials.iter().all(|c| c.issuer_authenticated);
        r.issuer_trusted_for_claim_type = r
            .credentials
            .iter()
            .all(|c| c.issuer_trusted_for_claim_type);
        r.schema_valid = true;
        r.status = "active".into();
        r.evidence_verified = r.credentials.iter().all(|c| c.evidence_verified);
    } else {
        r.decision = "rejected".into();
    }
    r.complete_stages(&[
        "structure",
        "context",
        "holder-binding",
        "holder-authentication",
        "replay",
    ]);
    r
}
pub async fn run(app: &mut App, action: &str, m: &clap::ArgMatches) -> Result<Value> {
    app.development = yes(m, "local-development");
    match action {
        "inspect" => Ok(
            json!({"verified":false,"presentation":storage::read_json(Path::new(required(m,"presentation")?))?}),
        ),
        "create" => {
            let vc = storage::read_json(Path::new(required(m, "credential")?))?;
            let signer = if yes(m, "sign") {
                let s = app.suite(get(m, "suite"))?;
                let p = crate::key_storage::password(yes(m, "password-stdin"), false)?;
                let k = app.signing_key(&s, &p, false)?;
                Some((s, k))
            } else {
                None
            };
            create(
                app,
                vec![vc],
                get(m, "holder"),
                signer.as_ref().map(|(s, k)| (s, k)),
                get(m, "challenge"),
                get(m, "domain"),
                get(m, "expires"),
            )
            .await
        }
        "verify" => {
            let vp = storage::read_json(Path::new(required(m, "presentation")?))?;
            let policies = app.policies(get(m, "trust-store"))?;
            let mut replay = SqliteReplay::open(&app.root)?;
            Ok(json!(
                verify(
                    app,
                    &vp,
                    get(m, "challenge"),
                    get(m, "domain"),
                    &policies,
                    &mut replay
                )
                .await
            ))
        }
        _ => Err(error(
            "UNSUPPORTED_COMMAND",
            "cli",
            "Unknown presentation command",
        )),
    }
}
