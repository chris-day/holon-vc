//! Bounded HTTPS resolution with pinned offline copies and connect-time DNS pinning.
use crate::{
    app::App,
    config::PinnedResource,
    errors::{Result, error},
    models, storage,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use url::Url;

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 192 && o[1] == 0)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(v4));
            }
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && [0, 2, 0xdb8].contains(&s[1]))
        }
    }
}
pub fn checked_url(app: &App, value: &str) -> Result<Url> {
    let u = Url::parse(value)
        .map_err(|_| error("INVALID_URL", "resolution", "Absolute HTTPS URL required"))?;
    let dev = app.development
        && app
            .config
            .development_origins
            .contains(&u.origin().ascii_serialization());
    if (u.scheme() != "https" && !(dev && u.scheme() == "http"))
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
    {
        return Err(error(
            "URL_DENIED",
            "resolution",
            "Unsafe scheme, authority, credentials, or fragment",
        ));
    }
    Ok(u)
}
pub fn generated_pins(app: &App) -> Result<BTreeMap<String, PinnedResource>> {
    let p = app.root.join("config/resources.json");
    if !p.exists() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_value(storage::read_json(&p)?).map_err(|_| {
        error(
            "INVALID_CONFIG",
            "resolution",
            "Invalid local resource index",
        )
    })
}
pub fn pin(app: &App, url: &str, path: &Path, media_type: &str, seconds: i64) -> Result<()> {
    let mut pins = generated_pins(app)?;
    let bytes = storage::read(path, false)?;
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| {
                error(
                    "UNSAFE_STORAGE",
                    "resolution",
                    "Working directory unavailable",
                )
            })?
            .join(path)
    };
    pins.insert(
        url.into(),
        PinnedResource {
            retrieved_at: Some(chrono::Utc::now().to_rfc3339()),
            path: absolute,
            sha256: storage::digest(&bytes),
            expires: (chrono::Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339(),
            media_type: media_type.into(),
        },
    );
    storage::write_json(&app.root.join("config/resources.json"), &pins, true, true)
}

pub async fn retrieve(app: &App, address: &str, accepted: &[&str]) -> Result<Vec<u8>> {
    let url = checked_url(app, address)?;
    let pins = generated_pins(app)?;
    if let Some(p) = app
        .config
        .resources
        .get(address)
        .or_else(|| pins.get(address))
    {
        if models::date(&p.expires)? <= chrono::Utc::now() {
            return Err(error(
                "RESOURCE_UNAVAILABLE",
                "resolution",
                "Pinned resource has expired",
            ));
        }
        if !accepted.contains(&p.media_type.as_str()) {
            return Err(error(
                "MEDIA_TYPE",
                "resolution",
                "Pinned media type is not accepted",
            ));
        }
        let bytes = storage::read(&p.path, false)?;
        if storage::digest(&bytes) != p.sha256 {
            return Err(error(
                "DIGEST_MISMATCH",
                "resolution",
                "Pinned content digest mismatch",
            ));
        }
        return Ok(bytes);
    }
    if app.offline {
        return Err(error(
            "RESOURCE_UNAVAILABLE",
            "resolution",
            "Offline mode requires a fresh pinned copy",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| error("URL_DENIED", "resolution", "Missing host"))?;
    let addresses: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443))),
    )
    .await
    .map_err(|_| error("RESOURCE_UNAVAILABLE", "resolution", "DNS timeout"))?
    .map_err(|_| error("RESOURCE_UNAVAILABLE", "resolution", "DNS lookup failed"))?
    .collect();
    let dev = app.development
        && app
            .config
            .development_origins
            .contains(&url.origin().ascii_serialization());
    if addresses.is_empty() || (!dev && addresses.iter().any(|a| !public_ip(a.ip()))) {
        return Err(error(
            "SSRF_DENIED",
            "resolution",
            "Resolution returned a prohibited network address",
        ));
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|_| {
            error(
                "RESOURCE_UNAVAILABLE",
                "resolution",
                "HTTP client initialization failed",
            )
        })?;
    let mut response = client
        .get(url)
        .header("Accept", accepted.join(", "))
        .header("Accept-Encoding", "identity")
        .send()
        .await
        .map_err(|_| {
            error(
                "RESOURCE_UNAVAILABLE",
                "resolution",
                "HTTPS retrieval failed",
            )
        })?;
    if !response.status().is_success() {
        return Err(error(
            "RESOURCE_UNAVAILABLE",
            "resolution",
            "HTTP error or redirect rejected",
        ));
    }
    if response
        .remote_addr()
        .is_none_or(|a| !addresses.iter().any(|p| p.ip() == a.ip()))
    {
        return Err(error(
            "SSRF_DENIED",
            "resolution",
            "Connected address differs from validated DNS results",
        ));
    }
    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|h| h != "identity")
    {
        return Err(error(
            "ENCODING_DENIED",
            "resolution",
            "HTTP compression is disabled",
        ));
    }
    let media = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if !accepted.contains(&media) {
        return Err(error(
            "MEDIA_TYPE",
            "resolution",
            "Unexpected response media type",
        ));
    }
    if response
        .content_length()
        .is_some_and(|n| n > 4 * 1024 * 1024)
    {
        return Err(error(
            "DOCUMENT_TOO_LARGE",
            "resolution",
            "Response exceeds 4 MiB",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| error("RESOURCE_UNAVAILABLE", "resolution", "Incomplete response"))?
    {
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err(error(
                "DOCUMENT_TOO_LARGE",
                "resolution",
                "Response exceeds 4 MiB",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn json(app: &App, url: &str) -> Result<Value> {
    models::parse(
        &retrieve(
            app,
            url,
            &[
                "application/json",
                "application/ld+json",
                "application/did+ld+json",
                "application/did+json",
                "application/vc",
                "application/vp",
            ],
        )
        .await?,
    )
}

/// Enforce the signed status TTL independently of a pin's operator-selected expiry.
pub fn status_cache_age(app: &App, address: &str, ttl_ms: u64) -> Result<()> {
    if ttl_ms == 0 || ttl_ms > 86_400_000 {
        return Err(error(
            "INVALID_STATUS_TTL",
            "status",
            "Unsupported status TTL",
        ));
    }
    let pins = generated_pins(app)?;
    if let Some(p) = app
        .config
        .resources
        .get(address)
        .or_else(|| pins.get(address))
    {
        let retrieved = p.retrieved_at.as_deref().ok_or_else(|| {
            error(
                "STATUS_UNAVAILABLE",
                "status",
                "Cached status requires a retrieval timestamp",
            )
        })?;
        let age = chrono::Utc::now()
            .signed_duration_since(models::date(retrieved)?)
            .num_milliseconds();
        if age < -30_000 || age > ttl_ms as i64 {
            return Err(error(
                "STATUS_UNAVAILABLE",
                "status",
                "Cached status exceeds the signed TTL",
            ));
        }
    }
    Ok(())
}
