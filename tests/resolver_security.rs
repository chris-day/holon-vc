use holon_vc::{
    app::App,
    config::{Config, PinnedResource},
    resolvers, storage,
};
#[test]
fn prohibited_addresses() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "192.168.0.1",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "::ffff:127.0.0.1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
    ] {
        assert!(!resolvers::public_ip(ip.parse().unwrap()), "{ip}");
    }
    assert!(resolvers::public_ip("8.8.8.8".parse().unwrap()));
}
#[tokio::test]
async fn offline_pins_fail_on_tampering_and_staleness() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = App {
        root: dir.path().into(),
        config: Config::default(),
        offline: true,
        development: false,
    };
    let path = dir.path().join("copy.json");
    storage::write(&path, b"{}", false, false).unwrap();
    let url = "https://issuer.example/data";
    app.config.resources.insert(
        url.into(),
        PinnedResource {
            retrieved_at: None,
            path: path.clone(),
            sha256: storage::digest(b"{}"),
            expires: "2099-01-01T00:00:00Z".into(),
            media_type: "application/json".into(),
        },
    );
    resolvers::json(&app, url).await.unwrap();
    storage::write(&path, b"{\"changed\":true}", false, true).unwrap();
    assert!(resolvers::json(&app, url).await.is_err());
    app.config.resources.get_mut(url).unwrap().expires = "2000-01-01T00:00:00Z".into();
    assert!(resolvers::json(&app, url).await.is_err());
    assert!(
        resolvers::json(&app, "https://unknown.example/a")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn actual_http_rejects_redirects_wrong_media_compression_and_oversize() {
    use std::io::{Read, Write};
    for (headers, body, expected) in [
        (
            "302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Type: application/json\r\nContent-Length: 2",
            "{}",
            "RESOURCE_UNAVAILABLE",
        ),
        (
            "200 OK\r\nContent-Type: text/html\r\nContent-Length: 2",
            "{}",
            "MEDIA_TYPE",
        ),
        (
            "200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2",
            "{}",
            "ENCODING_DENIED",
        ),
        (
            "200 OK\r\nContent-Type: application/json\r\nContent-Length: 4194305",
            "{}",
            "DOCUMENT_TOO_LARGE",
        ),
        (
            "200 OK\r\nContent-Type: application/json\r\nContent-Length: 13",
            "{\"x\":1,\"x\":2}",
            "INVALID_JSON",
        ),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("loopback fixture needs local socket permission");
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = [0; 2048];
            let _ = s.read(&mut request);
            let _ = write!(s, "HTTP/1.1 {headers}\r\nConnection: close\r\n\r\n{body}");
        });
        let dir = tempfile::tempdir().unwrap();
        let base = format!("http://{address}");
        let app = App {
            root: dir.path().join("data"),
            config: Config {
                development_origins: vec![base.clone()],
                ..Config::default()
            },
            offline: false,
            development: true,
        };
        let e = holon_vc::resolvers::json(&app, &format!("{base}/resource"))
            .await
            .unwrap_err();
        server.join().unwrap();
        assert_eq!(e.code, expected);
    }
}
