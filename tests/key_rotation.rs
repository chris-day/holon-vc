use holon_vc::{
    app::{App, generate_key, rotate_key},
    config::Config,
    key_storage,
    keys::Algorithm,
};
#[test]
fn rotation_preserves_history_and_retires_old_key() {
    let dir = tempfile::tempdir().unwrap();
    let app = App {
        root: dir.path().into(),
        config: Config::default(),
        offline: true,
        development: false,
    };
    let p = b"correct horse battery staple";
    let old = generate_key(
        &app,
        "old",
        "did:web:issuer.example",
        Algorithm::Ed25519,
        None,
        None,
        p,
        false,
    )
    .unwrap();
    let path = app.named("keys/private", "old").unwrap();
    let new = rotate_key(&app, &path, "new", p).unwrap();
    assert_ne!(old.fingerprint, new.fingerprint);
    assert_eq!(new.rotation_history, vec![old.id]);
    assert_eq!(key_storage::load(&path, p).unwrap().1.status, "retired");
}
