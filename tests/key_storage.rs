use holon_vc::{
    key_storage,
    keys::{Algorithm, PrivateKey},
    public_keys::PublicDocument,
    storage,
};
use std::os::unix::fs::{PermissionsExt, symlink};
#[test]
fn encryption_tampering_passwords_and_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private/secret.json");
    let key = PrivateKey::generate(Algorithm::Ed25519);
    let public = PublicDocument::new(&key, "key1", "did:web:issuer.example");
    let password = b"correct horse battery staple";
    key_storage::save(&path, &key, public.clone(), password, false).unwrap();
    let loaded = key_storage::load(&path, password).unwrap();
    assert_eq!(loaded.0.public(), key.public());
    assert!(key_storage::load(&path, b"wrong password").is_err());
    assert!(key_storage::save(&path, &key, public.clone(), password, false).is_err());
    let mut value = storage::read_json(&path).unwrap();
    value["public"]["controller"] = "did:web:attacker.example".into();
    storage::write_json(&path, &value, true, true).unwrap();
    assert!(key_storage::load(&path, password).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(key_storage::load(&path, password).is_err());
    assert!(key_storage::encrypt(&key, public, b"short").is_err());
}
#[test]
fn no_symlink_follow_or_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("private/real");
    storage::write(&real, b"original", true, false).unwrap();
    let link = dir.path().join("private/link");
    symlink(&real, &link).unwrap();
    assert!(storage::read(&link, true).is_err());
    assert!(storage::write(&link, b"changed", true, true).is_err());
    assert_eq!(storage::read(&real, true).unwrap(), b"original");
    assert!(storage::write(&dir.path().join("../escape"), b"no", true, false).is_err());
}
