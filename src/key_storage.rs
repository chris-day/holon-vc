use crate::{
    errors::{Result, error},
    keys::{Algorithm, PrivateKey},
    public_keys::PublicDocument,
    storage,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD as B64};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Envelope {
    pub version: u32,
    pub algorithm: Algorithm,
    pub public: PublicDocument,
    pub kdf: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub cipher: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}
fn failed() -> crate::errors::Error {
    error(
        "KEY_DECRYPT_FAILED",
        "key-storage",
        "Incorrect password, modified envelope, or invalid encrypted key",
    )
}
fn aad(e: &Envelope) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        e.version,
        e.algorithm,
        &e.public,
        &e.kdf,
        e.memory_kib,
        e.iterations,
        e.parallelism,
        &e.cipher,
        &e.salt,
        &e.nonce,
    ))
    .map_err(|_| failed())
}
fn derive(password: &[u8], e: &Envelope) -> Result<Zeroizing<[u8; 32]>> {
    if e.version != 1
        || e.kdf != "argon2id-v19"
        || e.cipher != "xchacha20poly1305"
        || e.memory_kib < 65536
        || e.memory_kib > 262144
        || e.iterations < 3
        || e.iterations > 10
        || e.parallelism != 1
    {
        return Err(failed());
    }
    let salt = B64.decode(&e.salt).map_err(|_| failed())?;
    if salt.len() != 16 {
        return Err(failed());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    let params = argon2::Params::new(e.memory_kib, e.iterations, e.parallelism, Some(32))
        .map_err(|_| failed())?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password, &salt, key.as_mut())
        .map_err(|_| failed())?;
    Ok(key)
}
pub fn encrypt(key: &PrivateKey, public: PublicDocument, password: &[u8]) -> Result<Envelope> {
    if password.len() < 12 || password.iter().all(|x| *x == password[0]) {
        return Err(error(
            "WEAK_PASSWORD",
            "key-storage",
            "Use a non-repeating password or passphrase of at least 12 bytes",
        ));
    }
    let (mut salt, mut nonce) = ([0u8; 16], [0u8; 24]);
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut e = Envelope {
        version: 1,
        algorithm: key.algorithm(),
        public,
        kdf: "argon2id-v19".into(),
        memory_kib: 65536,
        iterations: 3,
        parallelism: 1,
        cipher: "xchacha20poly1305".into(),
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        ciphertext: String::new(),
    };
    let derived = derive(password, &e)?;
    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_ref()).map_err(|_| failed())?;
    e.ciphertext = B64.encode(
        cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &key.secret_bytes(),
                    aad: &aad(&e)?,
                },
            )
            .map_err(|_| failed())?,
    );
    Ok(e)
}
pub fn decrypt(e: &Envelope, password: &[u8]) -> Result<PrivateKey> {
    let key = derive(password, e)?;
    let nonce: [u8; 24] = B64
        .decode(&e.nonce)
        .map_err(|_| failed())?
        .try_into()
        .map_err(|_| failed())?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| failed())?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &B64.decode(&e.ciphertext).map_err(|_| failed())?,
                    aad: &aad(e)?,
                },
            )
            .map_err(|_| failed())?,
    );
    let private = PrivateKey::from_bytes(e.algorithm, &plaintext)?;
    if private.public() != e.public.key()? {
        return Err(failed());
    }
    Ok(private)
}
pub fn load(path: &Path, password: &[u8]) -> Result<(PrivateKey, PublicDocument)> {
    let value = crate::models::parse(&storage::read(path, true)?)?;
    let e: Envelope = serde_json::from_value(value).map_err(|_| failed())?;
    let key = decrypt(&e, password)?;
    Ok((key, e.public))
}
pub fn public(path: &Path) -> Result<PublicDocument> {
    let value = crate::models::parse(&storage::read(path, true)?)?;
    let e: Envelope = serde_json::from_value(value).map_err(|_| failed())?;
    e.public.key()?;
    Ok(e.public)
}
pub fn save(
    path: &Path,
    key: &PrivateKey,
    public: PublicDocument,
    password: &[u8],
    force: bool,
) -> Result<()> {
    storage::write_json(path, &encrypt(key, public, password)?, true, force)
}
pub fn password(stdin: bool, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    let p = if stdin {
        use std::io::BufRead;
        let mut value = String::new();
        let n = std::io::stdin()
            .lock()
            .take(4097)
            .read_line(&mut value)
            .map_err(|_| failed())?;
        if n > 4096 {
            return Err(failed());
        }
        while value.ends_with(['\n', '\r']) {
            value.pop();
        }
        Zeroizing::new(value)
    } else {
        Zeroizing::new(rpassword::prompt_password("Key password: ").map_err(|_| failed())?)
    };
    if confirm && !stdin {
        let q =
            Zeroizing::new(rpassword::prompt_password("Confirm password: ").map_err(|_| failed())?);
        if *p != *q {
            return Err(failed());
        }
    }
    Ok(Zeroizing::new(p.as_bytes().to_vec()))
}
