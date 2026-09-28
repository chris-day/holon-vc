use serde::Serialize;

/// Stable, deliberately content-free errors: never echo untrusted claims or secrets.
#[derive(Debug, thiserror::Error, Serialize)]
#[error("{code}: {message}")]
pub struct Error {
    pub code: &'static str,
    pub stage: &'static str,
    pub message: &'static str,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn error(code: &'static str, stage: &'static str, message: &'static str) -> Error {
    Error {
        code,
        stage,
        message,
    }
}

pub fn crypto_error() -> Error {
    error("INVALID_PROOF", "signature", "Proof verification failed")
}
