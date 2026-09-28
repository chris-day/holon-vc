//! Standards-based cryptographic foundation for Holon assertions.
//!
//! See STATUS.md for verification results and SECURITY.md for assurance limits.
pub mod app;
pub mod canonicalization;
pub mod cli;
pub mod config;
pub mod credentials;
pub mod did;
pub mod disclosure;
pub mod errors;
pub mod evidence;
pub mod holon;
pub mod jsonld;
pub mod key_storage;
pub mod keys;
pub mod models;
pub mod presentations;
pub mod public_keys;
pub mod reports;
pub mod resolvers;
pub mod schemas;
pub mod status;
pub mod storage;
pub mod suites;
pub mod trust;
pub mod verification;
pub mod well_known;
