use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub default_suite: Option<String>,
    pub default_status_list: Option<PathBuf>,
    pub resources: BTreeMap<String, PinnedResource>,
    pub contexts: BTreeMap<String, PinnedResource>,
    pub schemas: BTreeMap<String, SchemaProfile>,
    pub development_origins: Vec<String>,
    pub openid: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedResource {
    #[serde(default)]
    pub retrieved_at: Option<String>,
    pub path: PathBuf,
    pub sha256: String,
    pub expires: String,
    pub media_type: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaProfile {
    pub full: PathBuf,
    pub disclosure: PathBuf,
    pub context: String,
    pub sha256: String,
    pub disclosure_sha256: String,
}
