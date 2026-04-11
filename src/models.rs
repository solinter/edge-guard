use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Fixed,
    Inline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub forwarded_method: String,
    pub forwarded_uri: String,
    pub forwarded_host: String,
    pub forwarded_proto: Option<String>,
    pub forwarded_for: Option<String>,
    pub user_agent: Option<String>,
    pub geo_country_iso: Option<String>,
    pub geo_continent_code: Option<String>,
    pub geo_is_in_eu: Option<bool>,
    pub all_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InlinePolicyEnvelope {
    pub policy_id: String,
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    pub active_policy_id: String,
    pub policies: Vec<NamedPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NamedPolicy {
    pub id: String,
    pub description: Option<String>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub action: RuleAction,
    #[serde(flatten)]
    pub kind: RuleKind,
}

fn default_priority() -> i32 {
    100
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleKind {
    PathContains { value: String },
    MethodIn { values: Vec<String> },
    HeaderEquals { header: String, value: String },
    HeaderRegex { header: String, pattern: String },
    IpInDenylist { values: Vec<String> },
    CountryIn { values: Vec<String> },
    ContinentIn { values: Vec<String> },
    IsInEuropeanUnion { value: bool },
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionResult {
    pub decision: Decision,
    pub reason: String,
    pub policy_id: String,
    pub trace_id: String,
}
