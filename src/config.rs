use crate::error::AppError;
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub listen_addr: String,
    pub policy_file: String,
    pub geoip_db_file: String,
    pub inline_policy_token: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let listen_addr = env::var("EDGE_GUARD_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let policy_file = env::var("EDGE_GUARD_POLICY_FILE")
            .unwrap_or_else(|_| "config/policies.yaml".to_string());
        let geoip_db_file = env::var("EDGE_GUARD_GEOIP_DB_FILE")
            .unwrap_or_else(|_| "/app/data/GeoLite2-Country.mmdb".to_string());
        let inline_policy_token = env::var("EDGE_GUARD_INLINE_POLICY_TOKEN").ok();

        if listen_addr.trim().is_empty() {
            return Err(AppError::Config(
                "EDGE_GUARD_LISTEN_ADDR cannot be empty".to_string(),
            ));
        }
        if policy_file.trim().is_empty() {
            return Err(AppError::Config(
                "EDGE_GUARD_POLICY_FILE cannot be empty".to_string(),
            ));
        }
        if geoip_db_file.trim().is_empty() {
            return Err(AppError::Config(
                "EDGE_GUARD_GEOIP_DB_FILE cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            listen_addr,
            policy_file,
            geoip_db_file,
            inline_policy_token,
        })
    }
}
