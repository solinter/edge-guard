mod config;
mod error;
mod geo;
mod models;
mod policy;
mod throttle;

use axum::{
    extract::State,
    http::{header::HeaderName, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::Engine;
use config::AppConfig;
use error::AppError;
use geo::GeoIpResolver;
use models::{AuthContext, Decision, InlinePolicyEnvelope, PolicyMode};
use policy::PolicyEngine;
use serde_json::json;
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, sync::Arc};
use throttle::ThrottleService;
use tokio::signal;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    engine: Arc<PolicyEngine>,
    geo: Arc<GeoIpResolver>,
    throttle: Arc<ThrottleService>,
    config: Arc<AppConfig>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    init_tracing();

    let config = Arc::new(AppConfig::from_env()?);
    let addr: SocketAddr = config
        .listen_addr
        .parse::<SocketAddr>()
        .map_err(|e| AppError::Config(format!("invalid EDGE_GUARD_LISTEN_ADDR: {e}")))?;
    let engine = Arc::new(PolicyEngine::from_file(&config.policy_file)?);
    let geo = Arc::new(GeoIpResolver::from_mmdb_file(&config.geoip_db_file)?);
    let throttle = Arc::new(ThrottleService::new());

    let state = AppState {
        engine,
        geo,
        throttle,
        config,
    };
    let app = router(state);

    info!("edge-guard listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| AppError::Internal(format!("bind failed: {e}")))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| AppError::Internal(format!("server error: {e}")))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received, stopping server");
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/authorize", get(authorize).post(authorize))
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let trace_id = get_trace_id(&headers);
    let mut context = context_from_headers(&headers)?;
    enrich_context_with_geo(&state.geo, &mut context);
    let policy_mode = policy_mode_from_headers(&headers)?;

    let decision_result = match policy_mode {
        PolicyMode::Fixed => {
            let requested_fixed_policy_id = header_str(&headers, "x-eg-fixed-policy-id");
            state
                .engine
                .evaluate_fixed(
                    &context,
                    requested_fixed_policy_id,
                    &state.throttle,
                    trace_id.clone(),
                )?
        }
        PolicyMode::Inline => {
            ensure_inline_allowed(&state.config, &headers)?;
            let inline = parse_inline_policy(&headers)?;
            state
                .engine
                .evaluate_inline(
                    &inline.policy_id,
                    &inline.rules,
                    &context,
                    &state.throttle,
                    trace_id.clone(),
                )
        }
    };

    let status = match decision_result.decision {
        Decision::Allow => StatusCode::OK,
        Decision::Deny => StatusCode::FORBIDDEN,
    };

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        HeaderName::from_static("x-eg-decision"),
        to_header_value(match decision_result.decision {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        })?,
    );
    response_headers.insert(
        HeaderName::from_static("x-eg-reason"),
        to_header_value(&decision_result.reason)?,
    );
    response_headers.insert(
        HeaderName::from_static("x-eg-policy-id"),
        to_header_value(&decision_result.policy_id)?,
    );
    response_headers.insert(
        HeaderName::from_static("x-eg-trace-id"),
        to_header_value(&decision_result.trace_id)?,
    );
    response_headers.insert(
        HeaderName::from_static("x-eg-geo-country"),
        to_header_value(context.geo_country_iso.as_deref().unwrap_or("unknown"))?,
    );
    response_headers.insert(
        HeaderName::from_static("x-eg-geo-continent"),
        to_header_value(context.geo_continent_code.as_deref().unwrap_or("unknown"))?,
    );
    response_headers.insert(
        HeaderName::from_static("x-eg-geo-eu"),
        to_header_value(match context.geo_is_in_eu {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        })?,
    );

    let body = Json(decision_result);
    Ok((status, response_headers, body))
}

fn get_trace_id(headers: &HeaderMap) -> String {
    header_str(headers, "x-request-id")
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn context_from_headers(headers: &HeaderMap) -> Result<AuthContext, AppError> {
    let forwarded_method = required_header(headers, "x-forwarded-method")?.to_string();
    let forwarded_uri = required_header(headers, "x-forwarded-uri")?.to_string();
    let forwarded_host = required_header(headers, "x-forwarded-host")?.to_string();
    let forwarded_proto = header_str(headers, "x-forwarded-proto").map(ToString::to_string);
    let forwarded_for = header_str(headers, "x-forwarded-for").map(ToString::to_string);
    let user_agent = header_str(headers, "user-agent").map(ToString::to_string);

    let all_headers = headers
        .iter()
        .filter_map(|(k, v)| {
            let value = v.to_str().ok()?.to_string();
            Some((k.as_str().to_ascii_lowercase(), value))
        })
        .collect::<HashMap<_, _>>();

    Ok(AuthContext {
        forwarded_method,
        forwarded_uri,
        forwarded_host,
        forwarded_proto,
        forwarded_for,
        user_agent,
        geo_country_iso: None,
        geo_continent_code: None,
        geo_is_in_eu: None,
        all_headers,
    })
}

fn enrich_context_with_geo(geo: &GeoIpResolver, context: &mut AuthContext) {
    let Some(ip_chain) = &context.forwarded_for else {
        return;
    };
    let Some(first_ip_raw) = ip_chain.split(',').next().map(str::trim) else {
        return;
    };
    let Ok(first_ip) = first_ip_raw.parse::<IpAddr>() else {
        warn!("failed to parse first x-forwarded-for IP: '{}'", first_ip_raw);
        return;
    };

    if let Some(geo_info) = geo.lookup(first_ip) {
        context.geo_country_iso = geo_info.country_iso.map(|v| v.to_ascii_uppercase());
        context.geo_continent_code = geo_info.continent_code.map(|v| v.to_ascii_uppercase());
        context.geo_is_in_eu = geo_info.is_in_eu;
    } else {
        warn!("geo lookup returned no data for client IP '{}'", first_ip);
    }
}

fn policy_mode_from_headers(headers: &HeaderMap) -> Result<PolicyMode, AppError> {
    match header_str(headers, "x-eg-policy-mode") {
        None => Ok(PolicyMode::Fixed),
        Some(raw) if raw.eq_ignore_ascii_case("fixed") => Ok(PolicyMode::Fixed),
        Some(raw) if raw.eq_ignore_ascii_case("inline") => Ok(PolicyMode::Inline),
        Some(raw) => Err(AppError::InvalidRequest(format!(
            "invalid x-eg-policy-mode '{raw}', expected fixed or inline"
        ))),
    }
}

fn ensure_inline_allowed(config: &AppConfig, headers: &HeaderMap) -> Result<(), AppError> {
    let Some(expected_token) = &config.inline_policy_token else {
        return Err(AppError::Forbidden(
            "inline policy mode is disabled by configuration".to_string(),
        ));
    };
    let provided = required_header(headers, "x-eg-inline-token")?;
    if provided != expected_token {
        warn!("inline policy rejected due to invalid token");
        return Err(AppError::Forbidden(
            "invalid inline policy token".to_string(),
        ));
    }
    Ok(())
}

fn parse_inline_policy(headers: &HeaderMap) -> Result<InlinePolicyEnvelope, AppError> {
    let encoded = required_header(headers, "x-eg-inline-policy-b64")?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| AppError::InvalidRequest(format!("invalid inline policy base64: {e}")))?;
    let parsed = serde_json::from_slice::<InlinePolicyEnvelope>(&decoded)
        .map_err(|e| AppError::InvalidRequest(format!("invalid inline policy json: {e}")))?;
    if parsed.rules.is_empty() {
        return Err(AppError::InvalidRequest(
            "inline policy must contain at least one rule".to_string(),
        ));
    }
    Ok(parsed)
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, AppError> {
    header_str(headers, name)
        .ok_or_else(|| AppError::InvalidRequest(format!("missing required header '{name}'")))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn to_header_value(raw: &str) -> Result<HeaderValue, AppError> {
    HeaderValue::from_str(raw).map_err(|e| AppError::Internal(format!("invalid header value: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let yaml = r#"
active_policy_id: baseline-v1
policies:
  - id: baseline-v1
    description: baseline denylist
    rules:
      - id: deny-admin-path
        priority: 200
        action: deny
        type: path_contains
        value: /admin
  - id: strict-v2
    description: denies /private
    rules:
      - id: deny-private
        priority: 200
        action: deny
        type: path_contains
        value: /private
"#;

        let file_path = "/tmp/edge_guard_test_policy.yaml";
        std::fs::write(file_path, yaml).expect("write policy file");

        let engine = Arc::new(PolicyEngine::from_file(file_path).expect("load policy"));
        let config = Arc::new(AppConfig {
            listen_addr: "0.0.0.0:8080".to_string(),
            policy_file: file_path.to_string(),
            geoip_db_file: "/tmp/GeoLite2-Country.mmdb".to_string(),
            inline_policy_token: Some("test-token".to_string()),
        });

        let geo = Arc::new(GeoIpResolver::disabled());
        let throttle = Arc::new(ThrottleService::new());

        AppState {
            engine,
            geo,
            throttle,
            config,
        }
    }

    #[tokio::test]
    async fn deny_admin_path_with_fixed_policy() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/authorize")
            .header("x-forwarded-method", "GET")
            .header("x-forwarded-uri", "/admin/home")
            .header("x-forwarded-host", "example.local")
            .body(Body::empty())
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn unknown_fixed_policy_id_returns_bad_request() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/authorize")
            .header("x-forwarded-method", "GET")
            .header("x-forwarded-uri", "/home")
            .header("x-forwarded-host", "example.local")
            .header("x-eg-fixed-policy-id", "non-existent-policy")
            .body(Body::empty())
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn can_select_non_active_fixed_policy_by_id() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/authorize")
            .header("x-forwarded-method", "GET")
            .header("x-forwarded-uri", "/private/data")
            .header("x-forwarded-host", "example.local")
            .header("x-eg-fixed-policy-id", "strict-v2")
            .body(Body::empty())
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let selected_policy = resp
            .headers()
            .get("x-eg-policy-id")
            .and_then(|v| v.to_str().ok());
        assert_eq!(selected_policy, Some("strict-v2"));
    }
}
