use crate::error::AppError;
use crate::models::{
    AuthContext, Decision, DecisionResult, NamedPolicy, PolicyFile, RuleAction, RuleConfig, RuleKind,
};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    active_policy_id: String,
    fixed_policies: HashMap<String, NamedPolicy>,
}

impl PolicyEngine {
    pub fn from_file(path: &str) -> Result<Self, AppError> {
        let raw = fs::read_to_string(path).map_err(|e| {
            AppError::PolicyConfig(format!("failed to read policy file '{path}': {e}"))
        })?;
        let parsed: PolicyFile = serde_yaml::from_str(&raw)
            .map_err(|e| AppError::PolicyConfig(format!("invalid yaml in '{path}': {e}")))?;

        let fixed_policies = parsed
            .policies
            .into_iter()
            .map(|p| (p.id.clone(), p))
            .collect::<HashMap<_, _>>();

        if !fixed_policies.contains_key(&parsed.active_policy_id) {
            return Err(AppError::PolicyConfig(format!(
                "active_policy_id '{}' not found in policies",
                parsed.active_policy_id
            )));
        }

        Ok(Self {
            active_policy_id: parsed.active_policy_id,
            fixed_policies,
        })
    }

    pub fn evaluate_fixed(
        &self,
        ctx: &AuthContext,
        requested_policy_id: Option<&str>,
        trace_id: String,
    ) -> Result<DecisionResult, AppError> {
        let policy_id = requested_policy_id.unwrap_or(&self.active_policy_id);
        let policy = self.fixed_policies.get(policy_id).ok_or_else(|| {
            AppError::InvalidRequest(format!(
                "unknown fixed policy id '{policy_id}'"
            ))
        })?;
        Ok(evaluate_rules(
            &policy.id,
            &policy.rules,
            ctx,
            trace_id,
        ))
    }

    pub fn evaluate_inline(
        &self,
        policy_id: &str,
        rules: &[RuleConfig],
        ctx: &AuthContext,
        trace_id: String,
    ) -> DecisionResult {
        evaluate_rules(policy_id, rules, ctx, trace_id)
    }
}

fn evaluate_rules(
    policy_id: &str,
    rules: &[RuleConfig],
    ctx: &AuthContext,
    trace_id: String,
) -> DecisionResult {
    let mut ordered = rules.to_vec();
    ordered.sort_by(|a, b| b.priority.cmp(&a.priority));

    for rule in ordered {
        if rule_matches(&rule, ctx) {
            let decision = match rule.action {
                RuleAction::Allow => Decision::Allow,
                RuleAction::Deny => Decision::Deny,
            };
            return DecisionResult {
                decision,
                reason: format!("matched_rule:{}", rule.id),
                policy_id: policy_id.to_string(),
                trace_id,
            };
        }
    }

    DecisionResult {
        decision: Decision::Allow,
        reason: "no_matching_rules".to_string(),
        policy_id: policy_id.to_string(),
        trace_id,
    }
}

fn rule_matches(rule: &RuleConfig, ctx: &AuthContext) -> bool {
    match &rule.kind {
        RuleKind::PathContains { value } => ctx.forwarded_uri.contains(value),
        RuleKind::MethodIn { values } => values
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&ctx.forwarded_method)),
        RuleKind::HeaderEquals { header, value } => header_value(ctx, header)
            .map(|v| v.eq_ignore_ascii_case(value))
            .unwrap_or(false),
        RuleKind::HeaderRegex { header, pattern } => {
            let Ok(regex) = Regex::new(pattern) else {
                warn!("invalid regex pattern in policy rule '{}'", rule.id);
                return false;
            };
            header_value(ctx, header)
                .map(|v| regex.is_match(v))
                .unwrap_or(false)
        }
        RuleKind::IpInDenylist { values } => {
            let Some(ip_chain) = &ctx.forwarded_for else {
                return false;
            };
            let first_ip = ip_chain.split(',').next().map(|v| v.trim());
            match first_ip {
                Some(ip) => values.iter().any(|blocked| blocked == ip),
                None => false,
            }
        }
        RuleKind::CountryIn { values } => {
            let Some(country) = &ctx.geo_country_iso else {
                return false;
            };
            values
                .iter()
                .any(|v| v.eq_ignore_ascii_case(country))
        }
        RuleKind::ContinentIn { values } => {
            let Some(continent) = &ctx.geo_continent_code else {
                return false;
            };
            values
                .iter()
                .any(|v| v.eq_ignore_ascii_case(continent))
        }
        RuleKind::IsInEuropeanUnion { value } => match ctx.geo_is_in_eu {
            Some(is_in_eu) => is_in_eu == *value,
            None => !*value,
        },
    }
}

fn header_value<'a>(ctx: &'a AuthContext, key: &str) -> Option<&'a str> {
    let needle = key.to_ascii_lowercase();
    ctx.all_headers.get(&needle).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{RuleAction, RuleKind};
    use std::collections::HashMap;

    fn sample_ctx() -> AuthContext {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "curl/8.0".to_string());
        AuthContext {
            forwarded_method: "GET".to_string(),
            forwarded_uri: "/admin/dashboard".to_string(),
            forwarded_host: "example.local".to_string(),
            forwarded_proto: Some("https".to_string()),
            forwarded_for: Some("203.0.113.10".to_string()),
            user_agent: Some("curl/8.0".to_string()),
            geo_country_iso: Some("DE".to_string()),
            geo_continent_code: Some("EU".to_string()),
            geo_is_in_eu: Some(true),
            all_headers: headers,
        }
    }

    #[test]
    fn deny_rule_matches_path() {
        let ctx = sample_ctx();
        let result = evaluate_rules(
            "test",
            &[RuleConfig {
                id: "deny_admin".to_string(),
                priority: 200,
                action: RuleAction::Deny,
                kind: RuleKind::PathContains {
                    value: "/admin".to_string(),
                },
            }],
            &ctx,
            "trace-1".to_string(),
        );
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn deny_rule_matches_country() {
        let ctx = sample_ctx();
        let result = evaluate_rules(
            "geo-test",
            &[RuleConfig {
                id: "deny-country-de".to_string(),
                priority: 200,
                action: RuleAction::Deny,
                kind: RuleKind::CountryIn {
                    values: vec!["DE".to_string()],
                },
            }],
            &ctx,
            "trace-2".to_string(),
        );
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn deny_rule_matches_non_eu_when_geo_unknown() {
        let mut ctx = sample_ctx();
        ctx.geo_is_in_eu = None;

        let result = evaluate_rules(
            "geo-test",
            &[RuleConfig {
                id: "deny-non-eu".to_string(),
                priority: 200,
                action: RuleAction::Deny,
                kind: RuleKind::IsInEuropeanUnion { value: false },
            }],
            &ctx,
            "trace-3".to_string(),
        );
        assert_eq!(result.decision, Decision::Deny);
    }
}
