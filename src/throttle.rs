use crate::models::{AuthContext, ThrottleKey, ThrottleRule};
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ThrottleDecision {
    pub limited: bool,
}

#[derive(Clone)]
pub struct ThrottleService {
    store: Arc<dyn ThrottleStore>,
}

impl ThrottleService {
    pub fn new() -> Self {
        Self {
            store: Arc::new(InMemoryThrottleStore::new()),
        }
    }

    pub fn evaluate(&self, rule_id: &str, rule: &ThrottleRule, ctx: &AuthContext) -> ThrottleDecision {
        if !method_match(rule, ctx) || !path_match(rule, ctx) {
            return ThrottleDecision { limited: false };
        }

        let key = build_throttle_key(rule_id, rule, ctx);
        let now = Instant::now();
        let window = Duration::from_secs(rule.window_seconds.max(1));
        let block = Duration::from_secs(rule.block_seconds.max(1));
        let limited = self
            .store
            .evaluate_and_update(&key, rule.max_requests.max(1), window, block, now);
        ThrottleDecision { limited }
    }
}

pub trait ThrottleStore: Send + Sync {
    fn evaluate_and_update(
        &self,
        key: &str,
        max_requests: u64,
        window: Duration,
        block: Duration,
        now: Instant,
    ) -> bool;
}

fn method_match(rule: &ThrottleRule, ctx: &AuthContext) -> bool {
    if rule.match_method_in.is_empty() {
        return true;
    }
    rule.match_method_in
        .iter()
        .any(|m| m.eq_ignore_ascii_case(&ctx.forwarded_method))
}

fn path_match(rule: &ThrottleRule, ctx: &AuthContext) -> bool {
    if rule.match_path_prefix_in.is_empty() {
        return true;
    }
    rule.match_path_prefix_in
        .iter()
        .any(|prefix| ctx.forwarded_uri.starts_with(prefix))
}

fn build_throttle_key(rule_id: &str, rule: &ThrottleRule, ctx: &AuthContext) -> String {
    let parts = if rule.key_by.is_empty() {
        vec![format!("client_ip={}", client_ip(ctx).unwrap_or("unknown"))]
    } else {
        rule.key_by
            .iter()
            .map(|k| match k {
                ThrottleKey::Method => format!("method={}", ctx.forwarded_method.to_ascii_uppercase()),
                ThrottleKey::Path => format!("path={}", ctx.forwarded_uri),
                ThrottleKey::ClientIp => format!("client_ip={}", client_ip(ctx).unwrap_or("unknown")),
            })
            .collect::<Vec<_>>()
    };
    format!("{}|{}", rule_id, parts.join("|"))
}

fn client_ip(ctx: &AuthContext) -> Option<&str> {
    ctx.forwarded_for
        .as_ref()
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

#[derive(Debug, Clone)]
struct InMemoryThrottleStore {
    entries: DashMap<String, ThrottleEntry>,
    ops_counter: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
struct ThrottleEntry {
    window_start: Instant,
    requests_in_window: u64,
    blocked_until: Option<Instant>,
}

impl InMemoryThrottleStore {
    fn new() -> Self {
        Self {
            entries: DashMap::new(),
            ops_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn cleanup_stale_entries(&self, now: Instant, window: Duration, block: Duration) {
        let counter = self.ops_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if counter % 2048 != 0 {
            return;
        }
        let ttl = window.saturating_add(block).saturating_add(Duration::from_secs(30));
        self.entries.retain(|_, entry| {
            let not_blocked = entry.blocked_until.is_none_or(|until| now >= until);
            let old_window = now.duration_since(entry.window_start) > ttl;
            !(not_blocked && old_window)
        });
    }
}

impl ThrottleStore for InMemoryThrottleStore {
    fn evaluate_and_update(
        &self,
        key: &str,
        max_requests: u64,
        window: Duration,
        block: Duration,
        now: Instant,
    ) -> bool {
        let limited = {
            let mut entry = self.entries.entry(key.to_string()).or_insert_with(|| ThrottleEntry {
                window_start: now,
                requests_in_window: 0,
                blocked_until: None,
            });

            if let Some(until) = entry.blocked_until {
                if now < until {
                    return true;
                }
                entry.blocked_until = None;
            }

            if now.duration_since(entry.window_start) >= window {
                entry.window_start = now;
                entry.requests_in_window = 0;
            }

            entry.requests_in_window += 1;
            if entry.requests_in_window > max_requests {
                entry.blocked_until = Some(now + block);
                true
            } else {
                false
            }
        };

        self.cleanup_stale_entries(now, window, block);
        limited
    }
}
