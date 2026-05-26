//! Blackhole security filter — the main orchestrator.
//!
//! Chains rate-limit → CSRF → (XSS on response path). Rejected requests
//! produce a `FilterResult::Reject` with a JSON error body.

use crate::csrf::CsrfValidator;
use crate::rate_limit::RateLimiter;
use crate::{FilterResult, Request, Response};
use std::sync::Mutex;

/// Configuration for the Blackhole security filter.
pub struct BlackholeConfig {
    pub xss_enabled: bool,
    pub csrf_enabled: bool,
    pub rate_limit: Option<(u32, u64)>,
}

impl Default for BlackholeConfig {
    fn default() -> Self {
        Self {
            xss_enabled: true,
            csrf_enabled: true,
            rate_limit: None,
        }
    }
}

pub struct BlackholeFilter {
    config: BlackholeConfig,
    rate_limiter: Option<RateLimiter>,
    csrf_validator: Mutex<CsrfValidator>,
}

impl BlackholeFilter {
    pub fn new(config: BlackholeConfig) -> Self {
        let rate_limiter = config.rate_limit.map(|(max, window)| RateLimiter::new(max, window));
        Self {
            config,
            rate_limiter,
            csrf_validator: Mutex::new(CsrfValidator::new()),
        }
    }

    pub fn config(&self) -> &BlackholeConfig { &self.config }

    pub fn generate_csrf_token(&self) -> String {
        let mut validator = self.csrf_validator.lock().unwrap_or_else(|e| e.into_inner());
        validator.generate_token()
    }

    pub fn check(&self, request: Request) -> FilterResult {
        if let Some(ref limiter) = self.rate_limiter {
            // Reject requests with no IP rather than sharing a global "unknown"
            // bucket — prevents unintentional DoS on all unauthenticated traffic.
            if request.remote_addr.is_empty() {
                return FilterResult::Reject(Response::json(400, r#"{"error":{"code":"MISSING_IP","message":"Cannot rate-limit: no remote address"}}"#));
            }
            if !limiter.check(&request.remote_addr) {
                return FilterResult::Reject(Response::json(429, r#"{"error":{"code":"RATE_LIMITED","message":"Too many requests"}}"#));
            }
        }

        if self.config.csrf_enabled && CsrfValidator::requires_csrf(&request.method) {
            let token = request.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-csrf-token")).map(|(_, v)| v).cloned();
            let mut validator = self.csrf_validator.lock().unwrap_or_else(|e| e.into_inner());
            match token {
                Some(t) if validator.validate(&t) => {}
                _ => return FilterResult::Reject(Response::json(403, r#"{"error":{"code":"CSRF_FAILED","message":"Invalid or missing CSRF token"}}"#)),
            }
        }

        FilterResult::Allow(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn req(method: &str, path: &str) -> Request {
        Request { method: method.into(), path: path.into(), query: String::new(), headers: HashMap::new(), body: String::new(), remote_addr: "127.0.0.1".into() }
    }

    #[test]
    fn allows_get() {
        let f = BlackholeFilter::new(BlackholeConfig { csrf_enabled: false, ..Default::default() });
        assert!(matches!(f.check(req("GET", "/api")), FilterResult::Allow(_)));
    }

    #[test]
    fn rate_limit_blocks() {
        let f = BlackholeFilter::new(BlackholeConfig { rate_limit: Some((2, 60)), csrf_enabled: false, ..Default::default() });
        assert!(matches!(f.check(req("GET", "/")), FilterResult::Allow(_)));
        assert!(matches!(f.check(req("GET", "/")), FilterResult::Allow(_)));
        assert!(matches!(f.check(req("GET", "/")), FilterResult::Reject(_)));
    }

    #[test]
    fn csrf_blocks_post() {
        let f = BlackholeFilter::new(BlackholeConfig::default());
        assert!(matches!(f.check(req("POST", "/")), FilterResult::Reject(_)));
    }

    #[test]
    fn csrf_allows_with_token() {
        let f = BlackholeFilter::new(BlackholeConfig::default());
        let token = f.generate_csrf_token();
        let mut headers = HashMap::new();
        headers.insert("x-csrf-token".into(), token);
        let r = Request { method: "POST".into(), path: "/".into(), query: String::new(), headers, body: String::new(), remote_addr: "127.0.0.1".into() };
        assert!(matches!(f.check(r), FilterResult::Allow(_)));
    }

    #[test]
    fn body_passes_through() {
        let f = BlackholeFilter::new(BlackholeConfig { csrf_enabled: false, ..Default::default() });
        let body = r#"{"name":"O'Brien"}"#.to_string();
        let r = Request { method: "POST".into(), path: "/".into(), query: String::new(), headers: HashMap::new(), body: body.clone(), remote_addr: "127.0.0.1".into() };
        match f.check(r) {
            FilterResult::Allow(r) => assert_eq!(r.body, body),
            _ => panic!("should pass"),
        }
    }

    #[test]
    fn rate_limit_rejects_missing_ip() {
        let f = BlackholeFilter::new(BlackholeConfig { rate_limit: Some((10, 60)), csrf_enabled: false, ..Default::default() });
        let mut r = req("GET", "/");
        r.remote_addr = String::new();
        assert!(matches!(f.check(r), FilterResult::Reject(_)));
    }
}
