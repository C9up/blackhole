//! Blackhole security filter — the main orchestrator.
//!
//! Chains rate-limit → CSRF → (XSS on response path). Rejected requests
//! produce a `FilterResult::Reject` with a JSON error body.

use crate::csrf::CsrfValidator;
use crate::rate_limit::RateLimiter;
use crate::{FilterResult, Request, Response};

/// Configuration for the Blackhole security filter.
pub struct BlackholeConfig {
    pub xss_enabled: bool,
    pub csrf_enabled: bool,
    pub rate_limit: Option<(u32, u64)>,
    pub path_traversal: bool,
    pub param_pollution: bool,
    /// Route patterns exempt from CSRF (exact, or trailing-`*` prefix).
    pub csrf_except_routes: Vec<String>,
    /// HTTP methods that require CSRF (empty = unsafe-verb default).
    pub csrf_methods: Vec<String>,
}

impl Default for BlackholeConfig {
    fn default() -> Self {
        Self {
            xss_enabled: true,
            csrf_enabled: true,
            rate_limit: None,
            path_traversal: true,
            param_pollution: true,
            csrf_except_routes: Vec::new(),
            csrf_methods: Vec::new(),
        }
    }
}

pub struct BlackholeFilter {
    config: BlackholeConfig,
    rate_limiter: Option<RateLimiter>,
    csrf_validator: CsrfValidator,
}

impl BlackholeFilter {
    pub fn new(config: BlackholeConfig) -> Self {
        let rate_limiter = config.rate_limit.map(|(max, window)| RateLimiter::new(max, window));
        let csrf_validator = CsrfValidator::with_routing(
            config.csrf_except_routes.clone(),
            config.csrf_methods.clone(),
        );
        Self {
            config,
            rate_limiter,
            csrf_validator,
        }
    }

    pub fn config(&self) -> &BlackholeConfig { &self.config }

    pub fn generate_csrf_token(&self) -> String {
        self.csrf_validator.generate_token()
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

        if self.config.path_traversal && crate::shield::contains_traversal(&request.path) {
            return FilterResult::Reject(Response::json(400, r#"{"error":{"code":"E_PATH_TRAVERSAL","message":"Path traversal detected"}}"#));
        }

        if self.config.param_pollution {
            if let Some(dup) = crate::shield::first_duplicate_key(&request.query) {
                let escaped = dup.replace('\\', r"\\").replace('"', r#"\""#);
                return FilterResult::Reject(Response::json(
                    400,
                    &format!(r#"{{"error":{{"code":"E_PARAMETER_POLLUTION","message":"Duplicate parameter: {}"}}}}"#, escaped),
                ));
            }
        }

        let v = &self.csrf_validator;
        if self.config.csrf_enabled && v.requires_csrf(&request.method) && !v.is_excepted(&request.path) {
            // Stateless double-submit: the token in the `XSRF-TOKEN` cookie must
            // match the one the client submits — via an `X-XSRF-TOKEN` /
            // `X-CSRF-TOKEN` header (SPA) or the `_csrf` form field (rendered form).
            let submitted = v
                .header_names
                .iter()
                .find_map(|hn| {
                    request
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(hn))
                        .map(|(_, val)| val.clone())
                })
                .or_else(|| v.token_from_body(&request.body));
            let cookie_token = request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .and_then(|(_, c)| v.token_from_cookie_header(c));
            if !v.validate(cookie_token.as_deref(), submitted.as_deref()) {
                return FilterResult::Reject(Response::json(403, r#"{"error":{"code":"CSRF_FAILED","message":"Invalid or missing CSRF token"}}"#));
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
    fn csrf_allows_when_cookie_matches_header() {
        let f = BlackholeFilter::new(BlackholeConfig::default());
        let token = f.generate_csrf_token();
        let mut headers = HashMap::new();
        headers.insert("x-xsrf-token".into(), token.clone());
        headers.insert("cookie".into(), format!("XSRF-TOKEN={}", token));
        let r = Request { method: "POST".into(), path: "/".into(), query: String::new(), headers, body: String::new(), remote_addr: "127.0.0.1".into() };
        assert!(matches!(f.check(r), FilterResult::Allow(_)));
    }

    #[test]
    fn csrf_allows_legacy_x_csrf_token_header() {
        // The manual `X-CSRF-TOKEN` convention is still accepted alongside Axios' `X-XSRF-TOKEN`.
        let f = BlackholeFilter::new(BlackholeConfig::default());
        let token = f.generate_csrf_token();
        let mut headers = HashMap::new();
        headers.insert("x-csrf-token".into(), token.clone());
        headers.insert("cookie".into(), format!("XSRF-TOKEN={}", token));
        let r = Request { method: "POST".into(), path: "/".into(), query: String::new(), headers, body: String::new(), remote_addr: "127.0.0.1".into() };
        assert!(matches!(f.check(r), FilterResult::Allow(_)));
    }

    #[test]
    fn csrf_allows_token_from_form_body() {
        // Server-rendered form: token rides in the `_csrf` body field, not a header.
        let f = BlackholeFilter::new(BlackholeConfig::default());
        let token = f.generate_csrf_token();
        let mut headers = HashMap::new();
        headers.insert("cookie".into(), format!("XSRF-TOKEN={}", token));
        let r = Request { method: "POST".into(), path: "/".into(), query: String::new(), headers, body: format!("name=x&_csrf={}", token), remote_addr: "127.0.0.1".into() };
        assert!(matches!(f.check(r), FilterResult::Allow(_)));
    }

    #[test]
    fn csrf_skips_excepted_route() {
        // A webhook route listed in exceptRoutes bypasses CSRF entirely.
        let f = BlackholeFilter::new(BlackholeConfig {
            csrf_except_routes: vec!["/api/webhooks/*".into()],
            ..Default::default()
        });
        assert!(matches!(f.check(req("POST", "/api/webhooks/stripe")), FilterResult::Allow(_)));
        // …but a non-excepted POST still requires the token.
        assert!(matches!(f.check(req("POST", "/api/users")), FilterResult::Reject(_)));
    }

    #[test]
    fn csrf_rejects_header_without_matching_cookie() {
        // Double-submit: a forged header alone (no matching cookie) is rejected.
        let f = BlackholeFilter::new(BlackholeConfig::default());
        let mut headers = HashMap::new();
        headers.insert("x-csrf-token".into(), f.generate_csrf_token());
        let r = Request { method: "POST".into(), path: "/".into(), query: String::new(), headers, body: String::new(), remote_addr: "127.0.0.1".into() };
        assert!(matches!(f.check(r), FilterResult::Reject(_)));
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
