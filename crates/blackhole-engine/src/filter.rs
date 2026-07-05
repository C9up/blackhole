//! Blackhole security filter — the main orchestrator.
//!
//! Chains rate-limit → CSRF → (XSS on response path). Rejected requests
//! produce a `FilterResult::Reject` with a JSON error body.

use crate::csrf::CsrfValidator;
use crate::rate_limit::{RateLimitOutcome, RateLimiter};
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
    /// Cross-origins trusted for state-changing requests (same-origin is always
    /// allowed). Empty = same-origin only.
    pub csrf_trusted_origins: Vec<String>,
    /// HMAC secret for signing CSRF tokens (the app's `APP_KEY`). Empty falls
    /// back to a per-process ephemeral key (single-instance dev safety net).
    pub csrf_secret: Vec<u8>,
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
            csrf_trusted_origins: Vec::new(),
            csrf_secret: Vec::new(),
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
            config.csrf_trusted_origins.clone(),
            config.csrf_secret.clone(),
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
        self.check_with_meta(request).0
    }

    /// Like `check`, but also returns the rate-limit outcome (limit / remaining /
    /// reset) when a limiter is configured — so the integration layer can emit
    /// `X-RateLimit-*` headers on the SUCCESS path too, not just the 429
    /// rejection (parity with @adonisjs/limiter, which sets them on every
    /// response). `None` when no limiter is configured.
    pub fn check_with_meta(&self, request: Request) -> (FilterResult, Option<RateLimitOutcome>) {
        let mut rate_meta: Option<RateLimitOutcome> = None;
        if let Some(ref limiter) = self.rate_limiter {
            // Reject requests with no IP rather than sharing a global "unknown"
            // bucket — prevents unintentional DoS on all unauthenticated traffic.
            if request.remote_addr.is_empty() {
                return (FilterResult::Reject(Response::json(400, r#"{"error":{"code":"MISSING_IP","message":"Cannot rate-limit: no remote address"}}"#)), None);
            }
            let outcome = limiter.check_detailed(&request.remote_addr);
            rate_meta = Some(outcome);
            if !outcome.allowed {
                // Emit backoff signals so well-behaved clients + proxies honour
                // the limit (Retry-After + X-RateLimit-* — parity with @adonisjs/limiter).
                let headers = vec![
                    ("Retry-After".to_string(), outcome.retry_after_secs.to_string()),
                    ("X-RateLimit-Limit".to_string(), outcome.limit.to_string()),
                    ("X-RateLimit-Remaining".to_string(), "0".to_string()),
                    ("X-RateLimit-Reset".to_string(), outcome.retry_after_secs.to_string()),
                ];
                return (FilterResult::Reject(Response::json_with_headers(
                    429,
                    r#"{"error":{"code":"RATE_LIMITED","message":"Too many requests"}}"#,
                    headers,
                )), rate_meta);
            }
        }

        if self.config.path_traversal && crate::shield::contains_traversal(&request.path) {
            return (FilterResult::Reject(Response::json(400, r#"{"error":{"code":"E_PATH_TRAVERSAL","message":"Path traversal detected"}}"#)), rate_meta);
        }

        if self.config.param_pollution {
            if let Some(dup) = crate::shield::first_duplicate_key(&request.query) {
                let escaped = dup.replace('\\', r"\\").replace('"', r#"\""#);
                return (FilterResult::Reject(Response::json(
                    400,
                    &format!(r#"{{"error":{{"code":"E_PARAMETER_POLLUTION","message":"Duplicate parameter: {}"}}}}"#, escaped),
                )), rate_meta);
            }
        }

        let v = &self.csrf_validator;
        if self.config.csrf_enabled && v.requires_csrf(&request.method) && !v.is_excepted(&request.path) {
            // Defense-in-depth: reject a state-changing request whose Origin /
            // Referer is cross-origin (and not trusted) BEFORE the token check —
            // this is what stops a planted-but-validly-signed token (sibling
            // subdomain / MITM cookie injection) that the token check alone can't.
            let find = |name: &str| {
                request
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            };
            if !v.verify_origin(find("host"), find("origin"), find("referer")) {
                return (FilterResult::Reject(Response::json(403, r#"{"error":{"code":"CSRF_ORIGIN_MISMATCH","message":"Cross-origin state-changing request rejected"}}"#)), rate_meta);
            }

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
                return (FilterResult::Reject(Response::json(403, r#"{"error":{"code":"CSRF_FAILED","message":"Invalid or missing CSRF token"}}"#)), rate_meta);
            }
        }

        (FilterResult::Allow(request), rate_meta)
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
    fn csrf_rejects_cross_origin_even_with_valid_token() {
        // Defense-in-depth: a validly-signed, cookie-matching token is NOT enough
        // if the request's Origin is cross-origin (planted-cookie attack).
        let f = BlackholeFilter::new(BlackholeConfig::default());
        let token = f.generate_csrf_token();
        let mut headers = HashMap::new();
        headers.insert("x-xsrf-token".into(), token.clone());
        headers.insert("cookie".into(), format!("XSRF-TOKEN={}", token));
        headers.insert("host".into(), "app.test".into());
        headers.insert("origin".into(), "https://evil.test".into());
        let r = Request { method: "POST".into(), path: "/".into(), query: String::new(), headers, body: String::new(), remote_addr: "127.0.0.1".into() };
        assert!(matches!(f.check(r), FilterResult::Reject(_)));
    }

    #[test]
    fn csrf_allows_same_origin_with_valid_token() {
        let f = BlackholeFilter::new(BlackholeConfig::default());
        let token = f.generate_csrf_token();
        let mut headers = HashMap::new();
        headers.insert("x-xsrf-token".into(), token.clone());
        headers.insert("cookie".into(), format!("XSRF-TOKEN={}", token));
        headers.insert("host".into(), "app.test".into());
        headers.insert("origin".into(), "https://app.test".into());
        let r = Request { method: "POST".into(), path: "/".into(), query: String::new(), headers, body: String::new(), remote_addr: "127.0.0.1".into() };
        assert!(matches!(f.check(r), FilterResult::Allow(_)));
    }

    #[test]
    fn rate_limit_reject_carries_retry_after() {
        let f = BlackholeFilter::new(BlackholeConfig { rate_limit: Some((1, 60)), csrf_enabled: false, ..Default::default() });
        assert!(matches!(f.check(req("GET", "/")), FilterResult::Allow(_)));
        match f.check(req("GET", "/")) {
            FilterResult::Reject(res) => {
                assert_eq!(res.status, 429);
                assert!(res.headers.iter().any(|(k, _)| k == "Retry-After"));
                assert!(res.headers.iter().any(|(k, _)| k == "X-RateLimit-Limit"));
            }
            _ => panic!("should be rate-limited"),
        }
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
