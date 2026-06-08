//! CSRF — stateless double-submit cookie validation (AdonisJS-compatible API).
//!
//! No server-side token store: on an unsafe request the token carried in the
//! `XSRF-TOKEN` cookie is compared (constant-time) against the token echoed by
//! the client. Because validation is purely a comparison of two values the
//! client already holds, it scales horizontally (no shared store, nothing to
//! purge, nothing lost on restart).
//!
//! Naming mirrors `@adonisjs/shield` so the muscle memory carries over:
//! - cookie `XSRF-TOKEN` (auto-read by Axios / Angular `HttpClient`)
//! - headers `X-XSRF-TOKEN` (SPA clients) **or** `X-CSRF-TOKEN` (manual)
//! - form field `_csrf` (server-rendered forms via `csrfField()`)
//! - `exceptRoutes` to skip validation (webhooks), `methods` to choose which
//!   verbs are guarded.
//!
//! @implements FR45

use crate::constant_time::constant_time_str_eq;

const DEFAULT_COOKIE_NAME: &str = "XSRF-TOKEN";
/// Accepted submission headers, in priority order: the Axios/Angular default
/// first, then the manual `X-CSRF-TOKEN` convention.
const DEFAULT_HEADER_NAMES: [&str; 2] = ["x-xsrf-token", "x-csrf-token"];
const DEFAULT_BODY_FIELD: &str = "_csrf";
const DEFAULT_METHODS: [&str; 4] = ["POST", "PUT", "PATCH", "DELETE"];

/// Stateless double-submit CSRF validator. Holds only naming + routing config.
pub struct CsrfValidator {
    /// Cookie the token is issued in (and read back from on validation).
    pub cookie_name: String,
    /// Headers the client may echo the token in (any one matches).
    pub header_names: Vec<String>,
    /// Form-body field carrying the token for server-rendered forms.
    pub body_field: String,
    /// Route patterns exempt from CSRF (exact, or trailing-`*` prefix).
    pub except_routes: Vec<String>,
    /// HTTP methods that require validation (upper-case).
    pub methods: Vec<String>,
}

impl CsrfValidator {
    pub fn new() -> Self {
        Self {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            header_names: DEFAULT_HEADER_NAMES.iter().map(|s| s.to_string()).collect(),
            body_field: DEFAULT_BODY_FIELD.to_string(),
            except_routes: Vec::new(),
            methods: DEFAULT_METHODS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Build a validator with custom exempt routes + guarded methods. Empty
    /// `methods` falls back to the unsafe-verb default.
    pub fn with_routing(except_routes: Vec<String>, methods: Vec<String>) -> Self {
        let mut v = Self::new();
        v.except_routes = except_routes;
        if !methods.is_empty() {
            v.methods = methods.iter().map(|m| m.to_ascii_uppercase()).collect();
        }
        v
    }

    /// Generate a fresh CSRF token (crypto-random hex). Stateless — the caller
    /// sets it as the `cookie_name` cookie; the client echoes it back.
    ///
    /// Panics if the OS entropy source is unavailable — a non-crypto fallback is
    /// worse than a clear failure because it creates a false sense of security.
    pub fn generate_token(&self) -> String {
        generate_crypto_random_hex(32)
            .expect("[blackhole] FATAL: getrandom failed — cannot generate CSRF token. OS entropy source is unavailable.")
    }

    /// Double-submit check: the cookie token and the submitted token must both
    /// be present, non-empty, and equal (constant-time). No store lookup.
    pub fn validate(&self, cookie_token: Option<&str>, submitted_token: Option<&str>) -> bool {
        match (cookie_token, submitted_token) {
            (Some(c), Some(h)) if !c.is_empty() && !h.is_empty() => constant_time_str_eq(c, h),
            _ => false,
        }
    }

    /// Extract the CSRF token from a raw `Cookie` header value
    /// (`a=1; XSRF-TOKEN=xyz; b=2`). Returns `None` when the cookie is absent.
    pub fn token_from_cookie_header(&self, cookie_header: &str) -> Option<String> {
        let prefix = format!("{}=", self.cookie_name);
        cookie_header
            .split(';')
            .map(str::trim)
            .find_map(|part| part.strip_prefix(&prefix).map(str::to_string))
    }

    /// Extract the token from a urlencoded form body (`a=1&_csrf=xyz&b=2`).
    /// Returns `None` for JSON or any body without the field.
    pub fn token_from_body(&self, body: &str) -> Option<String> {
        let prefix = format!("{}=", self.body_field);
        body.split('&')
            .find_map(|pair| pair.strip_prefix(&prefix))
            .map(|raw| urlencoding::decode(raw).map(|c| c.into_owned()).unwrap_or_else(|_| raw.to_string()))
    }

    /// Does this request method require CSRF validation?
    pub fn requires_csrf(&self, method: &str) -> bool {
        let upper = method.to_ascii_uppercase();
        self.methods.iter().any(|m| m == &upper)
    }

    /// Is this path exempt from CSRF (matches an `exceptRoutes` pattern)?
    /// A pattern ending in `*` is a prefix match; otherwise an exact match.
    pub fn is_excepted(&self, path: &str) -> bool {
        self.except_routes.iter().any(|pat| match pat.strip_suffix('*') {
            Some(prefix) => path.starts_with(prefix),
            None => path == pat,
        })
    }
}

impl Default for CsrfValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a hex string using cryptographic randomness (getrandom).
/// Returns Err if the OS entropy source is unavailable.
fn generate_crypto_random_hex(bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|e| format!("getrandom failed: {}", e))?;
    Ok(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_when_cookie_matches_header() {
        let v = CsrfValidator::new();
        let token = v.generate_token();
        assert!(v.validate(Some(&token), Some(&token)));
    }

    #[test]
    fn rejects_mismatch() {
        let v = CsrfValidator::new();
        assert!(!v.validate(Some("aaaa"), Some("bbbb")));
    }

    #[test]
    fn rejects_missing_cookie_or_header() {
        let v = CsrfValidator::new();
        assert!(!v.validate(None, Some("x")));
        assert!(!v.validate(Some("x"), None));
        assert!(!v.validate(None, None));
    }

    #[test]
    fn rejects_empty_tokens() {
        let v = CsrfValidator::new();
        assert!(!v.validate(Some(""), Some("")));
    }

    #[test]
    fn is_stateless_reusable() {
        // Same token validates repeatedly — no single-use store.
        let v = CsrfValidator::new();
        let token = v.generate_token();
        assert!(v.validate(Some(&token), Some(&token)));
        assert!(v.validate(Some(&token), Some(&token)));
    }

    #[test]
    fn parses_token_from_cookie_header() {
        let v = CsrfValidator::new();
        assert_eq!(
            v.token_from_cookie_header("sid=abc; XSRF-TOKEN=xyz123; theme=dark"),
            Some("xyz123".to_string())
        );
        assert_eq!(v.token_from_cookie_header("sid=abc"), None);
    }

    #[test]
    fn parses_token_from_form_body() {
        let v = CsrfValidator::new();
        assert_eq!(
            v.token_from_body("name=O%27Brien&_csrf=tok123&ok=1"),
            Some("tok123".to_string())
        );
        assert_eq!(v.token_from_body(r#"{"_csrf":"x"}"#), None);
    }

    #[test]
    fn token_is_crypto_random() {
        let v = CsrfValidator::new();
        let (t1, t2) = (v.generate_token(), v.generate_token());
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn requires_csrf_on_unsafe_methods() {
        let v = CsrfValidator::new();
        assert!(v.requires_csrf("POST"));
        assert!(v.requires_csrf("put"));
        assert!(v.requires_csrf("PATCH"));
        assert!(v.requires_csrf("DELETE"));
        assert!(!v.requires_csrf("GET"));
        assert!(!v.requires_csrf("HEAD"));
        assert!(!v.requires_csrf("OPTIONS"));
    }

    #[test]
    fn custom_methods_override_default() {
        let v = CsrfValidator::with_routing(Vec::new(), vec!["DELETE".to_string()]);
        assert!(v.requires_csrf("DELETE"));
        assert!(!v.requires_csrf("POST"));
    }

    #[test]
    fn except_routes_exact_and_prefix() {
        let v = CsrfValidator::with_routing(
            vec!["/api/health".to_string(), "/api/webhooks/*".to_string()],
            Vec::new(),
        );
        assert!(v.is_excepted("/api/health"));
        assert!(v.is_excepted("/api/webhooks/stripe"));
        assert!(!v.is_excepted("/api/users"));
        assert!(!v.is_excepted("/api/health/sub"));
    }
}
