//! CSRF — stateless **signed** double-submit cookie validation (AdonisJS-compatible API).
//!
//! No server-side token store. The token issued in the `XSRF-TOKEN` cookie is
//! `<random>.<HMAC-SHA256(secret, random)>`. On an unsafe request two things
//! must hold: (1) the cookie token equals the token the client echoes back
//! (the classic double-submit — an attacker can't set the `X-XSRF-TOKEN`
//! header cross-site), AND (2) the token carries a valid HMAC signature under
//! the server secret. (2) is what makes this *signed* double-submit: an
//! attacker cannot forge a brand-new valid token because they don't hold the
//! secret. A plain (unsigned) double-submit would accept any self-consistent
//! pair — this one does not.
//!
//! The signature alone does NOT bind the token to a user, so it does not by
//! itself stop an attacker who plants a token they were *legitimately* issued
//! (sibling-subdomain `Set-Cookie` / MITM on an http subdomain). That gap is
//! closed by [`CsrfValidator::verify_origin`] — a same-origin `Origin`/`Referer`
//! check on unsafe verbs, applied before the token check.
//!
//! Because validation is still purely cryptographic on values the request
//! carries, it scales horizontally with **no shared store** — every instance
//! only needs the same `secret` (the app's `APP_KEY`), which they already share.
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

/// Stateless **signed** double-submit CSRF validator. Holds naming + routing
/// config plus the HMAC `secret` used to sign and verify tokens.
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
    /// Origins allowed to make cross-origin state-changing requests, in addition
    /// to same-origin (always allowed). Matched by host
    /// (`https://app.example.com` or `app.example.com`).
    pub trusted_origins: Vec<String>,
    /// HMAC-SHA256 key for signing tokens. Seeded from the app's `APP_KEY` so
    /// every instance signs/verifies identically (stateless horizontal scale).
    /// Never empty: an empty input is replaced with a per-process ephemeral key
    /// so a token is **always** signed — there is no unsigned code path to
    /// downgrade to.
    secret: Vec<u8>,
}

impl CsrfValidator {
    /// Build with the unsafe-verb defaults and the given HMAC secret. An empty
    /// secret is replaced with an ephemeral per-process key (single-instance
    /// dev safety net) so tokens are always signed.
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            header_names: DEFAULT_HEADER_NAMES.iter().map(|s| s.to_string()).collect(),
            body_field: DEFAULT_BODY_FIELD.to_string(),
            except_routes: Vec::new(),
            methods: DEFAULT_METHODS.iter().map(|s| s.to_string()).collect(),
            trusted_origins: Vec::new(),
            secret: resolve_secret(secret),
        }
    }

    /// Build a validator with custom exempt routes + guarded methods + trusted
    /// origins + secret. Empty `methods` falls back to the unsafe-verb default.
    pub fn with_routing(
        except_routes: Vec<String>,
        methods: Vec<String>,
        trusted_origins: Vec<String>,
        secret: Vec<u8>,
    ) -> Self {
        let mut v = Self::new(secret);
        v.except_routes = except_routes;
        v.trusted_origins = trusted_origins;
        if !methods.is_empty() {
            v.methods = methods.iter().map(|m| m.to_ascii_uppercase()).collect();
        }
        v
    }

    /// Generate a fresh signed CSRF token: `<random-hex>.<base64url-HMAC>`.
    /// Stateless — the caller sets it as the `cookie_name` cookie; the client
    /// echoes it back. The signature lets `validate` reject any cookie value
    /// the server did not mint, even when cookie and submitted token match.
    ///
    /// Panics if the OS entropy source is unavailable — a non-crypto fallback is
    /// worse than a clear failure because it creates a false sense of security.
    pub fn generate_token(&self) -> String {
        let random = generate_crypto_random_hex(32)
            .expect("[blackhole] FATAL: getrandom failed — cannot generate CSRF token. OS entropy source is unavailable.");
        let sig = crate::crypto::hmac_sign(&random, &self.secret)
            .expect("[blackhole] FATAL: HMAC signing failed while minting CSRF token.");
        format!("{random}.{sig}")
    }

    /// Signed double-submit check. Both tokens must be present, non-empty, and
    /// equal (constant-time) — **and** the token must carry a valid HMAC under
    /// the server secret. The signature check is what defeats a cookie injected
    /// by a sibling subdomain / MITM: a self-consistent but unsigned pair fails.
    pub fn validate(&self, cookie_token: Option<&str>, submitted_token: Option<&str>) -> bool {
        match (cookie_token, submitted_token) {
            (Some(c), Some(h)) if !c.is_empty() && !h.is_empty() => {
                constant_time_str_eq(c, h) && self.verify_signature(c)
            }
            _ => false,
        }
    }

    /// Verify a token's `<random>.<sig>` HMAC against the server secret.
    fn verify_signature(&self, token: &str) -> bool {
        match token.split_once('.') {
            Some((random, sig)) if !random.is_empty() && !sig.is_empty() => {
                crate::crypto::hmac_verify(random, sig, &self.secret).unwrap_or(false)
            }
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

    /// Defense-in-depth Origin/Referer check for state-changing requests.
    ///
    /// The signed double-submit token proves the server minted it, but NOT that
    /// it was minted for *this* user — an attacker who plants a token they were
    /// legitimately issued (sibling-subdomain `Set-Cookie`, MITM on an http
    /// subdomain) passes the token check. Verifying that the request's `Origin`
    /// (or `Referer` fallback) is same-origin with the `Host` header closes that
    /// gap: the attacker's page has a different origin.
    ///
    /// Returns `true` (allow) when neither header is present — non-browser API
    /// clients omit them, and the token check still applies. Returns `false`
    /// only when a present Origin/Referer is cross-origin and not trusted.
    pub fn verify_origin(
        &self,
        host: Option<&str>,
        origin: Option<&str>,
        referer: Option<&str>,
    ) -> bool {
        let source = match origin.or(referer) {
            Some(s) if !s.is_empty() => s,
            _ => return true, // no browser-set header → fall through to the token check
        };
        let source_host = match origin_host(source) {
            Some(h) => h,
            None => return false, // malformed Origin/Referer on an unsafe verb
        };
        if let Some(h) = host {
            if source_host.eq_ignore_ascii_case(h) {
                return true;
            }
        }
        self.trusted_origins.iter().any(|trusted| {
            origin_host(trusted)
                .map(|th| th.eq_ignore_ascii_case(source_host))
                .unwrap_or(false)
        })
    }
}

/// Extract the `host[:port]` from an Origin / Referer / trusted-origin value,
/// stripping any `scheme://` prefix and trailing path. Scheme is intentionally
/// ignored (an http→https downgrade is HSTS's job, not CSRF's).
fn origin_host(value: &str) -> Option<&str> {
    let after_scheme = value.split_once("://").map(|(_, rest)| rest).unwrap_or(value);
    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

impl Default for CsrfValidator {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Replace an empty secret with an ephemeral per-process key so a token is
/// always signed — there is no unsigned downgrade path. A configured
/// (non-empty) secret passes through unchanged.
fn resolve_secret(secret: Vec<u8>) -> Vec<u8> {
    if secret.is_empty() {
        generate_crypto_random_hex(32)
            .expect("[blackhole] FATAL: getrandom failed — cannot derive ephemeral CSRF secret.")
            .into_bytes()
    } else {
        secret
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

    const TEST_SECRET: &[u8] = b"test-secret-key-32-bytes-long!!!";

    fn vd() -> CsrfValidator {
        CsrfValidator::new(TEST_SECRET.to_vec())
    }

    fn vd_routed(except: Vec<String>, methods: Vec<String>) -> CsrfValidator {
        CsrfValidator::with_routing(except, methods, Vec::new(), TEST_SECRET.to_vec())
    }

    #[test]
    fn valid_when_cookie_matches_header() {
        let v = vd();
        let token = v.generate_token();
        assert!(v.validate(Some(&token), Some(&token)));
    }

    #[test]
    fn rejects_mismatch() {
        let v = vd();
        assert!(!v.validate(Some("aaaa"), Some("bbbb")));
    }

    #[test]
    fn rejects_missing_cookie_or_header() {
        let v = vd();
        assert!(!v.validate(None, Some("x")));
        assert!(!v.validate(Some("x"), None));
        assert!(!v.validate(None, None));
    }

    #[test]
    fn rejects_empty_tokens() {
        let v = vd();
        assert!(!v.validate(Some(""), Some("")));
    }

    #[test]
    fn rejects_forged_unsigned_token() {
        // The whole point of *signed* double-submit: a self-consistent but
        // unsigned pair (an attacker-injected cookie echoed back) must FAIL.
        let v = vd();
        assert!(!v.validate(Some("forged123"), Some("forged123")));
        // A token shaped like ours but with a bogus signature also fails.
        assert!(!v.validate(
            Some("deadbeef.not-a-valid-signature"),
            Some("deadbeef.not-a-valid-signature")
        ));
    }

    #[test]
    fn rejects_token_signed_with_other_secret() {
        // A token minted under a different APP_KEY must not validate here —
        // cross-instance forgery and key-rotation safety.
        let other = CsrfValidator::new(b"a-different-secret-key-also-32by!".to_vec());
        let foreign = other.generate_token();
        let v = vd();
        assert!(!v.validate(Some(&foreign), Some(&foreign)));
    }

    #[test]
    fn is_stateless_reusable() {
        // Same token validates repeatedly — no single-use store.
        let v = vd();
        let token = v.generate_token();
        assert!(v.validate(Some(&token), Some(&token)));
        assert!(v.validate(Some(&token), Some(&token)));
    }

    #[test]
    fn parses_token_from_cookie_header() {
        let v = vd();
        assert_eq!(
            v.token_from_cookie_header("sid=abc; XSRF-TOKEN=xyz123; theme=dark"),
            Some("xyz123".to_string())
        );
        assert_eq!(v.token_from_cookie_header("sid=abc"), None);
    }

    #[test]
    fn parses_token_from_form_body() {
        let v = vd();
        assert_eq!(
            v.token_from_body("name=O%27Brien&_csrf=tok123&ok=1"),
            Some("tok123".to_string())
        );
        assert_eq!(v.token_from_body(r#"{"_csrf":"x"}"#), None);
    }

    #[test]
    fn token_is_signed_and_random() {
        let v = vd();
        let (t1, t2) = (v.generate_token(), v.generate_token());
        assert_ne!(t1, t2);
        // Shape: <64 hex random>.<base64url HMAC>
        let (random, sig) = t1.split_once('.').expect("token has a signature segment");
        assert_eq!(random.len(), 64); // 32 bytes = 64 hex chars
        assert!(!sig.is_empty());
    }

    #[test]
    fn requires_csrf_on_unsafe_methods() {
        let v = vd();
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
        let v = vd_routed(Vec::new(), vec!["DELETE".to_string()]);
        assert!(v.requires_csrf("DELETE"));
        assert!(!v.requires_csrf("POST"));
    }

    #[test]
    fn verify_origin_allows_same_origin_and_missing_headers() {
        let v = vd();
        // No Origin/Referer → allow (non-browser client; token check still applies).
        assert!(v.verify_origin(Some("app.test"), None, None));
        // Same-origin Origin → allow.
        assert!(v.verify_origin(Some("app.test"), Some("https://app.test"), None));
        // Same-origin via Referer fallback → allow.
        assert!(v.verify_origin(Some("app.test"), None, Some("https://app.test/page")));
    }

    #[test]
    fn verify_origin_rejects_cross_origin() {
        let v = vd();
        assert!(!v.verify_origin(Some("app.test"), Some("https://evil.test"), None));
        // Malformed Origin on an unsafe verb → reject.
        assert!(!v.verify_origin(Some("app.test"), Some("://"), None));
    }

    #[test]
    fn verify_origin_allows_trusted_cross_origin() {
        let v = CsrfValidator::with_routing(
            Vec::new(),
            Vec::new(),
            vec!["https://admin.test".to_string()],
            TEST_SECRET.to_vec(),
        );
        assert!(v.verify_origin(Some("app.test"), Some("https://admin.test"), None));
        assert!(!v.verify_origin(Some("app.test"), Some("https://other.test"), None));
    }

    #[test]
    fn except_routes_exact_and_prefix() {
        let v = vd_routed(
            vec!["/api/health".to_string(), "/api/webhooks/*".to_string()],
            Vec::new(),
        );
        assert!(v.is_excepted("/api/health"));
        assert!(v.is_excepted("/api/webhooks/stripe"));
        assert!(!v.is_excepted("/api/users"));
        assert!(!v.is_excepted("/api/health/sub"));
    }
}
