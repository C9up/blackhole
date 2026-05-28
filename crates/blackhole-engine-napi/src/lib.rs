//! NAPI bindings for blackhole-engine.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::panic::catch_unwind;

#[napi]
pub struct Blackhole {
    filter: blackhole_engine::BlackholeFilter,
}

#[napi]
impl Blackhole {
    #[napi(constructor)]
    pub fn new(xss_enabled: Option<bool>, csrf_enabled: Option<bool>, rate_limit_max: Option<u32>, rate_limit_window: Option<u32>) -> Self {
        let rate_limit = match (rate_limit_max, rate_limit_window) {
            (Some(max), Some(window)) => Some((max, window as u64)),
            _ => None,
        };
        Self {
            filter: blackhole_engine::BlackholeFilter::new(blackhole_engine::BlackholeConfig {
                xss_enabled: xss_enabled.unwrap_or(true),
                csrf_enabled: csrf_enabled.unwrap_or(true),
                rate_limit,
            }),
        }
    }

    #[napi]
    pub fn generate_csrf_token(&self) -> String {
        self.filter.generate_csrf_token()
    }

    /// Check a request. Returns `{ allowed: true, request }` or `{ allowed: false, status, body }`.
    #[napi]
    pub fn check(&self, method: String, path: String, query: String, headers_json: String, body: String, remote_addr: String) -> Result<serde_json::Value> {
        let headers: std::collections::HashMap<String, String> =
            serde_json::from_str(&headers_json)
                .map_err(|e| Error::from_reason(format!("Invalid headers JSON: {}", e)))?;
        let req = blackhole_engine::Request { method, path, query, headers, body, remote_addr };
        let result = catch_unwind(std::panic::AssertUnwindSafe(|| self.filter.check(req)));
        match result {
            Ok(blackhole_engine::FilterResult::Allow(_)) => {
                Ok(serde_json::json!({ "allowed": true }))
            }
            Ok(blackhole_engine::FilterResult::Reject(res)) => {
                Ok(serde_json::json!({ "allowed": false, "status": res.status, "body": res.body }))
            }
            Err(_) => Err(Error::from_reason("Internal panic in blackhole engine")),
        }
    }

    /// Sanitize an outgoing response body (XSS protection for HTML/text responses).
    /// Respects the `xss_enabled` config — returns body unchanged when XSS is disabled.
    #[napi]
    pub fn sanitize_response(&self, body: String, content_type: String) -> String {
        if !self.filter.config().xss_enabled {
            return body;
        }
        blackhole_engine::sanitize_response(&body, &content_type)
    }
}
