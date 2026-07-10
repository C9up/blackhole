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
    pub fn new(xss_enabled: Option<bool>, csrf_enabled: Option<bool>, rate_limit_max: Option<u32>, rate_limit_window: Option<u32>, path_traversal: Option<bool>, param_pollution: Option<bool>, csrf_except_routes: Option<Vec<String>>, csrf_methods: Option<Vec<String>>, csrf_secret: Option<String>, csrf_trusted_origins: Option<Vec<String>>) -> Self {
        let rate_limit = match (rate_limit_max, rate_limit_window) {
            (Some(max), Some(window)) => Some((max, window as u64)),
            _ => None,
        };
        Self {
            filter: blackhole_engine::BlackholeFilter::new(blackhole_engine::BlackholeConfig {
                xss_enabled: xss_enabled.unwrap_or(true),
                csrf_enabled: csrf_enabled.unwrap_or(true),
                rate_limit,
                path_traversal: path_traversal.unwrap_or(true),
                param_pollution: param_pollution.unwrap_or(true),
                csrf_except_routes: csrf_except_routes.unwrap_or_default(),
                csrf_methods: csrf_methods.unwrap_or_default(),
                csrf_trusted_origins: csrf_trusted_origins.unwrap_or_default(),
                csrf_secret: csrf_secret.map(String::into_bytes).unwrap_or_default(),
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
        let result = catch_unwind(std::panic::AssertUnwindSafe(|| self.filter.check_with_meta(req)));
        match result {
            Ok((blackhole_engine::FilterResult::Allow(_), meta, csrf_enforced)) => {
                let mut value = serde_json::json!({ "allowed": true, "csrfEnforced": csrf_enforced });
                if let Some(m) = meta {
                    value["rateLimit"] = serde_json::json!({ "limit": m.limit, "remaining": m.remaining, "resetSeconds": m.retry_after_secs });
                }
                Ok(value)
            }
            Ok((blackhole_engine::FilterResult::Reject(res), meta, _)) => {
                let headers: std::collections::HashMap<String, String> =
                    res.headers.into_iter().collect();
                let mut value = serde_json::json!({ "allowed": false, "status": res.status, "body": res.body, "headers": headers, "csrfEnforced": false });
                if let Some(m) = meta {
                    value["rateLimit"] = serde_json::json!({ "limit": m.limit, "remaining": m.remaining, "resetSeconds": m.retry_after_secs });
                }
                Ok(value)
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
