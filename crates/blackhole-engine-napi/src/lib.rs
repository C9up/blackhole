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
    // NAMED DEVIATION from `clippy::too_many_arguments`, and the one place a
    // NAPI constraint genuinely decides the shape: napi-rs generates the
    // JavaScript constructor signature FROM this parameter list, so folding
    // these into a config struct would change `new Blackhole(a, b, c, …)` into
    // `new Blackhole({ … })` for every consumer of a published binding. The
    // idiomatic napi answer — a `#[napi(object)]` parameter — is a breaking
    // change, not a refactor.
    #[allow(clippy::too_many_arguments)]
    #[napi(constructor)]
    pub fn new(
        csrf_enabled: Option<bool>,
        rate_limit_max: Option<u32>,
        rate_limit_window: Option<u32>,
        path_traversal: Option<bool>,
        param_pollution: Option<bool>,
        csrf_except_routes: Option<Vec<String>>,
        csrf_methods: Option<Vec<String>>,
        csrf_secret: Option<String>,
        csrf_trusted_origins: Option<Vec<String>>,
        xss_allow_attributes: Option<Vec<String>>,
    ) -> Result<Self> {
        let xss_allow_attributes = xss_allow_attributes.unwrap_or_default();
        // A name outside the opt-in list is refused rather than ignored: the
        // caller asked for an attribute to survive and would otherwise find
        // it silently stripped.
        if let Some(unknown) = xss_allow_attributes
            .iter()
            .find(|name| !blackhole_engine::xss::OPT_IN_ATTRIBUTES.contains(&name.as_str()))
        {
            return Err(Error::from_reason(format!(
                "[blackhole] xss.allowAttributes: '{}' cannot be allowed (expected one of {})",
                unknown,
                blackhole_engine::xss::OPT_IN_ATTRIBUTES.join(", ")
            )));
        }
        let rate_limit = match (rate_limit_max, rate_limit_window) {
            // A limit of 0 or a window of 0 would let every request through
            // (a zero window expires each hit at once): refused, not ignored.
            (Some(0), _) | (_, Some(0)) => {
                return Err(Error::from_reason(
                    "[blackhole] rate limit max and window must be greater than 0",
                ))
            }
            (Some(max), Some(window)) => Some((max, window as u64)),
            _ => None,
        };
        Ok(Self {
            filter: blackhole_engine::BlackholeFilter::new(blackhole_engine::BlackholeConfig {
                csrf_enabled: csrf_enabled.unwrap_or(true),
                rate_limit,
                path_traversal: path_traversal.unwrap_or(true),
                param_pollution: param_pollution.unwrap_or(true),
                csrf_except_routes: csrf_except_routes.unwrap_or_default(),
                csrf_methods: csrf_methods.unwrap_or_default(),
                csrf_trusted_origins: csrf_trusted_origins.unwrap_or_default(),
                csrf_secret: csrf_secret.map(String::into_bytes).unwrap_or_default(),
                xss_allow_attributes,
            }),
        })
    }

    /// A fresh CSRF token. With a `binding` (the session's secret), its
    /// signature covers that too, and it verifies only when `check` is given
    /// the same binding.
    #[napi]
    pub fn generate_csrf_token(&self, binding: Option<String>) -> String {
        self.filter
            .generate_bound_csrf_token(binding.as_deref().unwrap_or_default())
    }

    /// Check a request. Returns `{ allowed: true, request }` or `{ allowed: false, status, body }`.
    ///
    /// The value is built field by field below, so napi-rs cannot infer more
    /// than `any` from `serde_json::Value` — the shape is declared here
    /// instead, next to the code that builds it, and reaches TypeScript
    /// through the generated declarations. Keep the two in step: a renamed
    /// key here must be renamed there in the same edit.
    // Positional for the same NAPI reason as the constructor: the arguments
    // are the generated JavaScript signature, and `scheme`, `checks`, `host`
    // and `csrf_binding` are appended last so a caller that does not pass
    // them still works.
    #[allow(clippy::too_many_arguments)]
    #[napi(
        ts_return_type = "{ allowed: boolean; status?: number; body?: string; headers?: Record<string, string>; rateLimit?: { limit: number; remaining: number; resetSeconds: number }; csrfEnforced?: boolean }"
    )]
    pub fn check(
        &self,
        method: String,
        path: String,
        query: String,
        headers_json: String,
        body: String,
        remote_addr: String,
        scheme: Option<String>,
        checks: Option<Vec<String>>,
        host: Option<String>,
        csrf_binding: Option<String>,
    ) -> Result<serde_json::Value> {
        // Some of `rateLimit` / `shield` / `csrf` run part of a split
        // pipeline; none runs everything.
        let checks = match checks {
            None => blackhole_engine::Checks::ALL,
            Some(names) => {
                let mut checks = blackhole_engine::Checks {
                    rate_limit: false,
                    shield: false,
                    csrf: false,
                };
                for name in &names {
                    match name.as_str() {
                        "rateLimit" => checks.rate_limit = true,
                        "shield" => checks.shield = true,
                        "csrf" => checks.csrf = true,
                        other => {
                            return Err(Error::from_reason(format!(
                            "[blackhole] unknown check '{}' (expected rateLimit, shield or csrf)",
                            other
                        )))
                        }
                    }
                }
                checks
            }
        };
        let headers: std::collections::HashMap<String, String> =
            serde_json::from_str(&headers_json)
                .map_err(|e| Error::from_reason(format!("Invalid headers JSON: {}", e)))?;
        let req = blackhole_engine::Request {
            method,
            path,
            query,
            headers,
            body,
            remote_addr,
            scheme: scheme.unwrap_or_default(),
            host: host.unwrap_or_default(),
            csrf_binding: csrf_binding.unwrap_or_default(),
        };
        let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.filter.check_only(req, checks)
        }));
        match result {
            Ok((blackhole_engine::FilterResult::Allow(_), meta, csrf_enforced)) => {
                let mut value =
                    serde_json::json!({ "allowed": true, "csrfEnforced": csrf_enforced });
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

    /// Sanitize a body as untrusted markup when `content_type` is `text/html`
    /// (a full document excepted); any other type comes back unchanged.
    ///
    /// Always, whatever the `xss` option says: that option decides whether
    /// the host runs this on its own responses, while a direct call is how an
    /// application cleans input it is about to store.
    #[napi]
    pub fn sanitize_response(&self, body: String, content_type: String) -> String {
        blackhole_engine::xss::sanitize_response_with(
            &body,
            &content_type,
            &self.filter.config().xss_allow_attributes,
        )
    }
}
