//! # blackhole-engine
//!
//! Standalone Rust security filter — XSS sanitization, CSRF token validation,
//! rate limiting. Designed to run before the application layer (in Rust, before
//! NAPI crossing) so rejected requests never reach JS.
//!
//! Can be used with any Node.js framework via NAPI or WASM.
//!
//! @implements FR43, FR44, FR45, FR46, FR47

pub mod constant_time;
pub mod crypto;
pub mod csrf;
pub mod filter;
pub mod rate_limit;
pub mod xss;


use std::collections::HashMap;

// ─── Standalone types (no dependency on ream-http) ─────────────────────────────

/// Minimal request representation — only what Blackhole needs to make a
/// security decision. The framework integration layer (Ream/Express/Fastify)
/// converts its native request into this struct before calling `check()`.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub remote_addr: String,
}

/// Minimal response for rejected requests.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: String,
    pub content_type: String,
}

impl Response {
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_string(),
            content_type: "application/json".to_string(),
        }
    }
}

/// Result of a security check.
#[derive(Debug)]
pub enum FilterResult {
    /// Request passes all checks — continue to the application.
    Allow(Request),
    /// Request is rejected — return the response immediately, skip the app layer.
    Reject(Response),
}

pub use filter::{BlackholeConfig, BlackholeFilter};
pub use xss::sanitize_response;
