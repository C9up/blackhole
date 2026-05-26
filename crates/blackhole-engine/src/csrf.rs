//! CSRF token generation and validation.
//!
//! Tokens are cryptographically random, single-use, and expire after a configurable TTL.
//!
//! @implements FR45

use std::collections::HashMap;
use std::time::{Duration, Instant};

const DEFAULT_TOKEN_TTL_SECS: u64 = 3600; // 1 hour

/// CSRF token validator with single-use tokens and expiry.
pub struct CsrfValidator {
    /// Valid tokens mapped to their creation time
    tokens: HashMap<String, Instant>,
    /// Token time-to-live
    ttl: Duration,
    /// Header name to check
    pub header_name: String,
}

impl CsrfValidator {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
            ttl: Duration::from_secs(DEFAULT_TOKEN_TTL_SECS),
            header_name: "x-csrf-token".to_string(),
        }
    }

    /// Generate a new CSRF token using cryptographic randomness.
    /// Generate a new CSRF token. Panics if the OS entropy source is unavailable
    /// — a non-crypto fallback is worse than a clear failure because it creates
    /// a false sense of security. If getrandom fails, the server cannot safely
    /// issue CSRF tokens and must not pretend it can.
    pub fn generate_token(&mut self) -> String {
        self.purge_expired();
        let token = generate_crypto_random_hex(32)
            .expect("[blackhole] FATAL: getrandom failed — cannot generate CSRF token. OS entropy source is unavailable.");
        self.tokens.insert(token.clone(), Instant::now());
        token
    }

    /// Validate and consume a CSRF token (single-use).
    /// Returns true if valid, false if invalid/expired/already-used.
    pub fn validate(&mut self, token: &str) -> bool {
        match self.tokens.remove(token) {
            Some(created_at) => {
                // Check if token has expired
                created_at.elapsed() < self.ttl
            }
            None => false,
        }
    }

    /// Check if the request method requires CSRF validation.
    pub fn requires_csrf(method: &str) -> bool {
        matches!(method.to_ascii_uppercase().as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
    }

    /// Remove expired tokens to prevent memory growth.
    fn purge_expired(&mut self) {
        let ttl = self.ttl;
        self.tokens.retain(|_, created_at| created_at.elapsed() < ttl);
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
    fn test_csrf_generate_and_validate_single_use() {
        let mut validator = CsrfValidator::new();
        let token = validator.generate_token();

        // First use: valid
        assert!(validator.validate(&token));

        // Second use: invalid (consumed)
        assert!(!validator.validate(&token));
    }

    #[test]
    fn test_csrf_invalid_token() {
        let mut validator = CsrfValidator::new();
        assert!(!validator.validate("invalid_token"));
    }

    #[test]
    fn test_csrf_token_is_crypto_random() {
        let t1 = generate_crypto_random_hex(32).unwrap();
        let t2 = generate_crypto_random_hex(32).unwrap();
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_requires_csrf() {
        assert!(CsrfValidator::requires_csrf("POST"));
        assert!(CsrfValidator::requires_csrf("PUT"));
        assert!(CsrfValidator::requires_csrf("PATCH"));
        assert!(CsrfValidator::requires_csrf("DELETE"));
        assert!(!CsrfValidator::requires_csrf("GET"));
        assert!(!CsrfValidator::requires_csrf("HEAD"));
        assert!(!CsrfValidator::requires_csrf("OPTIONS"));
    }

    #[test]
    fn test_purge_expired() {
        let mut validator = CsrfValidator {
            tokens: HashMap::new(),
            ttl: Duration::from_millis(1), // Very short TTL for testing
            header_name: "x-csrf-token".to_string(),
        };

        let token = validator.generate_token();
        std::thread::sleep(Duration::from_millis(10));

        // Token should be expired
        assert!(!validator.validate(&token));
    }
}
