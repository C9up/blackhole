//! Crypto utilities — HMAC-SHA256 sign/verify.
//!
//! NOTE: AES-GCM and scrypt are NOT implemented here (an earlier doc claimed
//! them). `hmac_sign` / `hmac_verify` ARE load-bearing: they sign and verify
//! every CSRF token (see `csrf.rs`), so their output is a compatibility
//! surface, not an internal detail. CSRF mints its randomness straight from
//! `getrandom` (see `csrf.rs`).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 sign. Returns base64url-encoded signature.
pub fn hmac_sign(data: &str, secret: &[u8]) -> Result<String, String> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(data.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

/// HMAC-SHA256 verify (constant-time).
pub fn hmac_verify(data: &str, signature: &str, secret: &[u8]) -> Result<bool, String> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(data.as_bytes());
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "Invalid signature encoding".to_string())?;
    Ok(mac.verify_slice(&sig_bytes).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sign_verify() {
        let secret = b"test-secret-key-32-bytes-long!!!";
        let sig = hmac_sign("hello world", secret).unwrap();
        assert!(hmac_verify("hello world", &sig, secret).unwrap());
        assert!(!hmac_verify("tampered", &sig, secret).unwrap());
    }
}

#[cfg(test)]
mod rfc4231 {
    use super::*;

    /// RFC 4231 test case 2 for HMAC-SHA-256.
    ///
    /// HMAC is a specification, so its output cannot legitimately change under
    /// a crate bump — but "cannot" is worth an assertion when the crate in
    /// question signs this framework's CSRF tokens. A token this code produced
    /// yesterday has to verify tomorrow.
    #[test]
    fn hmac_sha256_matches_the_published_vector() {
        let mut mac = HmacSha256::new_from_slice(b"Jefe").expect("key");
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
