//! Crypto utilities — HMAC-SHA256 sign/verify + random bytes/hex.
//!
//! NOTE: AES-GCM and scrypt are NOT implemented here (the earlier doc claimed
//! them). This module is also not currently wired into the engine/napi crates —
//! kept as available primitives (audit 2026-06-13).

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

/// Generate cryptographically secure random bytes, returned as base64url.
pub fn random_bytes(len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; len];
    rand::RngExt::fill(&mut rand::rng(), &mut buf[..]);
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

/// Generate random bytes as hex string.
pub fn random_hex(len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; len];
    rand::RngExt::fill(&mut rand::rng(), &mut buf[..]);
    Ok(buf.iter().map(|b| format!("{:02x}", b)).collect())
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

    #[test]
    fn test_random_bytes() {
        let a = random_bytes(32).unwrap();
        let b = random_bytes(32).unwrap();
        assert_ne!(a, b);
        assert!(a.len() > 30); // base64url of 32 bytes
    }

    #[test]
    fn test_random_hex() {
        let hex = random_hex(16).unwrap();
        assert_eq!(hex.len(), 32); // 16 bytes = 32 hex chars
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

#[cfg(test)]
mod entropy {
    use super::*;
    use std::collections::HashSet;

    /// A CSPRNG swapped for something that is not one is the failure this
    /// guards: a stub returning zeros, or a seeded RNG producing the same
    /// token every call, would pass every other test in this crate. These
    /// bytes become session identifiers and CSRF tokens.
    #[test]
    fn random_bytes_are_neither_constant_nor_repeated() {
        let seen: HashSet<String> = (0..64)
            .map(|_| random_bytes(32).expect("generates"))
            .collect();
        assert_eq!(seen.len(), 64, "the generator repeated itself");

        let hex = random_hex(32).expect("generates");
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars().any(|c| c != '0'),
            "the generator produced all zeroes"
        );
    }
}
