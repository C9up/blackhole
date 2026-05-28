//! Constant-time comparison utilities — prevents timing attacks.
//!
//! @implements FR53

use subtle::ConstantTimeEq;

/// Compare two byte slices in constant time.
/// Both length and content comparison are constant-time — no early return on length mismatch.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_eq: subtle::Choice = (a.len() as u64).ct_eq(&(b.len() as u64));
    let min_len = a.len().min(b.len());
    let content_eq: subtle::Choice = a[..min_len].ct_eq(&b[..min_len]);
    (len_eq & content_eq).into()
}

/// Compare two strings in constant time.
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal_values() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_str_eq("token-abc-123", "token-abc-123"));
    }

    #[test]
    fn test_different_values() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_str_eq("token-abc-123", "token-abc-124"));
    }

    #[test]
    fn test_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(!constant_time_str_eq("a", "ab"));
    }

    #[test]
    fn test_empty() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_str_eq("", ""));
    }

    #[test]
    fn test_nearly_identical() {
        assert!(!constant_time_str_eq(
            "abcdefghijklmnopqrstuvwxyz0",
            "abcdefghijklmnopqrstuvwxyz1"
        ));
    }
}
