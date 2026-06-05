//! Wire-level request shield — rejects path-traversal and parameter-pollution
//! attempts. Ported from ream's `ream-http` shield so all request filtering
//! lives in one place (blackhole).

/// Whether the path matches one of the traversal patterns. Case-insensitive
/// for percent-encoded forms — `%2E%2E`, `%2e%2e` and `%252e` all decode to
/// `..` somewhere in the request pipeline.
pub fn contains_traversal(path: &str) -> bool {
    if path.contains("..") {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    lower.contains("%2e%2e") || lower.contains("%252e")
}

/// Walk the raw query string and surface the first duplicate key (after
/// percent-decoding). Keys ending with `[]` are intentionally allowed to
/// repeat — that's the framework's array-input convention.
pub fn first_duplicate_key(query: &str) -> Option<String> {
    if query.is_empty() {
        return None;
    }
    let mut seen: Vec<String> = Vec::new();
    for pair in query.split('&') {
        let raw_key = pair.split('=').next().unwrap_or("");
        if raw_key.is_empty() {
            continue;
        }
        let key = match urlencoding::decode(raw_key) {
            Ok(decoded) => decoded.into_owned(),
            Err(_) => raw_key.to_string(),
        };
        if key.ends_with("[]") {
            continue;
        }
        if seen.iter().any(|k| k == &key) {
            return Some(key);
        }
        seen.push(key);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_literal_traversal() {
        assert!(contains_traversal("/files/../etc/passwd"));
        assert!(!contains_traversal("/files/report.pdf"));
    }

    #[test]
    fn detects_encoded_traversal() {
        assert!(contains_traversal("/a/%2e%2e/b"));
        assert!(contains_traversal("/a/%252e/b"));
        assert!(contains_traversal("/a/%2E%2E/b")); // case-insensitive
    }

    #[test]
    fn finds_duplicate_param() {
        assert_eq!(first_duplicate_key("a=1&b=2&a=3"), Some("a".to_string()));
        assert_eq!(first_duplicate_key("a=1&b=2"), None);
        assert_eq!(first_duplicate_key(""), None);
    }

    #[test]
    fn allows_array_convention() {
        // `tags[]` may legitimately repeat.
        assert_eq!(first_duplicate_key("tags[]=a&tags[]=b"), None);
    }

    #[test]
    fn decodes_keys_before_comparing() {
        // `%61` decodes to `a` — the duplicate must be caught.
        assert_eq!(first_duplicate_key("a=1&%61=2"), Some("a".to_string()));
    }
}
