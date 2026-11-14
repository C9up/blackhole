//! Wire-level request shield — rejects path-traversal and parameter-pollution
//! attempts. Ported from ream's `ream-http` shield so all request filtering
//! lives in one place (blackhole).

use std::collections::HashSet;

/// Whether the path matches one of the traversal patterns. Case-insensitive
/// for percent-encoded forms — `%2E%2E`, `%2e%2e` and `%252e` all decode to
/// `..` somewhere in the request pipeline.
pub fn contains_traversal(path: &str) -> bool {
    if path.contains("..") {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e%2e") || lower.contains("%252e") {
        return true;
    }
    // Matching encoded spellings literally only catches the ones written the
    // same way twice. `%2e.` and `.%2e` are half-encoded, match none of the
    // patterns above, and still decode to `..` — so decode and look again.
    decodes_to_traversal(path)
}

/// Percent-decode up to twice and look for a literal `..`.
///
/// Twice because a proxy that decodes once turns `%252e%252e` into `%2e%2e`,
/// which the next hop decodes into `..` — a request can therefore arrive
/// encoded one level deeper than it will be read at. Decoding stops there: a
/// third level has no hop left to unwrap it. A segment that will not decode
/// (invalid UTF-8, a stray `%`) simply ends the walk — the literal checks above
/// have already seen the raw form.
fn decodes_to_traversal(path: &str) -> bool {
    let mut current = path.to_string();
    for _ in 0..2 {
        let Ok(decoded) = urlencoding::decode(&current) else {
            return false;
        };
        if decoded == current {
            return false; // nothing left to unwrap
        }
        if decoded.contains("..") {
            return true;
        }
        current = decoded.into_owned();
    }
    false
}

/// How deep the framework's query parser nests `a[b][c]…` before it keeps the
/// rest of the key as one literal segment. Matches Ream's parser (and `qs`).
const MAX_DEPTH: usize = 5;

/// The first parameter the query repeats, once the keys are read the way the
/// framework's parser reads them. `None` when every key lands somewhere of its
/// own.
///
/// Comparing raw keys is not enough: the parser decodes `+` to a space before
/// percent-decoding, reads `a.b` as `a[b]`, and merges `a`, `a[]` and `a[0]`
/// into one array. Two spellings that end up in the same place are the same
/// parameter, and a guard that compares spellings lets every one of them
/// through. What may still repeat is the append form alone (`tags[]=a&tags[]=b`)
/// and distinct indices (`a[0]=x&a[1]=y`) — that is how a form sends a list.
///
/// A leading `?` is ignored: hosts hand the search string over with it, and
/// read literally it turned the first key into `?key`, which never matched
/// its own duplicate.
pub fn first_duplicate_key(query: &str) -> Option<String> {
    let query = query.strip_prefix('?').unwrap_or(query);
    if query.is_empty() {
        return None;
    }
    // Sets, not lists: a linear search per key made a query of n distinct
    // keys cost n² comparisons — 10 000 keys held the request thread ~50 ms.
    // Paths given a value (`a`, `a[b]`, `a[0]`).
    let mut leaves: HashSet<Vec<String>> = HashSet::new();
    // Paths appended to (`a` for `a[]`).
    let mut appends: HashSet<Vec<String>> = HashSet::new();
    // Every strict prefix of the two above: a path that holds others.
    let mut containers: HashSet<Vec<String>> = HashSet::new();
    for pair in query.split('&') {
        let raw_key = pair.split('=').next().unwrap_or("");
        if raw_key.is_empty() {
            continue;
        }
        let key = decode_form_component(raw_key);
        if key.is_empty() {
            continue;
        }
        let mut path = split_key(&key);
        let appending = path.len() > 1 && path.last().is_some_and(String::is_empty);
        if appending {
            path.pop();
        }
        let shadows_a_leaf = (1..path.len()).any(|end| leaves.contains(&path[..end]));
        let collides = if appending {
            leaves.contains(&path) || shadows_a_leaf
        } else {
            leaves.contains(&path)
                || appends.contains(&path)
                || containers.contains(&path)
                || shadows_a_leaf
        };
        if collides {
            return Some(key);
        }
        for end in 1..path.len() {
            containers.insert(path[..end].to_vec());
        }
        if appending {
            appends.insert(path);
        } else {
            leaves.insert(path);
        }
    }
    None
}

/// A form key or value decoded the way the framework's parser decodes it: `+`
/// is a space, THEN percent-escapes are decoded. A malformed escape or bytes
/// that are not UTF-8 leave the spaced string undecoded, as
/// `decodeURIComponent` throwing does there.
fn decode_form_component(raw: &str) -> String {
    let spaced = raw.replace('+', " ");
    let bytes = spaced.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte != b'%' {
            out.push(byte);
            i += 1;
            continue;
        }
        let high = bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16));
        let low = bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16));
        match (high, low) {
            (Some(h), Some(l)) => {
                // Two hex digits make one byte, so the value fits in a u8.
                out.push(((h << 4) | l) as u8);
                i += 3;
            }
            _ => return spaced,
        }
    }
    String::from_utf8(out).unwrap_or(spaced)
}

/// Split `user[address][city]` into `user`, `address`, `city` — and `tags[]`
/// into `tags` and an empty segment, meaning "append". `a.b` reads as `a[b]`.
/// Past [`MAX_DEPTH`] the remainder stays one literal segment, which is where
/// the parser stops nesting too.
fn split_key(key: &str) -> Vec<String> {
    let dotted = if key.starts_with('.') {
        key.to_string()
    } else {
        dots_to_brackets(key)
    };
    let Some(first_bracket) = dotted.find('[') else {
        return vec![dotted];
    };
    let mut segments = vec![dotted[..first_bracket].to_string()];
    let mut rest = &dotted[first_bracket..];
    while segments.len() <= MAX_DEPTH {
        let Some(inner) = rest.strip_prefix('[') else {
            break;
        };
        let Some(close) = inner.find(']') else {
            break;
        };
        segments.push(inner[..close].to_string());
        rest = &inner[close + 1..];
        if rest.is_empty() {
            return segments;
        }
    }
    if !rest.is_empty() {
        if let Some(last) = segments.last_mut() {
            last.push_str(rest);
        }
    }
    segments
}

/// `a.b.c` → `a[b][c]`: every `.` followed by at least one character that is
/// not `.`, `[` or `]` opens a bracket around that run.
fn dots_to_brackets(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    let mut out = String::with_capacity(key.len() + 4);
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '.' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let run_end = chars[i + 1..]
            .iter()
            .position(|c| matches!(c, '.' | '[' | ']'))
            .map_or(chars.len(), |offset| i + 1 + offset);
        if run_end == i + 1 {
            out.push('.');
            i += 1;
            continue;
        }
        out.push('[');
        out.extend(&chars[i + 1..run_end]);
        out.push(']');
        i = run_end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distinct_keys(n: usize) -> String {
        (0..n)
            .map(|i| format!("k{i}=1"))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// The best of a few runs: the least disturbed by whatever else the
    /// machine is doing.
    fn fastest(query: &str) -> std::time::Duration {
        (0..5)
            .map(|_| {
                let started = std::time::Instant::now();
                assert_eq!(first_duplicate_key(query), None);
                started.elapsed()
            })
            .min()
            .unwrap_or_default()
    }

    #[test]
    fn many_distinct_keys_stay_linear() {
        // How the time GROWS, not a time: an absolute bound measured the
        // machine — a debug build spends ~30 ms on 10 000 keys and failed a
        // 40 ms bound one run in two. Eight times the keys costs about eight
        // times as much when linear, sixty-four when quadratic.
        let small = fastest(&distinct_keys(2_000));
        let large = fastest(&distinct_keys(16_000));
        assert!(
            large < small * 24,
            "8x the keys took {large:?} against {small:?}"
        );
        let query = distinct_keys(10_000);
        assert_eq!(
            first_duplicate_key(&format!("{query}&k9999=2")),
            Some("k9999".to_string())
        );
    }

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
    fn catches_the_first_key_behind_a_leading_question_mark() {
        assert_eq!(
            first_duplicate_key("?role=user&role=admin"),
            Some("role".to_string())
        );
        assert_eq!(first_duplicate_key("?role=user"), None);
        assert_eq!(first_duplicate_key("?"), None);
    }

    #[test]
    fn catches_spellings_the_parser_merges() {
        // Each pair lands in one parameter once parsed.
        for query in [
            "a[]=1&a=2",
            "a=1&a[]=2",
            "a[0]=1&a=2",
            "a=1&a[0]=2",
            "a+b=1&a%20b=2",
            "a.b=1&a[b]=2",
            "a[b]=1&a=2",
            "a=1&a[b][c]=2",
            "a[0]=1&a[0]=2",
            "a[x][]=1&a[x]=2",
        ] {
            assert!(
                first_duplicate_key(query).is_some(),
                "{query} must be refused"
            );
        }
    }

    #[test]
    fn lets_lists_and_distinct_paths_through() {
        for query in [
            "tags[]=a&tags[]=b",
            "a[0]=1&a[1]=2",
            "user[name]=x&user[email]=y",
            "user.name=x&user.email=y",
            "a=1&b=2",
            "a=1&ab=2",
        ] {
            assert_eq!(first_duplicate_key(query), None, "{query} must pass");
        }
    }

    #[test]
    fn a_malformed_escape_is_compared_undecoded() {
        // `%zz` is not an escape: the key stays as written, so it matches only
        // itself — not the `a` it would half-decode to.
        assert_eq!(first_duplicate_key("a%zz=1&a=2"), None);
        assert_eq!(
            first_duplicate_key("a%zz=1&a%zz=2"),
            Some("a%zz".to_string())
        );
    }

    #[test]
    fn nesting_stops_at_the_parser_depth() {
        // Past five levels the parser keeps the rest as one literal key.
        assert_eq!(split_key("a[b][c][d][e][f][g]").len(), 6);
        assert_eq!(
            split_key("a[b][c][d][e][f][g]").last().map(String::as_str),
            Some("f[g]")
        );
        assert_eq!(split_key("a.b[c]"), vec!["a", "b", "c"]);
        assert_eq!(split_key(".a"), vec![".a"]);
    }

    #[test]
    fn decodes_keys_before_comparing() {
        // `%61` decodes to `a` — the duplicate must be caught.
        assert_eq!(first_duplicate_key("a=1&%61=2"), Some("a".to_string()));
    }
}
