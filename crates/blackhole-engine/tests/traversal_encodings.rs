//! Traversal detection across the spellings an attacker actually uses.
//!
//! Matching encoded forms literally (`%2e%2e`) only catches a `..` written the
//! same way twice. Half-encoding one of the dots — `%2e.` or `.%2e` — matched
//! none of the patterns and still decodes to `..`, so it went through a check
//! whose whole stated purpose was to cover encoded forms.

use blackhole_engine::shield::contains_traversal;

#[test]
fn catches_half_encoded_dots() {
    // One dot literal, one encoded — either way round, either case.
    assert!(contains_traversal("/a/%2e./b"));
    assert!(contains_traversal("/a/.%2e/b"));
    assert!(contains_traversal("/a/%2E./b"));
    assert!(contains_traversal("/a/.%2E/b"));
}

#[test]
fn still_catches_the_plain_spellings() {
    assert!(contains_traversal("/a/../b"));
    assert!(contains_traversal("/a/%2e%2e/b"));
    assert!(contains_traversal("/a/%2E%2E/b"));
    assert!(contains_traversal("/a/%252e%252e/b"));
}

#[test]
fn leaves_ordinary_paths_alone() {
    // A single dot is a path segment, not a traversal — decoded or not.
    assert!(!contains_traversal("/files/report.pdf"));
    assert!(!contains_traversal("/a/%2e/b"));
    assert!(!contains_traversal("/api/v1/users"));
    // A stray percent must not be read as the start of an escape.
    assert!(!contains_traversal("/files/100%25-done.pdf"));
}
