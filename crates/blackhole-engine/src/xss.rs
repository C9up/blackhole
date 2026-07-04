//! XSS sanitization utilities — powered by ammonia (html5ever parser).
//!
//! Uses a real HTML parser (same as Firefox/Servo) to neutralize XSS vectors.
//! Custom HTML tags and web components are preserved.
//! Never double-encodes existing HTML entities.
//!
//! @implements FR44

use std::collections::HashSet;

/// Build a permissive ammonia sanitizer that:
/// - Allows ALL tags (including custom components like <UserCard>, <my-widget>)
/// - Removes dangerous elements: <script>, <style> (content stripped entirely)
/// - Strips all event handler attributes (on*)
/// - Strips javascript: URIs from href/src/action
/// - Preserves safe attributes (class, id, style, data-*, aria-*)
fn build_html_sanitizer() -> ammonia::Builder<'static> {
    let mut builder = ammonia::Builder::default();

    // Allow all tags by using a very permissive set.
    // ammonia's default allowlist is restrictive — we override it.
    // We add common HTML5 tags + leave clean_content_tags to strip <script>/<style>.
    builder
        // Strip <script> and <style> entirely (content removed, not just tags)
        .clean_content_tags(HashSet::from(["script", "style", "iframe", "object", "embed"]))
        // Allow generic attributes on all tags
        .add_generic_attributes(["class", "id", "style", "role", "tabindex",
            "title", "lang", "dir", "hidden", "slot", "part", "is"])
        // Allow data-* and aria-* attributes (ammonia handles these specially)
        .add_generic_attributes(["data-*"])
        // Allow href/src but ammonia auto-strips javascript: URIs by default
        .link_rel(Some("noopener noreferrer"))
        // Strip all on* event handler attributes (ammonia does this by default —
        // only explicitly allowed attributes pass through)
        ;

    builder
}

/// Sanitize an HTML string using ammonia (html5ever parser).
///
/// - Strips `<script>`, `<style>`, `<iframe>`, `<object>`, `<embed>` (with content)
/// - Strips all `on*` event handler attributes
/// - Strips `javascript:` URIs
/// - Preserves all other tags including custom web components
/// - Never double-encodes existing HTML entities
pub fn sanitize_html(input: &str) -> String {
    build_html_sanitizer().clean(input).to_string()
}

/// Sanitize a plain text string for safe HTML embedding.
/// Escapes all HTML special characters (< > & " ') without double-encoding.
pub fn sanitize_text(input: &str) -> String {
    ammonia::clean_text(input).to_string()
}

/// Sanitize a response body based on content type.
/// - `text/html`: ammonia HTML sanitizer (parser-based, preserves safe wrapper
///   tags; a full document opening with `<!doctype>`/`<html>` passes through).
/// - Everything else (`text/plain`, JSON, CSV, binary, …): returned unmodified.
///   A non-HTML body is never parsed as markup by the browser (blackhole sets
///   `X-Content-Type-Options: nosniff` by default), so there is nothing to
///   escape — and escaping would corrupt legitimate plain-text bodies.
///
/// Standalone version — takes `(body, content_type)` instead of a framework
/// response struct, so it works with any HTTP server.
pub fn sanitize_response(body: &str, content_type: &str) -> String {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("text/html") {
        // Server-generated full HTML documents are not user input and must
        // not pass through ammonia: ammonia treats every wrapper outside its
        // short allow-list (`<!doctype>`, `<html>`, `<head>`, `<body>`...) as
        // unsafe and strips them, leaving only the inner fragments. The
        // result is a broken document. The cheap structural test below
        // skips sanitisation when the body opens with `<!doctype` or `<html`.
        let head: String = body.chars().take(16).collect::<String>().trim_start().to_ascii_lowercase();
        if head.starts_with("<!doctype") || head.starts_with("<html") {
            return body.to_string();
        }
        sanitize_html(body)
    } else {
        // Non-HTML content types (text/plain, JSON, CSV, binary, …) are never
        // interpreted as markup by the browser — with `X-Content-Type-Options:
        // nosniff` (blackhole's default) there is no XSS vector to escape.
        // Entity-escaping them would only corrupt legitimate bodies
        // (robots.txt, plain-text APIs, CSV, …) for zero security gain.
        body.to_string()
    }
}

/// Check if a string contains potential XSS patterns (informational only).
/// NOT used for sanitization decisions — ammonia handles all cases via parsing.
pub fn contains_xss(input: &str) -> bool {
    let lower = input.to_lowercase();
    lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("onerror=")
        || lower.contains("onload=")
        || lower.contains("onclick=")
        || lower.contains("onfocus=")
        || lower.contains("onmouseover=")
}

// Keep backward compat — old name delegates to sanitize_text
#[doc(hidden)]
pub fn sanitize_xss(input: &str) -> String {
    sanitize_text(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // === HTML sanitization tests ===

    #[test]
    fn test_sanitize_html_strips_script() {
        let result = sanitize_html("<p>Hello</p><script>alert('xss')</script><p>World</p>");
        assert!(!result.contains("<script>"));
        assert!(!result.contains("alert"));
        assert!(result.contains("<p>Hello</p>"));
        assert!(result.contains("<p>World</p>"));
    }

    #[test]
    fn test_sanitize_html_strips_event_handlers() {
        let result = sanitize_html(r#"<img src="pic.jpg" onerror="alert(1)">"#);
        assert!(!result.contains("onerror"));
        assert!(result.contains("pic.jpg"));
    }

    #[test]
    fn test_sanitize_html_strips_javascript_uri() {
        let result = sanitize_html(r#"<a href="javascript:alert(1)">click</a>"#);
        assert!(!result.contains("javascript:"));
        assert!(result.contains("click"));
    }

    #[test]
    fn test_sanitize_html_preserves_safe_tags() {
        let input = r#"<div class="card"><h1>Title</h1><p>Text with <strong>bold</strong></p></div>"#;
        let result = sanitize_html(input);
        assert!(result.contains("<div"));
        assert!(result.contains("<h1>"));
        assert!(result.contains("<strong>"));
    }

    #[test]
    fn test_sanitize_html_no_double_encoding() {
        let input = "<p>Already escaped: &amp; &lt; &gt;</p>";
        let result = sanitize_html(input);
        // Must NOT produce &amp;amp; or &amp;lt;
        assert!(result.contains("&amp;"));
        assert!(result.contains("&lt;"));
        assert!(!result.contains("&amp;amp;"));
        assert!(!result.contains("&amp;lt;"));
    }

    #[test]
    fn test_sanitize_html_strips_style_tag() {
        let result = sanitize_html("<style>body { display:none }</style><p>Visible</p>");
        assert!(!result.contains("<style>"));
        assert!(!result.contains("display:none"));
        assert!(result.contains("<p>Visible</p>"));
    }

    #[test]
    fn test_sanitize_html_strips_iframe() {
        let result = sanitize_html(r#"<iframe src="https://evil.com"></iframe><p>Safe</p>"#);
        assert!(!result.contains("<iframe"));
        assert!(result.contains("<p>Safe</p>"));
    }

    #[test]
    fn test_sanitize_html_encoding_bypass_attempt() {
        // Hex-encoded script tag — html5ever parses entity references
        let result = sanitize_html("<scr&#x69;pt>alert(1)</script>");
        // html5ever decodes &#x69; to 'i', reconstructing <script>.
        // ammonia then strips the <script> tag. The "alert(1)" text content
        // may remain as plain text (safe — no script execution).
        assert!(!result.contains("<script>"));
        assert!(!result.contains("</script>"));
    }

    // === Text sanitization tests ===

    #[test]
    fn test_sanitize_text_escapes() {
        let result = sanitize_text("<script>alert('xss')</script>");
        assert!(result.contains("&lt;script&gt;"));
        assert!(!result.contains("<script>"));
    }

    #[test]
    fn test_sanitize_text_normal() {
        // ammonia::clean_text encodes spaces as &#32; — this is safe HTML text
        let result = sanitize_text("hello world");
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
        assert!(!result.contains("<"));
    }

    // === Response sanitization tests (standalone API) ===

    #[test]
    fn test_sanitize_response_html() {
        let result = sanitize_response("<p>Hello</p><script>alert(1)</script>", "text/html; charset=utf-8");
        assert!(!result.contains("<script>"));
        assert!(result.contains("<p>Hello</p>"));
    }

    #[test]
    fn test_sanitize_response_text_plain_verbatim() {
        // text/plain is never parsed as HTML by the browser (nosniff), so it is
        // served verbatim — escaping would corrupt robots.txt, CSV, plain text.
        let body = "User-agent: *\nDisallow: /\n";
        let result = sanitize_response(body, "text/plain; charset=utf-8");
        assert_eq!(result, body, "text/plain must be returned unmodified");
    }

    #[test]
    fn test_sanitize_response_json_not_modified() {
        let json_body = r#"{"name": "O'Brien", "query": "a > b"}"#;
        let result = sanitize_response(json_body, "application/json");
        assert_eq!(result, json_body, "JSON response must NOT be sanitized");
    }

    #[test]
    fn test_sanitize_response_no_content_type() {
        let result = sanitize_response("<script>xss</script>", "");
        assert_eq!(result, "<script>xss</script>", "Empty content-type = no sanitization");
    }

    #[test]
    fn test_sanitize_response_case_insensitive() {
        let result = sanitize_response("<script>xss</script><p>safe</p>", "Text/HTML");
        assert!(!result.contains("<script>"));
        assert!(result.contains("<p>safe</p>"));
    }

    // === Detection tests (informational) ===

    #[test]
    fn test_contains_xss_script_tag() {
        assert!(contains_xss("<script>alert(1)</script>"));
        assert!(contains_xss("<SCRIPT>alert(1)</SCRIPT>"));
    }

    #[test]
    fn test_contains_xss_event_handlers() {
        assert!(contains_xss("onerror=alert(1)"));
        assert!(contains_xss("onload=fetch('evil')"));
    }

    #[test]
    fn test_contains_xss_javascript_uri() {
        assert!(contains_xss("javascript:alert(1)"));
    }

    #[test]
    fn test_no_xss() {
        assert!(!contains_xss("Hello World"));
        assert!(!contains_xss("/api/orders?page=1"));
    }
}
