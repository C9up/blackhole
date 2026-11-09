//! XSS sanitization utilities — powered by ammonia (html5ever parser).
//!
//! Uses a real HTML parser (same as Firefox/Servo) to neutralize XSS vectors in
//! UNTRUSTED HTML *fragments*. This is an allow-LIST sanitizer: ammonia keeps a
//! curated set of safe tags/attributes and UNWRAPS anything else — including
//! custom elements (`<my-widget>`) and non-allowlisted HTML5 tags. Do not rely
//! on it to pass trusted markup through unchanged; it reparses + re-serialises,
//! so exact bytes (inline SVG, `<pre>`, SRI-hashed inline content) may change.
//! That's why the response pipeline skips full documents (`<!doctype>`/`<html>`)
//! and only sanitises fragments. Never double-encodes existing HTML entities.
//!
//! @implements FR44

use std::collections::HashSet;

/// CSS properties an untrusted fragment may set.
///
/// Presentation only. Deliberately absent: `position`, `top`/`left`/`right`/
/// `bottom` and `z-index` (which together lift content out of the flow and
/// over the rest of the page), and every property that takes a URL —
/// `background`, `background-image`, `list-style-image`, `border-image`,
/// `content`, `cursor`, `mask`, `filter` — each of which is an outbound
/// request the page never asked for. `background-color` is kept: it is the
/// half of `background` that cannot fetch anything.
const SAFE_STYLE_PROPERTIES: [&str; 34] = [
    "color",
    "background-color",
    "font",
    "font-family",
    "font-size",
    "font-style",
    "font-weight",
    "font-variant",
    "line-height",
    "letter-spacing",
    "text-align",
    "text-decoration",
    "text-indent",
    "text-transform",
    "white-space",
    "word-break",
    "vertical-align",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "border",
    "border-color",
    "border-style",
    "border-width",
    "border-radius",
    "width",
    "height",
];

/// Attributes an untrusted fragment loses by default, and that an application
/// may opt back into.
///
/// Each is harmless to the markup and dangerous to the page around it: `id`
/// (and the named access it gives) shadows globals — `<a id="config">`
/// replaces `window.config` for any script that reads it (DOM clobbering);
/// `is` instantiates a customized built-in element; `data-*` is what
/// client-side frameworks read bindings and templates from, a script gadget
/// without a single `<script>`; `slot` and `part` reach into shadow DOM.
pub const OPT_IN_ATTRIBUTES: [&str; 5] = ["id", "is", "slot", "part", "data-*"];

/// Build the ammonia sanitizer (safe allow-list) used for untrusted fragments:
/// - Keeps ammonia's default allow-list of safe tags; UNWRAPS everything else
///   (custom elements, non-allowlisted HTML5 tags) — NOT an "allow all tags" pass.
/// - Removes dangerous elements with their content: <script>, <style>, <iframe>,
///   <object>, <embed>.
/// - Strips all event-handler attributes (on*) and `javascript:` URIs (ammonia
///   default: only explicitly-allowed attributes/URIs survive).
/// - Allows a set of presentational generic attributes (class, role, title, …),
///   plus `style` narrowed to presentation-only properties. The attributes of
///   [`OPT_IN_ATTRIBUTES`] are kept only when listed in `allow`.
fn build_html_sanitizer<'a>(allow: &'a [String]) -> ammonia::Builder<'a> {
    let mut builder = ammonia::Builder::default();

    // ammonia's default is a curated SAFE allow-list — we keep it and only
    // tighten it (clean_content_tags strips <script>/<style>/… with content).
    builder
        // Strip <script> and <style> entirely (content removed, not just tags)
        .clean_content_tags(HashSet::from(["script", "style", "iframe", "object", "embed"]))
        // Generic attributes kept on every tag: presentation and semantics
        // only — nothing a script or the shadow DOM reads as an address.
        .add_generic_attributes(["class", "style", "role", "tabindex",
            "title", "lang", "dir", "hidden"])
        // `style` carries no script, but unrestricted it is still a takeover:
        // `position:fixed` at full size covers the real page with the
        // attacker's (a login form over the login form), and any `url(...)`
        // makes the victim's browser call out to them. Neither needs a single
        // character of JavaScript, so nothing above this line stops it.
        // Restricting it to properties that only describe appearance keeps the
        // legitimate `style="color:red"` working and removes both.
        .filter_style_properties(HashSet::from(SAFE_STYLE_PROPERTIES))
        // Allow href/src but ammonia auto-strips javascript: URIs by default
        .link_rel(Some("noopener noreferrer"))
        // Strip all on* event handler attributes (ammonia does this by default —
        // only explicitly allowed attributes pass through)
        ;

    // The opt-ins, and nothing else: an unknown name is ignored here rather
    // than widening the allow-list to whatever the caller passed.
    for name in allow {
        match name.as_str() {
            "data-*" => {
                builder.add_generic_attribute_prefixes(["data-"]);
            }
            other if OPT_IN_ATTRIBUTES.contains(&other) => {
                builder.add_generic_attributes([other]);
            }
            _ => {}
        }
    }

    builder
}

/// Sanitize an untrusted HTML fragment using ammonia (html5ever parser).
///
/// - Strips `<script>`, `<style>`, `<iframe>`, `<object>`, `<embed>` (with content)
/// - Strips all `on*` event handler attributes
/// - Strips `javascript:` URIs
/// - Keeps ammonia's safe tag allow-list and UNWRAPS anything else (custom
///   elements / non-allowlisted tags are removed, not preserved)
/// - Restricts `style` to presentation properties — no `position`/`z-index`
///   (page takeover) and nothing taking a `url()` (outbound request)
/// - Drops `id`, `is`, `slot`, `part` and `data-*` (see [`OPT_IN_ATTRIBUTES`])
/// - Never double-encodes existing HTML entities
pub fn sanitize_html(input: &str) -> String {
    sanitize_html_with(input, &[])
}

/// [`sanitize_html`], keeping the attributes of [`OPT_IN_ATTRIBUTES`] named in
/// `allow`.
pub fn sanitize_html_with(input: &str, allow: &[String]) -> String {
    build_html_sanitizer(allow).clean(input).to_string()
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
    sanitize_response_with(body, content_type, &[])
}

/// [`sanitize_response`], keeping the opted-in attributes of `allow` (see
/// [`OPT_IN_ATTRIBUTES`]).
pub fn sanitize_response_with(body: &str, content_type: &str, allow: &[String]) -> String {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("text/html") {
        // Server-generated full HTML documents are not user input and must
        // not pass through ammonia: ammonia treats every wrapper outside its
        // short allow-list (`<!doctype>`, `<html>`, `<head>`, `<body>`...) as
        // unsafe and strips them, leaving only the inner fragments. The
        // result is a broken document. The cheap structural test below
        // skips sanitisation when the body opens with `<!doctype` or `<html`.
        let head: String = body
            .chars()
            .take(16)
            .collect::<String>()
            .trim_start()
            .to_ascii_lowercase();
        if head.starts_with("<!doctype") || head.starts_with("<html") {
            return body.to_string();
        }
        sanitize_html_with(body, allow)
    } else {
        // Non-HTML content types (text/plain, JSON, CSV, binary, …) are never
        // interpreted as markup by the browser — with `X-Content-Type-Options:
        // nosniff` (blackhole's default) there is no XSS vector to escape.
        // Entity-escaping them would only corrupt legitimate bodies
        // (robots.txt, plain-text APIs, CSV, …) for zero security gain.
        body.to_string()
    }
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
        let input =
            r#"<div class="card"><h1>Title</h1><p>Text with <strong>bold</strong></p></div>"#;
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

    #[test]
    fn test_sanitize_html_drops_page_level_attributes() {
        let out = sanitize_html(
            r#"<a id="config" is="x-y" slot="s" part="p" data-bind="x" class="c" title="t">l</a>"#,
        );
        for attribute in ["id=", "is=", "slot=", "part=", "data-bind="] {
            assert!(!out.contains(attribute), "{attribute} survived: {out}");
        }
        // The presentational ones stay.
        assert!(out.contains(r#"class="c""#));
        assert!(out.contains(r#"title="t""#));
    }

    #[test]
    fn test_sanitize_html_keeps_only_the_opted_in_attributes() {
        let input = r#"<p id="intro" data-x="1" is="x-y" slot="s" part="p">t</p>"#;
        let out = sanitize_html_with(input, &["id".to_string(), "data-*".to_string()]);
        assert!(out.contains(r#"id="intro""#));
        assert!(out.contains(r#"data-x="1""#));
        assert!(!out.contains("is="));
        assert!(!out.contains("slot="));
        assert!(!out.contains("part="));
        let each = sanitize_html_with(
            input,
            &["is".to_string(), "slot".to_string(), "part".to_string()],
        );
        assert!(each.contains(r#"is="x-y""#));
        assert!(each.contains(r#"slot="s""#));
        assert!(each.contains(r#"part="p""#));
    }

    #[test]
    fn test_sanitize_html_ignores_an_opt_in_outside_the_list() {
        let out = sanitize_html_with(
            r#"<p onclick="alert(1)" formaction="x">t</p>"#,
            &["onclick".to_string(), "formaction".to_string()],
        );
        assert!(!out.contains("onclick"));
        assert!(!out.contains("formaction"));
    }

    // === Response sanitization tests (standalone API) ===

    #[test]
    fn test_sanitize_response_html() {
        let result = sanitize_response(
            "<p>Hello</p><script>alert(1)</script>",
            "text/html; charset=utf-8",
        );
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
        assert_eq!(
            result, "<script>xss</script>",
            "Empty content-type = no sanitization"
        );
    }

    #[test]
    fn test_sanitize_response_case_insensitive() {
        let result = sanitize_response("<script>xss</script><p>safe</p>", "Text/HTML");
        assert!(!result.contains("<script>"));
        assert!(result.contains("<p>safe</p>"));
    }
}
