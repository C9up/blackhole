//! XSS sanitization utilities — powered by ammonia (html5ever parser).
//!
//! Uses a real HTML parser (same as Firefox/Servo) to neutralize XSS vectors in
//! UNTRUSTED HTML *fragments*. This is an allow-LIST sanitizer: ammonia keeps a
//! curated set of safe tags/attributes and UNWRAPS anything else — including
//! custom elements (`<my-widget>`) and non-allowlisted HTML5 tags. Do not rely
//! on it to pass trusted markup through unchanged; it reparses + re-serialises,
//! so exact bytes (inline SVG, `<pre>`, SRI-hashed inline content) may change.
//! A whole document an application renders itself is therefore not handed to
//! it: the host's response pass skips a body the APPLICATION marked as its own
//! (never one that merely looks like a document — its first bytes are written
//! by whoever wrote the content). Never double-encodes existing HTML entities.
//!
//! @implements FR44

use std::collections::HashSet;

use crate::html_limits::{self, HtmlLimits, HtmlRefusal};

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
/// without a single `<script>`; `slot` and `part` reach into shadow DOM;
/// `class` selects every rule of the page's own stylesheet — on a page built
/// with utility classes, `class="fixed inset-0 z-50"` is the full-page
/// overlay the `style` filter below refuses.
pub const OPT_IN_ATTRIBUTES: [&str; 6] = ["id", "is", "slot", "part", "data-*", "class"];

/// Build the ammonia sanitizer (safe allow-list) used for untrusted fragments:
/// - Keeps ammonia's default allow-list of safe tags; UNWRAPS everything else
///   (custom elements, non-allowlisted HTML5 tags) — NOT an "allow all tags" pass.
/// - Removes dangerous elements with their content: <script>, <style>, <iframe>,
///   <object>, <embed>.
/// - Strips all event-handler attributes (on*) and `javascript:` URIs (ammonia
///   default: only explicitly-allowed attributes/URIs survive).
/// - Allows a set of presentational generic attributes (role, title, …),
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
        .add_generic_attributes(["style", "role", "tabindex",
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
/// - Refuses an input past the default [`HtmlLimits`] (see [`html_limits`])
pub fn sanitize_html(input: &str) -> Result<String, HtmlRefusal> {
    sanitize_html_with(input, &[], &HtmlLimits::default())
}

/// [`sanitize_html`], keeping the attributes of [`OPT_IN_ATTRIBUTES`] named in
/// `allow` and holding the input to `limits`.
///
/// The parse is not linear in its input (misnested formatting elements are
/// re-created in every block, deep nesting rescans the open elements), so an
/// input is measured before ammonia parses it: one that is too long, nests
/// too deep or builds far more markup than it holds is refused, never
/// passed through.
pub fn sanitize_html_with(
    input: &str,
    allow: &[String],
    limits: &HtmlLimits,
) -> Result<String, HtmlRefusal> {
    html_limits::check(input, limits)?;
    Ok(build_html_sanitizer(allow).clean(input).to_string())
}

/// Sanitize a response body based on content type.
/// - `text/html`: ammonia HTML sanitizer (parser-based, preserves safe wrapper
///   tags). Every body of that type, a "document" included: whether a body is
///   one cannot be read off its first bytes, which belong to whoever wrote it
///   — a `<!doctype html>` prefix on an untrusted comment would otherwise turn
///   the sanitizer off.
/// - Everything else (`text/plain`, JSON, CSV, binary, …): returned unmodified.
///   A non-HTML body is never parsed as markup by the browser (blackhole sets
///   `X-Content-Type-Options: nosniff` by default), so there is nothing to
///   escape — and escaping would corrupt legitimate plain-text bodies.
///
/// Standalone version — takes `(body, content_type)` instead of a framework
/// response struct, so it works with any HTTP server.
pub fn sanitize_response(body: &str, content_type: &str) -> Result<String, HtmlRefusal> {
    sanitize_response_with(body, content_type, &[], &HtmlLimits::default())
}

/// [`sanitize_response`], keeping the opted-in attributes of `allow` (see
/// [`OPT_IN_ATTRIBUTES`]) and holding a `text/html` body to `limits`.
pub fn sanitize_response_with(
    body: &str,
    content_type: &str,
    allow: &[String],
    limits: &HtmlLimits,
) -> Result<String, HtmlRefusal> {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("text/html") {
        sanitize_html_with(body, allow, limits)
    } else {
        // Non-HTML content types (text/plain, JSON, CSV, binary, …) are never
        // interpreted as markup by the browser — with `X-Content-Type-Options:
        // nosniff` (blackhole's default) there is no XSS vector to escape.
        // Entity-escaping them would only corrupt legitimate bodies
        // (robots.txt, plain-text APIs, CSV, …) for zero security gain.
        Ok(body.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitize_html(input: &str) -> String {
        super::sanitize_html(input).expect("within the default limits")
    }

    fn sanitize_html_with(input: &str, allow: &[String]) -> String {
        super::sanitize_html_with(input, allow, &HtmlLimits::default())
            .expect("within the default limits")
    }

    fn sanitize_response(body: &str, content_type: &str) -> String {
        super::sanitize_response(body, content_type).expect("within the default limits")
    }

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
        for attribute in ["id=", "is=", "slot=", "part=", "data-bind=", "class="] {
            assert!(!out.contains(attribute), "{attribute} survived: {out}");
        }
        // The presentational ones stay.
        assert!(out.contains(r#"title="t""#));
    }

    #[test]
    fn test_sanitize_html_drops_a_class_overlay_unless_opted_in() {
        // On a page built with utility classes, the class list is the style:
        // the overlay `style="position:fixed"` cannot draw.
        let overlay = r#"<div class="fixed inset-0 z-50 bg-white">Session expired</div>"#;
        assert_eq!(sanitize_html(overlay), "<div>Session expired</div>");
        assert_eq!(sanitize_html_with(overlay, &["class".to_string()]), overlay);
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

    const DOCUMENT: &str = "<!DOCTYPE html><html><head><title>T</title></head><body><main><h1>Hi</h1></main></body></html>";

    /// What an attacker appends to a body that looks like a document.
    const PAYLOAD: &str = "<img src=x onerror=alert(1)><script>alert(2)</script>";

    fn assert_neutralised(out: &str) {
        assert!(!out.contains("<script"), "script kept: {out}");
        assert!(!out.contains("onerror"), "handler kept: {out}");
    }

    #[test]
    fn a_body_opening_with_a_doctype_is_still_sanitized() {
        // The first bytes belong to whoever wrote the content: an untrusted
        // comment starting with `<!doctype html>` must not switch the pass off.
        assert_neutralised(&sanitize_response(
            &format!("<!doctype html>{PAYLOAD}"),
            "text/html",
        ));
        assert_neutralised(&sanitize_response(
            &format!("{DOCUMENT}{PAYLOAD}"),
            "text/html; charset=utf-8",
        ));
    }

    #[test]
    fn a_body_opening_with_html_or_a_comment_is_still_sanitized() {
        assert_neutralised(&sanitize_response(
            &format!("<!-- x --><html>{PAYLOAD}"),
            "text/html",
        ));
        assert_neutralised(&sanitize_response(
            &format!("<HTML lang=\"en\">{PAYLOAD}"),
            "text/html",
        ));
        assert_neutralised(&sanitize_response(
            &format!(
                "\u{feff}<?xml version=\"1.0\"?>\n{}<!doctype html>{PAYLOAD}",
                " ".repeat(20)
            ),
            "text/html",
        ));
    }

    #[test]
    fn a_fragment_behind_a_comment_is_still_sanitized() {
        let out = sanitize_response(
            "<!-- partial --><p>Hi</p><script>alert(1)</script>",
            "text/html",
        );
        assert!(!out.contains("<script"));
        assert!(out.contains("<p>Hi</p>"));
    }

    #[test]
    fn test_sanitize_response_case_insensitive() {
        let result = sanitize_response("<script>xss</script><p>safe</p>", "Text/HTML");
        assert!(!result.contains("<script>"));
        assert!(result.contains("<p>safe</p>"));
    }
}
