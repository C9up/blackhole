//! The inputs behind the sanitizer's published advisories, held against what
//! blackhole's configuration lets out.
//!
//! RUSTSEC-2021-0158: SVG `animateMotion` / `animateTransform` /
//! `animateColor` carried script into the output. RUSTSEC-2021-0157 and
//! RUSTSEC-2026-0373: a CSS `url("")` escaped its quoting, and `URL(` in
//! capitals was not recognised as one. The fixed sanitizer is pinned in
//! `Cargo.lock`; these keep the output honest whichever version runs.

use blackhole_engine::xss::{sanitize_html, sanitize_html_with};

const ANIMATE: [&str; 3] = ["animateMotion", "animateTransform", "animateColor"];

#[test]
fn svg_animation_elements_carry_nothing_out() {
    for element in ANIMATE {
        let input = format!(
            r#"<svg><a><{element} attributeName="href" values="javascript:alert(1)"/><text>x</text></a></svg>"#
        );
        let out = sanitize_html(&input);
        let lower = out.to_ascii_lowercase();
        assert!(
            !lower.contains(&element.to_ascii_lowercase()),
            "{input} -> {out}"
        );
        assert!(!lower.contains("javascript:"), "{input} -> {out}");
        assert!(!lower.contains("<svg"), "{input} -> {out}");
    }
}

#[test]
fn svg_animation_elements_carry_nothing_out_with_every_opt_in() {
    let allow: Vec<String> = ["id", "is", "slot", "part", "data-*"]
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    for element in ANIMATE {
        let input =
            format!(r#"<svg><{element} attributeName="href" to="javascript:alert(1)"/></svg>"#);
        let out = sanitize_html_with(&input, &allow).to_ascii_lowercase();
        assert!(!out.contains("javascript:"), "{input} -> {out}");
    }
}

/// The guard is by property: none of the properties `style` keeps takes a
/// URL, so a `url()` written into one of them (`color:url(…)`) is a
/// declaration the browser drops without fetching anything. What must never
/// come out is a property that does fetch.
#[test]
fn no_css_url_survives_whatever_its_case_or_quoting() {
    for input in [
        r#"<p style="color:red;background:URL(https://evil.example/a)">x</p>"#,
        r#"<p style="color:red;background:Url('https://evil.example/a')">x</p>"#,
        r#"<p style='color:red;background-image:url("https://evil.example/a")'>x</p>"#,
        r#"<p style="color:red;background:url(&quot;https://evil.example/a&quot;)">x</p>"#,
        r#"<p style="color:red;background:url(&quot;&quot;);x:url(https://evil.example/a)">x</p>"#,
    ] {
        let out = sanitize_html(input);
        assert!(!out.contains("evil.example"), "{input} -> {out}");
        assert!(
            !out.to_ascii_lowercase().contains("url("),
            "{input} -> {out}"
        );
    }
}
