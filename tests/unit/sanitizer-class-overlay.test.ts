/**
 * `style` loses `position` and `z-index` so untrusted markup cannot cover the
 * page with its own. On a page that ships utility classes the class list is
 * the style, so `class` is dropped too unless the application opts it back in.
 */
import { describe, expect, it } from "vitest";
import { createBlackhole } from "../../src/index.js";

const OVERLAY =
	'<div class="fixed inset-0 z-[9999] bg-white">Session expired. <a href="https://evil.example/login" rel="noopener noreferrer">Sign in again</a></div>';

describe("blackhole > sanitizer > the class attribute", () => {
	it("the overlay written as `style` loses its positioning", () => {
		const out = createBlackhole({ csrf: false }).sanitizeResponse(
			'<div style="position:fixed;top:0;left:0;z-index:9999;width:100%;height:100%;background-color:#fff">Session expired.</div>',
			"text/html",
		);
		expect(out).not.toContain("position");
		expect(out).not.toContain("z-index");
		expect(out).toContain("background-color:#fff");
	});

	it("the same overlay written as utility classes loses them by default", () => {
		const out = createBlackhole({ csrf: false }).sanitizeResponse(
			OVERLAY,
			"text/html",
		);
		expect(out).toBe(
			'<div>Session expired. <a href="https://evil.example/login" rel="noopener noreferrer">Sign in again</a></div>',
		);
	});

	it("`allowAttributes: ['class']` keeps them, for a page that reads none from untrusted markup", () => {
		const out = createBlackhole({
			csrf: false,
			xss: { allowAttributes: ["class"] },
		}).sanitizeResponse(OVERLAY, "text/html");
		expect(out).toBe(OVERLAY);
	});
});
