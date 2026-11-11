/**
 * What the XSS pass leaves on untrusted markup, and what a client IP counts
 * under in the rate limit.
 */
import { describe, expect, it } from "vitest";
import { runResponsePhase } from "../../src/core.js";
import { clientKey, createBlackhole } from "../../src/index.js";
import {
	hasFunctions,
	loadNativeBinary,
} from "../../src/vendor/nativeBinary.js";
import { ADAPTERS, viaAdapter } from "./support/adapters.js";

const FRAGMENT =
	'<a id="config" is="x-y" slot="s" part="p" data-bind="x" class="c" href="/x">l</a>';

describe("blackhole > XSS sanitizer attributes", () => {
	it("drops id, is, slot, part and data-* by default", () => {
		const out = createBlackhole({ csrf: false }).sanitizeResponse(
			FRAGMENT,
			"text/html",
		);
		for (const attribute of ["id=", "is=", "slot=", "part=", "data-bind="]) {
			expect(out).not.toContain(attribute);
		}
		expect(out).toContain('class="c"');
	});

	it("keeps the attributes an application opts into", () => {
		const out = createBlackhole({
			csrf: false,
			xss: { allowAttributes: ["id", "data-*"] },
		}).sanitizeResponse(FRAGMENT, "text/html");
		expect(out).toContain('id="config"');
		expect(out).toContain('data-bind="x"');
		expect(out).not.toContain("is=");
		expect(out).not.toContain("slot=");
	});

	it("refuses an attribute outside the opt-in list", () => {
		// The engine itself refuses it: a config file written in JavaScript is
		// not held to the type.
		const attempt = loadNativeBinary(
			(
				value,
			): value is Pick<
				typeof import("../../src/native/generated.js"),
				"Blackhole"
			> => hasFunctions(value, ["Blackhole"]),
		);
		if (!attempt.loaded) throw new Error("the engine binary is not built");
		const { Blackhole } = attempt.binary;
		expect(
			() =>
				new Blackhole(
					false,
					undefined,
					undefined,
					true,
					true,
					[],
					[],
					undefined,
					[],
					["onclick"],
				),
		).toThrow(/cannot be allowed/);
	});

	it("turns the pass off with enabled: false", () => {
		const bh = createBlackhole({ csrf: false, xss: { enabled: false } });
		expect(bh.xssEnabled()).toBe(false);
		const out = runResponsePhase(bh, {
			body: "<script>x</script>",
			contentType: "text/html",
		});
		expect(out.body).toBe("<script>x</script>");
	});

	it("turns the pass on with the object form", () => {
		const bh = createBlackhole({
			csrf: false,
			xss: { allowAttributes: ["id"] },
		});
		expect(bh.xssEnabled()).toBe(true);
	});
});

describe("blackhole > rate-limit client key", () => {
	it("keeps an IPv4 address as is", () => {
		expect(clientKey("192.0.2.1")).toBe("192.0.2.1");
	});

	it("counts an IPv6 address under its /64", () => {
		expect(clientKey("2001:db8:85a3:8d3:1319:8a2e:370:7348")).toBe(
			"2001:db8:85a3:8d3::/64",
		);
		// Every address of the same /64 shares one budget.
		expect(clientKey("2001:db8:85a3:8d3::1")).toBe(
			clientKey("2001:db8:85a3:8d3:ffff::42"),
		);
		expect(clientKey("2001:0DB8:0000:0001::1")).toBe("2001:db8:0:1::/64");
		expect(clientKey("::1")).toBe("0:0:0:0::/64");
		expect(clientKey("fe80::1%eth0")).toBe("fe80:0:0:0::/64");
	});

	it("expands an address written with a trailing dotted quad", () => {
		expect(clientKey("64:ff9b::192.0.2.1")).toBe("64:ff9b:0:0::/64");
		expect(clientKey("2001:db8:1:2:3:4:192.0.2.1")).toBe("2001:db8:1:2::/64");
	});

	it("reads an IPv4-mapped address as the IPv4 address", () => {
		expect(clientKey("::ffff:192.0.2.1")).toBe("192.0.2.1");
	});

	it("leaves what is not an address alone", () => {
		expect(clientKey("unknown")).toBe("unknown");
		expect(clientKey("")).toBe("");
	});

	it("limits a client rotating through its /64", () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 2, windowSeconds: 60 },
		});
		const statuses = ["::1", "::2", "::3"].map((suffix) => {
			const key = bh.rateLimitKey({
				request: { ip: () => `2001:db8:1:2${suffix}` },
			});
			return bh.check({
				method: "GET",
				path: "/",
				headers: {},
				remoteAddr: key,
			}).status;
		});
		expect(statuses).toEqual([undefined, undefined, 429]);
	});
});

describe("blackhole > the app's own HTML is not sanitized unless asked", () => {
	const FORM =
		'<section><form method="post" action="/save"><input type="hidden" name="_csrf" value="abc"><label>Name <input name="name"></label><select name="x"><option>1</option></select><textarea name="t"></textarea><button type="submit">Save</button></form></section>';
	const MEDIA =
		'<div><svg width="10"><circle r="1"></circle></svg><video src="/v.mp4"></video></div>';

	it("serves a form fragment and a media fragment as written by default", () => {
		const bh = createBlackhole({ csrf: false });
		for (const body of [FORM, MEDIA]) {
			const out = runResponsePhase(bh, {
				body,
				contentType: "text/html; charset=utf-8",
			});
			expect(out.body).toBe(body);
		}
	});

	it("serves them as written through every adapter", async () => {
		for (const adapter of ADAPTERS) {
			const res = await viaAdapter(
				adapter,
				{ csrf: false },
				{ target: "/", routeBody: FORM },
			);
			expect(res.sentBody).toBe(FORM);
		}
	});

	it("sanitizes every fragment on the way out once `xss` is on", () => {
		const bh = createBlackhole({ csrf: false, xss: true });
		const out = runResponsePhase(bh, {
			body: `${FORM}<script>alert(1)</script>`,
			contentType: "text/html",
		});
		expect(out.body).not.toContain("<script");
		expect(out.body).not.toContain("<form");
	});

	it("still sanitizes what the app hands `sanitizeResponse` itself", () => {
		// The explicit call is how untrusted input is cleaned before it is
		// stored: it must not depend on the automatic pass being on.
		const bh = createBlackhole({ csrf: false });
		const out = bh.sanitizeResponse(
			'<p onclick="x()">hi</p><script>alert(1)</script>',
			"text/html",
		);
		expect(out).not.toContain("<script");
		expect(out).not.toContain("onclick");
		expect(out).toContain("<p>hi</p>");
	});
});
