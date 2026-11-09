/**
 * What the XSS pass leaves on untrusted markup, and what a client IP counts
 * under in the rate limit.
 */
import { describe, expect, it } from "vitest";
import { clientKey, createBlackhole } from "../../src/index.js";
import { loadNativeBinary } from "../../src/vendor/nativeBinary.js";

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
		const attempt =
			loadNativeBinary<typeof import("../../src/native/generated.js")>();
		if (!attempt.loaded) throw new Error("the engine binary is not built");
		const { Blackhole } = attempt.binary;
		expect(
			() =>
				new Blackhole(
					true,
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
		expect(bh.sanitizeResponse("<script>x</script>", "text/html")).toBe(
			"<script>x</script>",
		);
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
