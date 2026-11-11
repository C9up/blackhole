/**
 * The CSP and HSTS settings, as written in a config file.
 *
 * A CSP the browser cannot read is no CSP at all, and nothing fails to say
 * so: camelCase directive names, an unquoted keyword or a stray `;` each left
 * the site without the policy it was configured with. They are refused when
 * the filter is created instead.
 */
import { describe, expect, it } from "vitest";
import {
	type BlackholeOptions,
	type CspConfig,
	createBlackhole,
	dangerouslyDisableDefaultSrc,
} from "../../src/index.js";

function cspOf(csp: string | CspConfig): string | undefined {
	return createBlackhole({
		csrf: false,
		csp: typeof csp === "string" ? { policy: csp } : csp,
	}).securityHeaders()["content-security-policy"];
}

function hstsOf(maxAge: number | string): string | undefined {
	return createBlackhole({
		csrf: false,
		hsts: { maxAge },
	}).securityHeaders()["strict-transport-security"];
}

describe("blackhole > object-form CSP", () => {
	it("writes camelCase directive names dashed", () => {
		expect(
			cspOf({
				useDefaults: false,
				directives: {
					defaultSrc: ["'self'"],
					frameAncestors: ["'none'"],
					upgradeInsecureRequests: [],
				},
			}),
		).toBe(
			"default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
		);
	});

	it("reads camelCase and dashed names as the same directive", () => {
		const camel = cspOf({ directives: { scriptSrc: ["'self'", "cdn.test"] } });
		const dashed = cspOf({
			directives: { "script-src": ["'self'", "cdn.test"] },
		});
		expect(camel).toBe(dashed);
		expect(camel).toContain("script-src 'self' cdn.test");
		// Overriding the baseline's directive, not adding a second one.
		expect(camel?.match(/script-src /g)).toHaveLength(1);
	});

	it("accepts a single source given as a string", () => {
		expect(
			cspOf({ useDefaults: false, directives: { defaultSrc: "'self'" } }),
		).toBe("default-src 'self'");
	});

	it("refuses the same directive given twice", () => {
		expect(() =>
			cspOf({
				directives: { scriptSrc: ["'self'"], "script-src": ["'none'"] },
			}),
		).toThrow(/given twice/);
	});

	for (const keyword of [
		"self",
		"none",
		"unsafe-inline",
		"wasm-unsafe-eval",
		"inline-speculation-rules",
		"nonce-abc",
		"sha256-abc",
		"sha384-abc",
		"sha512-abc",
	]) {
		it(`refuses the unquoted ${keyword}`, () => {
			expect(() =>
				cspOf({ directives: { scriptSrc: ["'self'", keyword] } }),
			).toThrow(/single-quoted/);
		});
	}

	it("refuses a `;` or `,` inside a source", () => {
		expect(() =>
			cspOf({ directives: { imgSrc: ["'self'; script-src *"] } }),
		).toThrow(/invalid value/);
		expect(() => cspOf({ directives: { imgSrc: ["a.test, b.test"] } })).toThrow(
			/invalid value/,
		);
	});

	it("refuses a line break inside a source", () => {
		// A CR/LF in the header value is a second header, or a split response
		// on a host that does not validate.
		for (const source of [
			"'self'\r\nX-Injected: 1",
			"'self'\nX: 1",
			"'self'\r",
		]) {
			expect(() =>
				createBlackhole({
					csrf: false,
					csp: { directives: { scriptSrc: [source] } },
				}),
			).toThrow(/invalid value/);
		}
	});

	it("refuses an invalid directive name", () => {
		expect(() => cspOf({ directives: { "script src": ["'self'"] } })).toThrow(
			/invalid directive name/,
		);
	});

	it("needs a default-src once the baseline is off", () => {
		expect(() =>
			cspOf({ useDefaults: false, directives: { scriptSrc: ["'self'"] } }),
		).toThrow(/needs a `default-src`/);
		expect(() => cspOf({ useDefaults: false, directives: {} })).toThrow(
			/no directives/,
		);
	});

	it("drops default-src only through the explicit marker", () => {
		expect(() => cspOf({ directives: { defaultSrc: null } })).toThrow(
			/cannot be `null`/,
		);
		expect(() =>
			cspOf({ directives: { scriptSrc: dangerouslyDisableDefaultSrc } }),
		).toThrow(/only applies to `default-src`/);
		const csp = cspOf({
			directives: { defaultSrc: dangerouslyDisableDefaultSrc },
		});
		expect(csp).not.toContain("default-src");
		expect(csp).toContain("script-src");
	});

	it("drops a baseline directive set to null", () => {
		const csp = cspOf({ directives: { upgradeInsecureRequests: null } });
		expect(csp).not.toContain("upgrade-insecure-requests");
		expect(csp).toContain("default-src 'self'");
	});

	it("keeps the @nonce token for per-request substitution", () => {
		const bh = createBlackhole({
			csrf: false,
			csp: { directives: { scriptSrc: ["'self'", "@nonce"] } },
		});
		expect(bh.cspHasNonce()).toBe(true);
		expect(bh.securityHeaders("abc")["content-security-policy"]).toContain(
			"script-src 'self' 'nonce-abc'",
		);
	});
});

describe("blackhole > csp.policy (the string form)", () => {
	it("refuses an unquoted keyword instead of warning", () => {
		expect(() => cspOf("default-src self")).toThrow(/single-quoted/);
		expect(() => cspOf("default-src 'self'; script-src nonce-x")).toThrow(
			/single-quoted/,
		);
	});

	it("refuses a line break anywhere in the policy", () => {
		for (const policy of [
			"default-src 'self'\r\nX: 1",
			"default-src 'self';\nimg-src 'self'",
		]) {
			expect(() => createBlackhole({ csrf: false, csp: { policy } })).toThrow(
				/line break/,
			);
		}
	});

	it("refuses a directive given twice", () => {
		expect(() => cspOf("default-src 'self'; Default-Src 'none'")).toThrow(
			/given twice/,
		);
	});

	it("passes a well-formed policy through", () => {
		expect(cspOf("default-src 'self'; img-src 'self' data:")).toBe(
			"default-src 'self'; img-src 'self' data:",
		);
	});
});

describe("blackhole > HSTS maxAge", () => {
	it("reads a duration string", () => {
		expect(hstsOf("180 days")).toBe("max-age=15552000");
		expect(hstsOf("1 year")).toBe("max-age=31557600");
		expect(hstsOf("2h")).toBe("max-age=7200");
	});

	it("takes a number as seconds", () => {
		expect(hstsOf(3600)).toBe("max-age=3600");
	});

	it("accepts zero, which tells browsers to drop the policy", () => {
		expect(hstsOf(0)).toBe("max-age=0");
	});

	it("refuses a negative or unreadable value", () => {
		expect(() => hstsOf(-1)).toThrow(/HSTS maxAge/);
		expect(() => hstsOf("soon")).toThrow(/HSTS maxAge/);
		expect(() => hstsOf(Number.NaN)).toThrow(/HSTS maxAge/);
	});
});

describe("blackhole > protective headers, one key each", () => {
	const headersOf = (options: BlackholeOptions) =>
		createBlackhole({ csrf: false, ...options }).securityHeaders();

	it("sets every header with its default when nothing is configured", () => {
		expect(headersOf({})).toEqual({
			"x-xss-protection": "0",
			"x-content-type-options": "nosniff",
			"x-frame-options": "SAMEORIGIN",
			"strict-transport-security": "max-age=15552000; includeSubDomains",
			"content-security-policy":
				"default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'; script-src 'self'",
			"referrer-policy": "strict-origin-when-cross-origin",
			"permissions-policy": "camera=(), microphone=(), geolocation=()",
		});
	});

	it("reads shield's xFrame, hsts, contentTypeSniffing and csp objects", () => {
		const headers = headersOf({
			xFrame: { enabled: true, action: "DENY" },
			hsts: { enabled: true, maxAge: "1 year", preload: true },
			contentTypeSniffing: { enabled: false },
			csp: {
				enabled: true,
				directives: { defaultSrc: ["'self'"] },
				reportOnly: true,
			},
		});
		expect(headers["x-frame-options"]).toBe("DENY");
		expect(headers["strict-transport-security"]).toBe(
			"max-age=31557600; preload",
		);
		expect(headers["x-content-type-options"]).toBeUndefined();
		expect(headers["content-security-policy"]).toBeUndefined();
		expect(headers["content-security-policy-report-only"]).toContain(
			"default-src 'self'",
		);
	});

	it("turns each header off with enabled: false, and keeps an object without it on", () => {
		const headers = headersOf({
			xFrame: { enabled: false },
			referrerPolicy: { policy: "no-referrer" },
			permissionsPolicy: { enabled: false },
			hsts: {},
		});
		expect(headers["x-frame-options"]).toBeUndefined();
		expect(headers["referrer-policy"]).toBe("no-referrer");
		expect(headers["permissions-policy"]).toBeUndefined();
		// An hsts object without maxAge: 180 days, subdomains only if asked.
		expect(headers["strict-transport-security"]).toBe("max-age=15552000");
	});

	it("writes ALLOW-FROM with its domain, and refuses it without one", () => {
		expect(
			headersOf({
				xFrame: { action: "ALLOW-FROM", domain: "https://partner.example" },
			})["x-frame-options"],
		).toBe("ALLOW-FROM https://partner.example");
		expect(() => headersOf({ xFrame: { action: "ALLOW-FROM" } })).toThrow(
			/domain/,
		);
	});

	it("refuses csp.policy together with csp.directives", () => {
		expect(() =>
			headersOf({
				csp: {
					policy: "default-src 'self'",
					directives: { defaultSrc: ["'self'"] },
				},
			}),
		).toThrow(/not both/);
	});

	it("refuses an unknown key inside a header's object", () => {
		const xFrame = { enabled: true, acton: "DENY" };
		expect(() => headersOf({ xFrame })).toThrow(
			/`xFrame` has no option "acton"/,
		);
	});

	it("refuses the retired securityHeaders option, naming the new keys", () => {
		const options = { csrf: false, securityHeaders: { frameOptions: "DENY" } };
		expect(() => createBlackhole(options)).toThrow(
			/`securityHeaders` is no longer an option.*`xFrame`, `hsts`, `contentTypeSniffing`, `csp`, `referrerPolicy` and `permissionsPolicy`/,
		);
	});
});

describe("blackhole > free-text header values are refused at boot", () => {
	const INJECTED = "no-referrer\r\nX-Injected: 1";

	it("refuses a line break in referrerPolicy.policy", () => {
		expect(() =>
			createBlackhole({ csrf: false, referrerPolicy: { policy: INJECTED } }),
		).toThrow(/referrerPolicy\.policy/);
	});

	it("refuses a line break in permissionsPolicy.policy", () => {
		expect(() =>
			createBlackhole({
				csrf: false,
				permissionsPolicy: { policy: "camera=()\nX-Injected: 1" },
			}),
		).toThrow(/permissionsPolicy\.policy/);
	});

	it("refuses a line break in xFrame.domain", () => {
		expect(() =>
			createBlackhole({
				csrf: false,
				xFrame: {
					action: "ALLOW-FROM",
					domain: "https://a.example\r\nX-Injected: 1",
				},
			}),
		).toThrow(/xFrame\.domain/);
	});

	it("refuses any other control character, a non-ASCII one, or an empty value", () => {
		for (const policy of ["no-referrer\u0000", "no-referrer\u007f", "nö", ""]) {
			expect(() =>
				createBlackhole({ csrf: false, referrerPolicy: { policy } }),
			).toThrow(/referrerPolicy\.policy/);
		}
	});

	it("keeps a well-formed value", () => {
		const headers = createBlackhole({
			csrf: false,
			referrerPolicy: { policy: "no-referrer, strict-origin" },
			permissionsPolicy: { policy: "camera=(), geolocation=(self)" },
			xFrame: { action: "ALLOW-FROM", domain: "https://a.example" },
		}).securityHeaders();
		expect(headers["referrer-policy"]).toBe("no-referrer, strict-origin");
		expect(headers["permissions-policy"]).toBe("camera=(), geolocation=(self)");
		expect(headers["x-frame-options"]).toBe("ALLOW-FROM https://a.example");
	});
});
