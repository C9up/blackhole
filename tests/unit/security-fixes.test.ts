import { describe, expect, it } from "vitest";
import { createBlackhole } from "../../src/index.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";

describe("CSP hardening + Report-Only", () => {
	it("emits the Report-Only header when cspReportOnly is set", () => {
		const h = createBlackhole({
			secret: SECRET,
			securityHeaders: { csp: "default-src 'self'", cspReportOnly: true },
		}).securityHeaders();
		expect(h["content-security-policy-report-only"]).toBe("default-src 'self'");
		expect(h["content-security-policy"]).toBeUndefined();
	});

	it("substitutes @nonce inside the Report-Only header too", () => {
		const bh = createBlackhole({
			secret: SECRET,
			securityHeaders: { csp: "script-src @nonce", cspReportOnly: true },
		});
		const h = bh.securityHeaders("abc123");
		expect(h["content-security-policy-report-only"]).toBe("script-src 'nonce-abc123'");
	});
});

describe("HSTS maxAge validation", () => {
	it("throws on a negative maxAge (would silently disable HSTS)", () => {
		expect(() =>
			createBlackhole({ secret: SECRET, securityHeaders: { hsts: { maxAge: -1 } } }),
		).toThrow(/HSTS maxAge/);
	});
});

describe("CORS request validation", () => {
	const bh = (headers?: string[] | true) =>
		createBlackhole({
			secret: SECRET,
			cors: { origin: "https://app.test", methods: ["GET", "POST"], headers },
		});

	it("accepts a comma-separated origin allow-list", () => {
		const b = createBlackhole({
			secret: SECRET,
			cors: { origin: "https://a.test,https://b.test" },
		});
		expect(b.cors("https://b.test", "GET")?.headers["access-control-allow-origin"]).toBe(
			"https://b.test",
		);
		expect(b.cors("https://evil.test", "GET")?.headers["access-control-allow-origin"]).toBeUndefined();
	});

	it("refuses a preflight whose requested method isn't allowed", () => {
		const res = bh().cors("https://app.test", "OPTIONS", "DELETE");
		expect(res?.preflight).toBe(true);
		// No Allow-Methods → the browser blocks the request.
		expect(res?.headers["access-control-allow-methods"]).toBeUndefined();
	});

	it("allows a preflight whose method is in the list", () => {
		const res = bh().cors("https://app.test", "OPTIONS", "POST");
		expect(res?.headers["access-control-allow-methods"]).toBe("GET, POST");
	});

	it("refuses a preflight requesting a header outside the allow-list", () => {
		const res = bh(["Content-Type"]).cors("https://app.test", "OPTIONS", "POST", "X-Evil");
		expect(res?.headers["access-control-allow-headers"]).toBeUndefined();
	});

	it("reflects requested headers when headers: true", () => {
		const res = bh(true).cors("https://app.test", "OPTIONS", "POST", "X-Custom, X-Trace");
		expect(res?.headers["access-control-allow-headers"]).toBe("X-Custom, X-Trace");
	});
});

describe("rate-limit backoff headers (native)", () => {
	it("emits Retry-After + X-RateLimit-* on a 429", () => {
		const bh = createBlackhole({ secret: SECRET, csrf: false, rateLimit: { max: 1, windowSeconds: 60 } });
		const req = { method: "GET", path: "/", headers: {}, remoteAddr: "9.9.9.9" };
		expect(bh.check(req).allowed).toBe(true);
		const blocked = bh.check(req);
		expect(blocked.allowed).toBe(false);
		expect(blocked.status).toBe(429);
		expect(blocked.headers?.["Retry-After"]).toBeDefined();
		expect(blocked.headers?.["X-RateLimit-Limit"]).toBe("1");
		expect(blocked.headers?.["X-RateLimit-Remaining"]).toBe("0");
	});
});

describe("CSRF Origin/Referer defense-in-depth (native)", () => {
	const bh = createBlackhole({ secret: SECRET, csrf: true });

	function post(origin?: string) {
		const token = bh.generateCsrfToken();
		const headers: Record<string, string> = {
			"x-xsrf-token": token,
			cookie: `XSRF-TOKEN=${token}`,
			host: "app.test",
		};
		if (origin) headers.origin = origin;
		return bh.check({ method: "POST", path: "/", headers, remoteAddr: "127.0.0.1" });
	}

	it("allows a same-origin POST with a valid token", () => {
		expect(post("https://app.test").allowed).toBe(true);
	});

	it("rejects a cross-origin POST even with a valid token", () => {
		const res = post("https://evil.test");
		expect(res.allowed).toBe(false);
		expect(res.status).toBe(403);
	});

	it("allows a POST with no Origin/Referer (non-browser client) + valid token", () => {
		expect(post().allowed).toBe(true);
	});
});
