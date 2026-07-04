import { describe, expect, it } from "vitest";
import { createBlackhole, defineConfig } from "../../src/index.js";

/** Signed double-submit needs a secret whenever CSRF is enabled. */
const SECRET = "test-app-key-32-bytes-long-aaaaaa";

describe("blackhole", () => {
	it("allows a normal GET", () => {
		const bh = createBlackhole({ csrf: false });
		const result = bh.check({
			method: "GET",
			path: "/api/orders",
			headers: {},
		});
		expect(result.allowed).toBe(true);
	});

	it("blocks POST without CSRF token", () => {
		const bh = createBlackhole({ csrf: true, secret: SECRET });
		const result = bh.check({
			method: "POST",
			path: "/api/orders",
			headers: {},
		});
		expect(result.allowed).toBe(false);
		expect(result.status).toBe(403);
	});

	it("allows POST when the XSRF-TOKEN cookie matches the X-XSRF-TOKEN header (double-submit)", () => {
		const bh = createBlackhole({ csrf: true, secret: SECRET });
		const token = bh.generateCsrfToken();
		const result = bh.check({
			method: "POST",
			path: "/api/orders",
			headers: { "x-xsrf-token": token, cookie: `XSRF-TOKEN=${token}` },
		});
		expect(result.allowed).toBe(true);
	});

	it("allows POST via the _csrf form-body field (server-rendered form)", () => {
		const bh = createBlackhole({ csrf: true, secret: SECRET });
		const token = bh.generateCsrfToken();
		const result = bh.check({
			method: "POST",
			path: "/api/orders",
			headers: { cookie: `XSRF-TOKEN=${token}` },
			body: `name=widget&_csrf=${token}`,
		});
		expect(result.allowed).toBe(true);
	});

	it("skips CSRF for an exceptRoutes path (webhooks)", () => {
		const bh = createBlackhole({
			csrf: { exceptRoutes: ["/api/webhooks/*"] },
			secret: SECRET,
		});
		const result = bh.check({
			method: "POST",
			path: "/api/webhooks/stripe",
			headers: {},
		});
		expect(result.allowed).toBe(true);
	});

	it("rejects POST with a forged header but no matching cookie", () => {
		const bh = createBlackhole({ csrf: true, secret: SECRET });
		const result = bh.check({
			method: "POST",
			path: "/api/orders",
			headers: { "x-csrf-token": bh.generateCsrfToken() },
		});
		expect(result.allowed).toBe(false);
	});

	it("rate-limits after max requests", () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 2, windowSeconds: 60 },
		});
		expect(
			bh.check({ method: "GET", path: "/", headers: {}, remoteAddr: "1.2.3.4" })
				.allowed,
		).toBe(true);
		expect(
			bh.check({ method: "GET", path: "/", headers: {}, remoteAddr: "1.2.3.4" })
				.allowed,
		).toBe(true);
		const third = bh.check({
			method: "GET",
			path: "/",
			headers: {},
			remoteAddr: "1.2.3.4",
		});
		expect(third.allowed).toBe(false);
		expect(third.status).toBe(429);
	});

	it("rejects path-traversal in the request path", () => {
		const bh = createBlackhole({ csrf: false });
		expect(
			bh.check({ method: "GET", path: "/files/../etc/passwd", headers: {} })
				.allowed,
		).toBe(false);
		expect(
			bh.check({ method: "GET", path: "/files/report.pdf", headers: {} })
				.allowed,
		).toBe(true);
	});

	it("rejects parameter pollution (duplicate query keys, but allows `[]`)", () => {
		const bh = createBlackhole({ csrf: false });
		expect(
			bh.check({ method: "GET", path: "/", query: "a=1&a=2", headers: {} })
				.allowed,
		).toBe(false);
		expect(
			bh.check({ method: "GET", path: "/", query: "t[]=1&t[]=2", headers: {} })
				.allowed,
		).toBe(true);
	});

	it("sanitizes HTML response", () => {
		const bh = createBlackhole({ secret: SECRET });
		const result = bh.sanitizeResponse(
			"<p>Hello</p><script>alert(1)</script>",
			"text/html",
		);
		expect(result).not.toContain("<script>");
		expect(result).toContain("<p>Hello</p>");
	});

	it("does NOT sanitize JSON response", () => {
		const bh = createBlackhole({ secret: SECRET });
		const json = '{"name": "O\'Brien", "query": "a > b"}';
		expect(bh.sanitizeResponse(json, "application/json")).toBe(json);
	});

	it("does NOT sanitize a text/plain response (robots.txt served verbatim)", () => {
		// text/plain is never parsed as HTML (nosniff), so escaping it would only
		// corrupt the body. Newlines/slashes/spaces must reach the client as-is.
		const bh = createBlackhole({ secret: SECRET });
		const robots = "User-agent: *\nDisallow: /\n";
		expect(bh.sanitizeResponse(robots, "text/plain; charset=utf-8")).toBe(
			robots,
		);
	});

	it("computes security headers (Helmet-style)", () => {
		const h = createBlackhole({ secret: SECRET }).securityHeaders();
		expect(h["x-content-type-options"]).toBe("nosniff");
		expect(h["x-frame-options"]).toBe("SAMEORIGIN");
		// Hardened baseline: base-uri/form-action/object-src don't fall back to default-src.
		expect(h["content-security-policy"]).toBe(
			"default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'",
		);
		expect(
			createBlackhole({
				securityHeaders: false,
				secret: SECRET,
			}).securityHeaders(),
		).toEqual({});
	});

	it("CSP @nonce: substitutes per-request nonce (AdonisJS idiom)", () => {
		const bh = createBlackhole({
			securityHeaders: { csp: "default-src 'self'; script-src 'self' @nonce" },
			secret: SECRET,
		});
		expect(bh.cspHasNonce()).toBe(true);
		const nonce = bh.generateNonce();
		expect(nonce.length).toBeGreaterThan(0);
		const csp = bh.securityHeaders(nonce)["content-security-policy"];
		expect(csp).toContain(`'nonce-${nonce}'`);
		expect(csp).not.toContain("@nonce");
		// No nonce supplied → token is dropped, not left dangling.
		expect(bh.securityHeaders()["content-security-policy"]).not.toContain(
			"@nonce",
		);
		// A static CSP (no @nonce) reports cspHasNonce=false.
		expect(createBlackhole({ secret: SECRET }).cspHasNonce()).toBe(false);
	});

	it("CORS: allows a configured origin + answers preflight", () => {
		const bh = createBlackhole({
			cors: { origin: ["https://app.test"], credentials: true },
			secret: SECRET,
		});
		const ok = bh.cors("https://app.test", "GET");
		expect(ok?.headers["access-control-allow-origin"]).toBe("https://app.test");
		expect(ok?.headers["access-control-allow-credentials"]).toBe("true");
		expect(ok?.varyOrigin).toBe(true);

		const denied = bh.cors("https://evil.test", "GET");
		expect(denied?.headers["access-control-allow-origin"]).toBeUndefined();

		const preflight = bh.cors("https://app.test", "OPTIONS", "GET");
		expect(preflight?.preflight).toBe(true);
		expect(preflight?.headers["access-control-allow-methods"]).toContain(
			"POST",
		);

		// Audit 2026-06-13: only a genuine preflight short-circuits — a plain
		// OPTIONS (no Access-Control-Request-Method) or a disallowed origin must
		// not, so app OPTIONS routes stay reachable and disallowed origins aren't
		// answered with a bare 204.
		expect(bh.cors("https://app.test", "OPTIONS")?.preflight).toBe(false);
		expect(bh.cors("https://evil.test", "OPTIONS", "GET")?.preflight).toBe(
			false,
		);
	});

	it("defineConfig is re-exported from the package root", () => {
		expect(typeof defineConfig).toBe("function");
		expect(defineConfig({ csrf: true })).toEqual({ csrf: true });
	});

	it("CORS: undefined when not configured; throws on credentials + wildcard", () => {
		expect(
			createBlackhole({ secret: SECRET }).cors("https://x.test", "GET"),
		).toBeUndefined();
		expect(() =>
			createBlackhole({
				cors: { origin: "*", credentials: true },
				secret: SECRET,
			}),
		).toThrow();
	});
});
