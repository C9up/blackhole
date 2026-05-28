import { describe, expect, it } from "vitest";
import { createBlackhole } from "../../src/index.js";

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
		const bh = createBlackhole({ csrf: true });
		const result = bh.check({
			method: "POST",
			path: "/api/orders",
			headers: {},
		});
		expect(result.allowed).toBe(false);
		expect(result.status).toBe(403);
	});

	it("allows POST with valid CSRF token", () => {
		const bh = createBlackhole({ csrf: true });
		const token = bh.generateCsrfToken();
		const result = bh.check({
			method: "POST",
			path: "/api/orders",
			headers: { "x-csrf-token": token },
		});
		expect(result.allowed).toBe(true);
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

	it("sanitizes HTML response", () => {
		const bh = createBlackhole();
		const result = bh.sanitizeResponse(
			"<p>Hello</p><script>alert(1)</script>",
			"text/html",
		);
		expect(result).not.toContain("<script>");
		expect(result).toContain("<p>Hello</p>");
	});

	it("does NOT sanitize JSON response", () => {
		const bh = createBlackhole();
		const json = '{"name": "O\'Brien", "query": "a > b"}';
		expect(bh.sanitizeResponse(json, "application/json")).toBe(json);
	});
});
