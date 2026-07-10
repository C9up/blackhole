import { describe, expect, it } from "vitest";
import { createBlackhole } from "../../src/index.js";

/** Signed double-submit needs a secret whenever CSRF is enabled. */
const SECRET = "test-app-key-32-bytes-long-aaaaaa";

/**
 * `csrfEnforced` is the trustworthy "the token was validated for THIS request"
 * signal (story 57.6) — the anti-fail-open proof. A token is *seeded* on every
 * passing request (even GET / csrf:false / excepted routes), so token-presence
 * lies; `csrfEnforced` must be `true` ONLY when CSRF was enabled, the method
 * guarded, the route not excepted, AND the double-submit validated.
 */
describe("blackhole csrfEnforced (fail-close signal)", () => {
	const guardedMethods = ["POST", "PUT", "PATCH", "DELETE"] as const;

	for (const method of guardedMethods) {
		it(`is true for a passing guarded ${method} (enabled, non-excepted, validated)`, () => {
			const bh = createBlackhole({ csrf: true, secret: SECRET });
			const token = bh.generateCsrfToken();
			const result = bh.check({
				method,
				path: "/admin/posts",
				headers: { "x-xsrf-token": token, cookie: `XSRF-TOKEN=${token}` },
			});
			expect(result.allowed).toBe(true);
			expect(result.csrfEnforced).toBe(true);
		});
	}

	it("is false for a non-guarded GET (allowed, but never CSRF-verified)", () => {
		const bh = createBlackhole({ csrf: true, secret: SECRET });
		const result = bh.check({
			method: "GET",
			path: "/admin/posts",
			headers: {},
		});
		expect(result.allowed).toBe(true);
		expect(result.csrfEnforced).toBe(false);
	});

	it("is false for a non-guarded HEAD (allowed, but never CSRF-verified)", () => {
		const bh = createBlackhole({ csrf: true, secret: SECRET });
		const result = bh.check({
			method: "HEAD",
			path: "/admin/posts",
			headers: {},
		});
		expect(result.allowed).toBe(true);
		expect(result.csrfEnforced).toBe(false);
	});

	it("is false when CSRF is disabled — a token may still be seeded, verification is skipped", () => {
		const bh = createBlackhole({ csrf: false });
		const result = bh.check({
			method: "POST",
			path: "/admin/posts",
			headers: {},
		});
		expect(result.allowed).toBe(true);
		expect(result.csrfEnforced).toBe(false);
	});

	it("is false for an exceptRoutes-matched path (CSRF verification bypassed)", () => {
		const bh = createBlackhole({
			csrf: { exceptRoutes: ["/admin/webhooks/*"] },
			secret: SECRET,
		});
		const result = bh.check({
			method: "POST",
			path: "/admin/webhooks/stripe",
			headers: {},
		});
		expect(result.allowed).toBe(true);
		expect(result.csrfEnforced).toBe(false);
	});

	it("is false on a rejected request (never reached the handler)", () => {
		const bh = createBlackhole({ csrf: true, secret: SECRET });
		const result = bh.check({
			method: "POST",
			path: "/admin/posts",
			headers: {},
		});
		expect(result.allowed).toBe(false);
		expect(result.csrfEnforced).toBe(false);
	});
});
