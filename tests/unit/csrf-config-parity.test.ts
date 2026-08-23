/**
 * The CSRF options AdonisJS's shield exposes: turning the readable XSRF cookie
 * off, exempting routes by predicate, and `cookieOptions` as the config key.
 */
import { describe, expect, it } from "vitest";
import { runRequestPhase } from "../../src/core.js";
import { createBlackhole } from "../../src/index.js";

const request = (path = "/posts", method = "POST") => ({
	method,
	path,
	url: path,
	headers: {} as Record<string, string>,
	body: "",
	remoteAddr: "127.0.0.1",
});

describe("blackhole > enableXsrfCookie", () => {
	it("seeds the readable cookie by default", () => {
		const bh = createBlackhole({ secret: "x".repeat(32) });
		const outcome = runRequestPhase(bh, request("/", "GET"));
		expect(outcome.kind).toBe("pass");
		if (outcome.kind !== "pass") return;
		expect(outcome.setCookie?.name).toBe("XSRF-TOKEN");
	});

	it("does not seed it when the app turned it off", () => {
		// An all-SSR app sends the token in the `_csrf` field; not setting a
		// cookie is one less thing to leak.
		const bh = createBlackhole({
			secret: "x".repeat(32),
			csrf: { enableXsrfCookie: false },
		});
		const outcome = runRequestPhase(bh, request("/", "GET"));
		if (outcome.kind !== "pass") throw new Error("expected pass");
		expect(outcome.setCookie).toBeUndefined();
		// The token is still available for the form field.
		expect(outcome.csrfToken).toBeTruthy();
	});
});

describe("blackhole > exceptRoutes as a predicate", () => {
	it("exempts what the predicate says", () => {
		const bh = createBlackhole({
			secret: "x".repeat(32),
			csrf: { exceptRoutes: (req) => req.path.startsWith("/webhooks/") },
		});
		const exempt = runRequestPhase(bh, request("/webhooks/stripe"));
		expect(exempt.kind).toBe("pass");
		if (exempt.kind !== "pass") return;
		expect(exempt.csrfProtected).toBe(false);
	});

	it("still guards everything else", () => {
		const bh = createBlackhole({
			secret: "x".repeat(32),
			csrf: { exceptRoutes: (req) => req.path.startsWith("/webhooks/") },
		});
		// A POST with no token, on a guarded path, is rejected.
		expect(runRequestPhase(bh, request("/posts")).kind).toBe("reject");
	});

	it("keeps the array form working", () => {
		const bh = createBlackhole({
			secret: "x".repeat(32),
			csrf: { exceptRoutes: ["/webhooks/*"] },
		});
		expect(runRequestPhase(bh, request("/webhooks/stripe")).kind).toBe("pass");
	});
});

describe("blackhole > cookieOptions", () => {
	it("accepts the AdonisJS key as well as ours", () => {
		const adonis = createBlackhole({
			secret: "x".repeat(32),
			csrf: { cookieOptions: { sameSite: "strict" } },
		});
		expect(adonis.csrfCookie().options.sameSite).toBe("strict");

		const ours = createBlackhole({
			secret: "x".repeat(32),
			csrf: { cookie: { sameSite: "none", secure: true } },
		});
		expect(ours.csrfCookie().options.sameSite).toBe("none");
	});
});
