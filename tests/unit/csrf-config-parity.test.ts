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

describe("blackhole > an exempt route still seeds the cookie", () => {
	const bh = () =>
		createBlackhole({
			secret: "x".repeat(32),
			csrf: { exceptRoutes: ["/login"] },
		});

	it("seeds it on a route excluded from verification", () => {
		// Exemption skips verification, not the cookie. A login page excluded
		// from CSRF that hands out a token without persisting it leaves the
		// POST that follows with nothing to double-submit against.
		const outcome = runRequestPhase(bh(), request("/login", "GET"));

		if (outcome.kind !== "pass") throw new Error("expected pass");
		expect(outcome.csrfProtected).toBe(false);
		expect(outcome.setCookie?.name).toBe("XSRF-TOKEN");
		expect(outcome.setCookie?.value).toBe(outcome.csrfToken);
	});

	it("does not re-issue one the client already holds", () => {
		const token = createBlackhole({
			secret: "x".repeat(32),
		}).generateCsrfToken();
		const req = request("/login", "GET");
		req.headers.cookie = `XSRF-TOKEN=${token}`;

		const outcome = runRequestPhase(bh(), req);

		if (outcome.kind !== "pass") throw new Error("expected pass");
		expect(outcome.setCookie).toBeUndefined();
		expect(outcome.csrfToken).toBe(token);
	});

	it("respects an app that turned the readable cookie off", () => {
		const outcome = runRequestPhase(
			createBlackhole({
				secret: "x".repeat(32),
				csrf: { exceptRoutes: ["/login"], enableXsrfCookie: false },
			}),
			request("/login", "GET"),
		);

		if (outcome.kind !== "pass") throw new Error("expected pass");
		expect(outcome.setCookie).toBeUndefined();
	});
});

describe("blackhole > a cookie that no longer verifies is reissued", () => {
	const bh = () => createBlackhole({ secret: "x".repeat(32) });

	it("keeps a token that still verifies", () => {
		const token = bh().generateCsrfToken();
		const req = request("/", "GET");
		req.headers.cookie = `XSRF-TOKEN=${token}`;

		const outcome = runRequestPhase(bh(), req);

		if (outcome.kind !== "pass") throw new Error("expected pass");
		expect(outcome.csrfToken).toBe(token);
		expect(outcome.setCookie).toBeUndefined();
	});

	it("replaces one that was mangled in transit", () => {
		// Truncated by a proxy, or signed under a key since rotated. Handing it
		// back leaves the client submitting a token the server refuses on every
		// form, with no way out but clearing cookies by hand.
		const req = request("/", "GET");
		req.headers.cookie = "XSRF-TOKEN=abcdef.notasignature";

		const outcome = runRequestPhase(bh(), req);

		if (outcome.kind !== "pass") throw new Error("expected pass");
		expect(outcome.csrfToken).not.toBe("abcdef.notasignature");
		expect(outcome.setCookie?.value).toBe(outcome.csrfToken);
	});

	it("replaces one signed under a different secret", () => {
		const foreign = createBlackhole({
			secret: "y".repeat(32),
		}).generateCsrfToken();
		const req = request("/", "GET");
		req.headers.cookie = `XSRF-TOKEN=${foreign}`;

		const outcome = runRequestPhase(bh(), req);

		if (outcome.kind !== "pass") throw new Error("expected pass");
		expect(outcome.csrfToken).not.toBe(foreign);
		expect(outcome.setCookie).toBeDefined();
	});

	it("replaces a structurally broken one", () => {
		for (const value of ["", "nodot", ".onlysig", "onlyrandom."]) {
			const req = request("/", "GET");
			req.headers.cookie = `XSRF-TOKEN=${value}`;

			const outcome = runRequestPhase(bh(), req);

			if (outcome.kind !== "pass") throw new Error("expected pass");
			expect(outcome.csrfToken, value).not.toBe(value);
		}
	});

	it("does the same on an exempt route", () => {
		const guard = createBlackhole({
			secret: "x".repeat(32),
			csrf: { exceptRoutes: ["/login"] },
		});
		const req = request("/login", "GET");
		req.headers.cookie = "XSRF-TOKEN=abcdef.notasignature";

		const outcome = runRequestPhase(guard, req);

		if (outcome.kind !== "pass") throw new Error("expected pass");
		expect(outcome.setCookie?.value).toBe(outcome.csrfToken);
	});
});

describe("blackhole > the CSRF secret has to be a real one", () => {
	it("refuses the placeholder the scaffolding used to write", () => {
		// A token signed with a value printed in a README can be forged by
		// anyone who has read it — the same as not signing, but claiming to.
		expect(() =>
			createBlackhole({
				csrf: true,
				secret: "change-me-to-a-unique-32+-byte-secret!!",
			}),
		).toThrow(/placeholder/);
	});

	it("refuses it whatever case or padding it arrives in", () => {
		expect(() =>
			createBlackhole({
				csrf: true,
				secret: "  CHANGE-ME-TO-A-UNIQUE-32+-BYTE-SECRET!!  ",
			}),
		).toThrow(/placeholder/);
	});

	it("refuses one too short to sign with", () => {
		expect(() => createBlackhole({ csrf: true, secret: "short" })).toThrow(
			/too short to sign with/,
		);
	});

	it("still refuses an absent secret", () => {
		expect(() => createBlackhole({ csrf: true })).toThrow(/no `secret`/);
	});

	it("accepts a real one", () => {
		expect(() =>
			createBlackhole({ csrf: true, secret: "x".repeat(32) }),
		).not.toThrow();
	});

	it("says nothing when CSRF is off — there is no token to sign", () => {
		expect(() =>
			createBlackhole({ csrf: false, secret: "change-me" }),
		).not.toThrow();
	});
});
