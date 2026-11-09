/**
 * The two halves of the CSRF check: where the request comes from (Origin /
 * Referer against the host the request was addressed to) and whose token it
 * carries (bound to the session that was issued it).
 */
import { describe, expect, it } from "vitest";
import { createBlackhole } from "../../src/index.js";
import { blackholeMiddleware } from "../../src/middleware.js";
import { ADAPTERS, viaAdapter } from "./support/adapters.js";
import { FakeSession, reamContext, runRoute } from "./support/ream.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";
const OPTIONS = { csrf: true, secret: SECRET };
const TOKEN = createBlackhole(OPTIONS).generateCsrfToken();

/** A POST carrying a valid token pair, behind a proxy that rewrote `Host`. */
function proxiedPost(resolvedHost?: string) {
	return {
		method: "POST",
		target: "/orders",
		protocol: "https",
		resolvedHost,
		headers: {
			host: "upstream:3000",
			"x-forwarded-host": "app.example",
			origin: "https://app.example",
			cookie: `XSRF-TOKEN=${TOKEN}`,
			"x-xsrf-token": TOKEN,
		},
	};
}

describe("blackhole > the Origin is compared with the resolved host", () => {
	for (const adapter of ADAPTERS) {
		it(`accepts a same-origin POST behind a proxy on ${adapter}`, async () => {
			const res = await viaAdapter(
				adapter,
				OPTIONS,
				proxiedPost("app.example"),
			);
			expect(res.routeRan).toBe(true);
		});

		it(`still refuses another origin on ${adapter}`, async () => {
			const req = proxiedPost("app.example");
			const res = await viaAdapter(adapter, OPTIONS, {
				...req,
				headers: { ...req.headers, origin: "https://evil.example" },
			});
			expect(res.status).toBe(403);
			expect(res.routeRan).toBe(false);
		});
	}

	it("falls back to the Host header when the host resolved none", async () => {
		const res = await viaAdapter("ream", OPTIONS, proxiedPost(undefined));
		// `request.host()` answered the raw `upstream:3000`: not the Origin's.
		expect(res.status).toBe(403);
	});
});

describe("blackhole > an empty Origin is no Origin", () => {
	it("checks the Referer behind it", () => {
		const bh = createBlackhole(OPTIONS);
		const result = bh.check({
			method: "POST",
			path: "/orders",
			headers: {
				host: "app.example",
				origin: "",
				referer: "https://evil.example/page",
				cookie: `XSRF-TOKEN=${TOKEN}`,
				"x-xsrf-token": TOKEN,
			},
		});
		expect(result.allowed).toBe(false);
		expect(result.body).toContain("E_BLACKHOLE_CSRF_ORIGIN_MISMATCH");
	});
});

describe("blackhole > CSRF tokens are bound to the session", () => {
	const bh = createBlackhole(OPTIONS);

	async function issue(session: FakeSession): Promise<string> {
		const built = reamContext({ bh, session });
		const spy = await runRoute(blackholeMiddleware, built);
		const token = spy.cookies["XSRF-TOKEN"];
		if (token === undefined) throw new Error("no token was issued");
		return token;
	}

	async function post(session: FakeSession, token: string) {
		return runRoute(
			blackholeMiddleware,
			reamContext({
				bh,
				session,
				method: "POST",
				path: "/orders",
				headers: {
					cookie: `XSRF-TOKEN=${token}`,
					"x-xsrf-token": token,
					accept: "application/json",
				},
			}),
		);
	}

	it("keeps a per-session secret and accepts the session's own token", async () => {
		const session = new FakeSession();
		const token = await issue(session);
		expect(typeof session.get("csrf-secret")).toBe("string");
		const spy = await post(session, token);
		expect(spy.nextCalled).toBe(true);
	});

	it("refuses a token issued to another session", async () => {
		const token = await issue(new FakeSession());
		const spy = await post(new FakeSession(), token);
		expect(spy.status).toBe(403);
		expect(spy.json).toMatchObject({ error: { code: "E_BAD_CSRF_TOKEN" } });
		expect(spy.nextCalled).toBe(false);
	});

	it("refuses a token bound to no session", async () => {
		const spy = await post(new FakeSession(), TOKEN);
		expect(spy.status).toBe(403);
	});

	it("reissues the cookie when it belongs to another session", async () => {
		const foreign = await issue(new FakeSession());
		const spy = await runRoute(
			blackholeMiddleware,
			reamContext({
				bh,
				session: new FakeSession(),
				headers: { cookie: `XSRF-TOKEN=${foreign}` },
			}),
		);
		const fresh = spy.cookies["XSRF-TOKEN"];
		expect(fresh).toBeDefined();
		expect(fresh).not.toBe(foreign);
	});

	it("keeps the stateless token where there is no session", async () => {
		const built = reamContext({
			bh,
			method: "POST",
			path: "/orders",
			headers: { cookie: `XSRF-TOKEN=${TOKEN}`, "x-xsrf-token": TOKEN },
		});
		const spy = await runRoute(blackholeMiddleware, built);
		expect(spy.nextCalled).toBe(true);
	});
});
