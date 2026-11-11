/**
 * The two halves of the CSRF check: where the request comes from (Origin /
 * Referer against the host the request was addressed to) and whose token it
 * carries (bound to the session that was issued it).
 */
import { ConfigStore } from "@c9up/ream";
import { describe, expect, it } from "vitest";
import BlackholeProvider, {
	BLACKHOLE_KEY,
} from "../../src/BlackholeProvider.js";
import { type Blackhole, createBlackhole } from "../../src/index.js";
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

describe("blackhole > the session's CSRF secret turns over with the session id", () => {
	const bh = createBlackhole(OPTIONS);

	/** A GET whose handler runs `handler` — a login or a logout. */
	async function visit(
		session: FakeSession,
		handler: (session: FakeSession) => void = () => {},
		cookie?: string,
	) {
		const built = reamContext({
			bh,
			session,
			headers: cookie === undefined ? {} : { cookie: `XSRF-TOKEN=${cookie}` },
		});
		return runRoute(blackholeMiddleware, built, () => handler(session));
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

	function cookieOf(spy: { cookies: Record<string, string> }): string {
		const token = spy.cookies["XSRF-TOKEN"];
		if (token === undefined) throw new Error("no token was issued");
		return token;
	}

	it("refuses the pre-login token after a login regenerates the session, and hands out a new one", async () => {
		const session = new FakeSession();
		const anonymous = cookieOf(await visit(session));
		const secretBefore = session.get("csrf-secret");

		const login = await visit(session, (s) => s.regenerate(), anonymous);
		const afterLogin = cookieOf(login);

		expect(afterLogin).not.toBe(anonymous);
		expect(session.get("csrf-secret")).not.toBe(secretBefore);
		expect((await post(session, anonymous)).status).toBe(403);
		expect((await post(session, afterLogin)).nextCalled).toBe(true);
	});

	it("refuses the logged-in token after a logout regenerates the session again", async () => {
		const session = new FakeSession();
		const anonymous = cookieOf(await visit(session));
		const loggedIn = cookieOf(
			await visit(session, (s) => s.regenerate(), anonymous),
		);

		const afterLogout = cookieOf(
			await visit(session, (s) => s.regenerate(), loggedIn),
		);

		expect((await post(session, loggedIn)).status).toBe(403);
		expect((await post(session, afterLogout)).nextCalled).toBe(true);
	});

	it("keeps the secret while the session id does not change", async () => {
		const session = new FakeSession();
		const first = cookieOf(await visit(session));
		const secret = session.get("csrf-secret");
		const second = await visit(session, () => {}, first);
		expect(session.get("csrf-secret")).toBe(secret);
		expect(second.cookies["XSRF-TOKEN"]).toBeUndefined();
		expect((await post(session, first)).nextCalled).toBe(true);
	});
});

describe("blackhole > a session-bound app refuses to run without its session", () => {
	const bound = createBlackhole({
		csrf: { session: true },
		secret: SECRET,
	});

	it("throws E_BLACKHOLE_SESSION_NOT_READY instead of minting unbound tokens", async () => {
		const built = reamContext({ bh: bound });
		await expect(runRoute(blackholeMiddleware, built)).rejects.toMatchObject({
			code: "E_BLACKHOLE_SESSION_NOT_READY",
			status: 500,
		});
		expect(built.spy.nextCalled).toBe(false);
		expect(built.spy.cookies["XSRF-TOKEN"]).toBeUndefined();
	});

	it("refuses a POST carrying an unbound token the same way", async () => {
		const built = reamContext({
			bh: bound,
			method: "POST",
			path: "/orders",
			headers: { cookie: `XSRF-TOKEN=${TOKEN}`, "x-xsrf-token": TOKEN },
		});
		await expect(runRoute(blackholeMiddleware, built)).rejects.toThrow(
			/session/,
		);
		expect(built.spy.nextCalled).toBe(false);
	});

	it("binds to the session when one is there", async () => {
		const session = new FakeSession();
		const spy = await runRoute(
			blackholeMiddleware,
			reamContext({ bh: bound, session }),
		);
		expect(spy.nextCalled).toBe(true);
		expect(typeof session.get("csrf-secret")).toBe("string");
	});

	it("fails closed on hono, which answers the error as a 500", async () => {
		const res = await viaAdapter(
			"hono",
			{ csrf: { session: true }, secret: SECRET },
			{ target: "/" },
		);
		expect(res.status).toBe(500);
		expect(res.routeRan).toBe(false);
	});

	for (const adapter of ["express", "fastify"] as const) {
		it(`fails closed on ${adapter}, which has no session to bind to`, async () => {
			await expect(
				viaAdapter(
					adapter,
					{ csrf: { session: true }, secret: SECRET },
					{ target: "/" },
				),
			).rejects.toMatchObject({ code: "E_BLACKHOLE_SESSION_NOT_READY" });
		});
	}

	it("needs no session when CSRF is off", async () => {
		const off = createBlackhole({ csrf: { enabled: false, session: true } });
		const spy = await runRoute(blackholeMiddleware, reamContext({ bh: off }));
		expect(spy.nextCalled).toBe(true);
	});
});

describe("blackhole > the provider binds CSRF to the session the app configured", () => {
	function providerBlackhole(entries: Record<string, unknown>): Blackhole {
		const config = new ConfigStore();
		for (const [key, value] of Object.entries(entries)) config.set(key, value);
		const bindings = new Map<unknown, () => unknown>();
		new BlackholeProvider({
			container: {
				singleton(token, factory) {
					bindings.set(token, factory);
				},
			},
			config,
		}).register();
		const built = bindings.get(BLACKHOLE_KEY)?.();
		if (!isBlackhole(built)) throw new Error("no Blackhole was registered");
		return built;
	}

	function isBlackhole(value: unknown): value is Blackhole {
		return typeof value === "object" && value !== null && "check" in value;
	}

	it("requires the session when config/session exists", async () => {
		const bh = providerBlackhole({
			blackhole: { secret: SECRET },
			session: { driver: "memory" },
		});
		expect(bh.csrfSessionRequired()).toBe(true);
		await expect(
			runRoute(blackholeMiddleware, reamContext({ bh })),
		).rejects.toMatchObject({ code: "E_BLACKHOLE_SESSION_NOT_READY" });
	});

	it("keeps the boolean shorthand's switch while adding the session", () => {
		const bh = providerBlackhole({
			blackhole: { secret: SECRET, csrf: true },
			session: { driver: "cookie" },
		});
		expect(bh.csrfSessionRequired()).toBe(true);
	});

	it("does not require one when the app has no session config", () => {
		const bh = providerBlackhole({ blackhole: { secret: SECRET } });
		expect(bh.csrfSessionRequired()).toBe(false);
	});

	it("lets the app say otherwise explicitly", () => {
		const bh = providerBlackhole({
			blackhole: { secret: SECRET, csrf: { session: false } },
			session: { driver: "memory" },
		});
		expect(bh.csrfSessionRequired()).toBe(false);
	});

	it("does not require one when CSRF is off", () => {
		const bh = providerBlackhole({
			blackhole: { csrf: false },
			session: { driver: "memory" },
		});
		expect(bh.csrfSessionRequired()).toBe(false);
	});
});
