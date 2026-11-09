/**
 * Config written for a framework with routes, contexts and translations:
 * CSRF exemptions by route pattern, the CORS options and their callbacks, the
 * CSRF rejection message and Inertia visits, and a route's own protective
 * headers.
 */
import { describe, expect, it } from "vitest";
import {
	type BlackholeContext,
	type CorsConfig,
	createBlackhole,
} from "../../src/index.js";
import { blackholeMiddleware } from "../../src/middleware.js";
import { ADAPTERS, type AdapterName, viaAdapter } from "./support/adapters.js";
import { FakeSession, reamContext, runRoute } from "./support/ream.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";

describe("blackhole > csrf.exceptRoutes", () => {
	const options = {
		secret: SECRET,
		csrf: { exceptRoutes: ["/webhooks/:provider"] },
	};

	// The adapters whose framework has matched a route by then.
	const routed: AdapterName[] = ["ream", "fastify"];
	for (const adapter of routed) {
		it(`matches the route pattern on ${adapter}`, async () => {
			const res = await viaAdapter(adapter, options, {
				method: "POST",
				target: "/webhooks/stripe",
				routePattern: "/webhooks/:provider",
			});
			expect(res.routeRan).toBe(true);
		});

		it(`still guards another route on ${adapter}`, async () => {
			const res = await viaAdapter(adapter, options, {
				method: "POST",
				target: "/orders",
				routePattern: "/orders",
			});
			expect(res.status).toBe(403);
		});
	}

	it("hands the predicate the HTTP context under Ream", async () => {
		const seen: BlackholeContext[] = [];
		const bh = createBlackhole({
			secret: SECRET,
			csrf: {
				exceptRoutes: (ctx) => {
					seen.push(ctx);
					return ctx.route?.pattern === "/hooks/:id";
				},
			},
		});
		const built = reamContext({
			bh,
			method: "POST",
			path: "/hooks/1",
			route: { pattern: "/hooks/:id" },
		});
		const spy = await runRoute(blackholeMiddleware, built);
		expect(spy.nextCalled).toBe(true);
		expect(seen[0]).toBe(built.ctx);
	});

	for (const adapter of ADAPTERS) {
		it(`keeps the path prefix form on ${adapter}`, async () => {
			const res = await viaAdapter(
				adapter,
				{ secret: SECRET, csrf: { exceptRoutes: ["/webhooks/*"] } },
				{ method: "POST", target: "/webhooks/stripe" },
			);
			expect(res.routeRan).toBe(true);
		});
	}
});

function corsOf(
	cors: CorsConfig,
	origin: string,
	extra: {
		method?: string;
		requestMethod?: string;
		requestHeaders?: string;
	} = {},
) {
	return createBlackhole({ csrf: false, cors }).cors(
		origin,
		extra.method ?? "GET",
		extra.requestMethod,
		extra.requestHeaders,
	);
}

describe("blackhole > CORS options", () => {
	it("reads exposeHeaders", () => {
		const result = corsOf(
			{ origin: ["https://a.example"], exposeHeaders: ["X-Total"] },
			"https://a.example",
		);
		expect(result?.headers["access-control-expose-headers"]).toBe("x-total");
	});

	it("still reads exposedHeaders", () => {
		const result = corsOf(
			{ origin: ["https://a.example"], exposedHeaders: ["X-Total"] },
			"https://a.example",
		);
		expect(result?.headers["access-control-expose-headers"]).toBe("x-total");
	});

	it("leaves out headers the browser exposes anyway", () => {
		const result = corsOf(
			{ origin: ["https://a.example"], exposeHeaders: ["Content-Type"] },
			"https://a.example",
		);
		expect(result?.headers["access-control-expose-headers"]).toBeUndefined();
	});

	it("reflects the origin for origin: true, and varies on it", () => {
		const result = corsOf({ origin: true }, "https://a.example");
		expect(result?.headers["access-control-allow-origin"]).toBe(
			"https://a.example",
		);
		expect(result?.varyOrigin).toBe(true);
	});

	it("answers the literal wildcard for origin: '*'", () => {
		const result = corsOf({ origin: "*" }, "https://a.example");
		expect(result?.headers["access-control-allow-origin"]).toBe("*");
		expect(result?.varyOrigin).toBe(false);
	});

	it("still refuses true or '*' with credentials", () => {
		expect(() => corsOf({ origin: true, credentials: true }, "x")).toThrow(
			/cannot be combined with credentials/,
		);
	});

	it("passes the context to an origin callback and reads what it returns", () => {
		const seen: string[] = [];
		const cors: CorsConfig = {
			origin: (origin, ctx) => {
				seen.push(ctx.request.url());
				return origin.endsWith(".example") ? ["https://b.example"] : false;
			},
		};
		const bh = createBlackhole({ csrf: false, cors });
		const ctx: BlackholeContext = {
			request: {
				method: () => "GET",
				url: () => "/api",
				header: () => undefined,
			},
		};
		expect(
			bh.cors("https://b.example", "GET", undefined, undefined, ctx)?.headers[
				"access-control-allow-origin"
			],
		).toBe("https://b.example");
		expect(
			bh.cors("https://c.example", "GET", undefined, undefined, ctx)?.headers[
				"access-control-allow-origin"
			],
		).toBeUndefined();
		expect(seen).toEqual(["/api", "/api"]);
	});

	it("turns CORS off with enabled: false or a callback", () => {
		expect(corsOf({ origin: true, enabled: false }, "https://a.example")).toBe(
			undefined,
		);
		const byPath: CorsConfig = {
			origin: true,
			enabled: (ctx) => ctx.request.url().startsWith("/api"),
		};
		const bh = createBlackhole({ csrf: false, cors: byPath });
		const at = (url: string): BlackholeContext => ({
			request: { method: () => "GET", url: () => url, header: () => undefined },
		});
		expect(
			bh.cors("https://a.example", "GET", undefined, undefined, at("/api/x")),
		).toBeDefined();
		expect(
			bh.cors("https://a.example", "GET", undefined, undefined, at("/page")),
		).toBeUndefined();
	});

	it("takes headers as false, a string or a callback", () => {
		const preflight = (headers: CorsConfig["headers"], requested: string) =>
			corsOf({ origin: true, headers }, "https://a.example", {
				method: "OPTIONS",
				requestMethod: "POST",
				requestHeaders: requested,
			})?.headers["access-control-allow-headers"];
		expect(preflight(false, "x-custom")).toBeUndefined();
		expect(preflight("X-Custom, X-Other", "x-custom")).toBe(
			"X-Custom, X-Other",
		);
		expect(preflight("X-Custom", "x-forbidden")).toBeUndefined();
		expect(preflight((requested) => requested, "x-a, x-b")).toBe("x-a, x-b");
	});

	it("refuses an unknown option instead of dropping it", () => {
		const cors = { origin: true, exposeHeader: ["X-Total"] };
		expect(() => createBlackhole({ csrf: false, cors })).toThrow(
			/unknown option "exposeHeader"/,
		);
	});
});

describe("blackhole > CSRF rejection message and Inertia", () => {
	const bh = createBlackhole({ secret: SECRET, csrf: true });

	it("translates the message through ctx.i18n", async () => {
		const spy = await runRoute(
			blackholeMiddleware,
			reamContext({
				bh,
				method: "POST",
				path: "/orders",
				headers: { accept: "application/json" },
				i18n: {
					t: (key, _data, fallback) =>
						key === "errors.E_BAD_CSRF_TOKEN"
							? "Jeton CSRF invalide"
							: fallback,
				},
			}),
		);
		expect(spy.status).toBe(403);
		expect(spy.json).toEqual({
			error: { code: "E_BAD_CSRF_TOKEN", message: "Jeton CSRF invalide" },
		});
	});

	it("flashes the translated message on the redirect", async () => {
		const session = new FakeSession();
		const spy = await runRoute(
			blackholeMiddleware,
			reamContext({
				bh,
				session,
				method: "POST",
				path: "/orders",
				headers: { accept: "text/html" },
				i18n: { t: () => "Jeton CSRF invalide" },
			}),
		);
		expect(spy.redirectedBack).toBe(true);
		expect(session.flashes).toContainEqual([
			"flash",
			"error",
			"Jeton CSRF invalide",
		]);
	});

	it("redirects an Inertia visit back without re-flashing the form", async () => {
		const session = new FakeSession();
		const spy = await runRoute(
			blackholeMiddleware,
			reamContext({
				bh,
				session,
				method: "POST",
				path: "/orders",
				headers: {
					"x-inertia": "true",
					accept: "text/html, application/xhtml+xml",
				},
			}),
		);
		expect(spy.redirectedBack).toBe(true);
		expect(spy.json).toBeUndefined();
		expect(session.flashes.map(([kind]) => kind)).toEqual([
			"flash",
			"flashErrors",
		]);
	});

	it("redirects an Inertia visit even when it asks for JSON", async () => {
		const spy = await runRoute(
			blackholeMiddleware,
			reamContext({
				bh,
				session: new FakeSession(),
				method: "POST",
				path: "/orders",
				headers: { "x-inertia": "true", accept: "application/json" },
			}),
		);
		expect(spy.redirectedBack).toBe(true);
	});
});

describe("blackhole > a route sets its own protective headers", () => {
	for (const adapter of ADAPTERS) {
		it(`keeps the route's X-Frame-Options and CSP on ${adapter}`, async () => {
			const res = await viaAdapter(
				adapter,
				{ csrf: false },
				{
					target: "/embed",
					routeHeaders: {
						"X-Frame-Options": "DENY",
						"Content-Security-Policy":
							"default-src 'none'; frame-ancestors https://partner.example",
					},
				},
			);
			expect(res.headers["x-frame-options"]).toBe("DENY");
			expect(res.headers["content-security-policy"]).toBe(
				"default-src 'none'; frame-ancestors https://partner.example",
			);
		});

		it(`still sets the headers a route left alone on ${adapter}`, async () => {
			const res = await viaAdapter(
				adapter,
				{ csrf: false },
				{ target: "/page" },
			);
			expect(res.headers["x-frame-options"]).toBe("SAMEORIGIN");
			expect(res.headers["x-content-type-options"]).toBe("nosniff");
		});
	}
});
