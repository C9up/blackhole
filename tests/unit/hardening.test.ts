/**
 * The 2026-09-29 audit: a rate limit that did not limit, an http Origin taken
 * for the https site, refusals without the protective headers, and engine
 * codes outside the `E_BLACKHOLE_*` namespace.
 */
import { describe, expect, it } from "vitest";
import { BLACKHOLE_KEY } from "../../src/BlackholeProvider.js";
import { blackholeExpress } from "../../src/express.js";
import { type Blackhole, createBlackhole } from "../../src/index.js";
import { blackholeMiddleware, type ReamContext } from "../../src/middleware.js";
import { blackholeServerMiddleware } from "../../src/server_middleware.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";

describe("blackhole > a rate limit must limit", () => {
	const invalid = [
		{ max: 1, windowSeconds: 0 },
		{ max: 1, windowSeconds: 0.5 },
		{ max: 0, windowSeconds: 60 },
		{ max: -1, windowSeconds: 60 },
		{ max: 1.5, windowSeconds: 60 },
		{ max: Number.NaN, windowSeconds: 60 },
		{ max: 1, windowSeconds: 2 ** 32 },
	];
	for (const rateLimit of invalid) {
		it(`refuses ${JSON.stringify(rateLimit)}`, () => {
			expect(() => createBlackhole({ csrf: false, rateLimit })).toThrow(
				/must be a positive whole number/,
			);
		});
	}

	it("still limits a valid configuration, with the namespaced code", () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 1, windowSeconds: 60 },
		});
		const req = {
			method: "GET",
			path: "/",
			headers: {},
			remoteAddr: "1.2.3.4",
		};
		expect(bh.check(req).allowed).toBe(true);
		const refused = bh.check(req);
		expect(refused.allowed).toBe(false);
		expect(refused.status).toBe(429);
		// The same code the distributed-store path answers with.
		expect(refused.body).toContain("E_BLACKHOLE_RATE_LIMITED");
	});
});

describe("blackhole > the CSRF origin check compares the scheme", () => {
	const bh = createBlackhole({ secret: SECRET });
	const token = bh.generateCsrfToken();
	const post = (origin: string, protocol?: string) =>
		bh.check({
			method: "POST",
			path: "/orders",
			headers: {
				host: "app.test",
				origin,
				cookie: `XSRF-TOKEN=${token}`,
				"x-xsrf-token": token,
			},
			remoteAddr: "1.2.3.4",
			protocol,
		});

	it("refuses an http Origin on an https request, a valid token notwithstanding", () => {
		const refused = post("http://app.test", "https");
		expect(refused.allowed).toBe(false);
		expect(refused.status).toBe(403);
		expect(refused.body).toContain("E_BLACKHOLE_CSRF_ORIGIN_MISMATCH");
	});

	it("accepts the same scheme", () => {
		expect(post("https://app.test", "https").allowed).toBe(true);
		expect(post("http://app.test", "http").allowed).toBe(true);
	});

	it("compares hosts only when the host framework gives no scheme", () => {
		expect(post("http://app.test").allowed).toBe(true);
	});
});

describe("blackhole > namespaced engine codes", () => {
	it("answers a path traversal with E_BLACKHOLE_PATH_TRAVERSAL", () => {
		const bh = createBlackhole({ csrf: false });
		const refused = bh.check({
			method: "GET",
			path: "/files/../../etc/passwd",
			headers: {},
			remoteAddr: "1.2.3.4",
		});
		expect(refused.body).toContain("E_BLACKHOLE_PATH_TRAVERSAL");
	});
});

// ── The protective headers on every response ────────────────────────────

function reamContext(opts: {
	method?: string;
	path?: string;
	headers?: Record<string, string>;
	protocol?: string;
	bh?: Blackhole;
}) {
	const bh = opts.bh ?? createBlackhole({ secret: SECRET });
	const headers: Record<string, string> = {};
	let status = 200;
	const response: ReamContext["response"] = {
		status(code) {
			status = code;
			return response;
		},
		json() {},
		send() {},
		cookie() {
			return response;
		},
		plainCookie() {
			return response;
		},
		header(name, value) {
			headers[name.toLowerCase()] = value;
			return response;
		},
		getBody: () => "",
		getHeader: (name) => headers[name.toLowerCase()],
		setBody() {},
	};
	const ctx: ReamContext = {
		containerResolver: {
			async make(token) {
				if (token === BLACKHOLE_KEY) return bh;
				throw new Error(`No binding for ${String(token)}`);
			},
		},
		request: {
			method: () => opts.method ?? "GET",
			url: () => opts.path ?? "/orders",
			path: () => opts.path ?? "/orders",
			header: (name) => opts.headers?.[name],
			headers: () => opts.headers ?? {},
			body: () => undefined,
			ip: () => "1.2.3.4",
			protocol: () => opts.protocol ?? "https",
		},
		store: { set() {} },
		response,
	};
	return { ctx, headers, status: () => status, bh };
}

describe("blackhole > Ream: refusals and errors carry the security headers", () => {
	it("on a CSRF refusal", async () => {
		const { ctx, headers, status } = reamContext({ method: "POST" });
		await blackholeMiddleware(ctx, () => {
			throw new Error("next must not run");
		});
		expect(status()).toBe(403);
		expect(headers["x-content-type-options"]).toBe("nosniff");
		expect(headers["content-security-policy"]).toBeDefined();
	});

	it("on a response the handler never finished: the headers are set before it runs", async () => {
		const { ctx, headers } = reamContext({});
		await expect(
			blackholeMiddleware(ctx, () => {
				throw new Error("handler failed");
			}),
		).rejects.toThrow("handler failed");
		// The exception handler writes its error page on this same response.
		expect(headers["x-content-type-options"]).toBe("nosniff");
		expect(headers["content-security-policy"]).toBeDefined();
	});

	it("passes the request's scheme to the origin check", async () => {
		const { ctx, status, bh } = reamContext({
			method: "POST",
			protocol: "https",
		});
		const token = bh.generateCsrfToken();
		const withToken: ReamContext = {
			...ctx,
			request: {
				...ctx.request,
				headers: () => ({
					host: "app.test",
					origin: "http://app.test",
					cookie: `XSRF-TOKEN=${token}`,
					"x-xsrf-token": token,
				}),
			},
		};
		await blackholeMiddleware(withToken, () => {
			throw new Error("next must not run");
		});
		expect(status()).toBe(403);
	});
});

describe("blackhole > Express: refusals and raw responses carry the security headers", () => {
	function express(method: string) {
		const headers: Record<string, string | string[]> = {};
		let status = 200;
		const res = {
			headersSent: false,
			getHeader: (name: string) => headers[name.toLowerCase()],
			setHeader(name: string, value: string) {
				headers[name.toLowerCase()] = value;
			},
			append(name: string, value: string | string[]) {
				headers[name.toLowerCase()] = value;
			},
			status(code: number) {
				status = code;
				return res;
			},
			json() {},
			send() {},
		};
		const req = {
			method,
			url: "/orders",
			path: "/orders",
			headers: {},
			ip: "1.2.3.4",
			protocol: "https",
		};
		return { req, res, headers, status: () => status };
	}

	it("on a CSRF refusal", async () => {
		const { req, res, headers, status } = express("POST");
		await blackholeExpress({ secret: SECRET })(req, res, () => {
			throw new Error("next must not run");
		});
		expect(status()).toBe(403);
		expect(headers["x-content-type-options"]).toBe("nosniff");
	});

	it("before the handler, so a response that bypasses send() has them", async () => {
		const { req, res, headers } = express("GET");
		let reached = false;
		await blackholeExpress({ secret: SECRET })(req, res, () => {
			reached = true;
		});
		expect(reached).toBe(true);
		expect(headers["x-content-type-options"]).toBe("nosniff");
		expect(headers["content-security-policy"]).toBeDefined();
	});
});

describe("blackhole > Ream: the server-tier half", () => {
	it("guards a request no route matches: its 404 carries the headers", async () => {
		const { ctx, headers } = reamContext({ path: "/nowhere" });
		// Ream raises the 404 inside the server-tier onion.
		await expect(
			blackholeServerMiddleware(ctx, () => {
				throw new Error("E_ROUTE_NOT_FOUND");
			}),
		).rejects.toThrow("E_ROUTE_NOT_FOUND");
		expect(headers["x-content-type-options"]).toBe("nosniff");
		expect(headers["content-security-policy"]).toBeDefined();
	});

	it("refuses a path traversal before routing", async () => {
		const { ctx, status } = reamContext({ path: "/files/../../etc/passwd" });
		await blackholeServerMiddleware(ctx, () => {
			throw new Error("next must not run");
		});
		expect(status()).toBe(400);
	});

	it("counts each request once when both halves run", async () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 2, windowSeconds: 60 },
		});
		const statuses: number[] = [];
		for (let i = 0; i < 3; i++) {
			const { ctx, status } = reamContext({ bh });
			await blackholeServerMiddleware(ctx, () =>
				blackholeMiddleware(ctx, () => {}),
			);
			statuses.push(status());
		}
		// Counted twice per request, the second would already be refused.
		expect(statuses).toEqual([200, 200, 429]);
	});

	it("leaves a per-request key to the router-tier half", async () => {
		const asked: string[] = [];
		const bh = createBlackhole({
			csrf: false,
			rateLimit: {
				max: 1,
				windowSeconds: 60,
				keyFor: (ctx) => {
					asked.push(String(ctx.auth?.user?.id));
					return String(ctx.auth?.user?.id ?? ctx.request.ip());
				},
			},
		});
		const { ctx, status } = reamContext({ bh });
		await blackholeServerMiddleware(ctx, async () => {
			// What the auth middleware does on the router tier.
			Reflect.set(ctx, "auth", { user: { id: 7 } });
			await blackholeMiddleware(ctx, () => {});
		});
		expect(asked).toEqual(["7"]);
		expect(status()).toBe(200);
	});

	it("still runs every check when the router-tier half is alone", async () => {
		const { ctx, status } = reamContext({ path: "/files/../../etc/passwd" });
		await blackholeMiddleware(ctx, () => {
			throw new Error("next must not run");
		});
		expect(status()).toBe(400);
	});
});

describe("blackhole > a CSRF exemption exempts from CSRF only", () => {
	it("still rate-limits a route an exceptRoutes predicate exempts", async () => {
		const bh = createBlackhole({
			secret: SECRET,
			csrf: { exceptRoutes: (req) => req.path.startsWith("/webhooks/") },
			rateLimit: { max: 1, windowSeconds: 60 },
		});
		const statuses: number[] = [];
		for (let i = 0; i < 2; i++) {
			const { ctx, status } = reamContext({
				bh,
				method: "POST",
				path: "/webhooks/stripe",
			});
			await blackholeMiddleware(ctx, () => {});
			statuses.push(status());
		}
		expect(statuses).toEqual([200, 429]);
	});
});
