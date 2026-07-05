/**
 * AdonisJS-parity fixes: configurable rate-limit key (#4), injectable
 * distributed store (#3), X-RateLimit-* on success + ISO reset (#10), and the
 * structured CSP object (#9).
 */
import { describe, expect, it } from "vitest";
import { BLACKHOLE_KEY } from "../../src/BlackholeProvider.js";
import {
	type Blackhole,
	createBlackhole,
	type RateLimitStore,
} from "../../src/index.js";
import { blackholeMiddleware, type ReamContext } from "../../src/middleware.js";

interface Spy {
	status?: number;
	body?: unknown;
	headers: Record<string, string>;
}

function makeCtx(
	bh: Blackhole,
	opts: { method?: string; path?: string; ip?: string } = {},
): { ctx: ReamContext; spy: Spy } {
	const spy: Spy = { headers: {} };
	const response: ReamContext["response"] = {
		status(code) {
			spy.status = code;
			return response;
		},
		json(data) {
			spy.body = data;
		},
		send() {},
		cookie() {
			return response;
		},
		plainCookie() {
			return response;
		},
		header(name, value) {
			spy.headers[name.toLowerCase()] = value;
			return response;
		},
		getBody() {
			return "";
		},
		getHeader(name) {
			return spy.headers[name.toLowerCase()];
		},
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
			url: () => opts.path ?? "/",
			path: () => opts.path ?? "/",
			header: () => undefined,
			headers: () => ({}),
			body: () => undefined,
			ip: () => opts.ip ?? "127.0.0.1",
		},
		store: { set() {} },
		response,
	};
	return { ctx, spy };
}

/** A minimal fixed-window store, standing in for a Redis-backed implementation. */
function memoryStore(): RateLimitStore {
	const counts = new Map<string, number>();
	return {
		async increment(key, windowSeconds) {
			const next = (counts.get(key) ?? 0) + 1;
			counts.set(key, next);
			return { count: next, resetSeconds: windowSeconds };
		},
	};
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

describe("#4 configurable rate-limit key (keyFor)", () => {
	it("rateLimitKey() falls back to the client IP by default", () => {
		const bh = createBlackhole({ csrf: false });
		expect(bh.rateLimitKey({ request: { ip: () => "9.9.9.9" } })).toBe(
			"9.9.9.9",
		);
	});

	it("rateLimitKey() applies a custom keyFor (per-user)", () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: {
				max: 10,
				windowSeconds: 60,
				keyFor: (ctx) => `user:${ctx.auth?.user?.id ?? "anon"}`,
			},
		});
		expect(
			bh.rateLimitKey({
				request: { ip: () => "1.1.1.1" },
				auth: { user: { id: 42 } },
			}),
		).toBe("user:42");
	});

	it("buckets on the custom key so distinct IPs sharing a key collide", async () => {
		// keyFor pins every request to one bucket → max:1 blocks the 2nd request
		// even though it comes from a different IP (proves the key drives counting).
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 1, windowSeconds: 60, keyFor: () => "shared" },
		});
		const first = makeCtx(bh, { ip: "1.1.1.1" });
		let nextCount = 0;
		await blackholeMiddleware(first.ctx, () => {
			nextCount++;
		});
		expect(nextCount).toBe(1);
		const second = makeCtx(bh, { ip: "2.2.2.2" });
		await blackholeMiddleware(second.ctx, () => {
			nextCount++;
		});
		expect(nextCount).toBe(1); // 2nd blocked despite the different IP
		expect(second.spy.status).toBe(429);
	});
});

describe("#3 injectable distributed store", () => {
	it("counts + decides via the store, not the Rust counter", async () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 2, windowSeconds: 60, store: memoryStore() },
		});
		expect(bh.hasRateLimitStore()).toBe(true);

		const d1 = await bh.checkRateLimit("k");
		expect(d1).toEqual({
			allowed: true,
			limit: 2,
			remaining: 1,
			resetSeconds: 60,
		});
		const d2 = await bh.checkRateLimit("k");
		expect(d2.allowed).toBe(true);
		const d3 = await bh.checkRateLimit("k");
		expect(d3.allowed).toBe(false);
		expect(d3.remaining).toBe(0);
	});

	it("rejects with 429 + ISO reset through the middleware once over budget", async () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 1, windowSeconds: 60, store: memoryStore() },
		});
		const ok = makeCtx(bh, { ip: "5.5.5.5" });
		let passed = 0;
		await blackholeMiddleware(ok.ctx, () => {
			passed++;
		});
		expect(passed).toBe(1);
		expect(ok.spy.headers["x-ratelimit-limit"]).toBe("1");
		expect(ok.spy.headers["x-ratelimit-remaining"]).toBe("0");

		const blocked = makeCtx(bh, { ip: "5.5.5.5" });
		await blackholeMiddleware(blocked.ctx, () => {
			passed++;
		});
		expect(passed).toBe(1);
		expect(blocked.spy.status).toBe(429);
		expect(blocked.spy.headers["retry-after"]).toBe("60");
		expect(blocked.spy.headers["x-ratelimit-reset"]).toMatch(ISO);
	});

	it("hasRateLimitStore() is false and checkRateLimit throws without a store", async () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 1, windowSeconds: 60 },
		});
		expect(bh.hasRateLimitStore()).toBe(false);
		await expect(bh.checkRateLimit("k")).rejects.toThrow(/store/);
	});
});

describe("#10 X-RateLimit-* on the success path + ISO reset", () => {
	it("sets Limit/Remaining and an ISO Reset on an allowed request", async () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 5, windowSeconds: 60 },
		});
		const { ctx, spy } = makeCtx(bh, { ip: "8.8.8.8" });
		await blackholeMiddleware(ctx, () => {});
		expect(spy.headers["x-ratelimit-limit"]).toBe("5");
		expect(spy.headers["x-ratelimit-remaining"]).toBe("4");
		expect(spy.headers["x-ratelimit-reset"]).toMatch(ISO);
	});

	it("emits an ISO Reset on the native 429 rejection too", async () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: { max: 1, windowSeconds: 60 },
		});
		const first = makeCtx(bh, { ip: "7.7.7.7" });
		await blackholeMiddleware(first.ctx, () => {});
		const blocked = makeCtx(bh, { ip: "7.7.7.7" });
		await blackholeMiddleware(blocked.ctx, () => {});
		expect(blocked.spy.status).toBe(429);
		expect(blocked.spy.headers["x-ratelimit-reset"]).toMatch(ISO);
	});
});

describe("#9 structured CSP object", () => {
	it("serializes directives merged over the hardened baseline", () => {
		const h = createBlackhole({
			csrf: false,
			securityHeaders: {
				csp: { directives: { "script-src": ["'self'", "'nonce-x'"] } },
			},
		}).securityHeaders();
		const csp = h["content-security-policy"];
		expect(csp).toContain("default-src 'self'");
		expect(csp).toContain("object-src 'none'");
		// The caller's script-src overrides the baseline entry.
		expect(csp).toContain("script-src 'self' 'nonce-x'");
	});

	it("useDefaults:false emits ONLY the provided directives", () => {
		const h = createBlackhole({
			csrf: false,
			securityHeaders: {
				csp: { useDefaults: false, directives: { "default-src": ["'none'"] } },
			},
		}).securityHeaders();
		expect(h["content-security-policy"]).toBe("default-src 'none'");
	});

	it("reportOnly emits the Report-Only header", () => {
		const h = createBlackhole({
			csrf: false,
			securityHeaders: {
				csp: { directives: { "default-src": ["'self'"] }, reportOnly: true },
			},
		}).securityHeaders();
		expect(h["content-security-policy-report-only"]).toContain(
			"default-src 'self'",
		);
		expect(h["content-security-policy"]).toBeUndefined();
	});

	it("supports @nonce inside a directive (per-request substitution)", () => {
		const bh = createBlackhole({
			csrf: false,
			securityHeaders: {
				csp: { directives: { "script-src": ["'self'", "@nonce"] } },
			},
		});
		expect(bh.cspHasNonce()).toBe(true);
		const csp = bh.securityHeaders("abc")["content-security-policy"];
		expect(csp).toContain("'nonce-abc'");
		expect(csp).not.toContain("@nonce");
	});
});
