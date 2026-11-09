/**
 * Named, per-route limits and the manual limiter behind them.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import BlackholeProvider, {
	BLACKHOLE_LIMITER_KEY,
} from "../../src/BlackholeProvider.js";
import {
	Limiter,
	type LimiterHttpContext,
	LimiterManager,
	type LimiterRedisClient,
	LimiterResponse,
	limiterStores,
	MemoryLimiterStore,
	RedisLimiterStore,
	ThrottleException,
} from "../../src/limiter.js";
import limiter, {
	clearLimiter,
	setLimiter,
} from "../../src/services/limiter.js";

function memoryLimiter(options: {
	requests: number;
	duration: number | string;
	blockDuration?: number | string;
}): Limiter {
	return new Limiter(new MemoryLimiterStore(), options);
}

/** An HTTP context recording the response, with a fixed client IP. */
function httpContext(ip = "198.51.100.4", accept = "application/json") {
	const sent: {
		status?: number;
		body?: unknown;
		headers: Record<string, string>;
	} = { headers: {} };
	const ctx: LimiterHttpContext = {
		request: {
			ip: () => ip,
			header: (name) => (name.toLowerCase() === "accept" ? accept : undefined),
		},
		response: {
			header(name, value) {
				sent.headers[name] = value;
			},
			status(code) {
				sent.status = code;
			},
			send(body) {
				sent.body = body;
			},
		},
	};
	return { ctx, sent };
}

afterEach(() => {
	vi.useRealTimers();
});

describe("blackhole > Limiter", () => {
	it("consumes until the budget is spent, then throws a 429", async () => {
		const login = memoryLimiter({ requests: 2, duration: "1 minute" });
		expect((await login.consume("k")).remaining).toBe(1);
		expect((await login.consume("k")).remaining).toBe(0);
		const error = await login.consume("k").catch((e: unknown) => e);
		expect(error).toBeInstanceOf(ThrottleException);
		if (!(error instanceof ThrottleException)) return;
		expect(error.status).toBe(429);
		expect(error.code).toBe("E_TOO_MANY_REQUESTS");
		expect(error.response.limit).toBe(2);
		expect(error.response.availableIn).toBeGreaterThan(0);
	});

	it("resets the count when the window ends", async () => {
		vi.useFakeTimers();
		const login = memoryLimiter({ requests: 1, duration: 60 });
		await login.consume("k");
		await expect(login.consume("k")).rejects.toBeInstanceOf(ThrottleException);
		vi.advanceTimersByTime(61_000);
		await expect(login.consume("k")).resolves.toMatchObject({ remaining: 0 });
	});

	it("blocks a key that goes over its budget for blockDuration", async () => {
		vi.useFakeTimers();
		const login = memoryLimiter({
			requests: 1,
			duration: 60,
			blockDuration: "10 mins",
		});
		await login.consume("k");
		const error = await login.consume("k").catch((e: unknown) => e);
		expect(error).toBeInstanceOf(ThrottleException);
		if (error instanceof ThrottleException) {
			expect(error.response.availableIn).toBe(600);
		}
		// The window alone would have reset by now; the block has not.
		vi.advanceTimersByTime(120_000);
		await expect(login.consume("k")).rejects.toBeInstanceOf(ThrottleException);
		vi.advanceTimersByTime(600_000);
		await expect(login.consume("k")).resolves.toBeDefined();
	});

	it("reads, sets, increments and decrements a key", async () => {
		const l = memoryLimiter({ requests: 5, duration: 60 });
		expect(await l.get("k")).toBeNull();
		expect(await l.remaining("k")).toBe(5);
		await l.increment("k", 3);
		expect(await l.remaining("k")).toBe(2);
		await l.decrement("k", 10);
		expect((await l.get("k"))?.consumed).toBe(0);
		await l.set("k", 5);
		expect(await l.isBlocked("k")).toBe(true);
		expect(await l.availableIn("k")).toBeGreaterThan(0);
		expect(await l.delete("k")).toBe(true);
		expect(await l.isBlocked("k")).toBe(false);
	});

	it("blocks by hand", async () => {
		const l = memoryLimiter({ requests: 5, duration: 60 });
		await l.block("k", "5 mins");
		await expect(l.consume("k")).rejects.toBeInstanceOf(ThrottleException);
		expect(await l.availableIn("k")).toBe(300);
	});

	it("attempt runs the callback only while there is budget", async () => {
		const l = memoryLimiter({ requests: 1, duration: 60 });
		const callback = vi.fn(() => "sent");
		expect(await l.attempt("k", callback)).toBe("sent");
		expect(await l.attempt("k", callback)).toBeUndefined();
		expect(callback).toHaveBeenCalledTimes(1);
	});

	it("penalize counts failures, clears on success and blocks when spent", async () => {
		const l = memoryLimiter({ requests: 2, duration: 60, blockDuration: 900 });
		const fail = () => {
			throw new Error("wrong password");
		};
		await expect(l.penalize("k", fail)).rejects.toThrow("wrong password");
		const [none, value] = await l.penalize("k", () => "user");
		expect(none).toBeNull();
		expect(value).toBe("user");
		// Success cleared the count: two more failures are needed.
		await expect(l.penalize("k", fail)).rejects.toThrow();
		await expect(l.penalize("k", fail)).rejects.toThrow();
		const callback = vi.fn();
		const [error] = await l.penalize("k", callback);
		expect(error).toBeInstanceOf(ThrottleException);
		expect(callback).not.toHaveBeenCalled();
		expect(await l.availableIn("k")).toBe(900);
	});

	it("refuses a budget that would not limit", () => {
		expect(() => memoryLimiter({ requests: 0, duration: 60 })).toThrow();
		expect(() => memoryLimiter({ requests: 1, duration: 0 })).toThrow();
		expect(() => memoryLimiter({ requests: 1, duration: "soon" })).toThrow();
	});
});

describe("blackhole > ThrottleException", () => {
	it("renders JSON with the rate-limit headers", async () => {
		const l = memoryLimiter({ requests: 1, duration: 60 });
		await l.consume("k");
		const error = await l.consume("k").catch((e: unknown) => e);
		if (!(error instanceof ThrottleException)) throw new Error("expected 429");
		const { ctx, sent } = httpContext();
		await error.handle(error, ctx);
		expect(sent.status).toBe(429);
		expect(sent.headers["X-RateLimit-Limit"]).toBe("1");
		expect(sent.headers["X-RateLimit-Remaining"]).toBe("0");
		expect(Number(sent.headers["Retry-After"])).toBeGreaterThan(0);
		expect(sent.body).toEqual({
			errors: [
				{
					message: "Too many requests",
					retryAfter: error.response.availableIn,
				},
			],
		});
	});

	it("renders text for a browser and translates through ctx.i18n", async () => {
		const error = new ThrottleException(memoryLimiterResponse()).setMessage(
			"Slow down",
		);
		const { ctx, sent } = httpContext("198.51.100.4", "text/html");
		const withI18n = Object.assign(ctx, {
			i18n: { t: (key: string) => `translated:${key}` },
		});
		await error.handle(error, withI18n);
		expect(sent.body).toBe("translated:errors.E_TOO_MANY_REQUESTS");
	});

	it("renders the message it was given without a translator", async () => {
		const error = new ThrottleException(memoryLimiterResponse()).setMessage(
			"Slow down",
		);
		const { ctx, sent } = httpContext("198.51.100.4", "text/html");
		await error.handle(error, ctx);
		expect(sent.body).toBe("Slow down");
	});

	it("renders the JSON:API error object", async () => {
		const error = new ThrottleException(memoryLimiterResponse());
		const { ctx, sent } = httpContext(
			"198.51.100.4",
			"application/vnd.api+json",
		);
		await error.handle(error, ctx);
		expect(sent.body).toMatchObject({
			errors: [{ code: "E_TOO_MANY_REQUESTS", title: "Too many requests" }],
		});
	});
});

function memoryLimiterResponse(): LimiterResponse {
	return new LimiterResponse({
		limit: 1,
		remaining: 0,
		consumed: 2,
		availableIn: 30,
	});
}

describe("blackhole > limiter.define (throttle middleware)", () => {
	const manager = new LimiterManager({
		default: "memory",
		stores: { memory: () => new MemoryLimiterStore() },
	});

	it("counts per client IP, sets the headers, and throws once over", async () => {
		const throttle = manager.define("api", () =>
			manager.allowRequests(2).every("1 minute"),
		);
		const next = vi.fn(async () => {});
		const first = httpContext("198.51.100.10");
		await throttle(first.ctx, next);
		expect(first.sent.headers["X-RateLimit-Limit"]).toBe("2");
		expect(first.sent.headers["X-RateLimit-Remaining"]).toBe("1");
		await throttle(httpContext("198.51.100.10").ctx, next);
		await expect(
			throttle(httpContext("198.51.100.10").ctx, next),
		).rejects.toBeInstanceOf(ThrottleException);
		// Another client has its own budget.
		await throttle(httpContext("198.51.100.11").ctx, next);
		expect(next).toHaveBeenCalledTimes(3);
	});

	it("counts IPv6 clients by /64", async () => {
		const throttle = manager.define("v6", () =>
			manager.allowRequests(1).every(60),
		);
		await throttle(httpContext("2001:db8:1:1::1").ctx, async () => {});
		await expect(
			throttle(httpContext("2001:db8:1:1::2").ctx, async () => {}),
		).rejects.toBeInstanceOf(ThrottleException);
	});

	it("uses the key, the block and the exception modifier it is given", async () => {
		const throttle = manager.define("keyed", () =>
			manager
				.allowRequests(1)
				.every(60)
				.usingKey("user_42")
				.blockFor("1 hour")
				.limitExceeded((error) => error.setMessage("Easy").setStatus(503)),
		);
		await throttle(httpContext("198.51.100.20").ctx, async () => {});
		const error = await throttle(
			httpContext("198.51.100.21").ctx,
			async () => {},
		).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(ThrottleException);
		if (!(error instanceof ThrottleException)) return;
		expect(error.message).toBe("Easy");
		expect(error.status).toBe(503);
		expect(error.response.availableIn).toBe(3600);
	});

	it("lets a request through uncounted when the builder answers noLimit", async () => {
		const throttle = manager.define("open", () => manager.noLimit());
		const next = vi.fn(async () => {});
		for (let i = 0; i < 5; i++) await throttle(httpContext().ctx, next);
		expect(next).toHaveBeenCalledTimes(5);
	});

	it("refuses a limit without requests or a window", async () => {
		const throttle = manager.define("broken", () => manager.allowRequests(5));
		await expect(throttle(httpContext().ctx, async () => {})).rejects.toThrow(
			/every\(\)/,
		);
	});

	it("names the middleware after the limit", () => {
		expect(manager.define("global", () => null).name).toBe("globalThrottle");
	});
});

describe("blackhole > limiter service and provider", () => {
	it("counts a throttle defined at import time in the manager seated later", async () => {
		// A route file defines its throttle before the provider registers.
		const throttle = limiter.define("svc", () =>
			limiter.allowRequests(1).every(60),
		);
		const store = new MemoryLimiterStore();
		const seated = new LimiterManager({
			default: "shared",
			stores: { shared: () => store },
		});
		setLimiter(seated);
		try {
			await throttle(httpContext("198.51.100.30").ctx, async () => {});
			expect(store.size).toBe(1);
			await expect(
				throttle(httpContext("198.51.100.30").ctx, async () => {}),
			).rejects.toBeInstanceOf(ThrottleException);
		} finally {
			clearLimiter(seated);
		}
	});

	it("registers and seats a manager from the provider", () => {
		const bindings = new Map<unknown, () => unknown>();
		const provider = new BlackholeProvider({
			container: {
				singleton(token, factory) {
					bindings.set(token, factory);
				},
			},
			config: {
				get<T>(): T | undefined {
					return undefined;
				},
			},
		});
		provider.register();
		const manager = bindings.get(BLACKHOLE_LIMITER_KEY)?.();
		expect(manager).toBeInstanceOf(LimiterManager);
		provider.shutdown();
	});

	it("falls back to a memory store when nothing is seated", async () => {
		const l = limiter.use({ requests: 1, duration: 60 });
		await l.consume("fallback");
		await expect(l.consume("fallback")).rejects.toBeInstanceOf(
			ThrottleException,
		);
	});

	it("refuses a default store that is not declared", () => {
		expect(() => new LimiterManager({ default: "redis", stores: {} })).toThrow(
			/not in `stores`/,
		);
	});
});

describe("blackhole > RedisLimiterStore", () => {
	function fakeRedis(): LimiterRedisClient & { data: Map<string, string> } {
		const data = new Map<string, string>();
		const ttls = new Map<string, number>();
		return {
			data,
			async incrby(key, amount) {
				const next = Number(data.get(key) ?? "0") + amount;
				data.set(key, String(next));
				return next;
			},
			async pexpire(key, ms) {
				ttls.set(key, ms);
				return 1;
			},
			async pttl(key) {
				if (!data.has(key)) return -2;
				return ttls.get(key) ?? -1;
			},
			async get(key) {
				return data.get(key) ?? null;
			},
			async set(key, value, _mode, ms) {
				data.set(key, value);
				ttls.set(key, ms);
				return "OK";
			},
			async del(key) {
				ttls.delete(key);
				return data.delete(key) ? 1 : 0;
			},
			async scan(_cursor, _match, pattern) {
				const prefix = pattern.replace(/\*$/, "");
				return ["0", [...data.keys()].filter((k) => k.startsWith(prefix))];
			},
		};
	}

	it("opens a window on the first increment and counts under its prefix", async () => {
		const client = fakeRedis();
		const store = new RedisLimiterStore(client, { prefix: "app:limits" });
		const l = new Limiter(store, { requests: 2, duration: 60 });
		await l.consume("k");
		const second = await l.consume("k");
		expect(second.remaining).toBe(0);
		expect(second.availableIn).toBe(60);
		expect(client.data.get("app:limits:k")).toBe("2");
		await expect(l.consume("k")).rejects.toBeInstanceOf(ThrottleException);
	});

	it("clears only its own keys", async () => {
		const client = fakeRedis();
		client.data.set("sessions:abc", "keep");
		const store = new RedisLimiterStore(client);
		await store.increment("k", 1, 60);
		await store.clear();
		expect(client.data.has("sessions:abc")).toBe(true);
		expect(await store.get("k")).toBeNull();
	});
});

describe("blackhole > limiter surfaces", () => {
	it("serializes a response and an HTTP limit", () => {
		const response = memoryLimiterResponse();
		expect(response.toJSON()).toEqual({
			limit: 1,
			remaining: 0,
			consumed: 2,
			availableIn: 30,
		});
		const manager = new LimiterManager({
			default: "memory",
			stores: { memory: limiterStores.memory() },
		});
		expect(
			manager
				.allowRequests(3)
				.every("1 minute")
				.blockFor(30)
				.store("memory")
				.toJSON(),
		).toEqual({
			store: "memory",
			requests: 3,
			duration: "1 minute",
			blockDuration: 30,
		});
	});

	it("renders the headers and the translation key it was given", async () => {
		const error = new ThrottleException(memoryLimiterResponse())
			.setHeaders({ "Retry-After": 99 })
			.t("errors.slow_down", { minutes: 5 });
		const { ctx, sent } = httpContext("198.51.100.4", "text/html");
		const seen: unknown[] = [];
		await error.handle(
			error,
			Object.assign(ctx, {
				i18n: {
					t: (key: string, data: object) => {
						seen.push(key, data);
						return "translated";
					},
				},
			}),
		);
		expect(sent.headers).toEqual({ "Retry-After": "99" });
		expect(seen).toEqual(["errors.slow_down", { minutes: 5 }]);
		expect(sent.body).toBe("translated");
	});

	it("hands out one limiter per store and budget, and clears them all", async () => {
		const manager = new LimiterManager({
			default: "a",
			stores: { a: limiterStores.memory(), b: limiterStores.memory() },
		});
		const options = { requests: 1, duration: 60 };
		expect(manager.use(options)).toBe(manager.use("a", options));
		expect(manager.use("b", options)).not.toBe(manager.use(options));
		expect(() => manager.use("c", options)).toThrow(/unknown limiter store/);
		await manager.use(options).consume("k");
		await manager.clear();
		expect(await manager.use(options).get("k")).toBeNull();
		const throttle = manager.define("named", () =>
			manager.allowRequests(1).every(60).store("b"),
		);
		await throttle(httpContext().ctx, async () => {});
		expect(
			await manager.use("b", options).get("named_ip_198.51.100.4"),
		).not.toBeNull();
	});

	it("reaches the service's manager through use(store, options) and clear()", async () => {
		const l = limiter.use("memory", { requests: 2, duration: 60 });
		await l.consume("svc-key");
		await limiter.clear();
		expect(await l.get("svc-key")).toBeNull();
		expect(limiter.noLimit()).toBeNull();
	});

	it("builds a Redis store from a client", async () => {
		const data = new Map<string, string>();
		const client: LimiterRedisClient = {
			async incrby(key, amount) {
				const next = Number(data.get(key) ?? "0") + amount;
				data.set(key, String(next));
				return next;
			},
			pexpire: async () => 1,
			pttl: async (key) => (data.has(key) ? -1 : -2),
			get: async (key) => data.get(key) ?? null,
			async set(key, value) {
				data.set(key, value);
				return "OK";
			},
			del: async (key) => (data.delete(key) ? 1 : 0),
			scan: async () => ["0", []],
		};
		const store = limiterStores.redis({ connection: () => client })();
		expect(store.name).toBe("redis");
		const l = new Limiter(store, { requests: 3, duration: 60 });
		await l.set("k", 2, "30s");
		expect(await l.remaining("k")).toBe(1);
		await l.decrement("k");
		expect((await l.get("k"))?.consumed).toBe(1);
		expect(await l.delete("k")).toBe(true);
		expect(await l.delete("k")).toBe(false);
	});
});
