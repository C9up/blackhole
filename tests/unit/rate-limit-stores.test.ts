import { describe, expect, it, vi } from "vitest";
import BlackholeProvider, {
	type BlackholeAppContext,
} from "../../src/BlackholeProvider.js";
import type { BlackholeConfig } from "../../src/config.js";
import { createBlackhole } from "../../src/index.js";
import {
	MemoryRateLimitStore,
	RedisRateLimitStore,
	stores,
} from "../../src/stores.js";
import { ADAPTERS, viaAdapter } from "./support/adapters.js";

/**
 * `{ default, stores }` under `rateLimit`, and the two counters blackhole now
 * ships.
 *
 * It used to declare the `RateLimitStore` interface and nothing else, so every
 * application wrote the Redis counter itself — and got the window wrong, which
 * is the part that is easy to get wrong.
 */
describe("blackhole > rate-limit stores", () => {
	describe("memory", () => {
		it("counts within a window and reports the time left", async () => {
			const store = new MemoryRateLimitStore();

			expect(await store.increment("ip", 60)).toEqual({
				count: 1,
				resetSeconds: 60,
			});
			const second = await store.increment("ip", 60);
			expect(second.count).toBe(2);
			expect(second.resetSeconds).toBeLessThanOrEqual(60);
		});

		it("starts a new window once the old one has passed", async () => {
			vi.useFakeTimers();
			try {
				const store = new MemoryRateLimitStore();
				await store.increment("ip", 1);
				vi.advanceTimersByTime(1_100);

				expect(await store.increment("ip", 1)).toEqual({
					count: 1,
					resetSeconds: 1,
				});
			} finally {
				vi.useRealTimers();
			}
		});

		it("counts each key on its own", async () => {
			const store = new MemoryRateLimitStore();
			await store.increment("a", 60);
			await store.increment("a", 60);

			expect((await store.increment("b", 60)).count).toBe(1);
		});
	});

	describe("redis", () => {
		function fakeRedis() {
			const counts = new Map<string, number>();
			const ttls = new Map<string, number>();
			return {
				counts,
				ttls,
				client: {
					incr: vi.fn(async (key: string) => {
						const next = (counts.get(key) ?? 0) + 1;
						counts.set(key, next);
						return next;
					}),
					expire: vi.fn(async (key: string, seconds: number) => {
						ttls.set(key, seconds);
						return 1;
					}),
					ttl: vi.fn(async (key: string) => ttls.get(key) ?? -1),
				},
			};
		}

		it("sets the expiry once, on the first hit of a window", async () => {
			const redis = fakeRedis();
			const store = new RedisRateLimitStore(redis.client);

			await store.increment("ip", 60);
			await store.increment("ip", 60);
			await store.increment("ip", 60);

			// Refreshing it on every hit would push the window forward for ever,
			// and a client hitting steadily would never be limited.
			expect(redis.client.expire).toHaveBeenCalledTimes(1);
		});

		it("reports the real time left, from the key's TTL", async () => {
			const redis = fakeRedis();
			const store = new RedisRateLimitStore(redis.client);

			await store.increment("ip", 60);
			redis.ttls.set("blackhole:rate:ip", 42);

			expect(await store.increment("ip", 60)).toEqual({
				count: 2,
				resetSeconds: 42,
			});
		});

		it("treats a key with no expiry as a fresh window", async () => {
			const redis = fakeRedis();
			const store = new RedisRateLimitStore(redis.client);
			redis.counts.set("blackhole:rate:ip", 5);

			// -1 (no expiry) would otherwise count for ever; -2 (evicted) is the
			// same situation seen a moment later.
			expect(await store.increment("ip", 30)).toEqual({
				count: 6,
				resetSeconds: 30,
			});
		});

		it("namespaces its keys, and takes a prefix", async () => {
			const redis = fakeRedis();
			await new RedisRateLimitStore(redis.client).increment("ip", 60);
			await new RedisRateLimitStore(redis.client, { prefix: "app" }).increment(
				"ip",
				60,
			);

			expect([...redis.counts.keys()]).toEqual(["blackhole:rate:ip", "app:ip"]);
		});

		it("resolves a client answered by a function, once", async () => {
			const redis = fakeRedis();
			const resolve = vi.fn(async () => redis.client);
			const store = new RedisRateLimitStore(resolve);

			await store.increment("ip", 60);
			await store.increment("ip", 60);

			expect(resolve).toHaveBeenCalledTimes(1);
		});
	});

	describe("selection", () => {
		function blackholeFrom(config: BlackholeConfig): unknown {
			const bindings = new Map<unknown, () => unknown>();
			const app: BlackholeAppContext = {
				container: {
					singleton(token: unknown, factory: () => unknown) {
						bindings.set(token, factory);
					},
				},
				config: { get: <T>(): T | undefined => config as T },
			};
			new BlackholeProvider(app).register();
			return bindings.get("blackhole")?.();
		}

		it("builds the store `default` names", () => {
			let built = 0;
			blackholeFrom({
				csrf: false,
				rateLimit: {
					max: 10,
					windowSeconds: 60,
					default: "memory",
					stores: {
						memory: stores.memory(),
						never: () => {
							built += 1;
							return new MemoryRateLimitStore();
						},
					},
				},
			});

			// Only the selected one: building a Redis counter nobody selected
			// would open a connection the deployment never asked for.
			expect(built).toBe(0);
		});

		it("refuses a `default` that names nothing", () => {
			expect(() =>
				blackholeFrom({
					csrf: false,
					rateLimit: {
						max: 10,
						windowSeconds: 60,
						default: "redis",
						stores: { memory: stores.memory() },
					},
				}),
			).toThrow(/not in `stores`.*Declared: memory/s);
		});

		it("refuses `stores` with no `default`", () => {
			expect(() =>
				blackholeFrom({
					csrf: false,
					rateLimit: {
						max: 10,
						windowSeconds: 60,
						stores: { memory: stores.memory() },
					},
				}),
			).toThrow(/no `default`/);
		});

		it("still honours a store instance", () => {
			const store = new MemoryRateLimitStore();
			expect(() =>
				blackholeFrom({
					csrf: false,
					rateLimit: { max: 10, windowSeconds: 60, store },
				}),
			).not.toThrow();
		});
	});
});

describe("blackhole > a store never counts a request without a key", () => {
	const options = {
		csrf: false,
		rateLimit: {
			max: 2,
			windowSeconds: 60,
			keyFor: () => "",
			store: new MemoryRateLimitStore(),
		},
	};

	for (const adapter of ADAPTERS) {
		it(`refuses it with 400 E_BLACKHOLE_MISSING_IP on ${adapter}, as the engine does`, async () => {
			for (let i = 0; i < 3; i++) {
				const res = await viaAdapter(adapter, options, { target: "/" });
				expect(res.status).toBe(400);
				expect(res.body).toMatchObject({
					error: { code: "E_BLACKHOLE_MISSING_IP" },
				});
				expect(res.routeRan).toBe(false);
			}
		});
	}

	it("is refused by checkRateLimit itself", async () => {
		const bh = createBlackhole(options);
		await expect(bh.checkRateLimit("")).rejects.toThrow(/empty/);
	});

	it("still counts a request that has one", async () => {
		const bh = createBlackhole({
			csrf: false,
			rateLimit: {
				max: 1,
				windowSeconds: 60,
				store: new MemoryRateLimitStore(),
			},
		});
		expect((await bh.checkRateLimit("203.0.113.7")).allowed).toBe(true);
		expect((await bh.checkRateLimit("203.0.113.7")).allowed).toBe(false);
	});
});
