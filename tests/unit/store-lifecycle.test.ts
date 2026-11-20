/**
 * What the rate-limit stores leave behind.
 *
 * Both count per key, and the key is usually the client — so both are handed
 * an unbounded number of them by ordinary traffic, let alone by an attacker
 * varying a spoofable header. What happens to a key nobody uses again is the
 * whole question.
 */

import { describe, expect, it, vi } from "vitest";
import {
	type LimiterRedisClient,
	RedisLimiterStore,
} from "../../src/limiter.js";
import {
	MemoryRateLimitStore,
	type RateLimitRedisClient,
	RedisRateLimitStore,
} from "../../src/stores.js";

describe("blackhole > MemoryRateLimitStore", () => {
	it("does not keep windows that have expired", async () => {
		vi.useFakeTimers();
		try {
			const store = new MemoryRateLimitStore();
			// A thousand one-off clients, each seen once, none ever again.
			for (let i = 0; i < 1000; i++) {
				await store.increment(`client-${i}`, 60);
			}
			// Long past every one of those windows.
			vi.setSystemTime(Date.now() + 120_000);
			await store.increment("someone-else", 60);

			expect(store.size).toBeLessThan(10);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("blackhole > RedisRateLimitStore", () => {
	/** A Redis whose key survived without an expiry — INCR landed, EXPIRE did not. */
	function redisWithUnexpiringKey(): {
		client: RateLimitRedisClient;
		expireCalls: () => number;
	} {
		let count = 41;
		let expireCalls = 0;
		let hasTtl = false;
		return {
			client: {
				async incr() {
					count += 1;
					return count;
				},
				async expire() {
					expireCalls += 1;
					hasTtl = true;
					return 1;
				},
				// -1 is Redis for "this key exists and has no expiry".
				async ttl() {
					return hasTtl ? 60 : -1;
				},
			},
			expireCalls: () => expireCalls,
		};
	}

	// Without an expiry the counter only ever climbs, so the client it belongs
	// to is refused for good — a permanent lockout from one crash at the wrong
	// moment, and nothing in the request path can undo it.
	it("repairs a key that lost its expiry", async () => {
		const { client, expireCalls } = redisWithUnexpiringKey();
		const store = new RedisRateLimitStore(client);

		await store.increment("client", 60);

		expect(expireCalls()).toBe(1);
	});
});

/**
 * Quasar retires a connection whose socket ended for good (its retry strategy
 * gave up) and hands out a fresh one on the next `connection(name)`. Both
 * Redis stores kept the first one, so every rate-limited request failed with
 * "Connection is closed." until the process restarted, even once Redis was back.
 */
describe("blackhole > a Redis store whose connection ended for good", () => {
	function rateClient(status: string) {
		return {
			status,
			incr: vi.fn(async () => 1),
			expire: vi.fn(async () => 1),
			ttl: vi.fn(async () => 60),
		};
	}

	function limiterClient(status: string) {
		return {
			status,
			incrby: vi.fn(async () => 1),
			pexpire: vi.fn(async () => 1),
			pttl: vi.fn(async () => 60_000),
			get: vi.fn(async (): Promise<string | null> => null),
			set: vi.fn(async () => "OK"),
			del: vi.fn(async () => 0),
			scan: vi.fn(async (): Promise<[string, string[]]> => ["0", []]),
		};
	}

	it("RedisRateLimitStore asks its resolver again", async () => {
		const first = rateClient("ready");
		const second = rateClient("ready");
		const resolver = vi
			.fn<() => RateLimitRedisClient>()
			.mockReturnValueOnce(first)
			.mockReturnValueOnce(second);
		const store = new RedisRateLimitStore(resolver);

		await store.increment("ip", 60);
		first.status = "end";
		await store.increment("ip", 60);

		expect(resolver).toHaveBeenCalledTimes(2);
		expect(second.incr).toHaveBeenCalledOnce();
	});

	it("RedisLimiterStore asks its resolver again", async () => {
		const first = limiterClient("ready");
		const second = limiterClient("ready");
		const resolver = vi
			.fn<() => LimiterRedisClient>()
			.mockReturnValueOnce(first)
			.mockReturnValueOnce(second);
		const store = new RedisLimiterStore(resolver);

		await store.get("ip");
		first.status = "end";
		await store.get("ip");

		expect(resolver).toHaveBeenCalledTimes(2);
		expect(second.get).toHaveBeenCalledOnce();
	});

	it("keeps a client that closed but reconnects by itself", async () => {
		const client = limiterClient("ready");
		const resolver = vi.fn(() => client);
		const store = new RedisLimiterStore(resolver);

		await store.get("ip");
		client.status = "close";
		await store.get("ip");

		expect(resolver).toHaveBeenCalledOnce();
	});

	it("keeps a client handed in directly", async () => {
		const client = rateClient("end");
		const store = new RedisRateLimitStore(client);

		await store.increment("ip", 60);

		expect(client.incr).toHaveBeenCalledOnce();
	});
});
