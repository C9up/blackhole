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
