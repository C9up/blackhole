/**
 * `RedisLimiterStore.clear()` on a connection with a `keyPrefix`: ioredis
 * prefixes the key of every command but not SCAN's MATCH pattern, and SCAN
 * answers full key names. The store's keys go, every other key stays.
 */
import { describe, expect, it } from "vitest";
import { Limiter, RedisLimiterStore } from "../../src/limiter.js";
import { fakeRedis } from "./support/stores.js";

describe("blackhole > RedisLimiterStore.clear()", () => {
	it("deletes its keys under the connection's keyPrefix, and nothing else", async () => {
		const client = fakeRedis("app:");
		const store = new RedisLimiterStore(client);
		const limiter = new Limiter(store, { requests: 5, duration: 60 });
		for (const key of ["login:alice", "login:bob", "login:carol"]) {
			await limiter.consume(key);
		}
		await client.set("sessions:abc", "keep", "PX", 60_000);
		client.data.set("other:blackhole:limiter:x", "another app's");
		await store.clear();
		expect([...client.data.keys()].sort()).toEqual([
			"app:sessions:abc",
			"other:blackhole:limiter:x",
		]);
		expect(await limiter.get("login:alice")).toBeNull();
	});

	it("reads the prefix off a quasar connection's ioConnection", async () => {
		const io = fakeRedis("tenant:");
		const connection = Object.assign(Object.create(io), {
			ioConnection: io,
		});
		const store = new RedisLimiterStore(connection);
		await store.increment("k", 1, 60);
		await store.clear();
		expect(io.data.size).toBe(0);
	});

	it("matches the prefixes literally: a glob character in one matches itself only", async () => {
		const client = fakeRedis("a*:");
		const store = new RedisLimiterStore(client, { prefix: "lim?" });
		await store.increment("k", 1, 60);
		client.data.set("a*:limX:k", "not ours");
		client.data.set("ab:lim?:k", "not ours");
		await store.clear();
		expect([...client.data.keys()].sort()).toEqual(["a*:limX:k", "ab:lim?:k"]);
	});

	it("scans every master of a cluster", async () => {
		const client = fakeRedis("app:");
		const masters = [fakeRedis(), fakeRedis()];
		masters[0]?.data.set("app:blackhole:limiter:on-first", "1");
		masters[1]?.data.set("app:blackhole:limiter:on-second", "1");
		const deleted: string[] = [];
		const cluster = Object.assign(Object.create(client), {
			nodes: (role: string) => (role === "master" ? masters : []),
			del: async (key: string) => {
				deleted.push(key);
				return 1;
			},
		});
		await new RedisLimiterStore(cluster).clear();
		expect(deleted.sort()).toEqual([
			"blackhole:limiter:on-first",
			"blackhole:limiter:on-second",
		]);
	});
});
