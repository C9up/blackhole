/**
 * Each budget counts on its own counter, whatever the store: "5 a minute" and
 * "100 a day" on the same key never share one count or one expiry.
 */
import { describe, expect, it } from "vitest";
import {
	DatabaseLimiterStore,
	LimiterManager,
	type LimiterStoreFactory,
	limiterStores,
	RedisLimiterStore,
} from "../../src/limiter.js";
import { fakeRedis, sqliteClient } from "./support/stores.js";

/** The guide's login limit: two budgets on one key. */
function loginLimits(manager: LimiterManager) {
	return manager.multi([
		{ key: "login_203.0.113.9", requests: 5, duration: "1 minute" },
		{
			key: "login_203.0.113.9",
			requests: 100,
			duration: "1 day",
			blockDuration: "1 hour",
		},
	]);
}

const database = sqliteClient();
const redis = fakeRedis();
const SHARED: [string, LimiterStoreFactory, () => string[]][] = [
	[
		"database",
		() => new DatabaseLimiterStore(database),
		() =>
			database.db
				.prepare('SELECT "key" FROM rate_limits ORDER BY "key"')
				.all()
				.map((row) => String(row.key)),
	],
	[
		"redis",
		() => new RedisLimiterStore(redis, { prefix: "app:limits" }),
		() => [...redis.data.keys()].sort(),
	],
];
const STORES: [string, LimiterStoreFactory][] = [
	["memory", limiterStores.memory()],
	...SHARED.map(([name, factory]): [string, LimiterStoreFactory] => [
		name,
		factory,
	]),
];

describe.each(STORES)(
	"blackhole > limiter budgets on one key (%s store)",
	(_, factory) => {
		it("each budget counts once per request, in its own window, and the 6th request is refused", async () => {
			const manager = new LimiterManager({
				default: "s",
				stores: { s: factory },
			});
			await manager.clear();
			const [perMinute, perDay] = await loginLimits(manager).consume();
			expect(perMinute?.consumed).toBe(1);
			expect(perDay?.consumed).toBe(1);
			expect(perMinute?.availableIn).toBeLessThanOrEqual(60);
			expect(perDay?.availableIn).toBeGreaterThan(86_000);
			for (let i = 2; i <= 5; i++) await loginLimits(manager).consume();
			await expect(loginLimits(manager).consume()).rejects.toMatchObject({
				code: "E_TOO_MANY_REQUESTS",
			});
		});
	},
);

describe.each(SHARED)(
	"blackhole > limiter budgets on a shared store (%s)",
	(_, factory, storedKeys) => {
		it("stores one counter per budget, the budget written into the key", async () => {
			const manager = new LimiterManager({
				default: "s",
				stores: { s: factory },
			});
			await manager.clear();
			await loginLimits(manager).consume();
			expect(
				storedKeys().map((key) => key.replace(/^app:limits:/, "")),
			).toEqual([
				"100/86400/3600:login_203.0.113.9",
				"5/60/0:login_203.0.113.9",
			]);
		});
	},
);

describe("blackhole > limiter budgets > a long key on the database store", () => {
	it("is stored as its digest once the budget makes it longer than the column", async () => {
		const client = sqliteClient();
		const manager = new LimiterManager({
			default: "db",
			stores: { db: limiterStores.database({ connection: client }) },
		});
		const limiter = manager.use({ requests: 3, duration: 60 });
		const key = "k".repeat(250);
		await limiter.consume(key);
		expect((await limiter.get(key))?.consumed).toBe(1);
		const [row] = client.db.prepare('SELECT "key" FROM rate_limits').all();
		expect(String(row?.key)).toMatch(/^sha256:[0-9a-f]{64}$/);
	});
});
