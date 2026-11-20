/**
 * Bug 040: `limiter.multi()`, `clear(stores)` and the database store.
 *
 * The database store is exercised against a real SQLite engine (`node:sqlite`)
 * behind the structural client shape it takes — the same shape atlas' `db`
 * has — so its SQL runs for real without this package depending on atlas.
 */
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { afterEach, describe, expect, it, vi } from "vitest";
import { E_BLACKHOLE_UNSUPPORTED_DATABASE } from "../../src/errors.js";
import {
	DatabaseLimiterStore,
	type LimiterDatabase,
	LimiterManager,
	limiterStores,
	MultiLimiter,
	ThrottleException,
} from "../../src/limiter.js";
import limiter, {
	clearLimiter,
	setLimiter,
} from "../../src/services/limiter.js";

const MIGRATION = `CREATE TABLE rate_limits (
	"key" VARCHAR(255) NOT NULL PRIMARY KEY,
	"points" INTEGER NOT NULL DEFAULT 0,
	"expire" BIGINT
)`;

function sqlInput(value: unknown): SQLInputValue {
	if (
		value === null ||
		typeof value === "number" ||
		typeof value === "bigint" ||
		typeof value === "string"
	) {
		return value;
	}
	throw new Error(`unexpected binding ${String(value)}`);
}

/** A client of the store's shape over an in-memory SQLite database. */
function sqliteClient(): LimiterDatabase & {
	db: DatabaseSync;
	statements: string[];
} {
	const db = new DatabaseSync(":memory:");
	db.exec(MIGRATION);
	const statements: string[] = [];
	return {
		db,
		statements,
		dialect: "sqlite",
		async rawQuery(sql, bindings) {
			statements.push(sql);
			return db.prepare(sql).all(...bindings.map(sqlInput));
		},
	};
}

/** A client that records what it is sent and answers `rows`. */
function recordingClient(
	dialect: string,
	rows: Record<string, unknown>[] = [],
): LimiterDatabase & { calls: { sql: string; bindings: unknown[] }[] } {
	const calls: { sql: string; bindings: unknown[] }[] = [];
	return {
		calls,
		dialect,
		async rawQuery(sql, bindings) {
			calls.push({ sql, bindings });
			return rows;
		},
	};
}

afterEach(() => {
	vi.useRealTimers();
});

describe("blackhole > limiter.multi()", () => {
	const manager = () =>
		new LimiterManager({
			default: "memory",
			stores: { memory: limiterStores.memory() },
		});

	it("counts on every limiter and throws the first that is over", async () => {
		const multi = manager().multi([
			{ key: "ip", requests: 3, duration: 60 },
			{ key: "ip", requests: 2, duration: 3600 },
		]);
		expect(multi).toBeInstanceOf(MultiLimiter);
		const first = await multi.consume();
		expect(first.map((r) => r.remaining)).toEqual([2, 1]);
		await multi.consume();
		await expect(multi.consume()).rejects.toBeInstanceOf(ThrottleException);
		const state = await multi.get();
		expect(state.map((r) => r?.consumed)).toEqual([3, 3]);
	});

	it("attempt() runs the callback only while every limiter has budget", async () => {
		const multi = manager().multi([
			{ key: "a", requests: 5, duration: 60 },
			{ key: "b", requests: 1, duration: 60 },
		]);
		expect(await multi.attempt(() => "ran")).toBe("ran");
		expect(await multi.attempt(() => "ran again")).toBeUndefined();
	});

	it("penalize() counts failures on all, blocks the exhausted, clears on success", async () => {
		const multi = manager().multi([
			{ key: "user", requests: 2, duration: 60, blockDuration: 600 },
			{ key: "ip", requests: 10, duration: 60 },
		]);
		const fail = () => {
			throw new Error("wrong password");
		};
		await expect(multi.penalize(fail)).rejects.toThrow("wrong password");
		await expect(multi.penalize(fail)).rejects.toThrow("wrong password");
		const [error, result] = await multi.penalize(() => "never");
		expect(error).toBeInstanceOf(ThrottleException);
		expect(result).toBeNull();
		// The user key is blocked for its blockDuration, not its window.
		const [user] = await multi.get();
		expect(user?.availableIn).toBeGreaterThan(60);

		const fresh = manager().multi([
			{ key: "u2", requests: 3, duration: 60 },
			{ key: "i2", requests: 3, duration: 60 },
		]);
		await expect(fresh.penalize(fail)).rejects.toThrow();
		expect(await fresh.penalize(() => "ok")).toEqual([null, "ok"]);
		expect(await fresh.get()).toEqual([null, null]);
	});

	it("increment, decrement, set and delete reach every key", async () => {
		const multi = manager().multi([
			{ key: 1, requests: 5, duration: 60 },
			{ key: 2, requests: 5, duration: 60 },
		]);
		expect(multi.list().map((entry) => entry.key)).toEqual(["1", "2"]);
		await multi.increment();
		await multi.increment();
		expect((await multi.decrement()).map((r) => r.consumed)).toEqual([1, 1]);
		expect((await multi.set(4)).map((r) => r.remaining)).toEqual([1, 1]);
		expect(await multi.delete()).toEqual([true, true]);
	});

	it("counts in the named store, and refuses an empty list", () => {
		const m = new LimiterManager({
			default: "memory",
			stores: { memory: limiterStores.memory(), other: limiterStores.memory() },
		});
		const multi = m.multi("other", [{ key: "k", requests: 1, duration: 1 }]);
		expect(multi.list()[0]?.limiter.name).toBe("memory");
		expect(() => m.multi([])).toThrow(/one or more limiters/);
		expect(() =>
			m.multi("nope", [{ key: "k", requests: 1, duration: 1 }]),
		).toThrow(/unknown limiter store "nope"/);
	});

	it("is on the limiter service too", async () => {
		const m = manager();
		setLimiter(m);
		try {
			const multi = limiter.multi([{ key: "svc", requests: 1, duration: 60 }]);
			await multi.consume();
			await expect(multi.consume()).rejects.toBeInstanceOf(ThrottleException);
		} finally {
			clearLimiter(m);
		}
	});
});

describe("blackhole > limiter.clear(stores)", () => {
	it("clears the named stores only", async () => {
		const m = new LimiterManager({
			default: "a",
			stores: { a: limiterStores.memory(), b: limiterStores.memory() },
		});
		const a = m.use("a", { requests: 5, duration: 60 });
		const b = m.use("b", { requests: 5, duration: 60 });
		await a.increment("k");
		await b.increment("k");
		await m.clear(["a"]);
		expect(await a.get("k")).toBeNull();
		expect((await b.get("k"))?.consumed).toBe(1);
		await m.clear(["unknown"]);
		await m.clear();
		expect(await b.get("k")).toBeNull();
	});

	it("passes the list through the limiter service", async () => {
		const m = new LimiterManager({
			default: "a",
			stores: { a: limiterStores.memory(), b: limiterStores.memory() },
		});
		setLimiter(m);
		try {
			const b = m.use("b", { requests: 5, duration: 60 });
			await b.increment("k");
			await limiter.clear(["a"]);
			expect((await b.get("k"))?.consumed).toBe(1);
			await limiter.clear(["b"]);
			expect(await b.get("k")).toBeNull();
		} finally {
			clearLimiter(m);
		}
	});
});

describe("blackhole > the database limiter store (SQLite, for real)", () => {
	it("opens a window, counts in it, and reports what is left", async () => {
		const store = new DatabaseLimiterStore(sqliteClient());
		expect(await store.get("k")).toBeNull();
		const first = await store.increment("k", 1, 60);
		expect(first.consumed).toBe(1);
		expect(first.msBeforeNext).toBeGreaterThan(59_000);
		expect((await store.increment("k", 2, 60)).consumed).toBe(3);
		expect((await store.get("k"))?.consumed).toBe(3);
		expect((await store.increment("k", -5, 60)).consumed).toBe(0);
	});

	it("counts every one of many concurrent increments", async () => {
		const store = new DatabaseLimiterStore(sqliteClient());
		await Promise.all(
			Array.from({ length: 25 }, () => store.increment("burst", 1, 60)),
		);
		expect((await store.get("burst"))?.consumed).toBe(25);
	});

	it("starts a new window once the old one has expired", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
		const store = new DatabaseLimiterStore(sqliteClient());
		await store.increment("k", 4, 10);
		vi.setSystemTime(new Date("2026-01-01T00:00:11Z"));
		expect(await store.get("k")).toBeNull();
		expect((await store.increment("k", 1, 10)).consumed).toBe(1);
	});

	it("set, delete and clear", async () => {
		const client = sqliteClient();
		const store = new DatabaseLimiterStore(client);
		await store.set("a", 7, 60);
		await store.set("a", 9, 60);
		expect((await store.get("a"))?.consumed).toBe(9);
		expect(await store.delete("a")).toBe(true);
		expect(await store.delete("a")).toBe(false);
		await store.set("b", 1, 60);
		await store.clear();
		expect(
			client.db.prepare("SELECT COUNT(*) AS n FROM rate_limits").get(),
		).toEqual({ n: 0 });
	});

	it("sweeps expired rows, so picked keys cannot grow the table forever", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
		const client = sqliteClient();
		const store = new DatabaseLimiterStore(client);
		for (let i = 0; i < 20; i++) await store.increment(`attacker-${i}`, 1, 5);
		vi.setSystemTime(new Date("2026-01-01T00:02:00Z"));
		await store.increment("legit", 1, 60);
		const rows = client.db.prepare('SELECT "key" FROM rate_limits').all();
		expect(rows).toEqual([{ key: "legit" }]);
	});

	it("stores a key longer than the column as its digest", async () => {
		const client = sqliteClient();
		const store = new DatabaseLimiterStore(client);
		const long = `login_${"x".repeat(400)}`;
		await store.increment(long, 1, 60);
		expect((await store.increment(long, 1, 60)).consumed).toBe(2);
		const [row] = client.db.prepare('SELECT "key" FROM rate_limits').all();
		expect(String(row?.key)).toMatch(/^sha256:[0-9a-f]{64}$/);
	});

	it("throttles through a manager whose store is the database", async () => {
		const client = sqliteClient();
		const m = new LimiterManager({
			default: "db",
			stores: { db: limiterStores.database({ connection: client }) },
		});
		const login = m.use({ requests: 2, duration: 60 });
		await login.consume("u");
		await login.consume("u");
		await expect(login.consume("u")).rejects.toBeInstanceOf(ThrottleException);
		await m.clear(["db"]);
		expect(await login.get("u")).toBeNull();
	});

	it("binds every value: nothing from the key reaches the SQL text", async () => {
		const client = sqliteClient();
		const store = new DatabaseLimiterStore(client);
		const hostile = `x"; DROP TABLE rate_limits; --`;
		await store.increment(hostile, 1, 60);
		expect((await store.get(hostile))?.consumed).toBe(1);
		expect(client.statements.join("\n")).not.toContain("DROP");
	});
});

describe("blackhole > the database limiter store's dialects", () => {
	it("issues one upsert with RETURNING on PostgreSQL", async () => {
		const client = recordingClient("postgres", [
			{ points: "1", expire: String(Date.now() + 60_000) },
		]);
		const store = new DatabaseLimiterStore(client, {
			tableName: "public.rate_limits",
		});
		const record = await store.increment("k", 1, 60);
		expect(record.consumed).toBe(1);
		const [call] = client.calls;
		expect(call?.sql).toContain('INSERT INTO "public"."rate_limits" AS cur');
		expect(call?.sql).toContain('ON CONFLICT ("key") DO UPDATE SET');
		expect(call?.sql).toContain("GREATEST(0,");
		expect(call?.sql).toContain("RETURNING");
		expect(call?.bindings[0]).toBe("k");
	});

	it("upserts then reads back on MySQL, with `key` quoted", async () => {
		const client = recordingClient("mysql", [
			{ points: 2, expire: Date.now() + 60_000 },
		]);
		const store = new DatabaseLimiterStore(client);
		expect((await store.increment("k", 1, 60)).consumed).toBe(2);
		expect(client.calls[0]?.sql).toContain(
			"INSERT INTO `rate_limits` (`key`, `points`, `expire`)",
		);
		expect(client.calls[0]?.sql).toContain("ON DUPLICATE KEY UPDATE");
		expect(client.calls[1]?.sql).toContain("SELECT `points` AS points");
	});

	it("refuses a database it cannot count in", async () => {
		const store = new DatabaseLimiterStore(recordingClient("mssql"));
		await expect(store.get("k")).rejects.toBeInstanceOf(
			E_BLACKHOLE_UNSUPPORTED_DATABASE,
		);
	});

	it("refuses a table name that is not one, when the config is read", () => {
		expect(() =>
			limiterStores.database({ tableName: "rate_limits; DROP TABLE x" }),
		).toThrow(/not a table name/);
	});
});

describe("blackhole > the database store loads atlas lazily", () => {
	const SPECIFIER = "@c9up/atlas/services/db";

	afterEach(() => {
		vi.doUnmock(SPECIFIER);
		vi.resetModules();
	});

	it("does not load atlas until the first count", async () => {
		const factory = vi.fn();
		vi.doMock(SPECIFIER, () => {
			factory();
			return { default: sqliteClient() };
		});
		const { limiterStores: stores } = await import("../../src/limiter.js");
		const make = stores.database();
		const store = make();
		expect(factory).not.toHaveBeenCalled();
		expect((await store.increment("k", 1, 60)).consumed).toBe(1);
		expect(factory).toHaveBeenCalledTimes(1);
	});

	it("scopes atlas' db to the named connection", async () => {
		const named = sqliteClient();
		const connection = vi.fn(() => named);
		vi.doMock(SPECIFIER, () => ({
			default: { dialect: "sqlite", rawQuery: vi.fn(), connection },
		}));
		const { limiterStores: stores } = await import("../../src/limiter.js");
		await stores.database({ connection: "limits" })().increment("k", 1, 60);
		expect(connection).toHaveBeenCalledWith("limits");
		expect(named.statements.length).toBeGreaterThan(0);
	});

	it("says atlas is missing, and offers the alternative", async () => {
		vi.doMock(SPECIFIER, () => {
			throw new Error("Cannot find module");
		});
		const { limiterStores: stores } = await import("../../src/limiter.js");
		const { E_BLACKHOLE_DATABASE_UNAVAILABLE: Unavailable } = await import(
			"../../src/errors.js"
		);
		const attempt = stores.database()().get("k");
		await expect(attempt).rejects.toBeInstanceOf(Unavailable);
		await expect(stores.database()().get("k")).rejects.toThrow(
			/not installed.*connection: db/,
		);
	});

	it("says so when atlas has not booted", async () => {
		vi.doMock(SPECIFIER, () => ({
			default: {
				get dialect(): string {
					throw new Error("db singleton accessed before AtlasProvider.boot()");
				},
				rawQuery: vi.fn(),
			},
		}));
		const { limiterStores: stores } = await import("../../src/limiter.js");
		await expect(stores.database()().get("k")).rejects.toThrow(
			/provider has not booted/,
		);
	});
});
