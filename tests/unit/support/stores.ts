/**
 * Clients for the shared limiter stores, without a server: a Redis that
 * behaves like ioredis under a `keyPrefix`, and a SQL database on
 * `node:sqlite`.
 */
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import type {
	LimiterDatabase,
	LimiterRedisClient,
} from "../../../src/limiter.js";

export interface FakeRedis extends LimiterRedisClient {
	/** Every key as the server holds it, the connection prefix included. */
	data: Map<string, string>;
	ttls: Map<string, number>;
	options: { keyPrefix?: string };
}

/** A Redis glob (`*`, `?`, `\` escapes) as a regular expression. */
function globToRegExp(pattern: string): RegExp {
	let source = "";
	for (let i = 0; i < pattern.length; i++) {
		const char = pattern.charAt(i);
		if (char === "\\" && i + 1 < pattern.length) {
			i += 1;
			source += pattern.charAt(i).replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
		} else if (char === "*") {
			source += ".*";
		} else if (char === "?") {
			source += ".";
		} else {
			source += char.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
		}
	}
	return new RegExp(`^${source}$`);
}

/**
 * A Redis client as ioredis is one: the connection's `keyPrefix` is added to
 * the key of every command, but not to SCAN's MATCH pattern, and SCAN answers
 * full key names. SCAN pages two keys at a time.
 */
export function fakeRedis(keyPrefix = ""): FakeRedis {
	const data = new Map<string, string>();
	const ttls = new Map<string, number>();
	const full = (key: string) => `${keyPrefix}${key}`;
	let scanned: string[] = [];
	return {
		data,
		ttls,
		options: { keyPrefix },
		async incrby(key, amount) {
			const next = Number(data.get(full(key)) ?? "0") + amount;
			data.set(full(key), String(next));
			return next;
		},
		async pexpire(key, ms) {
			ttls.set(full(key), ms);
			return 1;
		},
		async pttl(key) {
			if (!data.has(full(key))) return -2;
			return ttls.get(full(key)) ?? -1;
		},
		async get(key) {
			return data.get(full(key)) ?? null;
		},
		async set(key, value, _mode, ms) {
			data.set(full(key), value);
			ttls.set(full(key), ms);
			return "OK";
		},
		async del(key) {
			ttls.delete(full(key));
			return data.delete(full(key)) ? 1 : 0;
		},
		async scan(cursor, _match, pattern) {
			const matcher = globToRegExp(pattern);
			// Every key present for the whole scan is returned, as Redis
			// guarantees, even when keys are deleted between two pages.
			if (cursor === "0") scanned = [...data.keys()].sort();
			const keys = scanned;
			const from = Number(cursor);
			const page = keys.slice(from, from + 2).filter((k) => matcher.test(k));
			const next = from + 2 >= keys.length ? "0" : String(from + 2);
			return [next, page];
		},
	};
}

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

/** A client of the database store's shape over an in-memory SQLite database. */
export function sqliteClient(): LimiterDatabase & { db: DatabaseSync } {
	const db = new DatabaseSync(":memory:");
	db.exec(`CREATE TABLE rate_limits (
		"key" VARCHAR(255) NOT NULL PRIMARY KEY,
		"points" INTEGER NOT NULL DEFAULT 0,
		"expire" BIGINT
	)`);
	return {
		db,
		dialect: "sqlite",
		async rawQuery(sql, bindings) {
			return db.prepare(sql).all(...bindings.map(sqlInput));
		},
	};
}
