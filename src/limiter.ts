/**
 * Named, per-route rate limits — and the counters behind them, for code that
 * limits by hand (login attempts, password resets, an expensive export).
 *
 * The global `rateLimit` option counts every request under one budget. This
 * is the other half: a limit defined once, by name, and attached to the
 * routes it belongs to.
 *
 *   // start/limiter.ts
 *   import limiter from '@c9up/blackhole/services/limiter'
 *
 *   export const throttle = limiter.define('api', (ctx) =>
 *     limiter.allowRequests(60).every('1 minute').usingKey(ctx.auth?.user?.id),
 *   )
 *
 *   // start/routes.ts
 *   router.post('/login', [AuthController, 'login']).use(throttle)
 *
 * And by hand:
 *
 *   const login = limiter.use({ requests: 5, duration: '1 minute', blockFor: '20 mins' })
 *   const [error, user] = await login.penalize(`login_${email}`, () => verify(email, password))
 *
 * Counting is a fixed window per key, opened by the key's first request and
 * reset when it ends. `blockFor` holds a key that went over its budget for
 * that long instead.
 */

import { createHash } from "node:crypto";
import { clientKey } from "./clientKey.js";
import { durationToSeconds } from "./duration.js";
import {
	E_BLACKHOLE_DATABASE_UNAVAILABLE,
	E_BLACKHOLE_INCOMPLETE_CONNECTION,
	E_BLACKHOLE_INCOMPLETE_THROTTLE,
	E_BLACKHOLE_INVALID_RATE_LIMIT,
	E_BLACKHOLE_INVALID_TABLE_NAME,
	E_BLACKHOLE_LIMITER_OPTIONS_MISSING,
	E_BLACKHOLE_QUASAR_MISSING,
	E_BLACKHOLE_UNKNOWN_STORE,
	E_BLACKHOLE_UNSUPPORTED_DATABASE,
	E_TOO_MANY_REQUESTS,
	type ThrottleException,
} from "./errors.js";
import {
	hasCommands,
	hasEnded,
	quasarConnection as loadQuasarConnection,
} from "./vendor/quasarConnection.js";

// ── Responses and the error ──────────────────────────────────────────────

/** Where a key stands: its budget, what is left, and when it resets. */
export class LimiterResponse {
	/** Requests allowed per window. */
	limit: number;
	/** Requests left in the current window. */
	remaining: number;
	/** Requests counted in the current window (past the limit when blocked). */
	consumed: number;
	/** Seconds until the window — or the block — ends. */
	availableIn: number;

	constructor(values: {
		limit: number;
		remaining: number;
		consumed: number;
		availableIn: number;
	}) {
		this.limit = values.limit;
		this.remaining = values.remaining;
		this.consumed = values.consumed;
		this.availableIn = values.availableIn;
	}

	toJSON(): {
		limit: number;
		remaining: number;
		consumed: number;
		availableIn: number;
	} {
		return {
			limit: this.limit,
			remaining: this.remaining,
			consumed: this.consumed,
			availableIn: this.availableIn,
		};
	}
}

/** What the 429 handler reads off the HTTP context. */
export interface ThrottleContext {
	request: {
		header(name: string): string | undefined;
		/**
		 * Content negotiation (ream's `request.accepts`): the first of `types`
		 * the client accepts, or `null`. The 429 is shaped by it when the host
		 * has it, by the `Accept` header read directly otherwise.
		 */
		accepts?<T extends string>(types: T[]): T | null;
	};
	response: {
		header(name: string, value: string): unknown;
		status(code: number): unknown;
		send(body: unknown): unknown;
	};
}

// ── Stores ───────────────────────────────────────────────────────────────

/** One key's count and how long until it resets. */
export interface LimiterRecord {
	consumed: number;
	/** Milliseconds until the window (or the block) ends. */
	msBeforeNext: number;
}

/**
 * Where the counts live. Each operation is on one key; the window starts with
 * the key's first increment and ends `durationSeconds` later.
 */
export interface LimiterStore {
	readonly name: string;
	/** Add `amount` (negative to take some back), opening a window if none runs. */
	increment(
		key: string,
		amount: number,
		durationSeconds: number,
	): Promise<LimiterRecord>;
	/** Overwrite the count, with a window of `durationSeconds` from now. */
	set(
		key: string,
		consumed: number,
		durationSeconds: number,
	): Promise<LimiterRecord>;
	get(key: string): Promise<LimiterRecord | null>;
	delete(key: string): Promise<boolean>;
	/** Forget every key this store holds. */
	clear(): Promise<void>;
}

/** A store, built for one limiter's options. */
export type LimiterStoreFactory = () => LimiterStore;

/**
 * Counts in this process's memory. Single process only — several instances
 * each count their own share. Expired keys are swept periodically, so keys an
 * attacker picks cannot grow the map without bound.
 */
export class MemoryLimiterStore implements LimiterStore {
	readonly name = "memory";
	readonly #entries = new Map<
		string,
		{ consumed: number; expiresAt: number }
	>();
	#lastSweep = Date.now();
	static readonly #SWEEP_INTERVAL_MS = 30_000;

	/** How many keys are currently held. */
	get size(): number {
		return this.#entries.size;
	}

	#live(key: string, now: number) {
		if (now - this.#lastSweep >= MemoryLimiterStore.#SWEEP_INTERVAL_MS) {
			for (const [k, entry] of this.#entries) {
				if (entry.expiresAt <= now) this.#entries.delete(k);
			}
			this.#lastSweep = now;
		}
		const entry = this.#entries.get(key);
		return entry && entry.expiresAt > now ? entry : undefined;
	}

	async increment(
		key: string,
		amount: number,
		durationSeconds: number,
	): Promise<LimiterRecord> {
		const now = Date.now();
		const entry = this.#live(key, now) ?? {
			consumed: 0,
			expiresAt: now + durationSeconds * 1000,
		};
		entry.consumed = Math.max(0, entry.consumed + amount);
		this.#entries.set(key, entry);
		return { consumed: entry.consumed, msBeforeNext: entry.expiresAt - now };
	}

	async set(
		key: string,
		consumed: number,
		durationSeconds: number,
	): Promise<LimiterRecord> {
		const now = Date.now();
		this.#entries.set(key, {
			consumed,
			expiresAt: now + durationSeconds * 1000,
		});
		return { consumed, msBeforeNext: durationSeconds * 1000 };
	}

	async get(key: string): Promise<LimiterRecord | null> {
		const now = Date.now();
		const entry = this.#live(key, now);
		return entry
			? { consumed: entry.consumed, msBeforeNext: entry.expiresAt - now }
			: null;
	}

	async delete(key: string): Promise<boolean> {
		return this.#entries.delete(key);
	}

	async clear(): Promise<void> {
		this.#entries.clear();
	}
}

/** The Redis commands the limiter issues. ioredis- and quasar-shaped. */
export interface LimiterRedisClient {
	incrby(key: string, amount: number): Promise<number>;
	pexpire(key: string, milliseconds: number): Promise<unknown>;
	pttl(key: string): Promise<number>;
	get(key: string): Promise<string | null>;
	set(
		key: string,
		value: string,
		mode: "PX",
		milliseconds: number,
	): Promise<unknown>;
	del(key: string): Promise<number>;
	scan(
		cursor: string,
		match: "MATCH",
		pattern: string,
		count: "COUNT",
		size: number,
	): Promise<[string, string[]]>;
}

/** Every command of {@link LimiterRedisClient}: the limiter issues them all. */
const LIMITER_COMMANDS = [
	"incrby",
	"pexpire",
	"pttl",
	"get",
	"set",
	"del",
	"scan",
] as const;

function isLimiterRedisClient(value: unknown): value is LimiterRedisClient {
	return hasCommands(value, LIMITER_COMMANDS);
}

export type LimiterRedisSource =
	| LimiterRedisClient
	| (() => LimiterRedisClient | Promise<LimiterRedisClient>);

/**
 * Counts in Redis, shared by every process.
 *
 * `clear()` deletes this store's own keys (by prefix) rather than flushing the
 * database: the limiter rarely has a Redis database to itself.
 */
export class RedisLimiterStore implements LimiterStore {
	readonly name = "redis";
	readonly #source: LimiterRedisSource;
	readonly #prefix: string;
	#resolved: LimiterRedisClient | undefined;

	constructor(source: LimiterRedisSource, options: { prefix?: string } = {}) {
		this.#source = source;
		this.#prefix = options.prefix ?? "blackhole:limiter";
	}

	/**
	 * The client, resolved on first use and again once it has ended for good:
	 * quasar retires a connection whose retry strategy gave up and hands out a
	 * fresh one, and keeping the dead client failed every request with
	 * "Connection is closed." until restart. NAMED DEVIATION, better than
	 * upstream, whose limiter captures `ioConnection` once. A client handed in
	 * directly is kept whatever its state.
	 */
	async #client(): Promise<LimiterRedisClient> {
		if (typeof this.#source === "function" && hasEnded(this.#resolved)) {
			this.#resolved = undefined;
		}
		this.#resolved ??=
			typeof this.#source === "function" ? await this.#source() : this.#source;
		return this.#resolved;
	}

	#key(key: string): string {
		return `${this.#prefix}:${key}`;
	}

	async increment(
		key: string,
		amount: number,
		durationSeconds: number,
	): Promise<LimiterRecord> {
		const client = await this.#client();
		const namespaced = this.#key(key);
		const consumed = await client.incrby(namespaced, amount);
		let ttl = await client.pttl(namespaced);
		// No expiry: the key was just created, or lost the PEXPIRE that should
		// have followed its first INCRBY. Either way the window starts now —
		// left without one, the count would only climb and lock the key out.
		if (ttl < 0) {
			ttl = durationSeconds * 1000;
			await client.pexpire(namespaced, ttl);
		}
		return { consumed: Math.max(0, consumed), msBeforeNext: ttl };
	}

	async set(
		key: string,
		consumed: number,
		durationSeconds: number,
	): Promise<LimiterRecord> {
		const client = await this.#client();
		const ms = durationSeconds * 1000;
		await client.set(this.#key(key), String(consumed), "PX", ms);
		return { consumed, msBeforeNext: ms };
	}

	async get(key: string): Promise<LimiterRecord | null> {
		const client = await this.#client();
		const namespaced = this.#key(key);
		const value = await client.get(namespaced);
		if (value === null) return null;
		const ttl = await client.pttl(namespaced);
		return { consumed: Number(value), msBeforeNext: Math.max(0, ttl) };
	}

	async delete(key: string): Promise<boolean> {
		const client = await this.#client();
		return (await client.del(this.#key(key))) > 0;
	}

	async clear(): Promise<void> {
		const client = await this.#client();
		let cursor = "0";
		do {
			const [next, keys] = await client.scan(
				cursor,
				"MATCH",
				`${this.#prefix}:*`,
				"COUNT",
				500,
			);
			for (const key of keys) await client.del(key);
			cursor = next;
		} while (cursor !== "0");
	}
}

// ── The database store ───────────────────────────────────────────────────

/** A row as the database hands it back. */
type LimiterRow = Record<string, unknown>;

/**
 * The slice of a database client the database store issues. atlas' `db`
 * service (`import db from '@c9up/atlas/services/db'`) has this shape, and so
 * can anything else: the store never imports a data layer.
 *
 * Raw SQL rather than a query builder, deliberately: a count has to be ONE
 * atomic upsert-and-increment, a dialect statement (`ON CONFLICT … DO UPDATE
 * … RETURNING`, `ON DUPLICATE KEY UPDATE`) that no portable builder call
 * expresses. `?` placeholders, bound positionally.
 */
export interface LimiterDatabase {
	/** `postgres`, `mysql` or `sqlite` (atlas' names; `pg`, `mysql2`, `sqlite3` and `better-sqlite3` too). */
	readonly dialect: string;
	rawQuery(
		sql: string,
		bindings: unknown[],
	): PromiseLike<readonly LimiterRow[]>;
}

export type LimiterDatabaseSource =
	| LimiterDatabase
	| (() => LimiterDatabase | Promise<LimiterDatabase>);

type SqlDialect = "postgres" | "mysql" | "sqlite";

const DIALECTS = new Map<string, SqlDialect>([
	["postgres", "postgres"],
	["postgresql", "postgres"],
	["pg", "postgres"],
	["mysql", "mysql"],
	["mysql2", "mysql"],
	["sqlite", "sqlite"],
	["sqlite3", "sqlite"],
	["better-sqlite3", "sqlite"],
]);

function isLimiterDatabase(value: unknown): value is LimiterDatabase {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof Reflect.get(value, "rawQuery") === "function" &&
		typeof Reflect.get(value, "dialect") === "string"
	);
}

/**
 * atlas' `db`, scoped to the named connection or left on the default one,
 * loaded only when a database store first counts. The specifier is built at
 * runtime: atlas is not a dependency of this package, and an application on
 * another data layer never loads it.
 */
async function atlasDatabase(
	name: string | undefined,
): Promise<LimiterDatabase> {
	const specifier = "@c9up/atlas/services/db";
	const which =
		name === undefined ? "default connection" : `connection "${name}"`;
	let loaded: unknown;
	try {
		loaded = await import(/* @vite-ignore */ specifier);
	} catch (cause) {
		throw new E_BLACKHOLE_DATABASE_UNAVAILABLE(
			[
				`the database limiter store asks for atlas' ${which}, but @c9up/atlas is not installed. Install it, or pass a client: \`limiterStores.database({ connection: db })\``,
			],
			{ cause },
		);
	}
	let scoped: unknown;
	try {
		const db: unknown = Reflect.get(Object(loaded), "default");
		const connection: unknown = Reflect.get(Object(db), "connection");
		scoped =
			name === undefined || typeof connection !== "function"
				? db
				: Reflect.apply(connection, db, [name]);
		// Reading `dialect` is what tells a booted atlas from one that is not.
		if (isLimiterDatabase(scoped)) return scoped;
	} catch (cause) {
		throw new E_BLACKHOLE_DATABASE_UNAVAILABLE(
			[
				`atlas' ${which} is not available to the database limiter store: its provider has not booted, or the connection is not configured`,
			],
			{ cause },
		);
	}
	throw new E_BLACKHOLE_DATABASE_UNAVAILABLE([
		`@c9up/atlas/services/db did not expose a client with \`dialect\` and \`rawQuery()\` for the ${which}`,
	]);
}

/** A whole number out of a column, however the driver typed it. */
function toInteger(value: unknown): number {
	if (typeof value === "number") return value;
	if (typeof value === "bigint" || typeof value === "string") {
		return Number(value);
	}
	return Number.NaN;
}

/** A table name: an identifier, optionally schema-qualified. */
const TABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?$/;

function assertTableName(table: string | undefined): void {
	if (table !== undefined && !TABLE_NAME.test(table)) {
		throw new E_BLACKHOLE_INVALID_TABLE_NAME([JSON.stringify(table)]);
	}
}

/** The longest key stored as written; a longer one is stored as its digest. */
const MAX_KEY_LENGTH = 255;

/**
 * Counts in a SQL table (PostgreSQL, MySQL, SQLite), shared by every process
 * that reaches the database — for an application without Redis.
 *
 * The table has three columns: `key` (primary), `points`, `expire` (epoch
 * milliseconds); the migration ships as
 * `stubs/database/migrations/9100_create_rate_limits.stub`. Each count is ONE
 * upsert-and-increment statement, so two replicas counting the same key at the
 * same moment both land. MySQL has no `RETURNING`: the count is read back
 * right after, and may already hold a concurrent request — it can only
 * over-count.
 *
 * Better than upstream, deliberately: expired rows are deleted as counting
 * goes (at most once a minute), so keys an attacker picks cannot grow the
 * table without bound; and a key longer than the column (255) is stored as
 * its SHA-256 instead of failing the insert. `clear()` empties the table, as
 * upstream's truncate does: give the limiter a table of its own.
 */
export class DatabaseLimiterStore implements LimiterStore {
	readonly name = "database";
	readonly #source: LimiterDatabaseSource;
	readonly #table: string;
	#resolved: { db: LimiterDatabase; dialect: SqlDialect } | undefined;
	#lastSweep = Date.now();
	static readonly #SWEEP_INTERVAL_MS = 60_000;

	constructor(
		source: LimiterDatabaseSource,
		options: { tableName?: string } = {},
	) {
		assertTableName(options.tableName);
		this.#source = source;
		this.#table = options.tableName ?? "rate_limits";
	}

	async #db(): Promise<{ db: LimiterDatabase; dialect: SqlDialect }> {
		if (this.#resolved) return this.#resolved;
		const db =
			typeof this.#source === "function" ? await this.#source() : this.#source;
		const dialect = DIALECTS.get(db.dialect.toLowerCase());
		if (dialect === undefined) {
			throw new E_BLACKHOLE_UNSUPPORTED_DATABASE(db.dialect);
		}
		this.#resolved = { db, dialect };
		return this.#resolved;
	}

	/** The identifiers, quoted for the dialect (`key` is reserved on MySQL). */
	#names(dialect: SqlDialect): {
		table: string;
		key: string;
		points: string;
		expire: string;
	} {
		const quote = (name: string) =>
			dialect === "mysql" ? `\`${name}\`` : `"${name}"`;
		return {
			table: this.#table.split(".").map(quote).join("."),
			key: quote("key"),
			points: quote("points"),
			expire: quote("expire"),
		};
	}

	#key(key: string): string {
		return key.length <= MAX_KEY_LENGTH
			? key
			: `sha256:${createHash("sha256").update(key).digest("hex")}`;
	}

	#record(row: LimiterRow | undefined, now: number): LimiterRecord | null {
		if (row === undefined) return null;
		const consumed = toInteger(row.points);
		const expire = toInteger(row.expire);
		if (!Number.isFinite(consumed) || !Number.isFinite(expire)) return null;
		if (expire <= now) return null;
		return { consumed: Math.max(0, consumed), msBeforeNext: expire - now };
	}

	/** Delete the expired rows, at most once per sweep interval. */
	async #sweep(
		db: LimiterDatabase,
		dialect: SqlDialect,
		now: number,
	): Promise<void> {
		if (now - this.#lastSweep < DatabaseLimiterStore.#SWEEP_INTERVAL_MS) {
			return;
		}
		this.#lastSweep = now;
		const n = this.#names(dialect);
		await db.rawQuery(`DELETE FROM ${n.table} WHERE ${n.expire} <= ?`, [now]);
	}

	async increment(
		key: string,
		amount: number,
		durationSeconds: number,
	): Promise<LimiterRecord> {
		const { db, dialect } = await this.#db();
		const now = Date.now();
		await this.#sweep(db, dialect, now);
		const n = this.#names(dialect);
		const id = this.#key(key);
		const fresh = Math.max(0, amount);
		const expire = now + durationSeconds * 1000;
		// A live row gains `amount` (never below zero); an expired one starts a
		// new window, as a missing one does.
		const bindings = [id, fresh, expire, now, fresh, amount, now, expire];
		let rows: readonly LimiterRow[];
		if (dialect === "mysql") {
			// Assignments run left to right: `expire` is still the old value
			// when the `points` one reads it.
			await db.rawQuery(
				`INSERT INTO ${n.table} (${n.key}, ${n.points}, ${n.expire}) VALUES (?, ?, ?) ` +
					"ON DUPLICATE KEY UPDATE " +
					`${n.points} = IF(${n.expire} <= ?, ?, GREATEST(0, ${n.points} + ?)), ` +
					`${n.expire} = IF(${n.expire} <= ?, ?, ${n.expire})`,
				bindings,
			);
			rows = await db.rawQuery(
				`SELECT ${n.points} AS points, ${n.expire} AS expire FROM ${n.table} WHERE ${n.key} = ?`,
				[id],
			);
		} else {
			const greatest = dialect === "postgres" ? "GREATEST" : "MAX";
			rows = await db.rawQuery(
				`INSERT INTO ${n.table} AS cur (${n.key}, ${n.points}, ${n.expire}) VALUES (?, ?, ?) ` +
					`ON CONFLICT (${n.key}) DO UPDATE SET ` +
					`${n.points} = CASE WHEN cur.${n.expire} <= ? THEN ? ELSE ${greatest}(0, cur.${n.points} + ?) END, ` +
					`${n.expire} = CASE WHEN cur.${n.expire} <= ? THEN ? ELSE cur.${n.expire} END ` +
					`RETURNING ${n.points} AS points, ${n.expire} AS expire`,
				bindings,
			);
		}
		// Just written: only a clock jump between the two reads makes it expired.
		return (
			this.#record(rows[0], now) ?? {
				consumed: fresh,
				msBeforeNext: durationSeconds * 1000,
			}
		);
	}

	async set(
		key: string,
		consumed: number,
		durationSeconds: number,
	): Promise<LimiterRecord> {
		const { db, dialect } = await this.#db();
		const n = this.#names(dialect);
		const ms = durationSeconds * 1000;
		const expire = Date.now() + ms;
		const conflict =
			dialect === "mysql"
				? "ON DUPLICATE KEY UPDATE"
				: `ON CONFLICT (${n.key}) DO UPDATE SET`;
		await db.rawQuery(
			`INSERT INTO ${n.table} (${n.key}, ${n.points}, ${n.expire}) VALUES (?, ?, ?) ` +
				`${conflict} ${n.points} = ?, ${n.expire} = ?`,
			[this.#key(key), consumed, expire, consumed, expire],
		);
		return { consumed, msBeforeNext: ms };
	}

	async get(key: string): Promise<LimiterRecord | null> {
		const { db, dialect } = await this.#db();
		const n = this.#names(dialect);
		const rows = await db.rawQuery(
			`SELECT ${n.points} AS points, ${n.expire} AS expire FROM ${n.table} WHERE ${n.key} = ?`,
			[this.#key(key)],
		);
		return this.#record(rows[0], Date.now());
	}

	async delete(key: string): Promise<boolean> {
		const { db, dialect } = await this.#db();
		const n = this.#names(dialect);
		const id = this.#key(key);
		const rows = await db.rawQuery(
			`SELECT ${n.key} AS id FROM ${n.table} WHERE ${n.key} = ?`,
			[id],
		);
		await db.rawQuery(`DELETE FROM ${n.table} WHERE ${n.key} = ?`, [id]);
		return rows.length > 0;
	}

	async clear(): Promise<void> {
		const { db, dialect } = await this.#db();
		await db.rawQuery(`DELETE FROM ${this.#names(dialect).table}`, []);
	}
}

/** Store factories for {@link LimiterConfig.stores}. */
export const limiterStores = {
	/** In this process's memory. Single process. */
	memory(): LimiterStoreFactory {
		return () => new MemoryLimiterStore();
	},

	/**
	 * In Redis, shared by every process. `connection` takes a client, a
	 * function answering one, or the NAME of a `@c9up/quasar` connection.
	 */
	redis(options: {
		connection: LimiterRedisSource | string;
		prefix?: string;
	}): LimiterStoreFactory {
		const { connection } = options;
		const source: LimiterRedisSource =
			typeof connection === "string"
				? () =>
						loadQuasarConnection({
							pkg: "blackhole",
							name: connection,
							required: LIMITER_COMMANDS,
							isConnection: isLimiterRedisClient,
							what: "the limiter",
							alternative: "or pass a client instead of a connection name",
							raise: (reason, message, cause) =>
								reason === "quasar-missing"
									? new E_BLACKHOLE_QUASAR_MISSING([message], { cause })
									: new E_BLACKHOLE_INCOMPLETE_CONNECTION([message], { cause }),
						})
				: connection;
		return () => new RedisLimiterStore(source, { prefix: options.prefix });
	},

	/**
	 * In a SQL table (PostgreSQL, MySQL, SQLite), shared by every process.
	 * `connection` takes a client of the {@link LimiterDatabase} shape (atlas'
	 * `db`), a function answering one, or the NAME of an atlas connection;
	 * left out, atlas' default connection — loaded on first use, so atlas is
	 * needed only by an application that counts this way. `tableName`
	 * defaults to `rate_limits`.
	 *
	 * Upstream names the connection `connectionName`; here it is `connection`,
	 * as for {@link limiterStores.redis}, because it also takes the client
	 * itself — the way this package stays free of any data layer.
	 */
	database(
		options: {
			connection?: LimiterDatabaseSource | string;
			tableName?: string;
		} = {},
	): LimiterStoreFactory {
		const { connection, tableName } = options;
		const source: LimiterDatabaseSource =
			connection === undefined || typeof connection === "string"
				? () => atlasDatabase(connection)
				: connection;
		// The table name is checked here, when the config is read, rather than
		// on the first request that counts.
		assertTableName(tableName);
		return () => new DatabaseLimiterStore(source, { tableName });
	},
};

// ── The limiter ──────────────────────────────────────────────────────────

/** A budget: `requests` per `duration`, optionally blocking for `blockDuration`. */
export interface LimiterOptions {
	requests: number;
	/** Seconds, or a duration string (`'1 minute'`). */
	duration: number | string;
	/** Seconds, or a duration string — how long a key over its budget is held. */
	blockDuration?: number | string;
}

/** Counts against one budget in one store. */
export class Limiter {
	readonly #store: LimiterStore;
	/** Requests allowed per window. */
	readonly requests: number;
	/** The window, in seconds. */
	readonly duration: number;
	/** How long a key over its budget is blocked, in seconds (0: not blocked). */
	readonly blockDuration: number;

	constructor(store: LimiterStore, options: LimiterOptions) {
		if (!Number.isSafeInteger(options.requests) || options.requests <= 0) {
			throw new E_BLACKHOLE_INVALID_RATE_LIMIT([
				`limiter requests must be a positive whole number, got ${String(options.requests)}.`,
			]);
		}
		this.#store = store;
		this.requests = options.requests;
		this.duration = durationToSeconds(options.duration, "a limiter duration");
		if (this.duration <= 0) {
			throw new E_BLACKHOLE_INVALID_RATE_LIMIT([
				"limiter duration must be longer than zero.",
			]);
		}
		this.blockDuration =
			options.blockDuration === undefined
				? 0
				: durationToSeconds(options.blockDuration, "a limiter blockDuration");
	}

	/** The store's name (`memory`, `redis`…). */
	get name(): string {
		return this.#store.name;
	}

	#response(record: LimiterRecord): LimiterResponse {
		return new LimiterResponse({
			limit: this.requests,
			remaining: Math.max(0, this.requests - record.consumed),
			consumed: record.consumed,
			availableIn: Math.max(0, Math.ceil(record.msBeforeNext / 1000)),
		});
	}

	/**
	 * Count `amount` requests (default 1) against `key`. Throws a
	 * {@link ThrottleException} once the key is over its budget — and, with a
	 * `blockDuration`, blocks it for that long the moment it goes over.
	 */
	async consume(key: string, amount = 1): Promise<LimiterResponse> {
		const points = amount > 0 ? amount : 1;
		let record = await this.#store.increment(key, points, this.duration);
		if (record.consumed > this.requests) {
			// Block on the request that went over, not on every later one: a
			// blocked key keeps its block, it does not have it extended.
			if (this.blockDuration > 0 && record.consumed <= this.requests + points) {
				record = await this.#store.set(
					key,
					record.consumed,
					this.blockDuration,
				);
			}
			throw new E_TOO_MANY_REQUESTS(this.#response(record));
		}
		return this.#response(record);
	}

	/** Count `amount` requests (default 1) without throwing. */
	async increment(key: string, amount = 1): Promise<LimiterResponse> {
		const points = amount > 0 ? amount : 1;
		return this.#response(
			await this.#store.increment(key, points, this.duration),
		);
	}

	/** Give `amount` requests (default 1) back, never below zero. */
	async decrement(key: string, amount = 1): Promise<LimiterResponse> {
		const existing = await this.#store.get(key);
		if (existing === null) return this.set(key, 0);
		const points = Math.min(amount > 0 ? amount : 1, existing.consumed);
		if (points <= 0) return this.#response(existing);
		return this.#response(
			await this.#store.increment(key, -points, this.duration),
		);
	}

	/** Block `key` for `duration`: every request until then is refused. */
	async block(
		key: string,
		duration: number | string,
	): Promise<LimiterResponse> {
		return this.#response(
			await this.#store.set(
				key,
				this.requests + 1,
				durationToSeconds(duration, "a block duration"),
			),
		);
	}

	/** Set `key`'s count to `requests`, for `duration` (default: the window). */
	async set(
		key: string,
		requests: number,
		duration?: number | string,
	): Promise<LimiterResponse> {
		const seconds =
			duration === undefined
				? this.duration
				: durationToSeconds(duration, "a limiter duration");
		return this.#response(await this.#store.set(key, requests, seconds));
	}

	/** Forget `key`. */
	delete(key: string): Promise<boolean> {
		return this.#store.delete(key);
	}

	/** Where `key` stands, or `null` when it has nothing counted. */
	async get(key: string): Promise<LimiterResponse | null> {
		const record = await this.#store.get(key);
		return record === null ? null : this.#response(record);
	}

	/** Requests `key` has left. */
	async remaining(key: string): Promise<number> {
		return (await this.get(key))?.remaining ?? this.requests;
	}

	/** Seconds until `key` may make a request again (0 when it may now). */
	async availableIn(key: string): Promise<number> {
		const response = await this.get(key);
		return response && response.remaining === 0 ? response.availableIn : 0;
	}

	/** Whether `key` has used its whole budget. */
	async isBlocked(key: string): Promise<boolean> {
		const response = await this.get(key);
		return response !== null && response.consumed >= response.limit;
	}

	/**
	 * Run `callback` if `key` has budget left, counting it. Returns the
	 * callback's result, or `undefined` without running it when over budget.
	 */
	async attempt<T>(
		key: string,
		callback: () => T | Promise<T>,
		amount?: number,
	): Promise<T | undefined> {
		const response = await this.get(key);
		if (response && response.consumed > response.limit) return undefined;
		try {
			await this.consume(key, amount);
		} catch (error) {
			if (error instanceof E_TOO_MANY_REQUESTS) return undefined;
			throw error;
		}
		return callback();
	}

	/**
	 * Run `callback`, counting only its FAILURES against `key` — the shape of
	 * a login: a wrong password costs an attempt, a right one clears the
	 * count. Returns `[error, null]` without running the callback when the key
	 * has no attempt left, `[null, result]` on success; a failure is re-thrown
	 * after it is counted (and the key blocked, with a `blockDuration`, once
	 * it runs out).
	 */
	async penalize<T>(
		key: string,
		callback: () => T | Promise<T>,
		amount?: number,
	): Promise<[ThrottleException, null] | [null, T]> {
		const response = await this.get(key);
		if (response && response.remaining <= 0) {
			return [new E_TOO_MANY_REQUESTS(response), null];
		}
		let result: T;
		try {
			result = await callback();
		} catch (error) {
			const { consumed, limit } = await this.increment(key, amount);
			if (consumed >= limit && this.blockDuration > 0) {
				await this.block(key, this.blockDuration);
			}
			throw error;
		}
		await this.delete(key);
		return [null, result];
	}

	/** Forget every key of this limiter's store. */
	clear(): Promise<void> {
		return this.#store.clear();
	}
}

/** One budget of a {@link MultiLimiter}: the limit, and the key it counts. */
export interface MultiLimiterOptions extends LimiterOptions {
	key: string | number;
}

/**
 * Several limits counted together — "5 a minute AND 100 a day" on one login,
 * or one budget per user plus one per IP — each limiter on its own key.
 */
export class MultiLimiter {
	readonly #limiters: { key: string; limiter: Limiter }[];

	constructor(limiters: { key: string | number; limiter: Limiter }[]) {
		this.#limiters = limiters.map(({ key, limiter }) => ({
			key: String(key),
			limiter,
		}));
	}

	/** The limiters, each with its key. */
	list(): readonly { key: string; limiter: Limiter }[] {
		return this.#limiters;
	}

	/**
	 * Count one request on every limiter, in order. Throws the first
	 * {@link ThrottleException}; the limiters before it have counted.
	 */
	async consume(): Promise<LimiterResponse[]> {
		const responses: LimiterResponse[] = [];
		for (const { key, limiter } of this.#limiters) {
			responses.push(await limiter.consume(key));
		}
		return responses;
	}

	/** Count one request on every limiter, without throwing. */
	increment(): Promise<LimiterResponse[]> {
		return Promise.all(
			this.#limiters.map(({ key, limiter }) => limiter.increment(key)),
		);
	}

	/** Give one request back on every limiter, never below zero. */
	decrement(): Promise<LimiterResponse[]> {
		return Promise.all(
			this.#limiters.map(({ key, limiter }) => limiter.decrement(key)),
		);
	}

	/** Where each key stands (`null` for one with nothing counted). */
	get(): Promise<(LimiterResponse | null)[]> {
		return Promise.all(
			this.#limiters.map(({ key, limiter }) => limiter.get(key)),
		);
	}

	/** Set every key's count to `requests`, for `duration` (default: each window). */
	set(
		requests: number,
		duration?: number | string,
	): Promise<LimiterResponse[]> {
		return Promise.all(
			this.#limiters.map(({ key, limiter }) =>
				limiter.set(key, requests, duration),
			),
		);
	}

	/** Forget every key. */
	delete(): Promise<boolean[]> {
		return Promise.all(
			this.#limiters.map(({ key, limiter }) => limiter.delete(key)),
		);
	}

	/**
	 * Run `callback` if every limiter has budget left, counting it on all of
	 * them. `undefined`, without running it, when one is over.
	 */
	async attempt<T>(callback: () => T | Promise<T>): Promise<T | undefined> {
		try {
			await this.consume();
		} catch (error) {
			if (error instanceof E_TOO_MANY_REQUESTS) return undefined;
			throw error;
		}
		return callback();
	}

	/**
	 * Run `callback`, counting only its FAILURES, on every limiter: a key
	 * that runs out is blocked for its limiter's `blockDuration`. `[error,
	 * null]` without running it when one key has no attempt left; on success
	 * every key is cleared and the result is `[null, result]`.
	 */
	async penalize<T>(
		callback: () => T | Promise<T>,
	): Promise<[ThrottleException, null] | [null, T]> {
		const responses = await this.get();
		const exhausted = responses.find(
			(response) => response !== null && response.remaining <= 0,
		);
		if (exhausted) return [new E_TOO_MANY_REQUESTS(exhausted), null];
		let result: T;
		try {
			result = await callback();
		} catch (error) {
			const counted = await this.increment();
			for (const [index, response] of counted.entries()) {
				const entry = this.#limiters[index];
				if (
					entry !== undefined &&
					entry.limiter.blockDuration > 0 &&
					response.consumed >= response.limit
				) {
					await entry.limiter.block(entry.key, entry.limiter.blockDuration);
				}
			}
			throw error;
		}
		await this.delete();
		return [null, result];
	}
}

// ── HTTP ─────────────────────────────────────────────────────────────────

/** What a throttle middleware reads off the HTTP context. */
export interface LimiterHttpContext extends ThrottleContext {
	request: ThrottleContext["request"] & { ip(): string };
}

/**
 * A limit for HTTP requests, built fluently:
 * `allowRequests(10).every('1 minute').usingKey(id).blockFor('5 mins')`.
 */
export class HttpLimiter {
	readonly #manager: () => LimiterManager;
	#requests?: number;
	#duration?: number | string;
	#blockDuration?: number | string;
	#store?: string;
	#key?: string | number;
	#exceptionModifier: (error: ThrottleException) => void = () => {};

	/**
	 * @param manager - the manager, or a function answering it when the limit
	 * is applied (so one built at import time counts in the store configured
	 * later).
	 */
	constructor(manager: LimiterManager | (() => LimiterManager)) {
		this.#manager = typeof manager === "function" ? manager : () => manager;
	}

	/** Count in the named store instead of the default one. */
	store(name: string): this {
		this.#store = name;
		return this;
	}

	allowRequests(requests: number): this {
		this.#requests = requests;
		return this;
	}

	/** The window: seconds, or a duration string. */
	every(duration: number | string): this {
		this.#duration = duration;
		return this;
	}

	/** Count under this key instead of the client IP. */
	usingKey(key: string | number | undefined | null): this {
		this.#key = key ?? undefined;
		return this;
	}

	/** Block a client that goes over its budget for this long. */
	blockFor(duration: number | string): this {
		this.#blockDuration = duration;
		return this;
	}

	/** Adjust the 429 before it is thrown (message, status, headers). */
	limitExceeded(callback: (error: ThrottleException) => void): this {
		this.#exceptionModifier = callback;
		return this;
	}

	toJSON(): {
		store?: string;
		requests?: number;
		duration?: number | string;
		blockDuration?: number | string;
	} {
		return {
			store: this.#store,
			requests: this.#requests,
			duration: this.#duration,
			blockDuration: this.#blockDuration,
		};
	}

	/**
	 * Count this request under `<prefix>_<key>` (the client IP by default; an
	 * IPv6 client by its /64). Throws a {@link ThrottleException} when over.
	 */
	async throttle(
		prefix: string,
		ctx: LimiterHttpContext,
	): Promise<LimiterResponse> {
		if (this.#requests === undefined || this.#duration === undefined) {
			throw new E_BLACKHOLE_INCOMPLETE_THROTTLE([prefix]);
		}
		const options: LimiterOptions = {
			requests: this.#requests,
			duration: this.#duration,
			blockDuration: this.#blockDuration,
		};
		const manager = this.#manager();
		const limiter =
			this.#store === undefined
				? manager.use(options)
				: manager.use(this.#store, options);
		const key = `${prefix}_${this.#key ?? `ip_${clientKey(ctx.request.ip())}`}`;
		const current = await limiter.get(key);
		if (current && current.consumed > current.limit) {
			const error = new E_TOO_MANY_REQUESTS(current);
			this.#exceptionModifier(error);
			throw error;
		}
		try {
			return await limiter.consume(key);
		} catch (error) {
			if (error instanceof E_TOO_MANY_REQUESTS) this.#exceptionModifier(error);
			throw error;
		}
	}
}

/** The limiter configuration: the stores, and which one counts by default. */
export interface LimiterConfig {
	default: string;
	stores: Record<string, LimiterStoreFactory>;
}

/** A throttle middleware, as `limiter.define` returns it. */
export type ThrottleMiddleware = (
	ctx: LimiterHttpContext,
	next: () => Promise<void>,
) => Promise<void>;

/** Hands out limiters, one per store and budget, and defines throttles. */
export class LimiterManager {
	readonly config: LimiterConfig;
	/** The limiters handed out, by store name, then by budget. */
	readonly #limiters = new Map<string, Map<string, Limiter>>();

	constructor(config: LimiterConfig) {
		if (!config.stores[config.default]) {
			const known = Object.keys(config.stores);
			throw new E_BLACKHOLE_UNKNOWN_STORE([
				`the limiter's default store "${config.default}" is not in \`stores\`` +
					(known.length > 0 ? ` (declared: ${known.join(", ")}).` : "."),
			]);
		}
		this.config = config;
	}

	/** A limiter in the default store, or in the named one. */
	use(options: LimiterOptions): Limiter;
	use(store: string, options: LimiterOptions): Limiter;
	use(
		storeOrOptions: string | LimiterOptions,
		maybe?: LimiterOptions,
	): Limiter {
		const store =
			typeof storeOrOptions === "string" ? storeOrOptions : this.config.default;
		const options = typeof storeOrOptions === "string" ? maybe : storeOrOptions;
		if (options === undefined) {
			throw new E_BLACKHOLE_LIMITER_OPTIONS_MISSING([
				"limiter.use() needs the allowed requests and the duration.",
			]);
		}
		const factory = this.config.stores[store];
		if (factory === undefined) {
			throw new E_BLACKHOLE_UNKNOWN_STORE([
				`unknown limiter store "${store}".`,
			]);
		}
		const id = [
			store,
			options.requests,
			options.duration,
			options.blockDuration ?? "",
		].join("|");
		let storeLimiters = this.#limiters.get(store);
		if (storeLimiters === undefined) {
			storeLimiters = new Map();
			this.#limiters.set(store, storeLimiters);
		}
		const cached = storeLimiters.get(id);
		if (cached) return cached;
		const limiter = new Limiter(factory(), options);
		storeLimiters.set(id, limiter);
		return limiter;
	}

	/**
	 * Several limits counted together, each on its own key, in the default
	 * store or in the named one:
	 *
	 *   limiter.multi([
	 *     { key: `login_${ip}`, requests: 5, duration: '1 minute' },
	 *     { key: `login_${ip}`, requests: 100, duration: '1 day' },
	 *   ])
	 */
	multi(options: MultiLimiterOptions[]): MultiLimiter;
	multi(store: string, options: MultiLimiterOptions[]): MultiLimiter;
	multi(
		storeOrOptions: string | MultiLimiterOptions[],
		maybe?: MultiLimiterOptions[],
	): MultiLimiter {
		const store =
			typeof storeOrOptions === "string" ? storeOrOptions : this.config.default;
		const options = typeof storeOrOptions === "string" ? maybe : storeOrOptions;
		if (options === undefined || options.length === 0) {
			throw new E_BLACKHOLE_LIMITER_OPTIONS_MISSING([
				"limiter.multi() needs the options of one or more limiters.",
			]);
		}
		return new MultiLimiter(
			options.map(({ key, ...budget }) => ({
				key,
				limiter: this.use(store, budget),
			})),
		);
	}

	/** Start an HTTP limit: `allowRequests(n).every(duration)…`. */
	allowRequests(requests: number): HttpLimiter {
		return new HttpLimiter(this).allowRequests(requests);
	}

	/** No limit — what a `define` builder returns for requests it lets through. */
	noLimit(): null {
		return null;
	}

	/**
	 * A route middleware enforcing the limit `builder` returns for each
	 * request (`null` lets the request through uncounted). Over the limit it
	 * throws a {@link ThrottleException}; otherwise the response carries
	 * `X-RateLimit-Limit` and `X-RateLimit-Remaining`.
	 */
	define(
		name: string,
		builder: (
			ctx: LimiterHttpContext,
		) => HttpLimiter | null | Promise<HttpLimiter | null>,
	): ThrottleMiddleware {
		return defineThrottle(name, builder);
	}

	/**
	 * Empty every store — or the named ones only — whether this process has
	 * handed out limiters from it or not.
	 *
	 * NAMED DEVIATION from @adonisjs/limiter, whose `clear()` reaches only the
	 * stores a limiter was handed out from in this process: a fresh process
	 * (a test run, a second instance) clearing a shared Redis or database
	 * store left the counters another one wrote, and the next `consume`
	 * throttled. Here a store's own `clear()` runs as well — for Redis, every
	 * key of its prefix; for the database, its table — on a store built for
	 * the purpose; the memory stores of the handed-out limiters are cleared
	 * one by one, as before (each limiter has its own).
	 */
	async clear(stores?: string[]): Promise<void> {
		for (const store of stores ?? Object.keys(this.config.stores)) {
			const factory = this.config.stores[store];
			if (factory === undefined) continue;
			for (const limiter of this.#limiters.get(store)?.values() ?? []) {
				await limiter.clear();
			}
			await factory().clear();
		}
	}
}

/**
 * The middleware behind `define`, apart from any manager: the builder is
 * called per request and brings its own.
 */
export function defineThrottle(
	name: string,
	builder: (
		ctx: LimiterHttpContext,
	) => HttpLimiter | null | Promise<HttpLimiter | null>,
): ThrottleMiddleware {
	const middleware: ThrottleMiddleware = async (ctx, next) => {
		const limiter = await builder(ctx);
		if (!limiter) return next();
		const response = await limiter.throttle(name, ctx);
		await next();
		ctx.response.header("X-RateLimit-Limit", String(response.limit));
		ctx.response.header("X-RateLimit-Remaining", String(response.remaining));
	};
	Object.defineProperty(middleware, "name", { value: `${name}Throttle` });
	return middleware;
}
