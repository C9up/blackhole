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

import { clientKey } from "./clientKey.js";
import { durationToSeconds } from "./duration.js";
import { quasarConnection as loadQuasarConnection } from "./vendor/quasarConnection.js";

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
	};
	response: {
		header(name: string, value: string): unknown;
		status(code: number): unknown;
		send(body: unknown): unknown;
	};
}

/**
 * A key over its budget. Thrown by `consume` and by a throttle middleware;
 * the HTTP layer renders it as a 429 through {@link ThrottleException.handle}.
 */
export class ThrottleException extends Error {
	readonly code = "E_TOO_MANY_REQUESTS";
	/** The translation key of the message (`ctx.i18n.t`). */
	readonly identifier = "errors.E_TOO_MANY_REQUESTS";
	status = 429;
	readonly response: LimiterResponse;
	/** Replaces the default `X-RateLimit-*` / `Retry-After` headers when set. */
	headers?: Record<string, string | number>;
	translation?: { identifier: string; data?: Record<string, unknown> };

	constructor(response: LimiterResponse, options?: ErrorOptions) {
		super("Too many requests", options);
		this.name = "ThrottleException";
		this.response = response;
	}

	/** The rate-limit headers a 429 carries by default. */
	getDefaultHeaders(): Record<string, string | number> {
		return {
			"X-RateLimit-Limit": this.response.limit,
			"X-RateLimit-Remaining": this.response.remaining,
			"Retry-After": this.response.availableIn,
			"X-RateLimit-Reset": new Date(
				Date.now() + this.response.availableIn * 1000,
			).toISOString(),
		};
	}

	/** The message, translated through `ctx.i18n` when the request has one. */
	getResponseMessage(ctx: object): string {
		const i18n: unknown = Reflect.get(ctx, "i18n");
		const t: unknown =
			typeof i18n === "object" && i18n !== null
				? Reflect.get(i18n, "t")
				: undefined;
		if (typeof t !== "function") return this.message;
		const translated: unknown = Reflect.apply(t, i18n, [
			this.translation?.identifier ?? this.identifier,
			this.translation?.data ?? {},
			this.message,
		]);
		return typeof translated === "string" ? translated : this.message;
	}

	setMessage(message: string): this {
		this.message = message;
		return this;
	}

	setStatus(status: number): this {
		this.status = status;
		return this;
	}

	setHeaders(headers: Record<string, string | number>): this {
		this.headers = headers;
		return this;
	}

	/** Translate the message under `identifier` instead of the default one. */
	t(identifier: string, data?: Record<string, unknown>): this {
		this.translation = { identifier, data };
		return this;
	}

	/**
	 * Render the 429: the headers, then a body shaped for what the client
	 * accepts — the message as text for a browser, `{ errors: [...] }` for
	 * JSON, the JSON:API error object for `application/vnd.api+json`.
	 */
	async handle(error: ThrottleException, ctx: ThrottleContext): Promise<void> {
		const message = error.getResponseMessage(ctx);
		const headers = error.headers ?? error.getDefaultHeaders();
		for (const [name, value] of Object.entries(headers)) {
			ctx.response.header(name, String(value));
		}
		ctx.response.status(error.status);
		const accept = ctx.request.header("accept") ?? "";
		if (accept.includes("application/vnd.api+json")) {
			ctx.response.send({
				errors: [
					{
						code: error.code,
						title: message,
						meta: { retryAfter: error.response.availableIn },
					},
				],
			});
		} else if (accept.includes("json") && !accept.includes("text/html")) {
			ctx.response.send({
				errors: [{ message, retryAfter: error.response.availableIn }],
			});
		} else {
			ctx.response.send(message);
		}
	}
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

	async #client(): Promise<LimiterRedisClient> {
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
						loadQuasarConnection<LimiterRedisClient>({
							pkg: "blackhole",
							name: connection,
							required: [
								"incrby",
								"pexpire",
								"pttl",
								"get",
								"set",
								"del",
								"scan",
							],
							what: "the limiter",
							alternative: "or pass a client instead of a connection name",
							raise: (_reason, message, cause) => new Error(message, { cause }),
						})
				: connection;
		return () => new RedisLimiterStore(source, { prefix: options.prefix });
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
			throw new Error(
				`[blackhole] limiter requests must be a positive whole number, got ${String(options.requests)}.`,
			);
		}
		this.#store = store;
		this.requests = options.requests;
		this.duration = durationToSeconds(options.duration, "a limiter duration");
		if (this.duration <= 0) {
			throw new Error("[blackhole] limiter duration must be longer than zero.");
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
			throw new ThrottleException(this.#response(record));
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
			if (error instanceof ThrottleException) return undefined;
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
			return [new ThrottleException(response), null];
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
			throw new Error(
				`[blackhole] cannot throttle "${prefix}": set allowRequests() and every() on its limiter.`,
			);
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
			const error = new ThrottleException(current);
			this.#exceptionModifier(error);
			throw error;
		}
		try {
			return await limiter.consume(key);
		} catch (error) {
			if (error instanceof ThrottleException) this.#exceptionModifier(error);
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
	readonly #limiters = new Map<string, Limiter>();

	constructor(config: LimiterConfig) {
		if (!config.stores[config.default]) {
			const known = Object.keys(config.stores);
			throw new Error(
				`[blackhole] the limiter's default store "${config.default}" is not in \`stores\`` +
					(known.length > 0 ? ` (declared: ${known.join(", ")}).` : "."),
			);
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
			throw new Error(
				"[blackhole] limiter.use() needs the allowed requests and the duration.",
			);
		}
		const factory = this.config.stores[store];
		if (factory === undefined) {
			throw new Error(`[blackhole] unknown limiter store "${store}".`);
		}
		const id = [
			store,
			options.requests,
			options.duration,
			options.blockDuration ?? "",
		].join("|");
		const cached = this.#limiters.get(id);
		if (cached) return cached;
		const limiter = new Limiter(factory(), options);
		this.#limiters.set(id, limiter);
		return limiter;
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

	/** Forget every key of every limiter handed out so far. */
	async clear(): Promise<void> {
		for (const limiter of this.#limiters.values()) await limiter.clear();
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
