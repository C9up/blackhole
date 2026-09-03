/**
 * Rate-limit store factories — `{ default, stores }` under `rateLimit`.
 *
 * The shape AdonisJS gives a package with several backends and one selected:
 * a `stores` namespace imported beside `defineConfig`, each entry that
 * namespace's result, and the selection read from the environment. Blackhole
 * took a ready-made `store` instance, which meant a config file had to build
 * the Redis client itself — and blackhole shipped no store at all, so every
 * application wrote the counter by hand.
 *
 *   import { defineConfig, stores } from '@c9up/blackhole'
 *
 *   export default defineConfig({
 *     rateLimit: {
 *       max: 100,
 *       windowSeconds: 60,
 *       default: env.get('RATE_LIMIT_STORE'),
 *       stores: {
 *         memory: stores.memory(),
 *         redis:  stores.redis({ connection: 'main' }),
 *       },
 *     },
 *   })
 *
 * Factories are lazy: only the store an application actually uses is built.
 */

import type { RateLimitStore } from "./index.js";
import { quasarConnection } from "./quasar.js";

/** A store, built on first use. */
export type RateLimitStoreFactory = () => RateLimitStore;

/** The Redis commands the counter issues. ioredis- and quasar-shaped. */
export interface RateLimitRedisClient {
	incr(key: string): Promise<number>;
	expire(key: string, seconds: number): Promise<unknown>;
	ttl(key: string): Promise<number>;
}

export type RateLimitRedisSource =
	| RateLimitRedisClient
	| (() => RateLimitRedisClient | Promise<RateLimitRedisClient>);

/**
 * Counts in this process's memory.
 *
 * Same reach as the Rust in-process counter — several instances each count
 * their own share, so N of them allow about N times the limit. It exists for
 * tests, and for a single-process deployment that wants the JS decision path.
 */
export class MemoryRateLimitStore implements RateLimitStore {
	readonly #windows = new Map<string, { count: number; expiresAt: number }>();
	#lastSweep = Date.now();

	/**
	 * How often expired windows are cleared out.
	 *
	 * A window is only ever replaced when its own key comes back, so a key that
	 * is seen once and never again used to stay for the life of the process.
	 * Keys are clients, and an attacker picks them freely — a rotating
	 * `X-Forwarded-For` grows this map until the process runs out of memory.
	 * Sweeping bounds it by the traffic of one window instead.
	 */
	static readonly #SWEEP_INTERVAL_MS = 30_000;

	/** How many windows are currently held. */
	get size(): number {
		return this.#windows.size;
	}

	async increment(
		key: string,
		windowSeconds: number,
	): Promise<{ count: number; resetSeconds: number }> {
		const now = Date.now();
		if (now - this.#lastSweep >= MemoryRateLimitStore.#SWEEP_INTERVAL_MS) {
			this.#sweep(now);
		}
		const current = this.#windows.get(key);
		if (!current || current.expiresAt <= now) {
			const expiresAt = now + windowSeconds * 1000;
			this.#windows.set(key, { count: 1, expiresAt });
			return { count: 1, resetSeconds: windowSeconds };
		}
		current.count += 1;
		return {
			count: current.count,
			resetSeconds: Math.max(1, Math.ceil((current.expiresAt - now) / 1000)),
		};
	}

	/** Drop every window that has already ended. */
	#sweep(now: number): void {
		for (const [key, window] of this.#windows) {
			if (window.expiresAt <= now) this.#windows.delete(key);
		}
		this.#lastSweep = now;
	}
}

/**
 * Counts in Redis, so every process shares one limit.
 *
 * `INCR` then `EXPIRE` on the first hit of a window: the expiry is set once,
 * never refreshed, or a client hitting the endpoint steadily would push the
 * window forward for ever and never be limited.
 */
export class RedisRateLimitStore implements RateLimitStore {
	readonly #source: RateLimitRedisSource;
	#resolved: RateLimitRedisClient | undefined;
	readonly #prefix: string;

	constructor(source: RateLimitRedisSource, options: { prefix?: string } = {}) {
		this.#source = source;
		this.#prefix = options.prefix ?? "blackhole:rate";
	}

	async #client(): Promise<RateLimitRedisClient> {
		if (this.#resolved) return this.#resolved;
		this.#resolved =
			typeof this.#source === "function" ? await this.#source() : this.#source;
		return this.#resolved;
	}

	async increment(
		key: string,
		windowSeconds: number,
	): Promise<{ count: number; resetSeconds: number }> {
		const client = await this.#client();
		const namespaced = `${this.#prefix}:${key}`;
		const count = await client.incr(namespaced);
		if (count === 1) {
			await client.expire(namespaced, windowSeconds);
			return { count, resetSeconds: windowSeconds };
		}
		const ttl = await client.ttl(namespaced);
		// A key with no expiry (-1) has lost the EXPIRE that should have followed
		// its INCR — the process died in between, or Redis dropped the second
		// command. Left alone the counter only climbs, so the client it belongs
		// to is refused for good and nothing in the request path can undo it.
		// Setting the expiry now costs one command and ends the lockout. (-2 is
		// a key that vanished between the INCR and the TTL; EXPIRE finds nothing
		// and does nothing, which is the right outcome too.)
		if (ttl < 0) {
			await client.expire(namespaced, windowSeconds);
			return { count, resetSeconds: windowSeconds };
		}
		return { count, resetSeconds: ttl };
	}
}

export const stores = {
	/** In this process's memory. Single process; see the class doc. */
	memory(): RateLimitStoreFactory {
		return () => new MemoryRateLimitStore();
	},

	/**
	 * In Redis, shared by every process. `connection` takes a client, a function
	 * answering one, or the NAME of a `@c9up/quasar` connection — the last
	 * resolved at first use, without blackhole importing quasar.
	 */
	redis(options: {
		connection: RateLimitRedisSource | string;
		prefix?: string;
	}): RateLimitStoreFactory {
		const source: RateLimitRedisSource =
			typeof options.connection === "string"
				? () => quasarConnection(options.connection as string)
				: options.connection;
		return () => new RedisRateLimitStore(source, { prefix: options.prefix });
	},
};
