/**
 * Blackhole configuration — declared in `config/blackhole.ts` of the user app.
 *
 * @example
 *   // config/blackhole.ts
 *   import { defineConfig } from '@c9up/blackhole'
 *   export default defineConfig({
 *     xss: true,
 *     csrf: true,
 *     rateLimit: { max: 100, windowSeconds: 60 },
 *   })
 */

import type {
	CorsConfig,
	CsrfConfig,
	RateLimitContext,
	RateLimitStore,
	SecurityHeadersOptions,
	XssConfig,
} from "./index.js";
import type { LimiterConfig } from "./limiter.js";
import type { RateLimitStoreFactory } from "./stores.js";

/**
 * The protective headers are top-level keys — `xFrame`, `hsts`,
 * `contentTypeSniffing`, `csp`, `referrerPolicy`, `permissionsPolicy` — each
 * `{ enabled, ... }` and on by default (see {@link SecurityHeadersOptions}).
 */
export interface BlackholeConfig extends SecurityHeadersOptions {
	/**
	 * XSS response sanitization of `text/html` fragments (default: true).
	 * `false` turns it off; an object keeps it on and opts attributes back in.
	 */
	xss?: boolean | XssConfig;
	/** CSRF validation — `true`/`false` to toggle, or an object (exceptRoutes, methods, cookie). */
	csrf?: boolean | CsrfConfig;
	/**
	 * Rate limiting configuration. Omit to disable.
	 *
	 * Without a `store`, counting uses the Rust in-process counter — **single-process
	 * only**: each instance counts independently, so N instances allow ~N×`max`.
	 * For horizontal scale, provide a distributed `store` (e.g. Redis-backed) so
	 * the limit is shared across every process.
	 */
	rateLimit?: {
		max: number;
		windowSeconds: number;
		/**
		 * Resolve the counting key per request (parity with limiter's `usingKey`).
		 * Defaults to the client IP. e.g. per-user:
		 * `keyFor: (ctx) => String(ctx.auth?.user?.id ?? ctx.request.ip())`.
		 */
		keyFor?: (ctx: RateLimitContext) => string;
		/**
		 * Which named store counts — a key of {@link stores}. Read from the
		 * environment in the generated config, so a deployment shares its counter
		 * across processes without editing a file.
		 */
		default?: string;
		/**
		 * The counters this application can use, by name. Each is a factory from
		 * `stores.*`, built only when it is the one selected.
		 */
		stores?: Record<string, RateLimitStoreFactory>;
		/**
		 * A ready-made store instance — the single-store form, kept for configs
		 * written against it. Prefer `default` + `stores`.
		 *
		 * With either, counting and the 429 decision run in JS and the in-process
		 * Rust counter is disabled. With neither, the Rust counter answers, which
		 * is single-process only.
		 */
		store?: RateLimitStore;
	};
	/**
	 * The stores behind the per-route limits (`limiter.define` + `throttle`,
	 * and the manual `limiter.use(...)`), and which one counts by default.
	 * Omitted: one store, in this process's memory.
	 *
	 *   limiter: {
	 *     default: env.get('LIMITER_STORE', 'memory'),
	 *     stores: { memory: limiterStores.memory(), redis: limiterStores.redis({ connection: 'main' }) },
	 *   }
	 */
	limiter?: LimiterConfig;
	/** Reject path-traversal sequences in the request path (default: true). */
	pathTraversal?: boolean;
	/** Reject duplicate query params / HTTP parameter pollution (default: true). */
	paramPollution?: boolean;
	/** Cross-Origin Resource Sharing policy. Omit to leave CORS unmanaged. */
	cors?: CorsConfig;
	/**
	 * HMAC secret for signing CSRF tokens (signed double-submit). Set to your
	 * `APP_KEY` — e.g. `secret: env.get('APP_KEY')`. **Required** when CSRF is on:
	 * `createBlackhole` throws if it's missing (fail-closed, no silent fallback).
	 */
	secret?: string;
}

/** Typed config helper — identity function for editor inference. */
export function defineConfig(config: BlackholeConfig): BlackholeConfig {
	return config;
}
