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
	SecurityHeadersConfig,
} from "./index.js";

export interface BlackholeConfig {
	/** Enable XSS response sanitization (default: true). */
	xss?: boolean;
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
		 * Distributed counter for horizontal scale. When set, counting + the 429
		 * decision run in JS against this store and the in-process Rust counter is
		 * disabled. Omit for the single-process default.
		 */
		store?: RateLimitStore;
	};
	/** Reject path-traversal sequences in the request path (default: true). */
	pathTraversal?: boolean;
	/** Reject duplicate query params / HTTP parameter pollution (default: true). */
	paramPollution?: boolean;
	/** Protective response headers. Defaults applied when omitted; `false` to disable. */
	securityHeaders?: SecurityHeadersConfig | false;
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
