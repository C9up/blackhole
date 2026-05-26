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

export interface BlackholeConfig {
	/** Enable XSS response sanitization (default: true). */
	xss?: boolean;
	/** Enable CSRF token validation (default: true). */
	csrf?: boolean;
	/** Rate limiting configuration. Omit to disable. */
	rateLimit?: {
		max: number;
		windowSeconds: number;
	};
}

/** Typed config helper — identity function for editor inference. */
export function defineConfig(config: BlackholeConfig): BlackholeConfig {
	return config;
}
