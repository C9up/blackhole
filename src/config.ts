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

import type { CorsConfig, CsrfConfig, SecurityHeadersConfig } from "./index.js";

export interface BlackholeConfig {
	/** Enable XSS response sanitization (default: true). */
	xss?: boolean;
	/** CSRF validation — `true`/`false` to toggle, or an object (exceptRoutes, methods, cookie). */
	csrf?: boolean | CsrfConfig;
	/** Rate limiting configuration. Omit to disable. */
	rateLimit?: {
		max: number;
		windowSeconds: number;
	};
	/** Reject path-traversal sequences in the request path (default: true). */
	pathTraversal?: boolean;
	/** Reject duplicate query params / HTTP parameter pollution (default: true). */
	paramPollution?: boolean;
	/** Protective response headers. Defaults applied when omitted; `false` to disable. */
	securityHeaders?: SecurityHeadersConfig | false;
	/** Cross-Origin Resource Sharing policy. Omit to leave CORS unmanaged. */
	cors?: CorsConfig;
}

/** Typed config helper — identity function for editor inference. */
export function defineConfig(config: BlackholeConfig): BlackholeConfig {
	return config;
}
