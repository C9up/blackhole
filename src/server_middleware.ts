/**
 * Blackhole's server-tier middleware — Ream adapter.
 *
 * Runs where every request passes, before route matching decides anything:
 * the rate limit, the shield (path traversal, parameter pollution), CORS and
 * the protective headers reach a 404 too. The router-tier
 * `@c9up/blackhole/middleware` then runs CSRF, once the body is parsed, and
 * skips what this one already did.
 *
 * @example
 *   // start/kernel.ts
 *   server.use([() => import('@c9up/blackhole/server_middleware')])
 *   router.use([() => import('@c9up/blackhole/middleware')])
 */

import { blackholeServerMiddleware, type ReamContext } from "./middleware.js";

export default class BlackholeServerMiddleware {
	handle(ctx: ReamContext, next: () => Promise<void> | void): Promise<void> {
		return blackholeServerMiddleware(ctx, next);
	}
}

export { blackholeServerMiddleware };
