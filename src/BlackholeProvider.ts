/**
 * BlackholeProvider — Ream provider that boots the security filter from
 * `config/blackhole.ts` and registers it in the IoC container.
 *
 * Middleware resolves the Blackhole instance from the container at request
 * time — no inline config needed.
 *
 * @example
 *   // adonisrc.ts / reamrc.ts
 *   providers: [() => import('@c9up/blackhole/provider')]
 */
import type { BlackholeConfig } from "./config.js";
import { createBlackhole } from "./index.js";

interface BlackholeContainer {
	singleton(token: unknown, factory: () => unknown): void;
}

interface BlackholeConfigStore {
	get<T = unknown>(key: string): T | undefined;
}

export interface BlackholeAppContext {
	container: BlackholeContainer;
	config: BlackholeConfigStore;
}

export const BLACKHOLE_KEY = "blackhole";

export default class BlackholeProvider {
	constructor(protected app: BlackholeAppContext) {}

	register() {
		this.app.container.singleton(BLACKHOLE_KEY, () => {
			const config = this.app.config.get<BlackholeConfig>("blackhole") ?? {};
			return createBlackhole({
				xss: config.xss,
				csrf: config.csrf,
				rateLimit: config.rateLimit,
				pathTraversal: config.pathTraversal,
				paramPollution: config.paramPollution,
				securityHeaders: config.securityHeaders,
				cors: config.cors,
				// Sign CSRF tokens with the app secret. Fall back to APP_KEY so the
				// common case (no explicit `secret` in config/blackhole.ts) still
				// gets signed tokens; createBlackhole throws if CSRF is on yet
				// neither is set.
				secret: config.secret ?? process.env.APP_KEY,
			});
		});
	}
}
