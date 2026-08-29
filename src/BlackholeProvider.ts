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
import { type BlackholeOptions, createBlackhole } from "./index.js";

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

/**
 * The rate-limit options `createBlackhole` takes, with the configured store
 * resolved.
 *
 * `default` + `stores` first — the form an environment variable can steer. A
 * `store` instance is the single-store form kept for configs written against
 * it. Naming a store that does not exist throws rather than falling back: an
 * application that meant to share its counter across processes and silently
 * got the in-process one would allow N times its limit without a sign.
 */
function resolveRateLimit(
	rateLimit: BlackholeConfig["rateLimit"],
): BlackholeOptions["rateLimit"] {
	if (!rateLimit) return undefined;
	const { default: name, stores, store, ...rest } = rateLimit;

	if (stores && name !== undefined) {
		const selected = stores[name];
		if (!selected) {
			const known = Object.keys(stores);
			throw new Error(
				`[blackhole] config.blackhole.rateLimit names the store '${name}', which is not in \`stores\`. ` +
					(known.length > 0
						? `Declared: ${known.join(", ")}.`
						: "`stores` is empty — declare one with stores.memory() or stores.redis()."),
			);
		}
		return { ...rest, store: selected() };
	}

	if (stores && name === undefined) {
		throw new Error(
			"[blackhole] config.blackhole.rateLimit declares `stores` but no `default` naming which one counts. " +
				`Set default to one of: ${Object.keys(stores).join(", ")}.`,
		);
	}

	return { ...rest, store };
}

export default class BlackholeProvider {
	constructor(protected app: BlackholeAppContext) {}

	register() {
		this.app.container.singleton(BLACKHOLE_KEY, () => {
			const config = this.app.config.get<BlackholeConfig>("blackhole") ?? {};
			return createBlackhole({
				xss: config.xss,
				csrf: config.csrf,
				rateLimit: resolveRateLimit(config.rateLimit),
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
