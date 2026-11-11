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
import {
	assertNoRetiredOptions,
	type BlackholeOptions,
	createBlackhole,
} from "./index.js";
import { LimiterManager, limiterStores } from "./limiter.js";
import { clearLimiter, setLimiter } from "./services/limiter.js";

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

/** The container binding of the {@link LimiterManager} (`limiter.define`…). */
export const BLACKHOLE_LIMITER_KEY = "blackhole.limiter";

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

/**
 * The CSRF options, bound to the session when the application has one
 * configured (`config/session.ts`) and has not said otherwise: a kernel that
 * then runs blackhole before the session middleware is refused at the first
 * request, instead of issuing tokens bound to nothing.
 */
function bindCsrfToSession(
	csrf: BlackholeConfig["csrf"],
	hasSession: boolean,
): BlackholeOptions["csrf"] {
	if (typeof csrf === "object") {
		return csrf.session === undefined ? { ...csrf, session: hasSession } : csrf;
	}
	return { enabled: csrf ?? true, session: hasSession };
}

export default class BlackholeProvider {
	#limiter: LimiterManager | undefined;

	constructor(protected app: BlackholeAppContext) {}

	register() {
		// The per-route limits: `limiter` in the config, or one memory store.
		// Seated now, so `@c9up/blackhole/services/limiter` counts in the
		// configured store from the first throttled request.
		const limiterConfig = this.app.config.get<BlackholeConfig>("blackhole")
			?.limiter ?? {
			default: "memory",
			stores: { memory: limiterStores.memory() },
		};
		const limiter = new LimiterManager(limiterConfig);
		this.#limiter = limiter;
		setLimiter(limiter);
		this.app.container.singleton(BLACKHOLE_LIMITER_KEY, () => limiter);

		this.app.container.singleton(BLACKHOLE_KEY, () => {
			const config = this.app.config.get<BlackholeConfig>("blackhole") ?? {};
			// Checked on the config itself: the options below are picked key by
			// key, so a retired key would otherwise just never be read.
			assertNoRetiredOptions(config);
			return createBlackhole({
				xss: config.xss,
				csrf: bindCsrfToSession(
					config.csrf,
					this.app.config.get("session") !== undefined,
				),
				rateLimit: resolveRateLimit(config.rateLimit),
				pathTraversal: config.pathTraversal,
				paramPollution: config.paramPollution,
				xFrame: config.xFrame,
				hsts: config.hsts,
				contentTypeSniffing: config.contentTypeSniffing,
				csp: config.csp,
				referrerPolicy: config.referrerPolicy,
				permissionsPolicy: config.permissionsPolicy,
				cors: config.cors,
				// Sign CSRF tokens with the app secret. Fall back to APP_KEY so the
				// common case (no explicit `secret` in config/blackhole.ts) still
				// gets signed tokens; createBlackhole throws if CSRF is on yet
				// neither is set.
				secret: config.secret ?? process.env.APP_KEY,
			});
		});
	}

	shutdown() {
		if (this.#limiter) clearLimiter(this.#limiter);
	}
}
