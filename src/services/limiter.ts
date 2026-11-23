/**
 * The application's limiter, reachable from a route file without threading it
 * through:
 *
 *   import limiter from '@c9up/blackhole/services/limiter'
 *
 *   export const throttle = limiter.define('global', () =>
 *     limiter.allowRequests(10).every('1 minute'),
 *   )
 *
 * `BlackholeProvider` seats the manager it builds from `config/blackhole.ts`
 * (`limiter: { default, stores }`). A route file is usually imported before
 * that, which is fine: a limit reaches the manager only when a request is
 * throttled.
 */

import { E_BLACKHOLE_LIMITER_OPTIONS_MISSING } from "../errors.js";
import {
	defineThrottle,
	HttpLimiter,
	type Limiter,
	type LimiterHttpContext,
	LimiterManager,
	type LimiterOptions,
	limiterStores,
	type MultiLimiter,
	type MultiLimiterOptions,
	type ThrottleMiddleware,
} from "../limiter.js";

let instance: LimiterManager | undefined;

/** Seat the manager — called by BlackholeProvider, or by an app wiring its own. */
export function setLimiter(manager: LimiterManager): void {
	instance = manager;
}

/** Drop the manager IF it is still the one passed in. */
export function clearLimiter(manager: LimiterManager): void {
	if (instance === manager) instance = undefined;
}

/**
 * The seated manager — or, when nothing seated one (a standalone app, a
 * test), one counting in this process's memory, built once.
 */
function manager(): LimiterManager {
	instance ??= new LimiterManager({
		default: "memory",
		stores: { memory: limiterStores.memory() },
	});
	return instance;
}

function use(options: LimiterOptions): Limiter;
function use(store: string, options: LimiterOptions): Limiter;
function use(
	storeOrOptions: string | LimiterOptions,
	options?: LimiterOptions,
): Limiter {
	if (typeof storeOrOptions !== "string") return manager().use(storeOrOptions);
	if (options === undefined) {
		throw new E_BLACKHOLE_LIMITER_OPTIONS_MISSING([
			"limiter.use(store, options) needs the allowed requests and the duration.",
		]);
	}
	return manager().use(storeOrOptions, options);
}

function multi(options: MultiLimiterOptions[]): MultiLimiter;
function multi(store: string, options: MultiLimiterOptions[]): MultiLimiter;
function multi(
	storeOrOptions: string | MultiLimiterOptions[],
	options?: MultiLimiterOptions[],
): MultiLimiter {
	if (typeof storeOrOptions !== "string") {
		return manager().multi(storeOrOptions);
	}
	if (options === undefined) {
		throw new E_BLACKHOLE_LIMITER_OPTIONS_MISSING([
			"limiter.multi(store, options) needs the options of one or more limiters.",
		]);
	}
	return manager().multi(storeOrOptions, options);
}

const limiter = {
	/** A limiter in the default store, or in the named one. */
	use,
	/** Several limits counted together, each on its own key. */
	multi,
	/** Start an HTTP limit: `allowRequests(n).every(duration)…`. */
	allowRequests(requests: number): HttpLimiter {
		return new HttpLimiter(manager).allowRequests(requests);
	},
	/** No limit — what a `define` builder returns for requests it lets through. */
	noLimit(): null {
		return null;
	},
	/**
	 * A route middleware enforcing the limit `builder` returns per request
	 * (`null` lets the request through uncounted).
	 */
	define(
		name: string,
		builder: (
			ctx: LimiterHttpContext,
		) => HttpLimiter | null | Promise<HttpLimiter | null>,
	): ThrottleMiddleware {
		return defineThrottle(name, builder);
	},
	/** Forget every key of the limiters handed out so far, in every store or the named ones. */
	clear(stores?: string[]): Promise<void> {
		return manager().clear(stores);
	},
};

export default limiter;
