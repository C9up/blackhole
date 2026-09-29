/**
 * Blackhole middleware — Ream adapter.
 *
 * Resolves the `Blackhole` instance from the IoC container (registered by
 * `BlackholeProvider` from `config/blackhole.ts`). No inline config —
 * same pattern as Warden, Atlas, etc. The security pipeline itself lives in
 * `./core` and is shared with the Express / Fastify adapters.
 *
 * @example
 *   // config/blackhole.ts
 *   import { defineConfig } from '@c9up/blackhole'
 *   export default defineConfig({ csrf: true, rateLimit: { max: 100, windowSeconds: 60 } })
 *
 *   // start/kernel.ts
 *   router.use([() => import('@c9up/blackhole/middleware')])
 */

import { BLACKHOLE_KEY } from "./BlackholeProvider.js";
import {
	appendVaryValue,
	type CoreRequest,
	csrfBodyString,
	rateLimitHeaders,
	runCsrfPhase,
	runGuardPhase,
	runResponsePhase,
} from "./core.js";
import {
	type Blackhole,
	type BlackholeOptions,
	createBlackhole,
	type EngineCheck,
} from "./index.js";

/**
 * Per-request IoC resolver Ream exposes as `ctx.containerResolver` (Adonis
 * idiom). Blackhole resolves its `Blackhole` instance through this — reading
 * from the context it is HANDED — so the package never imports `@c9up/ream` at
 * runtime and stays framework-agnostic. A host that provides none (non-Ream, or
 * a misconfigured kernel) yields no resolution and the middleware throws.
 */
interface ContainerResolver {
	make(token: string): Promise<unknown>;
}

/**
 * Structural subset of Ream's `HttpContext` that the adapter needs. Kept
 * narrow + permissive (readonly headers, broad return types) so the real
 * `HttpContext` class satisfies this shape without further casting.
 *
 * The Blackhole instance is resolved from `ctx.containerResolver` (Ream's
 * per-request IoC resolver), NOT by importing the app singleton — that keeps
 * blackhole agnostic of `@c9up/ream` at runtime.
 */
export interface ReamContext {
	/**
	 * Per-request IoC resolver (Ream's `ctx.containerResolver`). Blackhole
	 * resolves its `Blackhole` instance through it — agnostic, no `@c9up/ream`
	 * import.
	 */
	containerResolver?: ContainerResolver;
	request: {
		method(): string;
		url(full?: boolean): string;
		path(): string;
		header(name: string): string | undefined;
		headers(): Readonly<Record<string, string>>;
		body(): unknown;
		ip(): string;
		/** `http` / `https`, trusted-proxy aware (Ream's `request.protocol()`). */
		protocol?(): string;
		/** CSRF token for this request (Adonis idiom: `request.csrfToken`). Seeded by the middleware. */
		csrfToken?: string;
		/**
		 * `true` only when CSRF was enforced+validated for this request. Consumers
		 * that must fail-close on CSRF (e.g. an admin write route) read this — a
		 * seeded `csrfToken` is NOT proof of verification.
		 */
		csrfProtected?: boolean;
	};
	/** Per-request store — the CSRF token is published here for templating (inker `csrfField()`). */
	store: { set(key: string, value: unknown): void };
	response: {
		/** CSP nonce for this request (Adonis idiom: `response.nonce`). Seeded by the middleware when CSP uses `@nonce`. */
		nonce?: string;
		status(code: number): unknown;
		json(data: unknown): void;
		send(data: unknown): void;
		header(name: string, value: string): unknown;
		cookie(
			name: string,
			value: string,
			options?: Record<string, unknown>,
		): unknown;
		/**
		 * Unsigned cookie (Ream `plainCookie`). The XSRF-TOKEN is already an HMAC
		 * signed double-submit token, so it must NOT be re-signed by the host's
		 * default `cookie()` — the browser must read the raw value back for the
		 * double-submit check.
		 */
		plainCookie(
			name: string,
			value: string,
			options?: Record<string, unknown>,
		): unknown;
		getBody(): string;
		getHeader(name: string): string | undefined;
		setBody(body: string): void;
	};
}

type ReamNext = () => Promise<void> | void;

function isBlackhole(value: unknown): value is Blackhole {
	return (
		typeof value === "object" &&
		value !== null &&
		"check" in value &&
		typeof value.check === "function"
	);
}

/**
 * The protective headers (CSP, HSTS, nosniff…) on whatever this response turns
 * out to be. Set on the refusals too — a 403 or a 429 is still a page a
 * browser renders — and before the handler runs, so a response the exception
 * handler builds after a throw carries them as well.
 */
function applySecurityHeaders(
	ctx: ReamContext,
	bh: Blackhole,
	nonce?: string,
): void {
	for (const [name, value] of Object.entries(bh.securityHeaders(nonce))) {
		ctx.response.header(name, value);
	}
}

/** Append `value` to the context's `Vary` header (dedup, via the shared helper). */
function appendVary(ctx: ReamContext, value: string): void {
	const next = appendVaryValue(ctx.response.getHeader("vary") ?? "", value);
	ctx.response.header("vary", next);
}

/** The `Blackhole` the provider registered, from the request's own resolver. */
async function resolveBlackhole(ctx: ReamContext): Promise<Blackhole> {
	// Resolve the Blackhole instance from the request's IoC resolver
	// (`ctx.containerResolver`, Adonis idiom) — reading from the context Ream
	// hands us, NOT by importing `@c9up/ream/services/app`. That keeps blackhole
	// framework-agnostic at runtime while still builds standalone.
	const resolved = await ctx.containerResolver?.make(BLACKHOLE_KEY);
	if (!isBlackhole(resolved)) {
		throw new Error(
			"[BLACKHOLE_NOT_REGISTERED] BlackholeProvider must register BLACKHOLE_KEY before the middleware runs, and the host must expose ctx.containerResolver.",
		);
	}
	return resolved;
}

/**
 * Requests the server-tier middleware already guarded, so the router-tier one
 * runs only what is left — and the limiter counts each request once.
 */
const guardedByServer = new WeakSet<object>();

/**
 * The guard phase on a Ream context: the rate limit (the distributed store in
 * JS, or the engine's counter) when `checks` has it, the shield, and CORS.
 * Answers a refusal or a preflight itself and returns `true`; otherwise sets
 * the CORS, budget and protective headers and returns `false`.
 */
async function guard(
	ctx: ReamContext,
	bh: Blackhole,
	checks: EngineCheck[],
): Promise<boolean> {
	// Rate-limit key: the configured `keyFor(ctx)` (per-user / per-route) or the
	// client IP by default. Used both as the distributed-store key and as the
	// key the in-process Rust counter buckets on (passed as `remoteAddr`).
	const countHere = checks.includes("rateLimit");
	const rateLimitKey = countHere ? bh.rateLimitKey(ctx) : "";

	// Distributed store path: count + decide in JS (Redis, etc.) so the limit is
	// shared across instances — the Rust in-process counter is off in this mode.
	if (countHere && bh.hasRateLimitStore()) {
		const decision = await bh.checkRateLimit(rateLimitKey);
		const rlHeaders = rateLimitHeaders(decision);
		if (!decision.allowed) {
			ctx.response.header("Retry-After", String(decision.resetSeconds));
			for (const [name, value] of Object.entries(rlHeaders)) {
				ctx.response.header(name, value);
			}
			applySecurityHeaders(ctx, bh);
			ctx.response.status(429);
			ctx.response.json({
				error: {
					code: "E_BLACKHOLE_RATE_LIMITED",
					message: "Too many requests",
				},
			});
			return true;
		}
		// Allowed: surface the budget on the successful response below.
		for (const [name, value] of Object.entries(rlHeaders)) {
			ctx.response.header(name, value);
		}
	}

	const outcome = runGuardPhase(bh, coreRequest(ctx, rateLimitKey), checks);
	if (outcome.kind === "reject") {
		// Rate-limit rejections carry Retry-After / X-RateLimit-* so clients back off.
		for (const [name, value] of Object.entries(outcome.headers ?? {})) {
			ctx.response.header(name, value);
		}
		applySecurityHeaders(ctx, bh);
		// Two-step: `.status(...).json(...)` chaining relies on a self-typed
		// return the structural interface can't express. Splitting is equivalent.
		ctx.response.status(outcome.status);
		ctx.response.json(outcome.body);
		return true;
	}
	if (outcome.varyOrigin) appendVary(ctx, "Origin");
	if (outcome.kind === "preflight") {
		for (const [name, value] of Object.entries(outcome.headers)) {
			ctx.response.header(name, value);
		}
		applySecurityHeaders(ctx, bh);
		ctx.response.status(outcome.status);
		ctx.response.send("");
		return true;
	}
	for (const [name, value] of Object.entries(outcome.corsHeaders)) {
		ctx.response.header(name, value);
	}
	// Success-path X-RateLimit-* from the in-process limiter (store path already
	// set them above). Parity with @adonisjs/limiter (budget on every response).
	for (const [name, value] of Object.entries(outcome.rateLimitHeaders ?? {})) {
		ctx.response.header(name, value);
	}
	applySecurityHeaders(ctx, bh);
	return false;
}

/** The engine's view of a Ream request. */
function coreRequest(ctx: ReamContext, remoteAddr: string): CoreRequest {
	return {
		method: ctx.request.method(),
		path: ctx.request.path(),
		url: ctx.request.url(true),
		headers: ctx.request.headers(),
		// Ream's body parser has already run, so a server-rendered form arrives
		// as an object — the raw urlencoded string the engine would scan for
		// `_csrf` no longer exists. Rebuild the field, as the other adapters do.
		body: csrfBodyString(ctx.request.body()),
		remoteAddr,
		protocol: ctx.request.protocol?.(),
	};
}

/**
 * The server-tier half: the rate limit, the shield and CORS, for every
 * request — a route that does not exist included, whose 404 is raised before
 * any router middleware runs. The rate limit waits for the router-tier half
 * when `rateLimit.keyFor` is set: it may read what a router middleware sets,
 * such as the authenticated user.
 */
export async function blackholeServerMiddleware(
	ctx: ReamContext,
	next: ReamNext,
): Promise<void> {
	const bh = await resolveBlackhole(ctx);
	const checks: EngineCheck[] = bh.rateLimitKeyedByRequest()
		? ["shield"]
		: ["rateLimit", "shield"];
	if (await guard(ctx, bh, checks)) return;
	guardedByServer.add(ctx);
	await next();
}

export async function blackholeMiddleware(ctx: ReamContext, next: ReamNext) {
	const bh = await resolveBlackhole(ctx);

	// Alone, this middleware runs every check. After the server-tier one, only
	// what that one left: CSRF, and the rate limit when it is keyed per request.
	const afterServer = guardedByServer.has(ctx);
	const countHere = !afterServer || bh.rateLimitKeyedByRequest();
	if (!afterServer) {
		if (await guard(ctx, bh, ["rateLimit", "shield"])) return;
	} else if (countHere) {
		if (await guard(ctx, bh, ["rateLimit"])) return;
	}

	const outcome = runCsrfPhase(bh, coreRequest(ctx, ""));
	if (outcome.kind === "reject") {
		applySecurityHeaders(ctx, bh);
		if (handleCsrfRejectionForBrowser(ctx, outcome.body)) return;
		ctx.response.status(outcome.status);
		ctx.response.json(outcome.body);
		return;
	}

	// Pass: seed the CSRF token (both `request.csrfToken` and `ctx.store` for
	// templating), the XSRF-TOKEN cookie, and the CSP nonce.
	ctx.request.csrfToken = outcome.csrfToken;
	ctx.store.set("csrfToken", outcome.csrfToken);
	// The enforce signal (fail-close), distinct from the seeded token above: `true`
	// only when CSRF was enabled, guarded, non-excepted, AND validated. NOT mirrored
	// to `ctx.store` — the store's token is for the ALS-based inker `csrfField()`.
	ctx.request.csrfProtected = outcome.csrfProtected;
	if (outcome.setCookie) {
		// plainCookie: the XSRF token is already HMAC-signed by blackhole; the
		// browser must read the raw value for the double-submit check, so it must
		// not be re-signed by the host's default (signing) `cookie()`.
		ctx.response.plainCookie(
			outcome.setCookie.name,
			outcome.setCookie.value,
			// `encode: false`: the browser reads this cookie and echoes it in a
			// header for the double-submit check, so both sides must see the SAME
			// bytes. A packed envelope would be echoed packed and never match.
			{ ...outcome.setCookie.options, encode: false },
		);
	}
	if (outcome.cspNonce) {
		ctx.response.nonce = outcome.cspNonce;
		ctx.store.set("cspNonce", outcome.cspNonce);
		// Share it with the request's view, as AdonisJS's shield does, so a
		// migrated template writes `<script nonce="{{ cspNonce }}">` — a VALUE,
		// not a call. A no-op when the app has no template layer.
		const view = Reflect.get(Object(ctx), "view");
		const share = Reflect.get(Object(view), "share");
		if (typeof share === "function") {
			share.call(view, { cspNonce: outcome.cspNonce });
		}
	}

	applySecurityHeaders(ctx, bh, outcome.cspNonce);

	await next();

	const { headers, body } = runResponsePhase(bh, {
		body: ctx.response.getBody(),
		contentType: ctx.response.getHeader("content-type") ?? "",
		cspNonce: outcome.cspNonce,
	});
	for (const [name, value] of Object.entries(headers)) {
		ctx.response.header(name, value);
	}
	if (body !== ctx.response.getBody()) ctx.response.setBody(body);
}

/**
 * Default export — the Adonis-style class form Ream's lazy middleware resolver
 * expects (`new mod.default().handle(ctx, next)`). Without it,
 * `router.use([() => import('@c9up/blackhole/middleware')])` (the documented
 * form) crashes with `new undefined()`. The named `blackholeMiddleware` stays
 * for direct registration `router.use([blackholeMiddleware])`.
 */
export default class BlackholeMiddleware {
	handle(ctx: ReamContext, next: ReamNext): Promise<void> {
		return blackholeMiddleware(ctx, next);
	}
}

export { type Blackhole, type BlackholeOptions, createBlackhole };

/** The keys Adonis keeps out of the re-flashed form on a CSRF failure. */
const CSRF_FLASH_EXCEPT = [
	"_csrf",
	"_method",
	"password",
	"password_confirmation",
];

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function isBadCsrfBody(body: unknown): boolean {
	if (!isRecord(body)) return false;
	const error = body.error;
	return isRecord(error) && error.code === "E_BAD_CSRF_TOKEN";
}

/**
 * Turn a CSRF rejection into what `@adonisjs/shield` does for a browser: flash
 * the submitted form back (minus the token, the method override and any
 * password), flash the message, and redirect to the previous page.
 *
 * A JSON client still gets the JSON body — Shield's own handler only takes the
 * redirect path for a session-backed request.
 *
 * Returns whether it handled the response. Everything it needs is duck-typed:
 * blackhole does not depend on a session or a redirect builder existing, and a
 * host that has neither falls through to the JSON reply.
 */
function handleCsrfRejectionForBrowser(
	ctx: ReamContext,
	body: unknown,
): boolean {
	if (!isBadCsrfBody(body)) return false;

	const accept = ctx.request.header("accept") ?? "";
	// An explicit JSON request, an XHR, or a client that never asked for HTML
	// gets the JSON body — redirecting those would swallow the failure.
	if (!accept.includes("text/html")) return false;

	const session = Reflect.get(Object(ctx), "session");
	const redirect = Reflect.get(Object(ctx.response), "redirect");
	if (!isRecord(session) || typeof redirect !== "function") return false;

	const message =
		(isRecord(body) &&
		isRecord(body.error) &&
		typeof body.error.message === "string"
			? body.error.message
			: undefined) ?? "Invalid or expired CSRF token";

	callIfFunction(session, "flashExcept", CSRF_FLASH_EXCEPT);
	callIfFunction(session, "flash", "error", message);
	callIfFunction(session, "flashErrors", { E_BAD_CSRF_TOKEN: message });

	const builder = Reflect.apply(redirect, ctx.response, []);
	const back = isRecord(builder) ? builder.back : undefined;
	if (typeof back !== "function") return false;
	Reflect.apply(back, builder, []);
	return true;
}

/** Call `name` on `target` when it is there — the host may implement only some. */
function callIfFunction(
	target: Record<string, unknown>,
	name: string,
	...args: unknown[]
): void {
	const fn = target[name];
	if (typeof fn === "function") Reflect.apply(fn, target, args);
}
