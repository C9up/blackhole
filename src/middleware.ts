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

import { randomBytes } from "node:crypto";
import { BLACKHOLE_KEY } from "./BlackholeProvider.js";
import {
	appendVaryValue,
	type CoreRequest,
	type CsrfOutcomeCookie,
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
	/**
	 * The matched route (Ream's `ctx.route`). `csrf.exceptRoutes` entries are
	 * compared with its pattern.
	 */
	route?: { pattern: string } | null;
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
		/**
		 * `host[:port]`, trusted-proxy aware (Ream's `request.host()`) — the
		 * same resolution as `protocol()`, so the CSRF origin check compares an
		 * Origin with one consistent view of the request.
		 */
		host?(): string | null;
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
 *
 * The set also goes in the request store (`securityHeaders`): a view layer
 * with headers of its own (photon) reads there that this set was decided, so
 * a header left out (`frameOptions: false`) is not one it should add back.
 */
function applySecurityHeaders(
	ctx: ReamContext,
	bh: Blackhole,
	nonce?: string,
): void {
	const headers = bh.securityHeaders(nonce);
	for (const [name, value] of Object.entries(headers)) {
		ctx.response.header(name, value);
	}
	ctx.store.set("securityHeaders", headers);
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

/** Where the session keeps the secret its CSRF tokens are bound to. */
const CSRF_SECRET_SESSION_KEY = "csrf-secret";

/** The request's session, as far as its CSRF secret is concerned. */
interface CsrfSession {
	/** The secret the session's tokens are bound to, created on first use. */
	secret(): string;
	/** A new secret: every token bound to the previous one is refused from now on. */
	rotate(): string;
	/** The session's id, which changes when the host regenerates the session. */
	id(): unknown;
}

/**
 * The request's session (`ctx.session`, read structurally), or `undefined`
 * when the request has none — no session middleware, or one registered after
 * this one. Whether that is acceptable is `csrf.session`'s call, made in the
 * CSRF phase.
 *
 * Binding the token to the session is what makes a leaked token worthless
 * elsewhere: issued under one session's secret, it is refused under any
 * other, and it dies with the session that holds the secret.
 */
function csrfSessionOf(ctx: ReamContext): CsrfSession | undefined {
	const session: unknown = Reflect.get(Object(ctx), "session");
	if (typeof session !== "object" || session === null) return undefined;
	const get: unknown = Reflect.get(session, "get");
	const put: unknown = Reflect.get(session, "put");
	if (typeof get !== "function" || typeof put !== "function") return undefined;
	const rotate = (): string => {
		const secret = randomBytes(32).toString("base64url");
		Reflect.apply(put, session, [CSRF_SECRET_SESSION_KEY, secret]);
		return secret;
	};
	return {
		secret() {
			const stored: unknown = Reflect.apply(get, session, [
				CSRF_SECRET_SESSION_KEY,
			]);
			return typeof stored === "string" && stored.length > 0
				? stored
				: rotate();
		},
		rotate,
		id: () => Reflect.get(session, "sessionId"),
	};
}

/**
 * Hand the request its CSRF token: `request.csrfToken`, the store (for
 * templating), and the readable cookie when one is to be set.
 */
function seedCsrfToken(
	ctx: ReamContext,
	token: string,
	cookie: CsrfOutcomeCookie | undefined,
): void {
	ctx.request.csrfToken = token;
	ctx.store.set("csrfToken", token);
	if (cookie === undefined) return;
	// plainCookie: the XSRF token is already HMAC-signed by blackhole; the
	// browser must read the raw value for the double-submit check, so it must
	// not be re-signed by the host's default (signing) `cookie()`.
	ctx.response.plainCookie(
		cookie.name,
		cookie.value,
		// `encode: false`: the browser reads this cookie and echoes it in a
		// header for the double-submit check, so both sides must see the SAME
		// bytes. A packed envelope would be echoed packed and never match.
		{ ...cookie.options, encode: false },
	);
}

/**
 * The session was regenerated while the request ran — a login or a logout.
 * Its data survives a regeneration, the CSRF secret included, so without this
 * a token issued before the boundary stayed valid after it. The secret is
 * replaced, and the response carries a token bound to the new one.
 *
 * NAMED DEVIATION: the upstream guard keeps one secret for the life of the
 * session; blackhole turns it over at every regeneration.
 */
function rotateCsrfSecret(
	ctx: ReamContext,
	bh: Blackhole,
	session: CsrfSession,
): void {
	const token = bh.generateCsrfToken(session.rotate());
	const { name, options } = bh.csrfCookie();
	seedCsrfToken(
		ctx,
		token,
		bh.xsrfCookieEnabled() ? { name, value: token, options } : undefined,
	);
}

/** The engine's view of a Ream request. */
function coreRequest(
	ctx: ReamContext,
	remoteAddr: string,
	csrfBinding?: string,
): CoreRequest {
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
		host: ctx.request.host?.() ?? undefined,
		csrfBinding,
		routePattern: ctx.route?.pattern,
		context: ctx,
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

	const session = csrfSessionOf(ctx);
	const sessionId = session?.id();
	const outcome = runCsrfPhase(bh, coreRequest(ctx, "", session?.secret()));
	if (outcome.kind === "reject") {
		applySecurityHeaders(ctx, bh);
		const body = translateCsrfRejection(ctx, outcome.body);
		if (handleCsrfRejectionForBrowser(ctx, body)) return;
		ctx.response.status(outcome.status);
		ctx.response.json(body);
		return;
	}

	// Pass: seed the CSRF token (both `request.csrfToken` and `ctx.store` for
	// templating), the XSRF-TOKEN cookie, and the CSP nonce.
	seedCsrfToken(ctx, outcome.csrfToken, outcome.setCookie);
	// The enforce signal (fail-close), distinct from the seeded token above: `true`
	// only when CSRF was enabled, guarded, non-excepted, AND validated. NOT mirrored
	// to `ctx.store` — the store's token is for the ALS-based inker `csrfField()`.
	ctx.request.csrfProtected = outcome.csrfProtected;
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

	if (session !== undefined && session.id() !== sessionId) {
		rotateCsrfSecret(ctx, bh, session);
	}

	const { headers, body } = runResponsePhase(bh, {
		body: ctx.response.getBody(),
		contentType: ctx.response.getHeader("content-type") ?? "",
		cspNonce: outcome.cspNonce,
	});
	// Set before the handler ran; added again only where the response lost
	// one. A route that set its own (a page framed by a partner, a CSP of its
	// own) keeps it — overwriting it after the fact left no way to.
	for (const [name, value] of Object.entries(headers)) {
		if (ctx.response.getHeader(name) === undefined) {
			ctx.response.header(name, value);
		}
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

/** The translation key of the CSRF rejection message. */
const CSRF_MESSAGE_IDENTIFIER = "errors.E_BAD_CSRF_TOKEN";

/**
 * The CSRF rejection with its message translated, when the request carries a
 * translator (`ctx.i18n.t(key, data, fallback)`) — the English message
 * otherwise, and anything that is not a CSRF token rejection unchanged.
 */
function translateCsrfRejection(ctx: ReamContext, body: unknown): unknown {
	if (!isBadCsrfBody(body) || !isRecord(body) || !isRecord(body.error)) {
		return body;
	}
	const fallback =
		typeof body.error.message === "string"
			? body.error.message
			: "Invalid or expired CSRF token";
	const i18n: unknown = Reflect.get(Object(ctx), "i18n");
	const t: unknown = isRecord(i18n) ? i18n.t : undefined;
	if (!isRecord(i18n) || typeof t !== "function") return body;
	const translated: unknown = Reflect.apply(t, i18n, [
		CSRF_MESSAGE_IDENTIFIER,
		{},
		fallback,
	]);
	const message = typeof translated === "string" ? translated : fallback;
	return { ...body, error: { ...body.error, message } };
}

/**
 * Turn a CSRF rejection into a flash and a redirect back for a browser: flash
 * the submitted form back (minus the token, the method override and any
 * password), flash the message, and redirect to the previous page.
 *
 * An Inertia visit (`X-Inertia`) takes the same redirect — its client follows
 * it and shows the flashed error — but does not re-flash the form: Inertia
 * keeps the form's state on the client.
 *
 * A JSON client still gets the JSON body: redirecting a fetch or an XHR would
 * swallow the failure.
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

	const inertia = Boolean(ctx.request.header("x-inertia"));
	const accept = ctx.request.header("accept") ?? "";
	// An explicit JSON request, an XHR, or a client that never asked for HTML
	// gets the JSON body — redirecting those would swallow the failure.
	if (!inertia && !accept.includes("text/html")) return false;

	const session = Reflect.get(Object(ctx), "session");
	const redirect = Reflect.get(Object(ctx.response), "redirect");
	if (!isRecord(session) || typeof redirect !== "function") return false;

	const message =
		(isRecord(body) &&
		isRecord(body.error) &&
		typeof body.error.message === "string"
			? body.error.message
			: undefined) ?? "Invalid or expired CSRF token";

	if (!inertia) callIfFunction(session, "flashExcept", CSRF_FLASH_EXCEPT);
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
