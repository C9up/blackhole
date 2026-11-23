/**
 * Blackhole errors, one class per code. Every refusal blackhole raises is a
 * flare `Exception` with a code in the `E_BLACKHOLE_` namespace, so a caller
 * can match on `error.code` or `error instanceof errors.E_BLACKHOLE_…`.
 *
 * The codes of a refused request (`E_BLACKHOLE_BLOCKED`, `E_TOO_MANY_REQUESTS`
 * from the global rate limit, `E_BLACKHOLE_MISSING_IP`) are not thrown: they
 * are the `code` of the response body. A rejected CSRF token is
 * {@link E_BAD_CSRF_TOKEN}, which renders itself.
 */
import { createError, Exception, format } from "@c9up/flare";
import type { LimiterResponse, ThrottleContext } from "./limiter.js";

/** The Rust engine is not loaded. */
export const E_BLACKHOLE_NAPI_REQUIRED = createError(
	"[blackhole] The Blackhole Rust engine is required but not loaded.\n" +
		"  Fix: cd packages/blackhole && pnpm build:napi",
	"E_BLACKHOLE_NAPI_REQUIRED",
);

/** The middleware ran before BlackholeProvider registered the instance. */
export const E_BLACKHOLE_NOT_REGISTERED = createError(
	"[blackhole] BlackholeProvider must register BLACKHOLE_KEY before the middleware runs, and the host must expose ctx.containerResolver.",
	"E_BLACKHOLE_NOT_REGISTERED",
);

/** An option the config no longer takes. */
export const E_BLACKHOLE_REMOVED_OPTION = createError<[string, string]>(
	"[blackhole] `%s` is no longer an option: %s.",
	"E_BLACKHOLE_REMOVED_OPTION",
);

/** An option a config object does not know. */
export const E_BLACKHOLE_UNKNOWN_OPTION = createError<[string]>(
	"%s",
	"E_BLACKHOLE_UNKNOWN_OPTION",
);

/** A header option holds a value no header can carry. */
export const E_BLACKHOLE_INVALID_HEADER_VALUE = createError<[string, string]>(
	"[blackhole] %s: %s cannot be written as a header value (empty, or a control or non-ASCII character).",
	"E_BLACKHOLE_INVALID_HEADER_VALUE",
);

/** An invalid `xFrame` option. */
export const E_BLACKHOLE_INVALID_XFRAME = createError<[string]>(
	"[blackhole] xFrame.action %s",
	"E_BLACKHOLE_INVALID_XFRAME",
);

/** An invalid Content-Security-Policy. The value says what is wrong. */
export const E_BLACKHOLE_INVALID_CSP = createError<[string]>(
	"[blackhole] %s",
	"E_BLACKHOLE_INVALID_CSP",
);

/** An invalid CORS config. */
export const E_BLACKHOLE_INVALID_CORS = createError<[string]>(
	"CORS misconfiguration: %s",
	"E_BLACKHOLE_INVALID_CORS",
);

/** A duration option that cannot be read as one. */
export const E_BLACKHOLE_INVALID_DURATION = createError<[string, string]>(
	"[blackhole] Cannot read %s as %s: use a non-negative number of seconds, or a duration such as '30s', '1 minute' or '180 days'.",
	"E_BLACKHOLE_INVALID_DURATION",
);

/** CSRF is enabled without a `secret`. */
export const E_BLACKHOLE_SECRET_MISSING = createError(
	"[blackhole] CSRF is enabled but no `secret` was provided. Pass your APP_KEY as " +
		"`secret` so CSRF tokens are signed (signed double-submit). Disable with " +
		"`csrf: false` only if you have an alternative CSRF defense.",
	"E_BLACKHOLE_SECRET_MISSING",
);

/** The CSRF `secret` is a scaffolding placeholder or too short. */
export const E_BLACKHOLE_WEAK_SECRET = createError<[string]>(
	"[blackhole] the CSRF `secret` %s",
	"E_BLACKHOLE_WEAK_SECRET",
);

/** The CSRF `secret` is neither a string nor a Secret wrapping one. */
export const E_BLACKHOLE_INVALID_SECRET = createError(
	"[blackhole] the CSRF `secret` must be a string or a Secret wrapping one",
	"E_BLACKHOLE_INVALID_SECRET",
);

/**
 * CSRF is bound to the session (`csrf.session`), and the request reached the
 * check without one.
 *
 * Minting an unbound token instead would quietly hand every visitor a token
 * valid for any session — the very thing the binding exists to prevent — so
 * the request stops here. It is a wiring error, not a client error: the
 * session middleware is missing, or registered after blackhole's.
 */
export const E_BLACKHOLE_SESSION_NOT_READY = createError(
	"[blackhole] CSRF tokens are bound to the session (`csrf.session`), but this request has none. " +
		"Register the session middleware before blackhole's router middleware, " +
		"or set `csrf: { session: false }` for an application without sessions.",
	"E_BLACKHOLE_SESSION_NOT_READY",
);

/**
 * A CSP names an `@keyword` nothing resolves, or a keyword is registered
 * under an invalid name. Raised when the policy is built — at boot, not on
 * the first page a browser renders.
 */
export class E_BLACKHOLE_UNKNOWN_CSP_KEYWORD extends Exception {
	static override code = "E_BLACKHOLE_UNKNOWN_CSP_KEYWORD";
	static override status = 500;

	constructor(
		readonly keyword: string,
		reason: string,
		options?: ErrorOptions,
	) {
		super(
			format("[blackhole] Content-Security-Policy keyword %s: %s.", [
				JSON.stringify(keyword),
				reason,
			]),
			options,
		);
	}
}

/**
 * A CSP keyword's resolver answered something that cannot go in the header:
 * not a string, or a value with `;`, `,` or a line break, which would end the
 * directive or start another policy.
 */
export class E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE extends Exception {
	static override code = "E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE";
	static override status = 500;

	constructor(
		readonly keyword: string,
		value: unknown,
		options?: ErrorOptions,
	) {
		super(
			format(
				"[blackhole] Content-Security-Policy keyword %s resolved to %s, which cannot go in the header (`;`, `,` and line breaks would end the directive).",
				[JSON.stringify(keyword), JSON.stringify(value)],
			),
			options,
		);
	}
}

/** An invalid rate limit: a count or a duration that is not positive. */
export const E_BLACKHOLE_INVALID_RATE_LIMIT = createError<[string]>(
	"[blackhole] %s",
	"E_BLACKHOLE_INVALID_RATE_LIMIT",
);

/** `checkRateLimit` was called without a configured store. */
export const E_BLACKHOLE_RATE_LIMIT_STORE_MISSING = createError(
	"[blackhole] checkRateLimit called without a configured rateLimit.store.",
	"E_BLACKHOLE_RATE_LIMIT_STORE_MISSING",
);

/** `checkRateLimit` was given an empty key. */
export const E_BLACKHOLE_EMPTY_RATE_LIMIT_KEY = createError(
	"[blackhole] checkRateLimit was given an empty key: every request without one would be counted in a single shared bucket.",
	"E_BLACKHOLE_EMPTY_RATE_LIMIT_KEY",
);

/** The rate limit or the limiter names a store `stores` does not declare. */
export const E_BLACKHOLE_UNKNOWN_STORE = createError<[string]>(
	"[blackhole] %s",
	"E_BLACKHOLE_UNKNOWN_STORE",
);

/** `stores` is declared without a `default`. */
export const E_BLACKHOLE_NO_DEFAULT_STORE = createError<[string]>(
	"[blackhole] config.blackhole.rateLimit declares `stores` but no `default` naming which one counts. " +
		"Set default to one of: %s.",
	"E_BLACKHOLE_NO_DEFAULT_STORE",
);

/** A limiter was asked for without its options. */
export const E_BLACKHOLE_LIMITER_OPTIONS_MISSING = createError<[string]>(
	"[blackhole] %s",
	"E_BLACKHOLE_LIMITER_OPTIONS_MISSING",
);

/** A throttle's limiter lacks `allowRequests()` or `every()`. */
export const E_BLACKHOLE_INCOMPLETE_THROTTLE = createError<[string]>(
	'[blackhole] cannot throttle "%s": set allowRequests() and every() on its limiter.',
	"E_BLACKHOLE_INCOMPLETE_THROTTLE",
);

/** A Redis connection was named, but `@c9up/quasar` is not installed. */
export const E_BLACKHOLE_QUASAR_MISSING = createError<[string]>(
	"%s",
	"E_BLACKHOLE_QUASAR_MISSING",
);

/** The named Redis connection lacks a command the store issues. */
export const E_BLACKHOLE_INCOMPLETE_CONNECTION = createError<[string]>(
	"%s",
	"E_BLACKHOLE_INCOMPLETE_CONNECTION",
);

/**
 * The database limiter store has no database to count in: `@c9up/atlas` is
 * not installed, its provider has not booted, or the connection named is not
 * one. Raised on the first count, with the original failure as `cause`.
 */
export const E_BLACKHOLE_DATABASE_UNAVAILABLE = createError<[string]>(
	"[blackhole] %s.",
	"E_BLACKHOLE_DATABASE_UNAVAILABLE",
);

/** The database limiter store was given a database it cannot count in. */
export class E_BLACKHOLE_UNSUPPORTED_DATABASE extends Exception {
	static override code = "E_BLACKHOLE_UNSUPPORTED_DATABASE";
	static override status = 500;

	constructor(
		readonly dialect: string,
		options?: ErrorOptions,
	) {
		super(
			format(
				"[blackhole] Unsupported database %s: the database limiter store works with PostgreSQL, MySQL and SQLite.",
				[JSON.stringify(dialect)],
			),
			options,
		);
	}
}

/** The database limiter store's `tableName` is not a table name. */
export const E_BLACKHOLE_INVALID_TABLE_NAME = createError<[string]>(
	"[blackhole] the database limiter store's tableName %s is not a table name.",
	"E_BLACKHOLE_INVALID_TABLE_NAME",
);

/**
 * A key over its budget. Thrown by `consume` and by a throttle middleware;
 * the HTTP layer renders it as a 429 through {@link ThrottleException.handle}.
 */
export class ThrottleException extends Exception {
	static override code = "E_TOO_MANY_REQUESTS";
	static override status = 429;
	static override message = "Too many requests";

	/** The translation key of the message (`ctx.i18n.t`). */
	readonly identifier = "errors.E_TOO_MANY_REQUESTS";
	readonly response: LimiterResponse;
	/** Replaces the default `X-RateLimit-*` / `Retry-After` headers when set. */
	headers?: Record<string, string | number>;
	translation?: { identifier: string; data?: Record<string, unknown> };

	constructor(response: LimiterResponse, options?: ErrorOptions) {
		super(undefined, options);
		this.response = response;
	}

	/** The rate-limit headers a 429 carries by default. */
	getDefaultHeaders(): Record<string, string | number> {
		return {
			"X-RateLimit-Limit": this.response.limit,
			"X-RateLimit-Remaining": this.response.remaining,
			"Retry-After": this.response.availableIn,
			"X-RateLimit-Reset": new Date(
				Date.now() + this.response.availableIn * 1000,
			).toISOString(),
		};
	}

	/** The message, translated through `ctx.i18n` when the request has one. */
	getResponseMessage(ctx: object): string {
		const i18n: unknown = Reflect.get(ctx, "i18n");
		const t: unknown =
			typeof i18n === "object" && i18n !== null
				? Reflect.get(i18n, "t")
				: undefined;
		if (typeof t !== "function") return this.message;
		const translated: unknown = Reflect.apply(t, i18n, [
			this.translation?.identifier ?? this.identifier,
			this.translation?.data ?? {},
			this.message,
		]);
		return typeof translated === "string" ? translated : this.message;
	}

	setMessage(message: string): this {
		this.message = message;
		return this;
	}

	setStatus(status: number): this {
		this.status = status;
		return this;
	}

	setHeaders(headers: Record<string, string | number>): this {
		this.headers = headers;
		return this;
	}

	/** Translate the message under `identifier` instead of the default one. */
	t(identifier: string, data?: Record<string, unknown>): this {
		this.translation = { identifier, data };
		return this;
	}

	/**
	 * Render the 429: the headers, then a body shaped for what the client
	 * accepts — the message as text for a browser, `{ errors: [...] }` for
	 * JSON, the JSON:API error object for `application/vnd.api+json`.
	 */
	async handle(error: ThrottleException, ctx: ThrottleContext): Promise<void> {
		const message = error.getResponseMessage(ctx);
		const headers = error.headers ?? error.getDefaultHeaders();
		for (const [name, value] of Object.entries(headers)) {
			ctx.response.header(name, String(value));
		}
		ctx.response.status(error.status);
		const format = negotiate(ctx);
		if (format === "application/vnd.api+json") {
			ctx.response.send({
				errors: [
					{
						code: error.code,
						title: message,
						meta: { retryAfter: error.response.availableIn },
					},
				],
			});
		} else if (format === "json") {
			ctx.response.send({
				errors: [{ message, retryAfter: error.response.availableIn }],
			});
		} else {
			ctx.response.send(message);
		}
	}
}

/** The body formats a 429 is written in, in upstream's order. */
const THROTTLE_FORMATS = ["html", "application/vnd.api+json", "json"];

/**
 * The format of the 429: the host's content negotiation when it has one, as
 * upstream; otherwise the `Accept` header read directly — JSON:API, then JSON
 * from a client that does not also ask for HTML, then text.
 */
function negotiate(ctx: ThrottleContext): string | null {
	if (typeof ctx.request.accepts === "function") {
		return ctx.request.accepts(THROTTLE_FORMATS);
	}
	const accept = ctx.request.header("accept") ?? "";
	if (accept.includes("application/vnd.api+json")) {
		return "application/vnd.api+json";
	}
	if (accept.includes("json") && !accept.includes("text/html")) return "json";
	return "html";
}

/** The code of {@link ThrottleException}: the same class under its code. */
export const E_TOO_MANY_REQUESTS = ThrottleException;

/** The keys kept out of the form flashed back on a CSRF failure. */
const CSRF_FLASH_EXCEPT = [
	"_csrf",
	"_method",
	"password",
	"password_confirmation",
];

/**
 * What {@link InvalidCSRFToken.handle} reads from the request's context.
 * Structural: blackhole does not depend on a host. The session, the
 * redirect builder and the translator are read when the host has them.
 */
export interface CsrfErrorContext {
	request: { header(name: string): string | undefined };
	response: { status(code: number): unknown; json(data: unknown): void };
}

function isObject(value: unknown): value is object {
	return typeof value === "object" && value !== null;
}

/** Call `name` on `target` when it is there: the host may implement only some. */
function callIfFunction(
	target: object,
	name: string,
	...args: unknown[]
): void {
	const fn: unknown = Reflect.get(target, name);
	if (typeof fn === "function") Reflect.apply(fn, target, args);
}

/**
 * A missing, mismatched or forged CSRF token: 403, "Invalid or expired CSRF
 * token". A missing token and a wrong one are the same error, as upstream.
 */
export class InvalidCSRFToken extends Exception {
	static override code = "E_BAD_CSRF_TOKEN";
	static override status = 403;
	static override message = "Invalid or expired CSRF token";

	/** The translation key of the message (`ctx.i18n.t`). */
	readonly identifier = "errors.E_BAD_CSRF_TOKEN";

	/** The message, translated through `ctx.i18n` when the request has one. */
	getResponseMessage(error: InvalidCSRFToken, ctx: object): string {
		const i18n: unknown = Reflect.get(ctx, "i18n");
		const t: unknown = isObject(i18n) ? Reflect.get(i18n, "t") : undefined;
		if (!isObject(i18n) || typeof t !== "function") return error.message;
		const translated: unknown = Reflect.apply(t, i18n, [
			error.identifier,
			{},
			error.message,
		]);
		return typeof translated === "string" ? translated : error.message;
	}

	/**
	 * A browser (`Accept: text/html`, or an Inertia visit) with a session gets
	 * the form flashed back — minus the token, the method override and any
	 * password; not for Inertia, which keeps the form's state on the client —
	 * the message flashed as `error` and under `E_BAD_CSRF_TOKEN`, and a
	 * redirect to the previous page.
	 *
	 * DEVIATION (named): upstream always takes the redirect. A JSON client, an
	 * XHR, or a host without a session or a redirect builder gets
	 * `403 { error: { code, message } }` instead: redirecting those would
	 * swallow the failure, and blackhole does not require a session.
	 */
	async handle(error: InvalidCSRFToken, ctx: CsrfErrorContext): Promise<void> {
		const message = error.getResponseMessage(error, ctx);
		const inertia = Boolean(ctx.request.header("x-inertia"));
		const accept = ctx.request.header("accept") ?? "";
		const session: unknown = Reflect.get(ctx, "session");
		const redirect: unknown = Reflect.get(ctx.response, "redirect");
		if (
			(inertia || accept.includes("text/html")) &&
			isObject(session) &&
			typeof redirect === "function"
		) {
			if (!inertia) callIfFunction(session, "flashExcept", CSRF_FLASH_EXCEPT);
			callIfFunction(session, "flash", "error", message);
			callIfFunction(session, "flashErrors", {
				[error.code ?? InvalidCSRFToken.code]: message,
			});
			const builder: unknown = Reflect.apply(redirect, ctx.response, []);
			const back: unknown = isObject(builder)
				? Reflect.get(builder, "back")
				: undefined;
			if (isObject(builder) && typeof back === "function") {
				Reflect.apply(back, builder, []);
				return;
			}
		}
		ctx.response.status(error.status);
		ctx.response.json({ error: { code: error.code, message } });
	}
}

/** The code of {@link InvalidCSRFToken}: the same class under its code. */
export const E_BAD_CSRF_TOKEN = InvalidCSRFToken;
