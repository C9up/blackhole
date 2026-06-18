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
	runRequestPhase,
	runResponsePhase,
} from "./core.js";
import {
	type Blackhole,
	type BlackholeOptions,
	createBlackhole,
} from "./index.js";

/**
 * Per-request IoC resolver Ream exposes as `ctx.containerResolver` (Adonis
 * idiom). Blackhole resolves its `Blackhole` instance through this — reading
 * from the context it is HANDED — so the package never imports `@c9up/ream` at
 * runtime and stays framework-agnostic. A host that provides none (non-Ream, or
 * a misconfigured kernel) yields no resolution and the middleware throws.
 */
interface ContainerResolver {
	make(token: string): unknown;
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
		/** CSRF token for this request (Adonis idiom: `request.csrfToken`). Seeded by the middleware. */
		csrfToken?: string;
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

/** Append `value` to the context's `Vary` header (dedup, via the shared helper). */
function appendVary(ctx: ReamContext, value: string): void {
	const next = appendVaryValue(ctx.response.getHeader("vary") ?? "", value);
	ctx.response.header("vary", next);
}

export async function blackholeMiddleware(ctx: ReamContext, next: ReamNext) {
	// Resolve the Blackhole instance from the request's IoC resolver
	// (`ctx.containerResolver`, Adonis idiom) — reading from the context Ream
	// hands us, NOT by importing `@c9up/ream/services/app`. That keeps blackhole
	// framework-agnostic at runtime while still builds standalone.
	const resolved = ctx.containerResolver?.make(BLACKHOLE_KEY);
	if (!isBlackhole(resolved)) {
		throw new Error(
			"[BLACKHOLE_NOT_REGISTERED] BlackholeProvider must register BLACKHOLE_KEY before the middleware runs, and the host must expose ctx.containerResolver.",
		);
	}
	const bh = resolved;

	const rawBody = ctx.request.body();
	const req: CoreRequest = {
		method: ctx.request.method(),
		path: ctx.request.path(),
		url: ctx.request.url(true),
		headers: ctx.request.headers(),
		body: typeof rawBody === "string" ? rawBody : undefined,
		remoteAddr: ctx.request.ip(),
	};
	const outcome = runRequestPhase(bh, req);

	if (outcome.kind === "reject") {
		// Two-step: `.status(...).json(...)` chaining relies on a self-typed
		// return the structural interface can't express. Splitting is equivalent.
		ctx.response.status(outcome.status);
		ctx.response.json(outcome.body);
		return;
	}
	if (outcome.kind === "preflight") {
		if (outcome.varyOrigin) appendVary(ctx, "Origin");
		for (const [name, value] of Object.entries(outcome.headers)) {
			ctx.response.header(name, value);
		}
		ctx.response.status(outcome.status);
		ctx.response.send("");
		return;
	}

	// Pass: apply CORS headers, seed the CSRF token (both `request.csrfToken`
	// and `ctx.store` for templating), the XSRF-TOKEN cookie, and the CSP nonce.
	if (outcome.varyOrigin) appendVary(ctx, "Origin");
	for (const [name, value] of Object.entries(outcome.corsHeaders)) {
		ctx.response.header(name, value);
	}
	ctx.request.csrfToken = outcome.csrfToken;
	ctx.store.set("csrfToken", outcome.csrfToken);
	if (outcome.setCookie) {
		ctx.response.cookie(
			outcome.setCookie.name,
			outcome.setCookie.value,
			outcome.setCookie.options,
		);
	}
	if (outcome.cspNonce) {
		ctx.response.nonce = outcome.cspNonce;
		ctx.store.set("cspNonce", outcome.cspNonce);
	}

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
