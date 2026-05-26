/**
 * Blackhole middleware — Ream adapter.
 *
 * Resolves the `Blackhole` instance from the IoC container (registered by
 * `BlackholeProvider` from `config/blackhole.ts`). No inline config —
 * same pattern as Warden, Atlas, etc.
 *
 * @example
 *   // config/blackhole.ts
 *   import { defineConfig } from '@c9up/blackhole'
 *   export default defineConfig({ csrf: true, rateLimit: { max: 100, windowSeconds: 60 } })
 *
 *   // start/kernel.ts
 *   router.use([() => import('@c9up/blackhole/middleware')])
 */

import app from "@c9up/ream/services/app";
import { BLACKHOLE_KEY } from "./BlackholeProvider.js";
import {
	type Blackhole,
	type BlackholeOptions,
	createBlackhole,
} from "./index.js";

/** Safe JSON parse — returns fallback error object if body is not valid JSON. */
function safeJsonParse(body: string | undefined): unknown {
	if (!body) return { error: { code: "BLOCKED", message: "Request rejected" } };
	try {
		return JSON.parse(body);
	} catch {
		return { error: { code: "BLOCKED", message: body } };
	}
}

/** Safe URL parsing — never throws on malformed input. */
function safeQuery(url: string): string {
	try {
		return new URL(url, "http://localhost").search;
	} catch {
		return "";
	}
}

/**
 * Structural subset of Ream's `HttpContext` that the adapter needs. Kept
 * narrow + permissive (readonly headers, broad return types) so the real
 * `HttpContext` class satisfies this shape without further casting.
 *
 * The Blackhole instance is resolved from `app.container` (imported below)
 * rather than from the context — Ream's HttpContext does not expose the
 * IoC container per-request, so the middleware reaches the singleton
 * registry directly.
 */
export interface ReamContext {
	request: {
		method(): string;
		url(full?: boolean): string;
		path(): string;
		header(name: string): string | undefined;
		headers(): Readonly<Record<string, string>>;
		body(): unknown;
		ip(): string;
	};
	response: {
		status(code: number): unknown;
		json(data: unknown): void;
		send(data: unknown): void;
		header(name: string, value: string): unknown;
		getBody(): string;
		getHeader(name: string): string | undefined;
		setBody(body: string): void;
	};
}

type ReamNext = () => Promise<void> | void;

/**
 * Ream middleware — reads the Blackhole instance from the container.
 * The config lives in `config/blackhole.ts` and is booted by `BlackholeProvider`.
 */
function isBlackhole(value: unknown): value is Blackhole {
	return (
		typeof value === "object" &&
		value !== null &&
		"check" in value &&
		typeof value.check === "function"
	);
}

export async function blackholeMiddleware(ctx: ReamContext, next: ReamNext) {
	const resolved = app.container.resolve(BLACKHOLE_KEY);
	if (!isBlackhole(resolved)) {
		throw new Error(
			"[BLACKHOLE_NOT_REGISTERED] BlackholeProvider must register BLACKHOLE_KEY before the middleware runs.",
		);
	}
	const bh = resolved;
	const rawBody = ctx.request.body();
	const result = bh.check({
		method: ctx.request.method(),
		path: ctx.request.path(),
		query: safeQuery(ctx.request.url(true)),
		headers: ctx.request.headers(),
		body: typeof rawBody === "string" ? rawBody : undefined,
		remoteAddr: ctx.request.ip(),
	});
	if (!result.allowed) {
		// Two-step: `.status(...).json(...)` chaining relies on a self-typed
		// return that the structural ReamContext interface can't express
		// without specialising. Splitting is functionally equivalent.
		ctx.response.status(result.status ?? 500);
		ctx.response.json(safeJsonParse(result.body));
		return;
	}
	await next();
	const body = ctx.response.getBody();
	if (body) {
		const ct = ctx.response.getHeader("content-type") ?? "";
		const ctLower = ct.toLowerCase();
		if (ctLower.startsWith("text/html") || ctLower.startsWith("text/plain")) {
			// Skip server-generated full HTML documents — ammonia is built for
			// sanitising user-supplied fragments, and treating a complete
			// document as one strips `<!doctype>` / `<html>` / `<head>`
			// (every wrapper that's not on its short allow-list). Anything
			// that opens with `<!doctype` or `<html` is server-typed output;
			// blackhole has nothing useful to do to it.
			const head = body.slice(0, 16).toLowerCase().trimStart();
			const isFullDocument =
				head.startsWith("<!doctype") || head.startsWith("<html");
			if (!isFullDocument) {
				ctx.response.setBody(bh.sanitizeResponse(body, ct));
			}
		}
	}
}

export { type Blackhole, type BlackholeOptions, createBlackhole };
