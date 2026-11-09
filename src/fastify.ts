/**
 * Blackhole — Fastify adapter.
 *
 * Thin wrapper over the shared `./core` pipeline; no Fastify dependency (types
 * are structural). `preValidation` runs filtering + CSRF/CORS (after body
 * parsing, so the `_csrf` form field is readable); `onSend` applies protective
 * headers + response sanitization.
 *
 * @example
 *   import { blackholeFastify } from '@c9up/blackhole/fastify'
 *   fastify.register(blackholeFastify({ csrf: true, rateLimit: { max: 100, windowSeconds: 60 } }))
 */

import {
	appendVaryValue,
	type CoreRequest,
	csrfBodyString,
	rateLimitHeaders,
	rawPathOf,
	runRequestPhase,
	runResponsePhase,
	serializeCookie,
} from "./core.js";
import {
	type BlackholeOptions,
	createBlackhole,
	type RateLimitContext,
} from "./index.js";

/** Structural subset of a Fastify request the adapter reads. */
interface FastifyRequest {
	method: string;
	/** The request target as received — path and query, nothing resolved. */
	url: string;
	raw?: { url?: string };
	/** The matched route's pattern (Fastify 4). */
	routerPath?: string;
	/** The matched route's options; `url` is its pattern (Fastify ≥ 4.10). */
	routeOptions?: { url?: string };
	/** `host[:port]`, honouring `trustProxy` (Fastify 5). */
	host?: string;
	/** `host[:port]` on Fastify 4, the name alone on Fastify 5. */
	hostname?: string;
	headers: Record<string, string | string[] | undefined>;
	body?: unknown;
	ip?: string;
	/** `http` / `https` — honours Fastify's `trustProxy`. */
	protocol?: string;
	/** CSRF token for this request (Adonis idiom). Seeded by the adapter. */
	csrfToken?: string;
}

/** Structural subset of a Fastify reply the adapter writes. */
interface FastifyReply {
	code(statusCode: number): FastifyReply;
	header(name: string, value: string | string[]): FastifyReply;
	getHeader(name: string): number | string | string[] | undefined;
	send(payload?: unknown): FastifyReply;
	/** CSP nonce for this request (Adonis idiom). Seeded by the adapter. */
	nonce?: string;
}

/** Structural subset of the Fastify instance the plugin registers hooks on. */
interface FastifyInstance {
	addHook(
		name: "preValidation",
		hook: (request: FastifyRequest, reply: FastifyReply) => Promise<void>,
	): unknown;
	addHook(
		name: "onSend",
		hook: (
			request: FastifyRequest,
			reply: FastifyReply,
			payload: unknown,
		) => Promise<unknown>,
	): unknown;
}

function flattenHeaders(
	headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [key, value] of Object.entries(headers)) {
		if (Array.isArray(value)) out[key] = value.join(", ");
		else if (typeof value === "string") out[key] = value;
	}
	return out;
}

function appendVary(reply: FastifyReply, value: string): void {
	const current = reply.getHeader("vary");
	const base = typeof current === "string" ? current : "";
	reply.header("vary", appendVaryValue(base, value));
}

/**
 * Create a Fastify plugin enforcing the Blackhole security pipeline. Register
 * at the root scope so the hooks apply app-wide:
 * `fastify.register(blackholeFastify(options))`.
 */
export function blackholeFastify(options: BlackholeOptions = {}) {
	const bh = createBlackhole(options);

	return async (fastify: FastifyInstance): Promise<void> => {
		// preValidation (not onRequest): runs AFTER Fastify parses the body, so the
		// `_csrf` form-field token is available to CSRF validation. onRequest fires
		// before body parsing → request.body undefined → form CSRF was dead.
		fastify.addHook("preValidation", async (request, reply) => {
			const remoteAddr = request.ip ?? "";

			// Rate-limit key: the configured `keyFor` (per-user/route), else the
			// client IP. In distributed-store mode the count + 429 decision run in
			// JS here (the Rust in-process counter is off) — mirrors the Ream
			// middleware. Without this, a standalone app configuring
			// `rateLimit.store` would get NO limiting (Rust off AND store unused).
			const rlCtx: RateLimitContext = { request: { ip: () => remoteAddr } };
			const rateLimitKey = bh.rateLimitKey(rlCtx);
			if (bh.hasRateLimitStore()) {
				const decision = await bh.checkRateLimit(rateLimitKey);
				const rlHeaders = rateLimitHeaders(decision);
				if (!decision.allowed) {
					reply.header("Retry-After", String(decision.resetSeconds));
					for (const [name, value] of Object.entries(rlHeaders)) {
						reply.header(name, value);
					}
					await reply.code(429).send({
						error: {
							code: "E_BLACKHOLE_RATE_LIMITED",
							message: "Too many requests",
						},
					});
					return;
				}
				for (const [name, value] of Object.entries(rlHeaders)) {
					reply.header(name, value);
				}
			}

			const target = request.raw?.url ?? request.url;
			const coreReq: CoreRequest = {
				method: request.method,
				// The path as the client sent it. Not `routerPath` — that is the
				// route PATTERN (`/files/*`), which never holds a `..` — and not
				// `new URL().pathname`, which resolves `..` and `%2e%2e` away
				// before the traversal guard could see them.
				path: rawPathOf(target),
				url: target,
				// Fastify 5 names the host with its port `host`; Fastify 4 named
				// it `hostname`. Either honours `trustProxy`.
				host: request.host ?? request.hostname,
				routePattern: request.routeOptions?.url ?? request.routerPath,
				headers: flattenHeaders(request.headers),
				body: csrfBodyString(request.body),
				remoteAddr: rateLimitKey,
				protocol: request.protocol,
			};
			const outcome = runRequestPhase(bh, coreReq);

			if (outcome.kind === "reject") {
				for (const [name, value] of Object.entries(outcome.headers ?? {})) {
					reply.header(name, value);
				}
				await reply.code(outcome.status).send(outcome.body);
				return;
			}
			if (outcome.kind === "preflight") {
				if (outcome.varyOrigin) appendVary(reply, "Origin");
				for (const [name, value] of Object.entries(outcome.headers)) {
					reply.header(name, value);
				}
				await reply.code(204).send();
				return;
			}

			if (outcome.varyOrigin) appendVary(reply, "Origin");
			for (const [name, value] of Object.entries(outcome.corsHeaders)) {
				reply.header(name, value);
			}
			// Success-path X-RateLimit-* (parity with @adonisjs/limiter).
			if (outcome.rateLimitHeaders) {
				for (const [name, value] of Object.entries(outcome.rateLimitHeaders)) {
					reply.header(name, value);
				}
			}
			request.csrfToken = outcome.csrfToken;
			if (outcome.setCookie) {
				// Merge with any Set-Cookie already queued so we don't clobber it
				// (Set-Cookie must stay as separate header lines, never comma-joined).
				const cookie = serializeCookie(
					outcome.setCookie.name,
					outcome.setCookie.value,
					outcome.setCookie.options,
				);
				const existing = reply.getHeader("set-cookie");
				const merged: string | string[] = Array.isArray(existing)
					? [...existing, cookie]
					: typeof existing === "string"
						? [existing, cookie]
						: cookie;
				reply.header("set-cookie", merged);
			}
			if (outcome.cspNonce) reply.nonce = outcome.cspNonce;
		});

		fastify.addHook("onSend", async (_request, reply, payload) => {
			const ct = reply.getHeader("content-type");
			const { headers, body } = runResponsePhase(bh, {
				body: typeof payload === "string" ? payload : "",
				contentType: typeof ct === "string" ? ct : "",
				cspNonce: reply.nonce,
			});
			// Only where the route did not set its own: a page that must be
			// framed by a partner, or carries a CSP of its own, keeps it.
			for (const [name, value] of Object.entries(headers)) {
				if (reply.getHeader(name) === undefined) reply.header(name, value);
			}
			return typeof payload === "string" ? body : payload;
		});
	};
}
