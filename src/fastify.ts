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
	runRequestPhase,
	runResponsePhase,
	serializeCookie,
} from "./core.js";
import { type BlackholeOptions, createBlackhole } from "./index.js";

/** Structural subset of a Fastify request the adapter reads. */
interface FastifyRequest {
	method: string;
	url: string;
	routerPath?: string;
	headers: Record<string, string | string[] | undefined>;
	body?: unknown;
	ip?: string;
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

function bodyString(body: unknown): string | undefined {
	if (typeof body === "string") return body;
	if (typeof body === "object" && body !== null && "_csrf" in body) {
		const token = body._csrf;
		if (typeof token === "string") return `_csrf=${encodeURIComponent(token)}`;
	}
	return undefined;
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
			const coreReq: CoreRequest = {
				method: request.method,
				path:
					request.routerPath ??
					new URL(request.url, "http://localhost").pathname,
				url: request.url,
				headers: flattenHeaders(request.headers),
				body: bodyString(request.body),
				remoteAddr: request.ip ?? "",
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
			for (const [name, value] of Object.entries(headers)) {
				reply.header(name, value);
			}
			return typeof payload === "string" ? body : payload;
		});
	};
}
