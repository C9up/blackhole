/**
 * Blackhole — Hono adapter.
 *
 * The pipeline the Express and Fastify adapters run (`./core`), as a Hono
 * middleware: refusals are answered before the route, then the protective
 * headers, the CSRF cookie and the XSS pass are applied to whatever response
 * the route — or Hono's error handler — produced.
 *
 * @example
 *   import { Hono } from 'hono'
 *   import { blackholeHono } from '@c9up/blackhole/hono'
 *
 *   const app = new Hono()
 *   app.use(blackholeHono({ csrf: true, secret: process.env.APP_KEY }))
 *   app.post('/orders', (c) => c.json({ token: c.get('csrfToken') }))
 */

import type { Context, MiddlewareHandler } from "hono";
import {
	appendVaryValue,
	type CoreRequest,
	csrfBodyString,
	rateLimitHeaders,
	runRequestPhase,
	runResponsePhase,
	serializeCookie,
} from "./core.js";
import { type BlackholeOptions, createBlackhole } from "./index.js";

declare module "hono" {
	interface ContextVariableMap {
		/** This request's CSRF token (`c.get('csrfToken')`), for a form's `_csrf` field. */
		csrfToken: string;
		/** This request's CSP nonce, when the CSP uses `@nonce`. */
		cspNonce?: string;
	}
}

export interface BlackholeHonoOptions extends BlackholeOptions {
	/**
	 * The client address the rate limit counts under. Hono has no
	 * runtime-neutral one: pass your runtime's (`getConnInfo(c).remote.address`
	 * from `hono/bun`, `hono/deno`…). Default: the socket of `@hono/node-server`.
	 */
	clientIp?: (c: Context) => string;
	/**
	 * `http` or `https`, compared with the Origin on a CSRF-guarded request.
	 * Default: the scheme of the request URL — behind a proxy, derive it from
	 * a header only that proxy sets.
	 */
	protocol?: (c: Context) => string;
}

/** The socket address `@hono/node-server` exposes as `c.env.incoming`. */
function nodeSocketAddress(env: unknown): string | undefined {
	const incoming: unknown = Reflect.get(Object(env), "incoming");
	const socket: unknown = Reflect.get(Object(incoming), "socket");
	const address: unknown = Reflect.get(Object(socket), "remoteAddress");
	return typeof address === "string" ? address : undefined;
}

/**
 * The form fields the engine reads a `_csrf` token from. Hono caches the body,
 * so the route can still read it.
 */
async function csrfBody(c: Context): Promise<string | undefined> {
	const type = c.req.header("content-type") ?? "";
	if (type.startsWith("application/x-www-form-urlencoded")) {
		return c.req.text();
	}
	if (type.startsWith("multipart/form-data")) {
		return csrfBodyString(await c.req.parseBody());
	}
	return undefined;
}

/** A JSON refusal carrying `headers`. */
function refusal(
	status: number,
	body: unknown,
	headers: Record<string, string>,
): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { ...headers, "content-type": "application/json" },
	});
}

/** Create a Hono middleware enforcing the Blackhole security pipeline. */
export function blackholeHono(
	options: BlackholeHonoOptions = {},
): MiddlewareHandler {
	const { clientIp, protocol, ...blackholeOptions } = options;
	const bh = createBlackhole(blackholeOptions);

	return async (c, next) => {
		const remoteAddr = clientIp
			? clientIp(c)
			: (nodeSocketAddress(c.env) ?? "");
		const rateLimitKey = bh.rateLimitKey({
			request: { ip: () => remoteAddr },
		});

		// Distributed store: count + decide in JS, as the other adapters do.
		let storeHeaders: Record<string, string> = {};
		if (bh.hasRateLimitStore()) {
			const decision = await bh.checkRateLimit(rateLimitKey);
			storeHeaders = rateLimitHeaders(decision);
			if (!decision.allowed) {
				return refusal(
					429,
					{
						error: {
							code: "E_BLACKHOLE_RATE_LIMITED",
							message: "Too many requests",
						},
					},
					{
						...storeHeaders,
						"retry-after": String(decision.resetSeconds),
						...bh.securityHeaders(),
					},
				);
			}
		}

		const request: CoreRequest = {
			method: c.req.method,
			path: c.req.path,
			url: c.req.url,
			headers: c.req.header(),
			body: await csrfBody(c),
			remoteAddr: rateLimitKey,
			protocol: protocol
				? protocol(c)
				: new URL(c.req.url).protocol.replace(/:$/, ""),
		};
		const outcome = runRequestPhase(bh, request);

		if (outcome.kind === "reject") {
			return refusal(outcome.status, outcome.body, {
				...(outcome.headers ?? {}),
				...bh.securityHeaders(),
			});
		}
		if (outcome.kind === "preflight") {
			return new Response(null, {
				status: outcome.status,
				headers: {
					...outcome.headers,
					...bh.securityHeaders(),
					...(outcome.varyOrigin ? { vary: "Origin" } : {}),
				},
			});
		}

		c.set("csrfToken", outcome.csrfToken);
		if (outcome.cspNonce) c.set("cspNonce", outcome.cspNonce);

		// A route that throws still reaches here: Hono's compose hands the error
		// to `onError` and sets its response on `c.res` before `next` resolves.
		await next();

		const contentType = c.res.headers.get("content-type") ?? "";
		const html = contentType.toLowerCase().startsWith("text/html");
		const { headers, body } = runResponsePhase(bh, {
			body: html ? await c.res.clone().text() : "",
			contentType,
			cspNonce: outcome.cspNonce,
		});
		// A fresh Response: the route's own may have immutable headers (one
		// returned straight from `fetch`, for instance).
		const response = new Response(html ? body : c.res.body, c.res);
		for (const [name, value] of Object.entries({
			...outcome.corsHeaders,
			...storeHeaders,
			...(outcome.rateLimitHeaders ?? {}),
			...headers,
		})) {
			response.headers.set(name, value);
		}
		if (outcome.varyOrigin) {
			response.headers.set(
				"vary",
				appendVaryValue(response.headers.get("vary") ?? "", "Origin"),
			);
		}
		if (outcome.setCookie) {
			response.headers.append(
				"set-cookie",
				serializeCookie(
					outcome.setCookie.name,
					outcome.setCookie.value,
					outcome.setCookie.options,
				),
			);
		}
		c.res = undefined;
		c.res = response;
	};
}
