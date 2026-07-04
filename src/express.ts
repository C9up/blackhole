/**
 * Blackhole — Express adapter.
 *
 * Thin wrapper over the shared `./core` pipeline; no Express dependency (types
 * are structural). Filtering + CSRF/CORS run before your handler; protective
 * headers + response sanitization run as your handler sends.
 *
 * @example
 *   import { blackholeExpress } from '@c9up/blackhole/express'
 *   app.use(blackholeExpress({ csrf: true, rateLimit: { max: 100, windowSeconds: 60 } }))
 */

import {
	appendVaryValue,
	type CoreRequest,
	runRequestPhase,
	runResponsePhase,
	serializeCookie,
} from "./core.js";
import { type BlackholeOptions, createBlackhole } from "./index.js";

/** Structural subset of an Express request the adapter reads. */
interface ExpressRequest {
	method: string;
	originalUrl?: string;
	url: string;
	path?: string;
	headers: Record<string, string | string[] | undefined>;
	body?: unknown;
	ip?: string;
	socket?: { remoteAddress?: string };
	/** CSRF token for this request (Adonis idiom). Seeded by the adapter. */
	csrfToken?: string;
}

/** Structural subset of an Express response the adapter writes. */
interface ExpressResponse {
	headersSent: boolean;
	getHeader(name: string): number | string | string[] | undefined;
	setHeader(name: string, value: string): unknown;
	/** Appends a header value (used for Set-Cookie so prior cookies aren't clobbered). */
	append(name: string, value: string | string[]): unknown;
	status(code: number): ExpressResponse;
	json(body: unknown): unknown;
	send(body?: unknown): unknown;
	/** CSP nonce for this request (Adonis idiom). Seeded by the adapter. */
	nonce?: string;
}

type ExpressNext = (err?: unknown) => void;

/** Flatten Express's `string | string[]` headers to a plain record. */
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

/**
 * Build the body string the Rust filter sees. The header path (`X-XSRF-TOKEN`)
 * covers SPAs; for server-rendered forms behind `body-parser`, reconstruct just
 * the `_csrf` field so the form-field validation still works.
 */
function bodyString(body: unknown): string | undefined {
	if (typeof body === "string") return body;
	if (typeof body === "object" && body !== null && "_csrf" in body) {
		const token = body._csrf;
		if (typeof token === "string") return `_csrf=${encodeURIComponent(token)}`;
	}
	return undefined;
}

function appendVary(res: ExpressResponse, value: string): void {
	const current = res.getHeader("vary");
	const base = typeof current === "string" ? current : "";
	res.setHeader("vary", appendVaryValue(base, value));
}

/**
 * Create an Express middleware enforcing the Blackhole security pipeline.
 */
export function blackholeExpress(options: BlackholeOptions = {}) {
	const bh = createBlackhole(options);

	return (
		req: ExpressRequest,
		res: ExpressResponse,
		next: ExpressNext,
	): void => {
		const headers = flattenHeaders(req.headers);
		const coreReq: CoreRequest = {
			method: req.method,
			path: req.path ?? new URL(req.url, "http://localhost").pathname,
			url: req.originalUrl ?? req.url,
			headers,
			body: bodyString(req.body),
			remoteAddr: req.ip ?? req.socket?.remoteAddress ?? "",
		};
		const outcome = runRequestPhase(bh, coreReq);

		if (outcome.kind === "reject") {
			for (const [name, value] of Object.entries(outcome.headers ?? {})) {
				res.setHeader(name, value);
			}
			res.status(outcome.status).json(outcome.body);
			return;
		}
		if (outcome.kind === "preflight") {
			if (outcome.varyOrigin) appendVary(res, "Origin");
			for (const [name, value] of Object.entries(outcome.headers)) {
				res.setHeader(name, value);
			}
			res.status(204).send("");
			return;
		}

		// Pass: CORS headers, CSRF token + cookie, CSP nonce.
		if (outcome.varyOrigin) appendVary(res, "Origin");
		for (const [name, value] of Object.entries(outcome.corsHeaders)) {
			res.setHeader(name, value);
		}
		req.csrfToken = outcome.csrfToken;
		if (outcome.setCookie) {
			// append, not setHeader — setHeader('set-cookie') replaces any cookie an
			// earlier middleware already queued; append preserves them all.
			res.append(
				"set-cookie",
				serializeCookie(
					outcome.setCookie.name,
					outcome.setCookie.value,
					outcome.setCookie.options,
				),
			);
		}
		if (outcome.cspNonce) res.nonce = outcome.cspNonce;

		// Response phase: wrap `send` to apply protective headers + sanitize the
		// body as the handler responds (covers `res.send` and `res.json`, which
		// delegates to `send`). Raw `res.end(...)` streams are not post-processed.
		const originalSend = res.send.bind(res);
		res.send = (body?: unknown): unknown => {
			if (!res.headersSent) {
				// Express defaults a string body to text/html inside its real send(),
				// but that default isn't set yet here — mirror it so res.send("<p>"+x)
				// is still sanitized (the XSS guard was a no-op for plain strings).
				const ct =
					String(res.getHeader("content-type") ?? "") ||
					(typeof body === "string" ? "text/html" : "");
				const { headers: secHeaders, body: outBody } = runResponsePhase(bh, {
					body: typeof body === "string" ? body : "",
					contentType: ct,
					cspNonce: outcome.cspNonce,
				});
				for (const [name, value] of Object.entries(secHeaders)) {
					res.setHeader(name, value);
				}
				if (typeof body === "string") return originalSend(outBody);
			}
			return originalSend(body);
		};

		next();
	};
}
