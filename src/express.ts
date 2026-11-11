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
	csrfBodyString,
	rawPathOf,
	runRequestPhase,
	runResponsePhase,
	runStoreRateLimit,
	serializeCookie,
} from "./core.js";
import {
	type Blackhole,
	type BlackholeOptions,
	createBlackhole,
	type RateLimitContext,
} from "./index.js";

/** Structural subset of an Express request the adapter reads. */
interface ExpressRequest {
	method: string;
	originalUrl?: string;
	url: string;
	path?: string;
	headers: Record<string, string | string[] | undefined>;
	body?: unknown;
	ip?: string;
	/** `http` / `https` — honours Express's `trust proxy`. */
	protocol?: string;
	/** The host name without its port — honours Express's `trust proxy`. */
	hostname?: string;
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
 * `host[:port]` the way Express resolved it under its `trust proxy` setting.
 *
 * Express exposes the resolved name as `req.hostname` but drops the port, and
 * an Origin carries one. So the header it was read from is found again: the
 * first `X-Forwarded-Host` when that is where the name came from (Express
 * reads it only from a trusted proxy), the `Host` header otherwise.
 */
function expressHost(
	hostname: string | undefined,
	headers: Readonly<Record<string, string>>,
): string | undefined {
	if (hostname === undefined) return undefined;
	const forwarded = headers["x-forwarded-host"]?.split(",")[0]?.trim();
	const nameOf = (host: string) =>
		host.startsWith("[")
			? host.slice(0, host.indexOf("]") + 1)
			: (host.split(":")[0] ?? host);
	if (forwarded && nameOf(forwarded).toLowerCase() === hostname.toLowerCase()) {
		return forwarded;
	}
	return headers.host;
}

function appendVary(res: ExpressResponse, value: string): void {
	const current = res.getHeader("vary");
	const base = typeof current === "string" ? current : "";
	res.setHeader("vary", appendVaryValue(base, value));
}

/** The protective headers (CSP, HSTS, nosniff…), on refusals as on pages. */
function setSecurityHeaders(
	res: ExpressResponse,
	bh: Blackhole,
	nonce?: string,
): void {
	for (const [name, value] of Object.entries(bh.securityHeaders(nonce))) {
		res.setHeader(name, value);
	}
}

/**
 * Create an Express middleware enforcing the Blackhole security pipeline.
 */
export function blackholeExpress(options: BlackholeOptions = {}) {
	const bh = createBlackhole(options);

	return async (
		req: ExpressRequest,
		res: ExpressResponse,
		next: ExpressNext,
	): Promise<void> => {
		const headers = flattenHeaders(req.headers);
		const remoteAddr = req.ip ?? req.socket?.remoteAddress ?? "";

		// Rate-limit key: the configured `keyFor` (per-user/route), else the client
		// IP. In distributed-store mode the count + 429 decision run in JS here (the
		// Rust in-process counter is off) — mirrors the Ream middleware. Without
		// this, a standalone app configuring `rateLimit.store` would get NO limiting
		// at all (the Rust limiter is disabled AND the store was never consulted).
		const rlCtx: RateLimitContext = { request: { ip: () => remoteAddr } };
		const rateLimitKey = bh.rateLimitKey(rlCtx);
		if (bh.hasRateLimitStore()) {
			const counted = await runStoreRateLimit(bh, rateLimitKey);
			if (counted.kind === "reject") {
				for (const [name, value] of Object.entries(counted.headers ?? {})) {
					res.setHeader(name, value);
				}
				setSecurityHeaders(res, bh);
				res.status(counted.status).json(counted.body);
				return;
			}
			for (const [name, value] of Object.entries(counted.headers)) {
				res.setHeader(name, value);
			}
		}

		const coreReq: CoreRequest = {
			method: req.method,
			// `req.path` is the raw path (no `..` resolved); the fallback must be
			// too, never a WHATWG-normalized one.
			path: req.path ?? rawPathOf(req.url),
			url: req.originalUrl ?? req.url,
			headers,
			body: csrfBodyString(req.body),
			remoteAddr: rateLimitKey,
			protocol: req.protocol,
			host: expressHost(req.hostname, headers),
		};
		const outcome = runRequestPhase(bh, coreReq);

		if (outcome.kind === "reject") {
			for (const [name, value] of Object.entries(outcome.headers ?? {})) {
				res.setHeader(name, value);
			}
			setSecurityHeaders(res, bh);
			res.status(outcome.status).json(outcome.body);
			return;
		}
		if (outcome.kind === "preflight") {
			if (outcome.varyOrigin) appendVary(res, "Origin");
			for (const [name, value] of Object.entries(outcome.headers)) {
				res.setHeader(name, value);
			}
			setSecurityHeaders(res, bh);
			res.status(204).send("");
			return;
		}

		// Pass: CORS headers, CSRF token + cookie, CSP nonce.
		if (outcome.varyOrigin) appendVary(res, "Origin");
		for (const [name, value] of Object.entries(outcome.corsHeaders)) {
			res.setHeader(name, value);
		}
		// Success-path X-RateLimit-* (parity with @adonisjs/limiter).
		if (outcome.rateLimitHeaders) {
			for (const [name, value] of Object.entries(outcome.rateLimitHeaders)) {
				res.setHeader(name, value);
			}
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
		// Now, not only in the send wrapper below: a raw `res.end(...)`, a stream
		// or Express's own error handler never goes through `send`.
		setSecurityHeaders(res, bh, outcome.cspNonce);

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
				// Set before the handler ran; added again only where missing, so
				// a route's own CSP or X-Frame-Options stands.
				for (const [name, value] of Object.entries(secHeaders)) {
					if (res.getHeader(name) === undefined) res.setHeader(name, value);
				}
				if (typeof body === "string") return originalSend(outBody);
			}
			return originalSend(body);
		};

		next();
	};
}
