/**
 * Framework-agnostic security flow — the single source of truth shared by the
 * Ream middleware and the Express / Fastify adapters. No framework objects
 * cross this boundary: adapters translate their req/res to `CoreRequest` and
 * apply the returned outcomes. This is what keeps the three adapters from
 * duplicating the CORS → check → CSRF → headers → sanitize pipeline.
 */

import type { Blackhole } from "./index.js";

/** Framework-agnostic view of an incoming request. */
export interface CoreRequest {
	method: string;
	path: string;
	/** Full URL (or at least `path?query`) — used to extract the query string. */
	url: string;
	headers: Readonly<Record<string, string>>;
	body: string | undefined;
	remoteAddr: string;
}

/** Result of the request phase; the adapter applies it to its response/request. */
export type RequestOutcome =
	| {
			kind: "reject";
			status: number;
			body: unknown;
			/** Extra headers to set on the rejection (e.g. `Retry-After` on a 429). */
			headers?: Record<string, string>;
	  }
	| {
			kind: "preflight";
			status: number;
			headers: Record<string, string>;
			varyOrigin: boolean;
	  }
	| {
			kind: "pass";
			corsHeaders: Record<string, string>;
			varyOrigin: boolean;
			csrfToken: string;
			/** Present only when a fresh cookie must be set (none was sent). */
			setCookie?: {
				name: string;
				value: string;
				options: Record<string, unknown>;
			};
			cspNonce?: string;
			/**
			 * `X-RateLimit-*` headers to set on the SUCCESS response (parity with
			 * `@adonisjs/limiter`, which reports the budget on every response).
			 * Present only when the in-process limiter is active.
			 */
			rateLimitHeaders?: Record<string, string>;
	  };

/**
 * Build `X-RateLimit-*` headers from a rate-limit outcome. `X-RateLimit-Reset`
 * is emitted as an ISO-8601 timestamp (parity with `@adonisjs/limiter`), not a
 * raw seconds count.
 */
export function rateLimitHeaders(
	meta: { limit: number; remaining: number; resetSeconds: number },
	now: number = Date.now(),
): Record<string, string> {
	return {
		"X-RateLimit-Limit": String(meta.limit),
		"X-RateLimit-Remaining": String(meta.remaining),
		"X-RateLimit-Reset": new Date(now + meta.resetSeconds * 1000).toISOString(),
	};
}

/**
 * Normalise a rejection's `X-RateLimit-Reset` (the engine emits raw seconds) to
 * an ISO-8601 timestamp so both the success and 429 paths agree (limiter parity).
 */
function withIsoReset(
	headers: Record<string, string> | undefined,
	now: number = Date.now(),
): Record<string, string> | undefined {
	if (!headers) return headers;
	const reset = headers["X-RateLimit-Reset"];
	if (reset === undefined || !/^\d+$/.test(reset)) return headers;
	return {
		...headers,
		"X-RateLimit-Reset": new Date(now + Number(reset) * 1000).toISOString(),
	};
}

/** Safe JSON parse — returns a fallback error envelope if body is not valid JSON. */
export function safeJsonParse(body: string | undefined): unknown {
	if (!body) return { error: { code: "BLOCKED", message: "Request rejected" } };
	try {
		return JSON.parse(body);
	} catch {
		return { error: { code: "BLOCKED", message: body } };
	}
}

/** Safe URL → search string (`?a=1`). Never throws on malformed input. */
export function safeQuery(url: string): string {
	try {
		return new URL(url, "http://localhost").search;
	} catch {
		return "";
	}
}

/**
 * Append a token to a `Vary` header value without duplicating (case-insensitive).
 * Returns the new header value. Pure — adapters read/write their own header.
 */
export function appendVaryValue(current: string, value: string): string {
	const tokens = current
		.split(",")
		.map((t) => t.trim())
		.filter((t) => t.length > 0);
	const lowered = tokens.map((t) => t.toLowerCase());
	if (lowered.includes("*")) return current;
	if (!lowered.includes(value.toLowerCase())) tokens.push(value);
	return tokens.join(", ");
}

/**
 * Serialize a `Set-Cookie` header value. For adapters (Fastify) that have no
 * native cookie helper; Express/Ream use their framework's `res.cookie`.
 */
export function serializeCookie(
	name: string,
	value: string,
	options: Record<string, unknown> = {},
): string {
	const parts = [`${name}=${value}`];
	if (typeof options.path === "string") parts.push(`Path=${options.path}`);
	if (typeof options.sameSite === "string") {
		const s = options.sameSite;
		parts.push(`SameSite=${s.charAt(0).toUpperCase()}${s.slice(1)}`);
	}
	if (options.httpOnly === true) parts.push("HttpOnly");
	if (options.secure === true) parts.push("Secure");
	if (typeof options.maxAge === "number")
		parts.push(`Max-Age=${options.maxAge}`);
	return parts.join("; ");
}

/** Read a single cookie value from a raw `Cookie` header. */
function readCookie(cookieHeader: string, name: string): string | undefined {
	const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	return cookieHeader.match(new RegExp(`(?:^|;\\s*)${escaped}=([^;]+)`))?.[1];
}

/**
 * Request-phase security: CORS (incl. preflight short-circuit), the Rust filter
 * check, the CSRF double-submit token, and the CSP nonce. Returns a
 * framework-agnostic outcome — no side effects.
 */
export function runRequestPhase(
	bh: Blackhole,
	req: CoreRequest,
): RequestOutcome {
	const cors = bh.cors(
		req.headers.origin ?? "",
		req.method,
		req.headers["access-control-request-method"],
		req.headers["access-control-request-headers"],
	);
	const corsHeaders = cors?.headers ?? {};
	const varyOrigin = cors?.varyOrigin ?? false;
	if (cors?.preflight) {
		return { kind: "preflight", status: 204, headers: corsHeaders, varyOrigin };
	}

	const result = bh.check({
		method: req.method,
		path: req.path,
		query: safeQuery(req.url),
		headers: req.headers,
		body: req.body,
		remoteAddr: req.remoteAddr,
	});
	if (!result.allowed) {
		return {
			kind: "reject",
			status: result.status ?? 500,
			body: safeJsonParse(result.body),
			headers: withIsoReset(result.headers),
		};
	}

	const { name, options } = bh.csrfCookie();
	const existing = readCookie(req.headers.cookie ?? "", name);
	const csrfToken = existing ?? bh.generateCsrfToken();
	const cspNonce = bh.cspHasNonce() ? bh.generateNonce() : undefined;
	return {
		kind: "pass",
		corsHeaders,
		varyOrigin,
		csrfToken,
		setCookie: existing ? undefined : { name, value: csrfToken, options },
		cspNonce,
		rateLimitHeaders: result.rateLimit
			? rateLimitHeaders(result.rateLimit)
			: undefined,
	};
}

/**
 * Response-phase security: protective headers (with the per-request CSP nonce
 * substituted) plus body sanitization. Only `text/html` bodies are sanitized;
 * a server-rendered full document (`<!doctype>` / `<html>`) is left intact
 * (ammonia is for fragments, not whole documents). Non-HTML bodies (text/plain,
 * JSON, CSV, …) are served verbatim — the browser never parses them as markup
 * (`X-Content-Type-Options: nosniff`), so there is nothing to escape.
 */
export function runResponsePhase(
	bh: Blackhole,
	input: { body: string; contentType: string; cspNonce?: string },
): { headers: Record<string, string>; body: string } {
	const headers = bh.securityHeaders(input.cspNonce);
	let body = input.body;
	const ct = input.contentType.toLowerCase();
	if (body && ct.startsWith("text/html")) {
		const head = body.slice(0, 16).toLowerCase().trimStart();
		const isFullDocument =
			head.startsWith("<!doctype") || head.startsWith("<html");
		if (!isFullDocument) body = bh.sanitizeResponse(body, input.contentType);
	}
	return { headers, body };
}
