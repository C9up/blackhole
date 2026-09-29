/**
 * Framework-agnostic security flow — the single source of truth shared by the
 * Ream middleware and the Express / Fastify adapters. No framework objects
 * cross this boundary: adapters translate their req/res to `CoreRequest` and
 * apply the returned outcomes. This is what keeps the three adapters from
 * duplicating the CORS → check → CSRF → headers → sanitize pipeline.
 */

import type { Blackhole, CheckResult, EngineCheck } from "./index.js";

/** Framework-agnostic view of an incoming request. */
export interface CoreRequest {
	method: string;
	path: string;
	/** Full URL (or at least `path?query`) — used to extract the query string. */
	url: string;
	headers: Readonly<Record<string, string>>;
	body: string | undefined;
	remoteAddr: string;
	/**
	 * `http` or `https`, as the host resolved it (trusted-proxy aware). The CSRF
	 * origin check compares it with the Origin's scheme; without it, hosts only.
	 */
	protocol?: string;
}

/** A refusal: the adapter answers with it and stops. */
export interface RejectOutcome {
	kind: "reject";
	status: number;
	body: unknown;
	/** Extra headers to set on the rejection (e.g. `Retry-After` on a 429). */
	headers?: Record<string, string>;
}

/** A CORS preflight, answered without reaching the route. */
export interface PreflightOutcome {
	kind: "preflight";
	status: number;
	headers: Record<string, string>;
	varyOrigin: boolean;
}

/** What the guard phase lets through, with the headers it owes the response. */
export interface GuardPass {
	kind: "pass";
	corsHeaders: Record<string, string>;
	varyOrigin: boolean;
	/**
	 * `X-RateLimit-*` headers to set on the SUCCESS response (parity with
	 * `@adonisjs/limiter`, which reports the budget on every response).
	 * Present only when the in-process limiter ran.
	 */
	rateLimitHeaders?: Record<string, string>;
}

/** What the CSRF phase lets through: the token to publish, and the nonce. */
export interface CsrfPass {
	kind: "pass";
	csrfToken: string;
	/**
	 * `true` only when CSRF was enforced+validated for this request (not
	 * merely that a token was seeded). Consumers fail-close on this.
	 */
	csrfProtected: boolean;
	/** Present only when a fresh cookie must be set (none was sent). */
	setCookie?: {
		name: string;
		value: string;
		options: Record<string, unknown>;
	};
	cspNonce?: string;
	/** Present when the rate limit was counted in this phase. */
	rateLimitHeaders?: Record<string, string>;
}

export type GuardOutcome = RejectOutcome | PreflightOutcome | GuardPass;
export type CsrfOutcome = RejectOutcome | CsrfPass;

/** Result of the request phase; the adapter applies it to its response/request. */
export type RequestOutcome =
	| RejectOutcome
	| PreflightOutcome
	| (CsrfPass & Omit<GuardPass, "kind">);

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

/**
 * The body string the engine reads the `_csrf` form field out of.
 *
 * A server-rendered form submits its token as a body field — that is what
 * `csrfField()` is for — but every host parses the body before a middleware
 * sees it, so what arrives is an object and the raw urlencoded string is gone.
 * Rebuilding just the one field gives the engine something to find, without
 * re-serialising a body it has no other use for.
 *
 * Shared by all three adapters on purpose: it lived in two of them, and the
 * third silently rejected every server-rendered form because it did not.
 */
export function csrfBodyString(body: unknown): string | undefined {
	if (typeof body === "string") return body;
	if (typeof body === "object" && body !== null && "_csrf" in body) {
		const token = Reflect.get(body, "_csrf");
		if (typeof token === "string") return `_csrf=${encodeURIComponent(token)}`;
	}
	return undefined;
}

/** Safe JSON parse — returns a fallback error envelope if body is not valid JSON. */
function safeJsonParse(body: string | undefined): unknown {
	if (!body)
		return {
			error: { code: "E_BLACKHOLE_BLOCKED", message: "Request rejected" },
		};
	try {
		return JSON.parse(body);
	} catch {
		return { error: { code: "E_BLACKHOLE_BLOCKED", message: body } };
	}
}

/** Safe URL → search string (`?a=1`). Never throws on malformed input. */
function safeQuery(url: string): string {
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
/**
 * The CSRF token the client already holds, when it is still worth keeping.
 *
 * A cookie that no longer verifies — truncated by a proxy, mangled, or signed
 * under a key that has since been rotated — is NOT reused: handing it back
 * would leave the client submitting a token the server refuses on every form,
 * with no way out but clearing cookies by hand. Reissuing costs one Set-Cookie
 * and unsticks them.
 */
function usableCsrfToken(
	bh: Blackhole,
	req: { headers: Record<string, string> },
): string | undefined {
	const { name } = bh.csrfCookie();
	const existing = readCookie(req.headers.cookie ?? "", name);
	if (existing === undefined) return undefined;
	return bh.csrfTokenIsValid(existing) ? existing : undefined;
}

function readCookie(cookieHeader: string, name: string): string | undefined {
	const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	return cookieHeader.match(new RegExp(`(?:^|;\\s*)${escaped}=([^;]+)`))?.[1];
}

/** Ask the engine for `checks` only, and turn a refusal into an outcome. */
function engineCheck(
	bh: Blackhole,
	req: CoreRequest,
	checks: EngineCheck[],
): { reject?: RejectOutcome; result: CheckResult } {
	const result = bh.check({
		method: req.method,
		path: req.path,
		query: safeQuery(req.url),
		headers: req.headers,
		body: req.body,
		remoteAddr: req.remoteAddr,
		protocol: req.protocol,
		checks,
	});
	if (result.allowed) return { result };
	return {
		result,
		reject: {
			kind: "reject",
			status: result.status ?? 500,
			body: safeJsonParse(result.body),
			headers: withIsoReset(result.headers),
		},
	};
}

/**
 * The guards that need neither a route nor a parsed body: CORS (answering a
 * preflight), then the engine `checks` given — the rate limit and the shield
 * (path traversal, parameter pollution). What a host runs where every request
 * passes, unmatched routes included. No side effects.
 */
export function runGuardPhase(
	bh: Blackhole,
	req: CoreRequest,
	checks: EngineCheck[],
): GuardOutcome {
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
	if (checks.length === 0) return { kind: "pass", corsHeaders, varyOrigin };
	const { reject, result } = engineCheck(bh, req, checks);
	if (reject) return reject;
	return {
		kind: "pass",
		corsHeaders,
		varyOrigin,
		rateLimitHeaders: result.rateLimit
			? rateLimitHeaders(result.rateLimit)
			: undefined,
	};
}

/**
 * The CSRF double-submit token and the CSP nonce — and the rate limit too when
 * `rateLimit` is set, for a host whose counting key needs what the earlier
 * middlewares set. No side effects.
 */
export function runCsrfPhase(
	bh: Blackhole,
	req: CoreRequest,
	rateLimit = false,
): CsrfOutcome {
	const { name, options } = bh.csrfCookie();
	const existing = usableCsrfToken(bh, req);
	// A predicate `exceptRoutes` runs before the engine: a function cannot cross
	// the NAPI boundary, so the exemption is decided here. It exempts from CSRF
	// only — the rate limit still counts the request.
	const exempt = bh.csrfExempt({ method: req.method, path: req.path });
	const checks: EngineCheck[] = exempt ? [] : ["csrf"];
	if (rateLimit) checks.unshift("rateLimit");
	let result: CheckResult | undefined;
	if (checks.length > 0) {
		const checked = engineCheck(bh, req, checks);
		if (checked.reject) return checked.reject;
		result = checked.result;
	}
	const csrfToken = existing ?? bh.generateCsrfToken();
	return {
		kind: "pass",
		csrfToken,
		csrfProtected: exempt ? false : (result?.csrfEnforced ?? false),
		// Not seeded when the app turned the readable cookie off: an all-SSR app
		// sends the token in the `_csrf` field and has no use for it. Exemption
		// skips VERIFICATION, not the cookie: a page served from an exempt route
		// still hands the client a token for its next protected request.
		setCookie:
			existing || !bh.xsrfCookieEnabled()
				? undefined
				: { name, value: csrfToken, options },
		cspNonce: bh.cspHasNonce() ? bh.generateNonce() : undefined,
		rateLimitHeaders: result?.rateLimit
			? rateLimitHeaders(result.rateLimit)
			: undefined,
	};
}

/**
 * Request-phase security in one middleware: the guard phase, then the CSRF
 * phase. Returns a framework-agnostic outcome — no side effects.
 */
export function runRequestPhase(
	bh: Blackhole,
	req: CoreRequest,
): RequestOutcome {
	const guarded = runGuardPhase(bh, req, ["rateLimit", "shield"]);
	if (guarded.kind !== "pass") return guarded;
	const csrf = runCsrfPhase(bh, req);
	if (csrf.kind === "reject") return csrf;
	return {
		...csrf,
		corsHeaders: guarded.corsHeaders,
		varyOrigin: guarded.varyOrigin,
		rateLimitHeaders: guarded.rateLimitHeaders,
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
