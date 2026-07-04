/**
 * @c9up/blackhole — Rust-native security filter for any Node.js framework.
 *
 * Provides XSS response sanitization, CSRF token management, and sliding-window
 * rate limiting. All security checks run in Rust via NAPI — rejected requests
 * never reach JavaScript. Works standalone (Express, Fastify, Hono) or as a
 * Ream provider.
 *
 * @example
 *   import { blackholeExpress } from '@c9up/blackhole/express'
 *
 *   // Express adapter — handles request filtering AND response sanitization
 *   app.use(blackholeExpress({ csrf: true, rateLimit: { max: 100, windowSeconds: 60 } }))
 *
 *   // Or low-level usage — note: result.body may not always be valid JSON,
 *   // so wrap JSON.parse in try/catch (or use the express/fastify adapters which do this for you).
 *   import { createBlackhole } from '@c9up/blackhole'
 */

import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { arch, platform } from "node:process";
import { fileURLToPath } from "node:url";

const nodeRequire = createRequire(import.meta.url);
const currentDir = dirname(fileURLToPath(import.meta.url));

const platformMap: Record<string, string> = {
	"linux-x64": "linux-x64-gnu",
	"linux-arm64": "linux-arm64-gnu",
	"darwin-x64": "darwin-x64",
	"darwin-arm64": "darwin-arm64",
	"win32-x64": "win32-x64-msvc",
};

interface NativeBlackhole {
	generateCsrfToken(): string;
	check(
		method: string,
		path: string,
		query: string,
		headersJson: string,
		body: string,
		remoteAddr: string,
	): {
		allowed: boolean;
		status?: number;
		body?: string;
		headers?: Record<string, string>;
	};
	sanitizeResponse(body: string, contentType: string): string;
}

interface NativeModule {
	Blackhole: new (
		xssEnabled?: boolean,
		csrfEnabled?: boolean,
		rateLimitMax?: number,
		rateLimitWindow?: number,
		pathTraversal?: boolean,
		paramPollution?: boolean,
		csrfExceptRoutes?: string[],
		csrfMethods?: string[],
		csrfSecret?: string,
		csrfTrustedOrigins?: string[],
	) => NativeBlackhole;
}

let native: NativeModule | undefined;

try {
	const suffix = platformMap[`${platform}-${arch}`];
	if (suffix) {
		native = nodeRequire(join(currentDir, `../index.${suffix}.node`));
	}
} catch {
	// Binary not available — createBlackhole will throw.
}

/** Protective HTTP response headers (Helmet-style). */
export interface SecurityHeadersConfig {
	/** `X-Content-Type-Options: nosniff` (default: true). */
	contentTypeOptions?: boolean;
	/** `X-Frame-Options` (default: `SAMEORIGIN`; `false` to omit). */
	frameOptions?: "DENY" | "SAMEORIGIN" | false;
	/** `Strict-Transport-Security` (default: 180d + subdomains; `false` to omit). */
	hsts?:
		| { maxAge: number; includeSubDomains?: boolean; preload?: boolean }
		| false;
	/**
	 * `Content-Security-Policy` (default: a hardened baseline — see
	 * {@link SECURITY_HEADERS_DEFAULTS}; `false` to omit). Include the `@nonce`
	 * token (AdonisJS-style) and it's replaced per-request with `'nonce-<random>'`;
	 * the raw nonce is exposed as `ctx.response.nonce` (and `ctx.store` `cspNonce`)
	 * for `<script nonce="…">`. e.g. `"default-src 'self'; script-src 'self' @nonce"`.
	 *
	 * CSP keywords MUST be single-quoted (`'self'`, `'none'`, `'unsafe-inline'`,
	 * `'strict-dynamic'`, …). An unquoted keyword is parsed by the browser as a
	 * host literal and silently breaks the policy — blackhole warns when it spots one.
	 */
	csp?: string | false;
	/**
	 * Emit the CSP as `Content-Security-Policy-Report-Only` instead of enforcing
	 * it (default: false). Lets a team observe violations before switching a
	 * strict policy on — pair with a `report-to`/`report-uri` directive in `csp`.
	 */
	cspReportOnly?: boolean;
	/** `Referrer-Policy` (default: `strict-origin-when-cross-origin`). */
	referrerPolicy?: string;
	/** `Permissions-Policy` (default: camera/mic/geolocation denied). */
	permissionsPolicy?: string;
}

const SECURITY_HEADERS_DEFAULTS: SecurityHeadersConfig = {
	contentTypeOptions: true,
	frameOptions: "SAMEORIGIN",
	hsts: { maxAge: 15552000, includeSubDomains: true },
	// Hardened baseline: `base-uri` and `form-action` do NOT fall back to
	// `default-src` per the CSP spec, so they must be set explicitly — otherwise
	// an injected `<base href>` re-roots relative asset/script URLs and an
	// injected `<form>` can POST credentials off-origin. `object-src 'none'`
	// kills legacy plugin vectors (helmet hardens it the same way).
	csp: "default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'",
	referrerPolicy: "strict-origin-when-cross-origin",
	permissionsPolicy: "camera=(), microphone=(), geolocation=()",
};

/** CSP source keywords that MUST be single-quoted to be honoured by the browser. */
const CSP_KEYWORDS =
	/(?:^|\s)(self|none|unsafe-inline|unsafe-eval|unsafe-hashes|strict-dynamic|report-sample)(?:\s|;|$)/;

/** Warn (once, non-fatal) when a CSP keyword is used unquoted — a silent policy break. */
function warnUnquotedCspKeywords(csp: string): void {
	// Strip the substitutable @nonce token first, then flag bare keywords.
	if (CSP_KEYWORDS.test(csp.replaceAll("@nonce", ""))) {
		process.stderr.write(
			"[blackhole] WARNING: your CSP contains an UNQUOTED keyword (e.g. `self` instead " +
				"of `'self'`). Browsers parse an unquoted keyword as a host name, silently " +
				"breaking the directive. Single-quote every CSP keyword.\n",
		);
	}
}

/** Compute the protective response headers from config (empty when disabled). */
function computeSecurityHeaders(
	config: SecurityHeadersConfig | false | undefined,
): Record<string, string> {
	if (config === false) return {};
	const c = { ...SECURITY_HEADERS_DEFAULTS, ...config };
	const headers: Record<string, string> = { "x-xss-protection": "0" };
	if (c.contentTypeOptions) headers["x-content-type-options"] = "nosniff";
	if (c.frameOptions) headers["x-frame-options"] = c.frameOptions;
	if (c.hsts) {
		// A negative / zero max-age silently DISABLES HSTS (`max-age=0` tells the
		// browser to forget the policy) — reject it loudly like Shield does.
		if (!Number.isFinite(c.hsts.maxAge) || c.hsts.maxAge < 0) {
			throw new Error(
				`[blackhole] Invalid HSTS maxAge ${c.hsts.maxAge}: must be a non-negative number of seconds.`,
			);
		}
		let v = `max-age=${c.hsts.maxAge}`;
		if (c.hsts.includeSubDomains) v += "; includeSubDomains";
		if (c.hsts.preload) v += "; preload";
		headers["strict-transport-security"] = v;
	}
	if (c.csp) {
		warnUnquotedCspKeywords(c.csp);
		const cspHeader = c.cspReportOnly
			? "content-security-policy-report-only"
			: "content-security-policy";
		headers[cspHeader] = c.csp;
	}
	if (c.referrerPolicy) headers["referrer-policy"] = c.referrerPolicy;
	if (c.permissionsPolicy) headers["permissions-policy"] = c.permissionsPolicy;
	return headers;
}

/** Cross-Origin Resource Sharing policy. */
export interface CorsConfig {
	/** Allowed origin(s). `true`/`'*'` = any (forbidden with credentials), a string/array = allow-list, or a predicate. */
	origin: string | string[] | boolean | ((origin: string) => boolean);
	methods?: string[];
	/**
	 * Allowed request headers for preflight. An array is an allow-list (a
	 * preflight requesting a header outside it is refused); `true` reflects
	 * whatever the browser sends in `Access-Control-Request-Headers`. Defaults to
	 * a common allow-list when omitted.
	 */
	headers?: string[] | true;
	exposedHeaders?: string[];
	credentials?: boolean;
	maxAge?: number;
}

/** Per-request CORS decision: headers to set, Vary flag, and preflight short-circuit. */
export interface CorsResult {
	headers: Record<string, string>;
	varyOrigin: boolean;
	preflight: boolean;
}

/** Validate a CORS config (throws on the credential-leak combinations). */
function validateCors(cfg: CorsConfig): void {
	if (cfg.credentials === true && (cfg.origin === "*" || cfg.origin === true)) {
		throw new Error(
			'CORS misconfiguration: origin="*" (or true) cannot be combined with credentials=true. Pin to an explicit origin list.',
		);
	}
	if (Array.isArray(cfg.origin)) {
		for (const entry of cfg.origin) {
			if (typeof entry !== "string" || entry.length === 0) {
				throw new Error(
					"CORS misconfiguration: origin array must contain only non-empty strings.",
				);
			}
		}
	}
}

function isOriginAllowed(cfg: CorsConfig, origin: string): string | false {
	if (!origin) return false;
	const o = cfg.origin;
	if (o === true || o === "*") return "*";
	if (o === false) return false;
	if (typeof o === "function") return o(origin) ? origin : false;
	// A string may be a single origin OR a comma-separated allow-list (Adonis
	// accepts `'a.com,b.com'`); split so a ported Adonis config isn't silently
	// a deny-all.
	if (typeof o === "string") {
		const list = o.split(",").map((entry) => entry.trim());
		return list.includes(origin) ? origin : false;
	}
	if (Array.isArray(o)) return o.includes(origin) ? origin : false;
	return false;
}

/** Split the browser's `Access-Control-Request-Headers` into a trimmed list. */
function parseRequestedHeaders(value: string | undefined): string[] {
	if (!value) return [];
	return value
		.split(",")
		.map((h) => h.trim())
		.filter((h) => h.length > 0);
}

const DEFAULT_CORS_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const DEFAULT_CORS_HEADERS = ["Content-Type", "Authorization", "Accept", "X-Requested-With"];

/** Compute the CORS headers + flags for one request. */
function computeCors(
	cfg: CorsConfig,
	requestOrigin: string,
	method: string,
	requestMethod?: string,
	requestHeaders?: string,
): CorsResult {
	const allowed = isOriginAllowed(cfg, requestOrigin);
	const headers: Record<string, string> = {};
	// Vary on Origin unless the policy is static (`*` / `false`).
	const varyOrigin =
		cfg.origin !== true && cfg.origin !== "*" && cfg.origin !== false;
	if (allowed) {
		headers["access-control-allow-origin"] =
			allowed === "*" ? "*" : requestOrigin;
		if (cfg.credentials) headers["access-control-allow-credentials"] = "true";
		if (cfg.exposedHeaders?.length) {
			headers["access-control-expose-headers"] = cfg.exposedHeaders.join(", ");
		}
	}
	// A genuine CORS preflight is OPTIONS + an allowed origin + the
	// Access-Control-Request-Method header. Without these guards EVERY OPTIONS
	// (disallowed origins included) got a bare 204, hijacking app OPTIONS routes.
	const preflight =
		method.toUpperCase() === "OPTIONS" &&
		Boolean(allowed) &&
		typeof requestMethod === "string" &&
		requestMethod.length > 0;
	if (preflight && allowed && requestMethod) {
		const allowedMethods = cfg.methods ?? DEFAULT_CORS_METHODS;
		// Reject the preflight (emit NO Access-Control-Allow-* → browser blocks)
		// when the requested method isn't allowed, matching the CORS spec /
		// @adonisjs/cors — rather than advertising the full list regardless.
		if (!allowedMethods.map((m) => m.toUpperCase()).includes(requestMethod.toUpperCase())) {
			return { headers, varyOrigin, preflight };
		}
		headers["access-control-allow-methods"] = allowedMethods.join(", ");

		// Requested headers: `true` reflects them, an array is an allow-list (a
		// header outside it refuses the preflight), else the common default list.
		const requested = parseRequestedHeaders(requestHeaders);
		if (cfg.headers === true) {
			headers["access-control-allow-headers"] =
				requested.length > 0 ? requested.join(", ") : DEFAULT_CORS_HEADERS.join(", ");
		} else {
			const allowList = cfg.headers ?? DEFAULT_CORS_HEADERS;
			const lowered = allowList.map((h) => h.toLowerCase());
			const disallowed = requested.find((h) => !lowered.includes(h.toLowerCase()));
			if (disallowed) return { headers, varyOrigin, preflight };
			headers["access-control-allow-headers"] = allowList.join(", ");
		}
		if (cfg.maxAge) headers["access-control-max-age"] = String(cfg.maxAge);
	}
	return { headers, varyOrigin, preflight };
}

/** Attributes for the `XSRF-TOKEN` cookie the middleware seeds (Adonis-compatible). */
export interface CsrfCookieConfig {
	/** `SameSite` policy (default: `lax`). */
	sameSite?: "strict" | "lax" | "none";
	/** `Secure` flag (default: false — set true in production / over HTTPS). */
	secure?: boolean;
	/**
	 * `HttpOnly` flag (default: false). The double-submit flow needs the SPA to
	 * read the cookie and echo it in `X-XSRF-TOKEN`; set true only if every
	 * client is server-rendered (token then flows via the `_csrf` form field).
	 */
	httpOnly?: boolean;
	/** Cookie `Path` (default: `/`). */
	path?: string;
}

/**
 * CSRF protection config (AdonisJS-compatible). Stateless double-submit: the
 * `XSRF-TOKEN` cookie is matched against an `X-XSRF-TOKEN` / `X-CSRF-TOKEN`
 * header or the `_csrf` form field.
 */
export interface CsrfConfig {
	/** Enable CSRF validation (default: true). */
	enabled?: boolean;
	/** Route patterns to skip (exact, or trailing-`*` prefix), e.g. `/api/webhooks/*`. */
	exceptRoutes?: string[];
	/** HTTP methods to guard (default: POST, PUT, PATCH, DELETE). */
	methods?: string[];
	/**
	 * Cross-origins allowed to make state-changing requests, in addition to
	 * same-origin (always allowed). Unsafe verbs whose `Origin`/`Referer` is
	 * cross-origin AND not listed here are rejected before the token check — the
	 * defense-in-depth that stops a planted-but-signed token. Same-origin apps
	 * need nothing here. e.g. `['https://admin.example.com']`.
	 */
	trustedOrigins?: string[];
	/** Attributes for the seeded `XSRF-TOKEN` cookie. */
	cookie?: CsrfCookieConfig;
}

// Re-export the config helper so the documented `import { defineConfig } from
// '@c9up/blackhole'` resolves (it was previously reachable only via the
// '@c9up/blackhole/config' subpath).
export { type BlackholeConfig, defineConfig } from "./config.js";

export interface BlackholeOptions {
	/** Enable XSS response sanitization (default: true). */
	xss?: boolean;
	/** CSRF validation — `true`/`false` to toggle, or an object for fine-grained control. */
	csrf?: boolean | CsrfConfig;
	/** Rate limiting configuration. */
	rateLimit?: { max: number; windowSeconds: number };
	/** Reject requests with path-traversal sequences (`..`, `%2e%2e`) (default: true). */
	pathTraversal?: boolean;
	/** Reject requests with duplicate query params (HTTP parameter pollution) (default: true). */
	paramPollution?: boolean;
	/** Protective response headers. Defaults applied when omitted; `false` to disable. */
	securityHeaders?: SecurityHeadersConfig | false;
	/** Cross-Origin Resource Sharing policy. Omit to leave CORS unmanaged. */
	cors?: CorsConfig;
	/**
	 * HMAC secret used to **sign** CSRF tokens (signed double-submit). Pass the
	 * app's `APP_KEY`. Required when CSRF is enabled (fail-closed). Every instance
	 * must share the same secret (stateless horizontal scale).
	 *
	 * Scope of the signature: it proves a token was minted by this server, so an
	 * attacker can't forge a brand-new valid pair. It does NOT bind the token to a
	 * user/session, so it alone does not stop an attacker replaying a token they
	 * were legitimately issued — the same-origin `Origin`/`Referer` check on
	 * unsafe verbs (enabled by default) is what closes that cookie-injection gap.
	 */
	secret?: string;
}

export interface CheckResult {
	allowed: boolean;
	status?: number;
	body?: string;
	/** Extra headers to set on a rejection (e.g. `Retry-After` / `X-RateLimit-*` on a 429). */
	headers?: Record<string, string>;
}

export interface Blackhole {
	/** Run all security checks against an incoming request. */
	check(req: {
		method: string;
		path: string;
		query?: string;
		headers: Readonly<Record<string, string>>;
		body?: string;
		remoteAddr?: string;
	}): CheckResult;
	/** Generate a new CSRF token. */
	generateCsrfToken(): string;
	/** Sanitize an outgoing response body based on content type. */
	sanitizeResponse(body: string, contentType: string): string;
	/**
	 * Protective response headers (Helmet-style), computed from config. Pass a
	 * `nonce` to substitute the `@nonce` CSP token with `'nonce-<nonce>'`.
	 */
	securityHeaders(nonce?: string): Record<string, string>;
	/** Does the configured CSP use the `@nonce` token (→ a per-request nonce is needed)? */
	cspHasNonce(): boolean;
	/** Generate a fresh CSP nonce (base64). */
	generateNonce(): string;
	/** CORS decision for a request, or `undefined` when CORS isn't configured. */
	cors(
		requestOrigin: string,
		method: string,
		requestMethod?: string,
		requestHeaders?: string,
	): CorsResult | undefined;
	/** Name + attributes of the `XSRF-TOKEN` cookie the middleware should seed. */
	csrfCookie(): { name: string; options: Record<string, unknown> };
}

/** Cookie name shared by the Rust validator and the middleware (not configurable — Adonis fixes it). */
const CSRF_COOKIE_NAME = "XSRF-TOKEN";

/** Normalize the `csrf` option into a flat shape (boolean shorthand → full config). */
function resolveCsrf(csrf: boolean | CsrfConfig | undefined): {
	enabled: boolean;
	exceptRoutes: string[];
	methods: string[];
	trustedOrigins: string[];
	cookieOptions: Record<string, unknown>;
} {
	const cfg: CsrfConfig =
		typeof csrf === "boolean" ? { enabled: csrf } : (csrf ?? {});
	const cookie = cfg.cookie ?? {};
	// The XSRF-TOKEN cookie MUST stay readable by JS for the double-submit flow
	// (the SPA reads it and echoes X-XSRF-TOKEN). Setting httpOnly breaks that —
	// every non-form POST would 403. Allow it (all-SSR apps use the _csrf field)
	// but make the footgun loud.
	if (cookie.httpOnly === true) {
		process.stderr.write(
			"[blackhole] WARNING: csrf.cookie.httpOnly=true makes XSRF-TOKEN unreadable by JS. " +
				"SPA/RPC clients can't echo X-XSRF-TOKEN → their POSTs will 403. " +
				"Only set this when every client is server-rendered (token via the _csrf field).\n",
		);
	}
	return {
		enabled: cfg.enabled ?? true,
		exceptRoutes: cfg.exceptRoutes ?? [],
		methods: cfg.methods ?? [],
		trustedOrigins: cfg.trustedOrigins ?? [],
		cookieOptions: {
			path: cookie.path ?? "/",
			sameSite: cookie.sameSite ?? "lax",
			httpOnly: cookie.httpOnly ?? false,
			// Default Secure from the environment (parity with the session cookie),
			// instead of leaving it off unless explicitly opted in.
			secure: cookie.secure ?? process.env.NODE_ENV === "production",
		},
	};
}

/**
 * Create a Blackhole security filter instance.
 *
 * @throws If the NAPI binary is not available.
 */
export function createBlackhole(options: BlackholeOptions = {}): Blackhole {
	if (!native) {
		throw new Error(
			"[BLACKHOLE_NAPI_REQUIRED] The Blackhole Rust engine is required but not loaded.\n" +
				"  Fix: cd packages/blackhole && pnpm build:napi",
		);
	}

	const csrf = resolveCsrf(options.csrf);
	// Fail closed: signed double-submit needs a secret. Silently falling back to
	// an unsigned token (or a per-process ephemeral key that breaks multi-instance
	// verification) would be a quiet downgrade — exactly what we refuse to ship.
	if (csrf.enabled && !options.secret) {
		throw new Error(
			"[blackhole] CSRF is enabled but no `secret` was provided. Pass your APP_KEY as " +
				"`secret` so CSRF tokens are signed (signed double-submit). Disable with " +
				"`csrf: false` only if you have an alternative CSRF defense.",
		);
	}
	const filter = new native.Blackhole(
		options.xss ?? true,
		csrf.enabled,
		options.rateLimit?.max,
		options.rateLimit?.windowSeconds,
		options.pathTraversal ?? true,
		options.paramPollution ?? true,
		csrf.exceptRoutes,
		csrf.methods,
		options.secret,
		csrf.trustedOrigins,
	);

	const baseHeaders = computeSecurityHeaders(options.securityHeaders);
	// The CSP may live under either the enforcing or the Report-Only header key.
	const cspHeaderName = baseHeaders["content-security-policy-report-only"]
		? "content-security-policy-report-only"
		: "content-security-policy";
	const baseCsp = baseHeaders[cspHeaderName];
	const cspHasNonce = baseCsp?.includes("@nonce") ?? false;
	const corsConfig = options.cors;
	if (corsConfig) validateCors(corsConfig);

	return {
		check(req) {
			const headersJson = JSON.stringify(req.headers);
			return filter.check(
				req.method,
				req.path,
				req.query ?? "",
				headersJson,
				req.body ?? "",
				req.remoteAddr ?? "",
			);
		},
		generateCsrfToken() {
			return filter.generateCsrfToken();
		},
		sanitizeResponse(body: string, contentType: string) {
			return filter.sanitizeResponse(body, contentType);
		},
		securityHeaders(nonce?: string) {
			if (!cspHasNonce || baseCsp === undefined) return baseHeaders;
			// Substitute the `@nonce` token per request: `'nonce-<nonce>'` when a
			// nonce is supplied, otherwise drop the token (and tidy whitespace).
			const csp = nonce
				? baseCsp.replaceAll("@nonce", `'nonce-${nonce}'`)
				: baseCsp
						.replaceAll("@nonce", "")
						.replace(/\s{2,}/g, " ")
						.trim();
			return { ...baseHeaders, [cspHeaderName]: csp };
		},
		cspHasNonce() {
			return cspHasNonce;
		},
		generateNonce() {
			return randomBytes(16).toString("base64");
		},
		cors(
			requestOrigin: string,
			method: string,
			requestMethod?: string,
			requestHeaders?: string,
		) {
			return corsConfig
				? computeCors(corsConfig, requestOrigin, method, requestMethod, requestHeaders)
				: undefined;
		},
		csrfCookie() {
			return { name: CSRF_COOKIE_NAME, options: csrf.cookieOptions };
		},
	};
}
