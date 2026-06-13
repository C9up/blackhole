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
	): { allowed: boolean; status?: number; body?: string };
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
	 * `Content-Security-Policy` (default: `default-src 'self'`; `false` to omit).
	 * Include the `@nonce` token (AdonisJS-style) and it's replaced per-request
	 * with `'nonce-<random>'`; the raw nonce is exposed as `ctx.response.nonce`
	 * (and `ctx.store` `cspNonce`) for `<script nonce="…">`.
	 * e.g. `"default-src 'self'; script-src 'self' @nonce"`.
	 */
	csp?: string | false;
	/** `Referrer-Policy` (default: `strict-origin-when-cross-origin`). */
	referrerPolicy?: string;
	/** `Permissions-Policy` (default: camera/mic/geolocation denied). */
	permissionsPolicy?: string;
}

const SECURITY_HEADERS_DEFAULTS: SecurityHeadersConfig = {
	contentTypeOptions: true,
	frameOptions: "SAMEORIGIN",
	hsts: { maxAge: 15552000, includeSubDomains: true },
	csp: "default-src 'self'",
	referrerPolicy: "strict-origin-when-cross-origin",
	permissionsPolicy: "camera=(), microphone=(), geolocation=()",
};

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
		let v = `max-age=${c.hsts.maxAge}`;
		if (c.hsts.includeSubDomains) v += "; includeSubDomains";
		if (c.hsts.preload) v += "; preload";
		headers["strict-transport-security"] = v;
	}
	if (c.csp) headers["content-security-policy"] = c.csp;
	if (c.referrerPolicy) headers["referrer-policy"] = c.referrerPolicy;
	if (c.permissionsPolicy) headers["permissions-policy"] = c.permissionsPolicy;
	return headers;
}

/** Cross-Origin Resource Sharing policy. */
export interface CorsConfig {
	/** Allowed origin(s). `true`/`'*'` = any (forbidden with credentials), a string/array = allow-list, or a predicate. */
	origin: string | string[] | boolean | ((origin: string) => boolean);
	methods?: string[];
	headers?: string[];
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
	if (typeof o === "string") return o === origin ? origin : false;
	if (typeof o === "function") return o(origin) ? origin : false;
	if (Array.isArray(o)) return o.includes(origin) ? origin : false;
	return false;
}

/** Compute the CORS headers + flags for one request. */
function computeCors(
	cfg: CorsConfig,
	requestOrigin: string,
	method: string,
	requestMethod?: string,
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
	if (preflight && allowed) {
		headers["access-control-allow-methods"] = (
			cfg.methods ?? [
				"GET",
				"POST",
				"PUT",
				"PATCH",
				"DELETE",
				"HEAD",
				"OPTIONS",
			]
		).join(", ");
		headers["access-control-allow-headers"] = (
			cfg.headers ?? [
				"Content-Type",
				"Authorization",
				"Accept",
				"X-Requested-With",
			]
		).join(", ");
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
}

export interface CheckResult {
	allowed: boolean;
	status?: number;
	body?: string;
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
	cookieOptions: Record<string, unknown>;
} {
	const cfg: CsrfConfig =
		typeof csrf === "boolean" ? { enabled: csrf } : (csrf ?? {});
	const cookie = cfg.cookie ?? {};
	return {
		enabled: cfg.enabled ?? true,
		exceptRoutes: cfg.exceptRoutes ?? [],
		methods: cfg.methods ?? [],
		cookieOptions: {
			path: cookie.path ?? "/",
			sameSite: cookie.sameSite ?? "lax",
			httpOnly: cookie.httpOnly ?? false,
			...(cookie.secure ? { secure: true } : {}),
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
	const filter = new native.Blackhole(
		options.xss ?? true,
		csrf.enabled,
		options.rateLimit?.max,
		options.rateLimit?.windowSeconds,
		options.pathTraversal ?? true,
		options.paramPollution ?? true,
		csrf.exceptRoutes,
		csrf.methods,
	);

	const baseHeaders = computeSecurityHeaders(options.securityHeaders);
	const baseCsp = baseHeaders["content-security-policy"];
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
			return { ...baseHeaders, "content-security-policy": csp };
		},
		cspHasNonce() {
			return cspHasNonce;
		},
		generateNonce() {
			return randomBytes(16).toString("base64");
		},
		cors(requestOrigin: string, method: string, requestMethod?: string) {
			return corsConfig
				? computeCors(corsConfig, requestOrigin, method, requestMethod)
				: undefined;
		},
		csrfCookie() {
			return { name: CSRF_COOKIE_NAME, options: csrf.cookieOptions };
		},
	};
}
