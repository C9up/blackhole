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

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { clientKey } from "./clientKey.js";
import { durationToSeconds } from "./duration.js";
import { hasFunctions, loadNativeBinary } from "./vendor/nativeBinary.js";
import { inProduction } from "./vendor/nodeEnv.js";

/**
 * One of the engine's checks: the rate limit, the shield (path traversal and
 * parameter pollution), or CSRF (Origin and token).
 */
export type EngineCheck = "rateLimit" | "shield" | "csrf";

/** Rate-limit numbers the engine reports for `X-RateLimit-*` headers. */
export interface RateLimitMeta {
	/** Configured ceiling (`max`). */
	limit: number;
	/** Requests still permitted in the current window. */
	remaining: number;
	/** Seconds until a slot frees / the window resets for this key. */
	resetSeconds: number;
}

/**
 * What the `index.<platform>.node` binary exports.
 *
 * The class comes from `./native/generated.js` — written by
 * `pnpm build:napi-types` from napi-derive's own `type-def` output — rather
 * than restated here, where nothing would notice the engine gaining a
 * constructor argument or changing what `check` returns.
 */
const NATIVE_CALLS = ["Blackhole"] as const;

type NativeModule = Pick<
	typeof import("./native/generated.js"),
	(typeof NATIVE_CALLS)[number]
>;

/** The class is all this package uses; a stale binary without it is refused. */
function isNativeModule(value: unknown): value is NativeModule {
	return hasFunctions(value, NATIVE_CALLS);
}

// Absent is not an error here: `createBlackhole` throws at use time, naming
// what the caller was trying to do.
const attempt = loadNativeBinary(isNativeModule, NATIVE_CALLS);
const native = attempt.loaded ? attempt.binary : undefined;
const loadError = attempt.loaded ? undefined : attempt.cause;

/** `X-Frame-Options`: who may frame the pages. */
export interface XFrameConfig {
	/** Default: true once the object is given. */
	enabled?: boolean;
	/** Default: `SAMEORIGIN`. `ALLOW-FROM` needs `domain`. */
	action?: "DENY" | "SAMEORIGIN" | "ALLOW-FROM";
	/** The origin `ALLOW-FROM` names. */
	domain?: string;
}

/** `Strict-Transport-Security`: HTTPS only, for `maxAge`. */
export interface HstsConfig {
	/** Default: true once the object is given. */
	enabled?: boolean;
	/** Seconds, or a duration string (`'180 days'`). Default: 180 days. `0` clears the policy. */
	maxAge?: number | string;
	includeSubDomains?: boolean;
	preload?: boolean;
}

/** `X-Content-Type-Options: nosniff`. */
export interface ContentTypeSniffingConfig {
	/** Default: true once the object is given. */
	enabled?: boolean;
}

/**
 * `Content-Security-Policy`.
 *
 * `directives` names each directive in camelCase (`scriptSrc`) or dashed
 * (`script-src`); they are validated and serialized for you, with a hardened
 * baseline merged under them unless `useDefaults: false`. `policy` takes the
 * header value as a ready-made string instead (validated too). Neither: the
 * default policy below.
 *
 * Either way, the `@nonce` token is replaced per request with
 * `'nonce-<random>'`, and the raw nonce is exposed as `ctx.response.nonce` (and
 * `ctx.store` `cspNonce`) for `<script nonce="…">`.
 *
 * CSP keywords MUST be single-quoted (`'self'`, `'none'`, `'unsafe-inline'`,
 * `'strict-dynamic'`, `'nonce-…'`, `'sha256-…'`, …). An unquoted keyword is
 * parsed by the browser as a host literal and silently breaks the policy, so
 * `createBlackhole` throws on one — as on a directive given twice.
 */
export interface CspConfig {
	/** Default: true once the object is given. */
	enabled?: boolean;
	/**
	 * Directive → source list, e.g. `{ scriptSrc: ["'self'", '@nonce'] }`. A
	 * camelCase name is written dashed (`script-src`). `null` drops a directive
	 * the baseline supplies; `default-src` takes
	 * {@link dangerouslyDisableDefaultSrc} instead.
	 */
	directives?: Record<
		string,
		string | string[] | null | typeof dangerouslyDisableDefaultSrc
	>;
	/**
	 * Merge the hardened baseline ({@link getDefaultDirectives}) under
	 * `directives` (yours win per directive). Default: `true`.
	 */
	useDefaults?: boolean;
	/** The whole policy as a header string — instead of `directives`. */
	policy?: string;
	/**
	 * Emit `Content-Security-Policy-Report-Only` instead of enforcing
	 * (default: false) — to watch violations before enforcing a strict policy.
	 */
	reportOnly?: boolean;
}

/** `Referrer-Policy`. */
export interface ReferrerPolicyConfig {
	/** Default: true once the object is given. */
	enabled?: boolean;
	/** Default: `strict-origin-when-cross-origin`. */
	policy?: string;
}

/** `Permissions-Policy`. */
export interface PermissionsPolicyConfig {
	/** Default: true once the object is given. */
	enabled?: boolean;
	/** Default: `camera=(), microphone=(), geolocation=()`. */
	policy?: string;
}

/**
 * The protective response headers, one key each.
 *
 * Every one is ON with a hardened default when its key is omitted — turn one
 * off with `{ enabled: false }`. `referrerPolicy` and `permissionsPolicy` are
 * blackhole's own additions to the set.
 */
export interface SecurityHeadersOptions {
	/** `X-Frame-Options` (default: `SAMEORIGIN`). */
	xFrame?: XFrameConfig;
	/** `Strict-Transport-Security` (default: 180 days, subdomains included). */
	hsts?: HstsConfig;
	/** `X-Content-Type-Options: nosniff` (default: on). */
	contentTypeSniffing?: ContentTypeSniffingConfig;
	/** `Content-Security-Policy` (default: the policy in {@link DEFAULT_CSP_POLICY}). */
	csp?: CspConfig;
	/** `Referrer-Policy` (default: `strict-origin-when-cross-origin`). */
	referrerPolicy?: ReferrerPolicyConfig;
	/** `Permissions-Policy` (default: camera, microphone and geolocation denied). */
	permissionsPolicy?: PermissionsPolicyConfig;
}

/**
 * Remove a directive that the hardened baseline supplies.
 *
 * Put it as a directive's VALUE. Setting `default-src` to an empty array would
 * emit a bare `default-src`, which forbids everything; omitting the key leaves
 * the baseline's value in place. Neither is "drop this directive", which is
 * what a CSP built entirely from explicit sources needs — hence the marker.
 *
 * `dangerously` is upstream's word and it is earned: dropping `default-src`
 * removes the fallback every un-set fetch directive relies on.
 */
export const dangerouslyDisableDefaultSrc = Symbol.for(
	"blackhole.csp.dangerouslyDisableDefaultSrc",
);

/**
 * The hardened baseline, as a fresh object.
 *
 * Exposed so an app can EXTEND a directive rather than replace it —
 * `[...getDefaultDirectives()['script-src'], 'https://cdn.example']` keeps the
 * baseline's sources instead of silently dropping them, which is what writing
 * the directive out by hand does. A copy is returned: mutating the result must
 * not change what the next request gets.
 */
export function getDefaultDirectives(): Record<string, string[]> {
	return Object.fromEntries(
		Object.entries(CSP_DIRECTIVE_DEFAULTS).map(([k, v]) => [k, [...v]]),
	);
}

/**
 * Helmet's default CSP directives — the hardened baseline merged under a
 * {@link CspConfig}'s own `directives` when `useDefaults` isn't `false`.
 */
const CSP_DIRECTIVE_DEFAULTS: Record<string, string[]> = {
	"default-src": ["'self'"],
	"base-uri": ["'self'"],
	"font-src": ["'self'", "https:", "data:"],
	"form-action": ["'self'"],
	"frame-ancestors": ["'self'"],
	"img-src": ["'self'", "data:"],
	"object-src": ["'none'"],
	"script-src": ["'self'"],
	"script-src-attr": ["'none'"],
	"style-src": ["'self'", "https:", "'unsafe-inline'"],
	"upgrade-insecure-requests": [],
};

/** Keywords the browser honours only single-quoted; bare, each is a host name. */
const CSP_QUOTED_KEYWORDS = new Set([
	"none",
	"self",
	"strict-dynamic",
	"report-sample",
	"inline-speculation-rules",
	"unsafe-inline",
	"unsafe-eval",
	"unsafe-hashes",
	"wasm-unsafe-eval",
]);

/** `scriptSrc` → `script-src`. A dashed name is left as written. */
function dashify(name: string): string {
	return name.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
}

/**
 * Refuse a source that would break or widen the policy without a sound: a `;`
 * or `,` (which ends the directive, or starts another policy, inside the
 * header), or a keyword, nonce or hash left unquoted.
 */
function assertCspSource(directive: string, source: string): void {
	if (/[;,\r\n]/.test(source)) {
		throw new Error(
			`[blackhole] Content-Security-Policy: invalid value for ${JSON.stringify(directive)}: ${JSON.stringify(source)}.`,
		);
	}
	if (
		CSP_QUOTED_KEYWORDS.has(source.toLowerCase()) ||
		/^(?:nonce|sha256|sha384|sha512)-/i.test(source)
	) {
		throw new Error(
			`[blackhole] Content-Security-Policy: ${JSON.stringify(source)} in ${JSON.stringify(directive)} must be single-quoted ('${source}'). Unquoted, the browser reads it as a host name and the directive silently stops meaning what it says.`,
		);
	}
}

/** Refuse a directive name that is not one. */
function assertCspDirectiveName(name: string): void {
	if (name.length === 0 || /[^a-zA-Z0-9-]/.test(name)) {
		throw new Error(
			`[blackhole] Content-Security-Policy: invalid directive name ${JSON.stringify(name)}.`,
		);
	}
}

/**
 * The object form of the CSP, validated and resolved to an ordered directive
 * map: names dashed, the baseline merged under the caller's directives (unless
 * `useDefaults: false`), the ones marked for removal dropped.
 *
 * Throws on what would otherwise reach the browser broken: an invalid or
 * repeated name, an unquoted keyword, a `;` inside a value, a `default-src`
 * set to `null`, a policy left without directives or without `default-src`.
 */
function resolveCspDirectives(config: CspConfig): Map<string, string[]> {
	const own = new Map<string, string[]>();
	const disabled = new Set<string>();
	for (const [rawName, rawValue] of Object.entries(config.directives ?? {})) {
		assertCspDirectiveName(rawName);
		const name = dashify(rawName);
		if (own.has(name) || disabled.has(name)) {
			throw new Error(
				`[blackhole] Content-Security-Policy: directive ${JSON.stringify(name)} is given twice.`,
			);
		}
		if (rawValue === null) {
			if (name === "default-src") {
				throw new Error(
					"[blackhole] Content-Security-Policy: `default-src` cannot be `null` — every fetch directive you did not set falls back to it. To remove it anyway, set it to `dangerouslyDisableDefaultSrc`.",
				);
			}
			disabled.add(name);
			continue;
		}
		if (rawValue === dangerouslyDisableDefaultSrc) {
			if (name !== "default-src") {
				throw new Error(
					`[blackhole] Content-Security-Policy: \`dangerouslyDisableDefaultSrc\` only applies to \`default-src\`; to drop ${JSON.stringify(name)}, set it to \`null\`.`,
				);
			}
			disabled.add(name);
			continue;
		}
		const sources = typeof rawValue === "string" ? [rawValue] : rawValue;
		if (!Array.isArray(sources)) {
			throw new Error(
				`[blackhole] Content-Security-Policy: invalid value for ${JSON.stringify(name)}.`,
			);
		}
		for (const source of sources) assertCspSource(name, source);
		own.set(name, sources);
	}

	const merged = new Map<string, string[]>();
	if (config.useDefaults !== false) {
		// The baseline's order first, each overridden by the caller's value.
		for (const [name, sources] of Object.entries(CSP_DIRECTIVE_DEFAULTS)) {
			if (disabled.has(name)) continue;
			merged.set(name, own.get(name) ?? [...sources]);
		}
	}
	for (const [name, sources] of own) {
		if (!merged.has(name)) merged.set(name, sources);
	}

	if (merged.size === 0) {
		throw new Error(
			"[blackhole] Content-Security-Policy has no directives. Set some, or turn the header off with `csp: false`.",
		);
	}
	if (!merged.has("default-src") && !disabled.has("default-src")) {
		throw new Error(
			"[blackhole] Content-Security-Policy needs a `default-src`. To go without one anyway, set it to `dangerouslyDisableDefaultSrc`.",
		);
	}
	return merged;
}

/**
 * Validate a CSP given as a header string: each directive named once, no
 * keyword, nonce or hash left unquoted. Its `;` are the separators, so the
 * value rule of the object form cannot apply — control characters still
 * cannot.
 */
function assertCspString(csp: string): void {
	if (/[\r\n]/.test(csp)) {
		throw new Error(
			"[blackhole] Content-Security-Policy: the policy string contains a line break.",
		);
	}
	const seen = new Set<string>();
	for (const directive of csp.split(";")) {
		const [name, ...sources] = directive.trim().split(/\s+/);
		if (name === undefined || name.length === 0) continue;
		assertCspDirectiveName(name);
		const lowered = name.toLowerCase();
		if (seen.has(lowered)) {
			throw new Error(
				`[blackhole] Content-Security-Policy: directive ${JSON.stringify(lowered)} is given twice; the browser ignores the second.`,
			);
		}
		seen.add(lowered);
		for (const source of sources) {
			if (source !== "@nonce") assertCspSource(lowered, source);
		}
	}
}

/** Serialize a CSP directive map to a header string (`a 'self'; b; c x y`). */
function serializeCspDirectives(directives: Map<string, string[]>): string {
	return [...directives]
		.map(([name, sources]) =>
			sources.length > 0 ? `${name} ${sources.join(" ")}` : name,
		)
		.join("; ");
}

/**
 * The CSP when the config names none.
 *
 * `base-uri` and `form-action` do NOT fall back to `default-src` per the CSP
 * spec, so they are set explicitly — otherwise an injected `<base href>`
 * re-roots relative asset/script URLs and an injected `<form>` can POST
 * credentials off-origin. `object-src 'none'` kills legacy plugin vectors.
 * `script-src` is spelled out rather than left to fall back on `default-src`,
 * and it names `@nonce`: without it the policy forbids EVERY inline script,
 * which is what a server-rendered page emits to hydrate itself, and the page
 * renders and silently never comes alive. A policy that works is worth more
 * than one that ships disabled.
 */
export const DEFAULT_CSP_POLICY =
	"default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'; script-src 'self' @nonce";

const DEFAULT_HSTS_MAX_AGE = 180 * 24 * 60 * 60;

/** The keys each header's object takes. */
const SECURITY_HEADER_KEYS: Record<keyof SecurityHeadersOptions, string[]> = {
	xFrame: ["enabled", "action", "domain"],
	hsts: ["enabled", "maxAge", "includeSubDomains", "preload"],
	contentTypeSniffing: ["enabled"],
	csp: ["enabled", "directives", "useDefaults", "policy", "reportOnly"],
	referrerPolicy: ["enabled", "policy"],
	permissionsPolicy: ["enabled", "policy"],
};

const SECURITY_HEADER_NAMES: Array<keyof SecurityHeadersOptions> = [
	"xFrame",
	"hsts",
	"contentTypeSniffing",
	"csp",
	"referrerPolicy",
	"permissionsPolicy",
];

/** Options that no longer exist, and what replaced them. */
const RETIRED_OPTIONS: Record<string, string> = {
	securityHeaders:
		"the protective headers are configured one key each, at the top level: " +
		"`xFrame`, `hsts`, `contentTypeSniffing`, `csp`, `referrerPolicy` and " +
		"`permissionsPolicy`, each `{ enabled, ... }`",
};

/**
 * Refuse an option that was renamed or moved: read silently as nothing, it
 * would leave the app without the header it configured.
 */
export function assertNoRetiredOptions(options: object): void {
	for (const [key, replacement] of Object.entries(RETIRED_OPTIONS)) {
		if (Object.hasOwn(options, key)) {
			throw new Error(
				`[blackhole] \`${key}\` is no longer an option: ${replacement}.`,
			);
		}
	}
}

/** Refuse a key a header's object does not take — a typo would drop its setting. */
function assertHeaderKeys(
	name: keyof SecurityHeadersOptions,
	value: object,
): void {
	const known = SECURITY_HEADER_KEYS[name];
	for (const key of Object.keys(value)) {
		if (!known.includes(key)) {
			throw new Error(
				`[blackhole] \`${name}\` has no option "${key}". Known: ${known.join(", ")}.`,
			);
		}
	}
}

/** Whether a header is on: omitted means on, as does an object without `enabled`. */
function isOn(value: { enabled?: boolean } | undefined): boolean {
	return value?.enabled !== false;
}

/** Compute the protective response headers from config. */
function computeSecurityHeaders(
	options: SecurityHeadersOptions,
): Record<string, string> {
	for (const name of SECURITY_HEADER_NAMES) {
		const value = options[name];
		if (value !== undefined) assertHeaderKeys(name, value);
	}
	const {
		xFrame,
		hsts,
		contentTypeSniffing,
		csp,
		referrerPolicy,
		permissionsPolicy,
	} = options;
	const headers: Record<string, string> = { "x-xss-protection": "0" };

	if (isOn(contentTypeSniffing)) headers["x-content-type-options"] = "nosniff";

	if (isOn(xFrame)) {
		const action = xFrame?.action ?? "SAMEORIGIN";
		if (!["DENY", "SAMEORIGIN", "ALLOW-FROM"].includes(action)) {
			throw new Error(
				`[blackhole] xFrame.action must be DENY, SAMEORIGIN or ALLOW-FROM, got ${JSON.stringify(action)}.`,
			);
		}
		if (action === "ALLOW-FROM" && !xFrame?.domain) {
			throw new Error("[blackhole] xFrame.action ALLOW-FROM needs a `domain`.");
		}
		headers["x-frame-options"] =
			action === "ALLOW-FROM" ? `ALLOW-FROM ${xFrame?.domain}` : action;
	}

	if (isOn(hsts)) {
		// Seconds or a duration string. A negative or unreadable value is
		// refused; zero is valid — `max-age=0` is how a site tells browsers to
		// drop the HSTS policy they hold.
		const maxAge =
			hsts?.maxAge === undefined
				? DEFAULT_HSTS_MAX_AGE
				: durationToSeconds(hsts.maxAge, "an HSTS maxAge");
		// Omitted entirely, the default covers subdomains; an `hsts` object says
		// for itself.
		const subdomains = hsts === undefined ? true : hsts.includeSubDomains;
		let value = `max-age=${maxAge}`;
		if (subdomains) value += "; includeSubDomains";
		if (hsts?.preload) value += "; preload";
		headers["strict-transport-security"] = value;
	}

	if (isOn(csp)) {
		if (csp?.policy !== undefined && csp.directives !== undefined) {
			throw new Error(
				"[blackhole] csp takes `directives` or `policy`, not both.",
			);
		}
		const value =
			csp?.policy ??
			(csp?.directives !== undefined
				? serializeCspDirectives(resolveCspDirectives(csp))
				: DEFAULT_CSP_POLICY);
		assertCspString(value);
		headers[
			csp?.reportOnly
				? "content-security-policy-report-only"
				: "content-security-policy"
		] = value;
	}

	if (isOn(referrerPolicy)) {
		headers["referrer-policy"] =
			referrerPolicy?.policy ?? "strict-origin-when-cross-origin";
	}
	if (isOn(permissionsPolicy)) {
		headers["permissions-policy"] =
			permissionsPolicy?.policy ?? "camera=(), microphone=(), geolocation=()";
	}
	return headers;
}

/**
 * The request context a config callback receives (`csrf.exceptRoutes`,
 * `cors.origin`, `cors.headers`, `cors.enabled`).
 *
 * Under Ream it is the HTTP context itself — `ctx.request`, `ctx.route`,
 * `ctx.auth` and the rest are all there. The standalone adapters have no such
 * object and pass this much: the method, the path, the headers and, where the
 * framework has matched one, the route pattern.
 */
export interface BlackholeContext {
	request: {
		method(): string;
		/** The request path, without the query string. */
		url(): string;
		header(name: string): string | undefined;
	};
	/** The matched route, when the host has matched one by then. */
	route?: { pattern: string } | null;
}

/** What `origin` (or what an `origin` callback returns) allows. */
export type CorsOriginValue = boolean | string | string[];

/** What `headers` (or what a `headers` callback returns) allows. */
export type CorsHeadersValue = boolean | string | string[];

/** Cross-Origin Resource Sharing policy. */
export interface CorsConfig {
	/**
	 * Whether CORS headers are handled at all (default: true). A function
	 * decides per request.
	 */
	enabled?: boolean | ((ctx: BlackholeContext) => boolean);
	/**
	 * Allowed origin(s): `true` reflects any origin, `'*'` answers the literal
	 * wildcard, `false` allows none, a string (comma-separated) or an array is
	 * an allow-list, and a function decides per request — returning any of
	 * those. `true` and `'*'` are refused together with `credentials: true`:
	 * that would hand every site the user's cookies.
	 */
	origin:
		| CorsOriginValue
		| ((origin: string, ctx: BlackholeContext) => CorsOriginValue);
	/** Methods a preflight may ask for (default: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS). */
	methods?: string[];
	/**
	 * Request headers a preflight may ask for: `true` reflects what the browser
	 * asks for, `false` allows none, a string (comma-separated) or an array is
	 * an allow-list, a function decides per request. A preflight asking for a
	 * header outside it is refused. Default: a common allow-list.
	 */
	headers?:
		| CorsHeadersValue
		| ((headers: string[], ctx: BlackholeContext) => CorsHeadersValue);
	/** Response headers the browser may expose to the page (`Access-Control-Expose-Headers`). */
	exposeHeaders?: string[];
	/** Same as {@link exposeHeaders}; accepted under either name. */
	exposedHeaders?: string[];
	/** Send `Access-Control-Allow-Credentials: true`. */
	credentials?: boolean;
	/** Seconds a browser may cache a preflight answer. */
	maxAge?: number;
}

/** Per-request CORS decision: headers to set, Vary flag, and preflight short-circuit. */
export interface CorsResult {
	headers: Record<string, string>;
	varyOrigin: boolean;
	preflight: boolean;
}

const CORS_KEYS = new Set([
	"enabled",
	"origin",
	"methods",
	"headers",
	"exposeHeaders",
	"exposedHeaders",
	"credentials",
	"maxAge",
]);

/**
 * Validate a CORS config: no unknown key (a misspelled one would otherwise
 * drop its setting without a word), and none of the credential-leak
 * combinations.
 */
function validateCors(cfg: CorsConfig): void {
	for (const key of Object.keys(cfg)) {
		if (!CORS_KEYS.has(key)) {
			throw new Error(
				`CORS misconfiguration: unknown option "${key}". Known options: ${[...CORS_KEYS].join(", ")}.`,
			);
		}
	}
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

/** The `Access-Control-Allow-Origin` value for `origin`, or false when not allowed. */
function isOriginAllowed(
	cfg: CorsConfig,
	origin: string,
	ctx: BlackholeContext,
): string | false {
	if (!origin) return false;
	const allowed =
		typeof cfg.origin === "function" ? cfg.origin(origin, ctx) : cfg.origin;
	if (allowed === true) return origin;
	if (allowed === false) return false;
	// The literal wildcard. With credentials a browser refuses it — the static
	// form is already refused at boot, and a callback answering it gets what
	// it asked for, which the browser then blocks.
	if (allowed === "*") return "*";
	// A string may be a single origin OR a comma-separated allow-list.
	const list = Array.isArray(allowed)
		? allowed
		: allowed.split(",").map((entry) => entry.trim());
	return list.includes(origin) ? origin : false;
}

/** Split a comma-separated header list into trimmed, non-empty entries. */
function splitHeaderList(value: string | undefined): string[] {
	if (!value) return [];
	return value
		.split(",")
		.map((h) => h.trim())
		.filter((h) => h.length > 0);
}

/**
 * Response headers the browser exposes without being told: listing only these
 * is the same as listing nothing.
 */
const SIMPLE_EXPOSE_HEADERS = new Set([
	"cache-control",
	"content-language",
	"content-type",
	"expires",
	"last-modified",
	"pragma",
]);

const DEFAULT_CORS_METHODS = [
	"GET",
	"POST",
	"PUT",
	"PATCH",
	"DELETE",
	"HEAD",
	"OPTIONS",
];
const DEFAULT_CORS_HEADERS = [
	"Content-Type",
	"Authorization",
	"Accept",
	"X-Requested-With",
];

/** The headers a preflight may carry, per `cfg.headers`; `true` reflects. */
function allowedRequestHeaders(
	cfg: CorsConfig,
	requested: string[],
	ctx: BlackholeContext,
): string[] {
	const value =
		typeof cfg.headers === "function"
			? cfg.headers(requested, ctx)
			: (cfg.headers ?? DEFAULT_CORS_HEADERS);
	if (value === true) return requested;
	if (value === false) return [];
	return Array.isArray(value) ? value : splitHeaderList(value);
}

/** Compute the CORS headers + flags for one request. */
function computeCors(
	cfg: CorsConfig,
	requestOrigin: string,
	method: string,
	ctx: BlackholeContext,
	requestMethod?: string,
	requestHeaders?: string,
): CorsResult | undefined {
	const enabled =
		typeof cfg.enabled === "function" ? cfg.enabled(ctx) : cfg.enabled;
	if (enabled === false) return undefined;
	const allowed = isOriginAllowed(cfg, requestOrigin, ctx);
	const headers: Record<string, string> = {};
	// Vary on Origin unless the policy is static (`*` / `false`).
	const varyOrigin = cfg.origin !== "*" && cfg.origin !== false;
	if (allowed) {
		headers["access-control-allow-origin"] = allowed;
		if (cfg.credentials) headers["access-control-allow-credentials"] = "true";
		const exposed = (cfg.exposeHeaders ?? cfg.exposedHeaders ?? []).map((h) =>
			h.toLowerCase(),
		);
		if (exposed.some((h) => !SIMPLE_EXPOSE_HEADERS.has(h))) {
			headers["access-control-expose-headers"] = exposed.join(", ");
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
		// when the requested method isn't allowed, matching the CORS spec —
		// rather than advertising the full list regardless.
		if (
			!allowedMethods
				.map((m) => m.toUpperCase())
				.includes(requestMethod.toUpperCase())
		) {
			return { headers, varyOrigin, preflight };
		}
		headers["access-control-allow-methods"] = allowedMethods.join(", ");

		// A requested header outside the allowed ones refuses the preflight.
		const requested = splitHeaderList(requestHeaders);
		const allowList = allowedRequestHeaders(cfg, requested, ctx);
		const lowered = allowList.map((h) => h.toLowerCase());
		const disallowed = requested.find(
			(h) => h.toLowerCase() !== "origin" && !lowered.includes(h.toLowerCase()),
		);
		if (disallowed) return { headers, varyOrigin, preflight };
		if (allowList.length > 0) {
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
	/**
	 * Routes to skip: an array of patterns, or a predicate.
	 *
	 * An entry matches the pattern of the route the request matched
	 * (`'/webhooks/:provider'`), where the host has matched one by then — Ream
	 * and Fastify. It also matches the request path, exactly or, with a
	 * trailing `*`, by prefix (`'/webhooks/*'`), which is the only form the
	 * adapters without a route (Express, Hono) can apply.
	 *
	 * The predicate receives the request context ({@link BlackholeContext}; the
	 * HTTP context itself under Ream) and returns `true` to skip the check.
	 */
	exceptRoutes?: string[] | ((ctx: BlackholeContext) => boolean);
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
	/**
	 * Seed the readable `XSRF-TOKEN` cookie (AdonisJS `enableXsrfCookie`).
	 *
	 * Default true. An all-SSR app that only ever sends the `_csrf` form field
	 * has no use for it, and not setting a cookie is one less thing to leak.
	 */
	enableXsrfCookie?: boolean;
	/**
	 * Bind every token to the request's session, and refuse a request that
	 * reaches the check without one (`E_BLACKHOLE_SESSION_NOT_READY`).
	 *
	 * The Ream provider turns it on when the application has a session config
	 * (`config/session.ts`), so a kernel that runs blackhole before the session
	 * middleware fails loudly instead of issuing tokens bound to nothing.
	 * Without it, a request that has a session is still bound to it, and one
	 * without gets the stateless signed token. The standalone adapters have no
	 * session: turning it on there refuses every request.
	 *
	 * NAMED DEVIATION: the upstream guard always reads the session and has no
	 * stateless mode; blackhole keeps one for hosts without sessions, and this
	 * switch is what makes the session mandatory where the app has one.
	 */
	session?: boolean;
	/** Attributes for the seeded `XSRF-TOKEN` cookie. */
	cookie?: CsrfCookieConfig;
	/** AdonisJS spelling of {@link cookie}. Both are accepted. */
	cookieOptions?: CsrfCookieConfig;
}

// Re-export the config helper so the documented `import { defineConfig } from
// '@c9up/blackhole'` resolves (it was previously reachable only via the
// '@c9up/blackhole/config' subpath).
export { type BlackholeConfig, defineConfig } from "./config.js";

/**
 * Distributed counter backing rate limiting. Provide one (e.g. Redis-backed) so
 * the limit is shared across every process/instance instead of the default
 * in-process counter. Mirrors `@adonisjs/limiter`'s pluggable stores.
 */
export interface RateLimitStore {
	/**
	 * Atomically increment the counter for `key` and return the new count plus
	 * the seconds until the window resets. Implementations set the TTL to
	 * `windowSeconds` on the first hit of a window.
	 */
	increment(
		key: string,
		windowSeconds: number,
	): Promise<{ count: number; resetSeconds: number }>;
}

/**
 * Minimal request-context shape the rate-limit key resolver receives. Ream's
 * `HttpContext` satisfies it structurally, so `keyFor: (ctx) => ctx.auth.user.id`
 * type-checks in a real app without importing `@c9up/ream` here.
 */
export interface RateLimitContext {
	request: { ip(): string };
	auth?: { user?: { id?: string | number } | null };
}

/** Rate-limit decision computed against a distributed {@link RateLimitStore}. */
export interface RateLimitDecision {
	allowed: boolean;
	limit: number;
	remaining: number;
	resetSeconds: number;
}

/** The attributes an untrusted HTML fragment may keep when opted into. */
export type XssOptInAttribute = "id" | "is" | "slot" | "part" | "data-*";

/** XSS response sanitization, in its object form. */
export interface XssConfig {
	/** Sanitize `text/html` fragments (default: true). */
	enabled?: boolean;
	/**
	 * Attributes the sanitizer keeps although it drops them by default: `id`
	 * (DOM clobbering — `<a id="config">` shadows `window.config`), `is`
	 * (customized built-in elements), `data-*` (read by client-side frameworks
	 * as bindings), `slot` and `part` (shadow DOM). Opt in only when the page
	 * reads none of them from untrusted markup.
	 */
	allowAttributes?: XssOptInAttribute[];
}

export interface BlackholeOptions extends SecurityHeadersOptions {
	/**
	 * XSS response sanitization of `text/html` fragments (default: true).
	 * `false` turns it off; an object keeps it on and opts attributes back in.
	 */
	xss?: boolean | XssConfig;
	/** CSRF validation — `true`/`false` to toggle, or an object for fine-grained control. */
	csrf?: boolean | CsrfConfig;
	/** Rate limiting configuration. */
	rateLimit?: {
		max: number;
		windowSeconds: number;
		/**
		 * Resolve the counting key for a request (parity with limiter's
		 * `usingKey`). Defaults to the client IP. Return e.g. the authenticated
		 * user id for per-user limits: `keyFor: (ctx) => String(ctx.auth?.user?.id ?? ctx.request.ip())`.
		 */
		keyFor?: (ctx: RateLimitContext) => string;
		/**
		 * Distributed counter. When provided, counting + the 429 decision run in
		 * JS against this store (Redis, etc.) — the in-process Rust counter is
		 * disabled. Omit for the single-process default.
		 */
		store?: RateLimitStore;
	};
	/** Reject requests with path-traversal sequences (`..`, `%2e%2e`) (default: true). */
	pathTraversal?: boolean;
	/** Reject requests with duplicate query params (HTTP parameter pollution) (default: true). */
	paramPollution?: boolean;
	/** Cross-Origin Resource Sharing policy. Omit to leave CORS unmanaged. */
	cors?: CorsConfig;
	/**
	 * HMAC secret used to **sign** CSRF tokens (signed double-submit). Pass the
	 * app's `APP_KEY`. Required when CSRF is enabled (fail-closed). Every instance
	 * must share the same secret (stateless horizontal scale).
	 *
	 * Scope of the signature: it proves a token was minted by this server, so an
	 * attacker can't forge a brand-new valid pair. Under the Ream middleware with
	 * a session, the signature also covers a per-session secret, so a token is
	 * refused for any other session. Without a session (the standalone
	 * adapters) it binds to nothing, and the same-origin `Origin`/`Referer`
	 * check on unsafe verbs is what stops a replayed, legitimately issued token.
	 *
	 * A string, or a `Secret` (`env.get('APP_KEY')` when the env schema
	 * declares it with `Env.schema.secret()`), released once when the filter
	 * is built.
	 */
	secret?: string | ReleasableSecret;
}

/** Anything that releases a secret string — an environment `Secret`. */
export interface ReleasableSecret {
	release(): string;
}

export interface CheckResult {
	allowed: boolean;
	status?: number;
	body?: string;
	/** Extra headers to set on a rejection (e.g. `Retry-After` / `X-RateLimit-*` on a 429). */
	headers?: Record<string, string>;
	/** Rate-limit numbers (when a limiter is configured) for `X-RateLimit-*` on any path. */
	rateLimit?: RateLimitMeta;
	/**
	 * `true` only when CSRF was enabled, the method guarded, the route not
	 * excepted, AND the token validated for this request. A seeded token is NOT
	 * proof — consumers that must fail-close on CSRF read this, not the token.
	 */
	csrfEnforced?: boolean;
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
		/** `http` or `https`: the Origin must match it on a CSRF-guarded request. */
		protocol?: string;
		/**
		 * `host[:port]` as the host resolved it (trust-proxy aware), compared
		 * with the Origin on a CSRF-guarded request. The `Host` header when
		 * omitted.
		 */
		host?: string;
		/**
		 * The session's CSRF secret: the token must have been issued under it.
		 * Omitted (or empty) when the host has no session.
		 */
		csrfBinding?: string;
		/**
		 * Run only these checks — for a host that splits the pipeline across
		 * two middlewares. All of them when omitted.
		 */
		checks?: EngineCheck[];
	}): CheckResult;
	/**
	 * Generate a new CSRF token — bound to `binding` (the session's CSRF
	 * secret) when one is given, so it verifies for that session only.
	 */
	generateCsrfToken(binding?: string): string;
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
	/**
	 * CORS decision for a request, or `undefined` when CORS isn't configured
	 * (or `enabled` turns it off for this request).
	 */
	cors(
		requestOrigin: string,
		method: string,
		requestMethod?: string,
		requestHeaders?: string,
		ctx?: BlackholeContext,
	): CorsResult | undefined;
	/** Name + attributes of the `XSRF-TOKEN` cookie the middleware should seed. */
	csrfCookie(): { name: string; options: Record<string, unknown> };
	/**
	 * Whether a token the client already holds still verifies.
	 *
	 * Used to decide whether to REISSUE the cookie, never to authorise
	 * anything — the engine owns that decision, in `check()`. A disagreement
	 * between the two therefore costs at most a needless reissue, which is why
	 * repeating the signature check here is safe.
	 */
	csrfTokenIsValid(token: string, binding?: string): boolean;
	/** Whether CSRF is on: off, no token is minted and no cookie is set. */
	csrfEnabled(): boolean;
	/**
	 * Whether the readable `XSRF-TOKEN` cookie should be seeded at all — never
	 * with CSRF off.
	 */
	xsrfCookieEnabled(): boolean;
	/**
	 * Whether CSRF is on and must be bound to a session (`csrf.session`): a
	 * request without one is refused rather than given an unbound token.
	 */
	csrfSessionRequired(): boolean;
	/**
	 * Whether `exceptRoutes` exempts this request on what only JS knows: the
	 * predicate, or an entry naming the matched route's pattern. The path
	 * forms are applied by `check()` itself.
	 */
	csrfExempt(ctx: BlackholeContext): boolean;
	/**
	 * Counting key for a request — the configured `rateLimit.keyFor(ctx)`, or the
	 * client IP by default (parity with limiter's `usingKey`). An IPv6 client
	 * counts under its /64: one host holds the whole /64, and counting each of
	 * its 2^64 addresses separately was no limit at all.
	 */
	rateLimitKey(ctx: RateLimitContext): string;
	/**
	 * Whether the counting key comes from `rateLimit.keyFor(ctx)` — which may
	 * read what a later middleware sets (the authenticated user), so the limit
	 * cannot be taken before it.
	 */
	rateLimitKeyedByRequest(): boolean;
	/** Is a distributed {@link RateLimitStore} configured (JS counts, Rust skips)? */
	hasRateLimitStore(): boolean;
	/**
	 * Rate-limit decision via the configured store. Throws if none is configured
	 * (guard with {@link Blackhole.hasRateLimitStore} first).
	 */
	checkRateLimit(key: string): Promise<RateLimitDecision>;
}

/** Cookie name shared by the Rust validator and the middleware (not configurable — Adonis fixes it). */
const CSRF_COOKIE_NAME = "XSRF-TOKEN";

/** Normalize the `csrf` option into a flat shape (boolean shorthand → full config). */
/**
 * Secrets that appear in scaffolding, documentation and tutorials.
 *
 * Deliberately duplicated rather than imported: blackhole depends on no other
 * package in this workspace, and a security check that only holds when an
 * optional peer happens to be installed is not a check.
 */
const PUBLICLY_KNOWN_SECRETS = new Set([
	"change-me-to-a-unique-32+-byte-secret!!",
	"change-me",
	"your-app-key-here",
	"secret",
]);

/**
 * Refuse a secret that cannot sign anything.
 *
 * Presence is not enough: a CSRF token signed with a value printed in a README
 * can be forged by anyone who has read it, which is the same as not signing at
 * all — and worse, because the code says it is signed.
 */
/**
 * Refuse a limit that would not limit. The engine takes unsigned integers, so
 * a fraction was truncated (`windowSeconds: 0.5` became 0), a negative wrapped,
 * and a window of 0 expired every hit at once: all three let every request
 * through, silently.
 */
function assertRateLimit(rateLimit: {
	max: number;
	windowSeconds: number;
}): void {
	const fields: Array<[string, number]> = [
		["max", rateLimit.max],
		["windowSeconds", rateLimit.windowSeconds],
	];
	for (const [field, value] of fields) {
		if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffffffff) {
			throw new Error(
				`[blackhole] rateLimit.${field} must be a positive whole number, got ${String(value)}.`,
			);
		}
	}
}

function assertUsableSecret(secret: string): void {
	if (PUBLICLY_KNOWN_SECRETS.has(secret.trim().toLowerCase())) {
		throw new Error(
			"[blackhole] the CSRF `secret` is a placeholder from the scaffolding, which everyone can read — " +
				"anyone holding it can forge a valid CSRF token. Generate a real one with `ream generate:key`.",
		);
	}
	if (secret.length < 16) {
		throw new Error(
			`[blackhole] the CSRF \`secret\` is ${secret.length} characters, too short to sign with. Use at least 16 (a 32-byte random key is the norm).`,
		);
	}
}

/**
 * The secret as a string. Typed configs only hand over a string or a
 * `Secret`; the guard is for an untyped (JavaScript) config, whose `Secret`
 * would otherwise reach the HMAC as its redacted placeholder text.
 */
function releaseSecret(secret: unknown): string {
	if (typeof secret === "string") return secret;
	if (typeof secret === "object" && secret !== null && "release" in secret) {
		const release: unknown = secret.release;
		if (typeof release === "function") {
			const released: unknown = release.call(secret);
			if (typeof released === "string") return released;
		}
	}
	throw new TypeError(
		"[blackhole] the CSRF `secret` must be a string or a Secret wrapping one",
	);
}

/**
 * Whether a CSRF token still carries a valid signature under the app secret.
 *
 * The token is `<random>.<base64url HMAC-SHA256 of random>`, minted by the
 * engine. This repeats that check in TypeScript so the request phase can tell
 * a live token from a stale or mangled one WITHOUT crossing the native
 * boundary for what is only a "should I reissue the cookie?" decision.
 *
 * It never authorises anything: `check()` in the engine remains the only thing
 * that decides whether a request passes. So if the two ever disagreed, the
 * cost is a cookie reissued once too often, not a request wrongly allowed.
 */
function verifyCsrfToken(
	token: string,
	secret: string | undefined,
	binding = "",
): boolean {
	if (!secret) return false;
	const dot = token.indexOf(".");
	if (dot <= 0 || dot === token.length - 1) return false;
	const random = token.slice(0, dot);
	const signature = token.slice(dot + 1);
	// What the engine signs: the random part, and the session's binding after
	// a `:` when there is one (`signed_message` in csrf.rs).
	const expected = createHmac("sha256", secret)
		.update(binding ? `${random}:${binding}` : random)
		.digest("base64url");
	const given = Buffer.from(signature, "utf8");
	const want = Buffer.from(expected, "utf8");
	return given.length === want.length && timingSafeEqual(given, want);
}

function resolveCsrf(csrf: boolean | CsrfConfig | undefined): {
	enabled: boolean;
	exceptRoutes: string[];
	exceptPredicate?: (ctx: BlackholeContext) => boolean;
	methods: string[];
	trustedOrigins: string[];
	enableXsrfCookie: boolean;
	session: boolean;
	cookieOptions: Record<string, unknown>;
} {
	const cfg: CsrfConfig =
		typeof csrf === "boolean" ? { enabled: csrf } : (csrf ?? {});
	// `cookieOptions` (AdonisJS) and `cookie` (blackhole) name the same thing.
	const cookie = cfg.cookieOptions ?? cfg.cookie ?? {};
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
	const except = cfg.exceptRoutes;
	return {
		enabled: cfg.enabled ?? true,
		exceptRoutes: Array.isArray(except) ? except : [],
		exceptPredicate: typeof except === "function" ? except : undefined,
		methods: cfg.methods ?? [],
		trustedOrigins: cfg.trustedOrigins ?? [],
		enableXsrfCookie: cfg.enableXsrfCookie ?? true,
		session: cfg.session ?? false,
		cookieOptions: {
			path: cookie.path ?? "/",
			sameSite: cookie.sameSite ?? "lax",
			httpOnly: cookie.httpOnly ?? false,
			// Default Secure from the environment (parity with the session cookie),
			// instead of leaving it off unless explicitly opted in.
			// Through `inProduction()`, never `NODE_ENV === "production"`:
			// `NODE_ENV=prod` reads as "not production" verbatim, and this cookie
			// would then ship without `Secure`, over plain HTTP, in production.
			secure: cookie.secure ?? inProduction(),
		},
	};
}

/**
 * The {@link BlackholeContext} of a host that has no context object of its
 * own: the method, the path, the headers, and the route pattern if known.
 */
export function pathContext(
	method: string,
	path: string,
	headers: Readonly<Record<string, string>> = {},
	routePattern?: string,
): BlackholeContext {
	return {
		request: {
			method: () => method,
			url: () => path,
			header: (name) => headers[name.toLowerCase()],
		},
		route: routePattern === undefined ? null : { pattern: routePattern },
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
			loadError !== undefined ? { cause: loadError } : undefined,
		);
	}

	assertNoRetiredOptions(options);
	const csrf = resolveCsrf(options.csrf);
	const xss: XssConfig =
		typeof options.xss === "object"
			? options.xss
			: { enabled: options.xss ?? true };
	// Fail closed: signed double-submit needs a secret. Silently falling back to
	// an unsigned token (or a per-process ephemeral key that breaks multi-instance
	// verification) would be a quiet downgrade — exactly what we refuse to ship.
	const secret =
		options.secret === undefined ? undefined : releaseSecret(options.secret);
	if (csrf.enabled && !secret) {
		throw new Error(
			"[blackhole] CSRF is enabled but no `secret` was provided. Pass your APP_KEY as " +
				"`secret` so CSRF tokens are signed (signed double-submit). Disable with " +
				"`csrf: false` only if you have an alternative CSRF defense.",
		);
	}
	if (csrf.enabled && secret) {
		assertUsableSecret(secret);
	}
	if (options.rateLimit !== undefined) assertRateLimit(options.rateLimit);
	// A distributed store moves counting + the 429 decision into JS (see
	// `checkRateLimit`), so the in-process Rust counter must NOT also run — pass
	// no max/window to the engine when a store is configured.
	const rateLimit = options.rateLimit;
	const useRustLimiter =
		rateLimit !== undefined && rateLimit.store === undefined;
	const filter = new native.Blackhole(
		xss.enabled ?? true,
		csrf.enabled,
		useRustLimiter ? rateLimit?.max : undefined,
		useRustLimiter ? rateLimit?.windowSeconds : undefined,
		options.pathTraversal ?? true,
		options.paramPollution ?? true,
		csrf.exceptRoutes,
		csrf.methods,
		secret,
		csrf.trustedOrigins,
		xss.allowAttributes ?? [],
	);

	const baseHeaders = computeSecurityHeaders(options);
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
				req.protocol,
				req.checks,
				req.host,
				req.csrfBinding,
			);
		},
		generateCsrfToken(binding) {
			return filter.generateCsrfToken(binding);
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
		cors(requestOrigin, method, requestMethod, requestHeaders, ctx) {
			return corsConfig
				? computeCors(
						corsConfig,
						requestOrigin,
						method,
						ctx ?? pathContext(method, ""),
						requestMethod,
						requestHeaders,
					)
				: undefined;
		},
		csrfEnabled() {
			return csrf.enabled;
		},
		xsrfCookieEnabled() {
			return csrf.enabled && csrf.enableXsrfCookie;
		},
		csrfSessionRequired() {
			return csrf.enabled && csrf.session;
		},
		csrfExempt(ctx) {
			if (csrf.exceptPredicate) return csrf.exceptPredicate(ctx);
			// The path forms are applied inside the Rust check; the matched
			// route's pattern is only known here.
			const pattern = ctx.route?.pattern;
			return pattern !== undefined && csrf.exceptRoutes.includes(pattern);
		},
		csrfCookie() {
			return { name: CSRF_COOKIE_NAME, options: csrf.cookieOptions };
		},
		csrfTokenIsValid(token, binding) {
			return verifyCsrfToken(token, secret, binding);
		},
		rateLimitKey(ctx) {
			return rateLimit?.keyFor?.(ctx) ?? clientKey(ctx.request.ip());
		},
		rateLimitKeyedByRequest() {
			return rateLimit?.keyFor !== undefined;
		},
		hasRateLimitStore() {
			return rateLimit?.store !== undefined;
		},
		async checkRateLimit(key) {
			if (rateLimit?.store === undefined) {
				throw new Error(
					"[blackhole] checkRateLimit called without a configured rateLimit.store.",
				);
			}
			const { count, resetSeconds } = await rateLimit.store.increment(
				key,
				rateLimit.windowSeconds,
			);
			// Allowed while the running count is within `max` (this request is
			// already counted by `increment`) — matches @adonisjs/limiter.
			return {
				allowed: count <= rateLimit.max,
				limit: rateLimit.max,
				remaining: Math.max(0, rateLimit.max - count),
				resetSeconds,
			};
		},
	};
}

export { clientKey } from "./clientKey.js";
export { E_BLACKHOLE_SESSION_NOT_READY } from "./errors.js";
export {
	defineThrottle,
	HttpLimiter,
	Limiter,
	type LimiterConfig,
	type LimiterHttpContext,
	LimiterManager,
	type LimiterOptions,
	type LimiterRecord,
	type LimiterRedisClient,
	type LimiterRedisSource,
	LimiterResponse,
	type LimiterStore,
	type LimiterStoreFactory,
	limiterStores,
	MemoryLimiterStore,
	RedisLimiterStore,
	type ThrottleContext,
	ThrottleException,
	type ThrottleMiddleware,
} from "./limiter.js";
export { quasarConnection } from "./quasar.js";
export {
	MemoryRateLimitStore,
	type RateLimitRedisClient,
	type RateLimitRedisSource,
	type RateLimitStoreFactory,
	RedisRateLimitStore,
	stores,
} from "./stores.js";

export type {
	UnsafeStatementDecision,
	UnsafeStatementLike,
	UnsafeStatementPolicy,
} from "./unsafeStatement.js";
export { onUnsafeStatement } from "./unsafeStatement.js";
