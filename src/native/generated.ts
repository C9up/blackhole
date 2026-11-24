// GENERATED FROM THE RUST — do not edit.
//
// Produced by scripts/generate-napi-types.mjs from napi-derive's type-def
// output. Editing this file by hand puts it back where it started: a
// description that can disagree with the code it describes.

export declare class Blackhole {
	constructor(
		csrfEnabled?: boolean | undefined | null,
		rateLimitMax?: number | undefined | null,
		rateLimitWindow?: number | undefined | null,
		pathTraversal?: boolean | undefined | null,
		paramPollution?: boolean | undefined | null,
		csrfExceptRoutes?: Array<string> | undefined | null,
		csrfMethods?: Array<string> | undefined | null,
		csrfSecret?: string | undefined | null,
		csrfTrustedOrigins?: Array<string> | undefined | null,
		xssAllowAttributes?: Array<string> | undefined | null,
		xssMaxInputBytes?: number | undefined | null,
		xssMaxDepth?: number | undefined | null,
	);
	/**
	 * A fresh CSRF token. With a `binding` (the session's secret), its
	 * signature covers that too, and it verifies only when `check` is given
	 * the same binding.
	 */
	generateCsrfToken(binding?: string | undefined | null): string;
	/**
	 * Check a request. Returns `{ allowed: true, request }` or `{ allowed: false, status, body }`.
	 *
	 * The value is built field by field below, so napi-rs cannot infer more
	 * than `any` from `serde_json::Value` — the shape is declared here
	 * instead, next to the code that builds it, and reaches TypeScript
	 * through the generated declarations. Keep the two in step: a renamed
	 * key here must be renamed there in the same edit.
	 */
	check(
		method: string,
		path: string,
		query: string,
		headersJson: string,
		body: string,
		remoteAddr: string,
		scheme?: string | undefined | null,
		checks?: Array<string> | undefined | null,
		host?: string | undefined | null,
		csrfBinding?: string | undefined | null,
	): {
		allowed: boolean;
		status?: number;
		body?: string;
		headers?: Record<string, string>;
		rateLimit?: { limit: number; remaining: number; resetSeconds: number };
		csrfEnforced?: boolean;
	};
	/**
	 * Sanitize a body as untrusted markup when `content_type` is `text/html`
	 * (whatever its first bytes look like); any other type comes back
	 * unchanged.
	 *
	 * Always, whatever the `xss` option says: that option decides whether
	 * the host runs this on its own responses, while a direct call is how an
	 * application cleans input it is about to store.
	 *
	 * A `text/html` body past the configured bounds is refused with
	 * `E_BLACKHOLE_HTML_TOO_LARGE`, `E_BLACKHOLE_HTML_TOO_DEEP` or
	 * `E_BLACKHOLE_HTML_TOO_COMPLEX`, never returned unsanitized.
	 */
	sanitizeResponse(body: string, contentType: string): string;
}
