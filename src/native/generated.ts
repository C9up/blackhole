// GENERATED FROM THE RUST — do not edit.
//
// Produced by scripts/generate-napi-types.mjs from napi-derive's type-def
// output. Editing this file by hand puts it back where it started: a
// description that can disagree with the code it describes.

export declare class Blackhole {
	constructor(
		xssEnabled?: boolean | undefined | null,
		csrfEnabled?: boolean | undefined | null,
		rateLimitMax?: number | undefined | null,
		rateLimitWindow?: number | undefined | null,
		pathTraversal?: boolean | undefined | null,
		paramPollution?: boolean | undefined | null,
		csrfExceptRoutes?: Array<string> | undefined | null,
		csrfMethods?: Array<string> | undefined | null,
		csrfSecret?: string | undefined | null,
		csrfTrustedOrigins?: Array<string> | undefined | null,
	);
	generateCsrfToken(): string;
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
	): {
		allowed: boolean;
		status?: number;
		body?: string;
		headers?: Record<string, string>;
		rateLimit?: { limit: number; remaining: number; resetSeconds: number };
		csrfEnforced?: boolean;
	};
	/**
	 * Sanitize an outgoing response body (XSS protection for HTML/text responses).
	 * Respects the `xss_enabled` config — returns body unchanged when XSS is disabled.
	 */
	sanitizeResponse(body: string, contentType: string): string;
}
