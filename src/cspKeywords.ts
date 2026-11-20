/**
 * CSP keywords: `@word` sources a policy names and a resolver fills in per
 * request.
 *
 *   import { cspKeywords } from '@c9up/blackhole'
 *
 *   cspKeywords.register('@assetsUrl', () => process.env.ASSETS_URL ?? "'self'")
 *
 *   // config/blackhole.ts
 *   csp: { directives: { scriptSrc: ["'self'", '@nonce', '@assetsUrl'] } }
 *
 * A package contributes its own sources this way (an asset server, a CDN
 * helper, a dev server) without the application spelling them out. `@nonce`
 * is built in.
 *
 * A keyword must be registered before the policy that names it is built
 * (`createBlackhole`, i.e. the provider's boot): the policy is checked then,
 * and a keyword nothing resolves is refused there — emitted as is, the browser
 * would read it as a host named `@word` and the source would silently not be
 * allowed. The resolvers are captured at that moment too.
 *
 * Upstream's shape (`cspKeywords.register(keyword, (req, res) => string)`,
 * resolved per request), with three named deviations:
 * - the resolver also receives the request's nonce, and the framework objects
 *   are `unknown`: this package serves four frameworks, not one;
 * - an `@word` no resolver knows is REFUSED when the policy is built — upstream
 *   sends it as written, which the browser takes for a host (better: a policy
 *   that silently blocks the dev server or the CDN is found at boot, not in a
 *   browser console);
 * - a resolver's answer carrying `;`, `,` or a line break is refused per
 *   request instead of being spliced into the header (it would end the
 *   directive or start another policy).
 */

import {
	E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE,
	E_BLACKHOLE_UNKNOWN_CSP_KEYWORD,
} from "./errors.js";

/**
 * Turns a keyword into its sources for one request. `request` and `response`
 * are the framework's own objects (Ream's `ctx.request`/`ctx.response`,
 * Express's `req`/`res`, Fastify's `request`/`reply`, Hono's `c.req`/`c`), or
 * `undefined` where the header is built outside a request. `nonce` is this
 * request's CSP nonce, when there is one.
 *
 * An empty string drops the keyword from the policy.
 */
export type CspKeywordResolver = (
	request: unknown,
	response: unknown,
	nonce: string | undefined,
) => string;

/** A keyword: `@`, a letter, then letters, digits, `-` or `_`. */
const KEYWORD_PATTERN = /^@[A-Za-z][A-Za-z0-9_-]*$/;

/** The keywords a policy can name, and what each resolves to. */
export class CspKeywords {
	readonly #resolvers = new Map<string, CspKeywordResolver>();

	/**
	 * Register `keyword` (`@word`) and its resolver. Registering a keyword
	 * again replaces its resolver for policies built afterwards.
	 */
	register(keyword: string, resolver: CspKeywordResolver): this {
		if (!KEYWORD_PATTERN.test(keyword)) {
			throw new E_BLACKHOLE_UNKNOWN_CSP_KEYWORD(
				keyword,
				"a CSP keyword is `@` followed by a letter, then letters, digits, `-` or `_`",
			);
		}
		this.#resolvers.set(keyword, resolver);
		return this;
	}

	/** Whether `keyword` has a resolver. */
	has(keyword: string): boolean {
		return this.#resolvers.has(keyword);
	}

	/**
	 * The resolvers of the keywords `policy` names, captured now — and a
	 * refusal for one that has none.
	 */
	capture(policy: string): Map<string, CspKeywordResolver> {
		const captured = new Map<string, CspKeywordResolver>();
		for (const token of policy.split(/[\s;]+/)) {
			if (!token.startsWith("@")) continue;
			const resolver = this.#resolvers.get(token);
			if (resolver === undefined) {
				throw new E_BLACKHOLE_UNKNOWN_CSP_KEYWORD(
					token,
					"no resolver is registered for it (`cspKeywords.register`) — sent as is, the browser would read it as a host name",
				);
			}
			captured.set(token, resolver);
		}
		return captured;
	}
}

/** The registry every policy is checked and resolved against. */
export const cspKeywords = new CspKeywords();

cspKeywords.register("@nonce", (_request, _response, nonce) =>
	nonce ? `'nonce-${nonce}'` : "",
);

/**
 * `policy` with each keyword replaced by what its resolver answers for this
 * request. A value that would end the directive or start another policy
 * (`;`, `,`, a line break) is refused rather than sent.
 */
export function resolveCspKeywords(
	policy: string,
	resolvers: ReadonlyMap<string, CspKeywordResolver>,
	request: unknown,
	response: unknown,
	nonce: string | undefined,
): string {
	const resolved = policy.replace(
		/(^|\s)(@[A-Za-z][A-Za-z0-9_-]*)(?=\s|;|$)/g,
		(match, before: string, keyword: string) => {
			const resolver = resolvers.get(keyword);
			if (resolver === undefined) return match;
			const value = resolver(request, response, nonce);
			if (typeof value !== "string" || /[;,\r\n]/.test(value)) {
				throw new E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE(keyword, value);
			}
			return `${before}${value}`;
		},
	);
	return resolved
		.replace(/[ \t]{2,}/g, " ")
		.replace(/ +;/g, ";")
		.trim();
}
