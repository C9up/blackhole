/**
 * CSRF is bound to the session (`csrf.session`), and the request reached the
 * check without one.
 *
 * Minting an unbound token instead would quietly hand every visitor a token
 * valid for any session — the very thing the binding exists to prevent — so
 * the request stops here. It is a wiring error, not a client error: the
 * session middleware is missing, or registered after blackhole's.
 */
export class E_BLACKHOLE_SESSION_NOT_READY extends Error {
	readonly code = "E_BLACKHOLE_SESSION_NOT_READY";
	readonly status = 500;

	constructor() {
		super(
			"[blackhole] CSRF tokens are bound to the session (`csrf.session`), but this request has none. " +
				"Register the session middleware before blackhole's router middleware, " +
				"or set `csrf: { session: false }` for an application without sessions.",
		);
		this.name = "E_BLACKHOLE_SESSION_NOT_READY";
	}
}

/**
 * A CSP names an `@keyword` nothing resolves, or a keyword is registered
 * under an invalid name. Raised when the policy is built — at boot, not on
 * the first page a browser renders.
 */
export class E_BLACKHOLE_UNKNOWN_CSP_KEYWORD extends Error {
	readonly code = "E_BLACKHOLE_UNKNOWN_CSP_KEYWORD";
	readonly status = 500;
	readonly keyword: string;

	constructor(keyword: string, reason: string) {
		super(
			`[blackhole] Content-Security-Policy keyword ${JSON.stringify(keyword)}: ${reason}.`,
		);
		this.name = "E_BLACKHOLE_UNKNOWN_CSP_KEYWORD";
		this.keyword = keyword;
	}
}

/**
 * A CSP keyword's resolver answered something that cannot go in the header:
 * not a string, or a value with `;`, `,` or a line break, which would end the
 * directive or start another policy.
 */
export class E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE extends Error {
	readonly code = "E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE";
	readonly status = 500;
	readonly keyword: string;

	constructor(keyword: string, value: unknown) {
		super(
			`[blackhole] Content-Security-Policy keyword ${JSON.stringify(keyword)} resolved to ${JSON.stringify(value)}, which cannot go in the header (\`;\`, \`,\` and line breaks would end the directive).`,
		);
		this.name = "E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE";
		this.keyword = keyword;
	}
}

/**
 * The database limiter store has no database to count in: `@c9up/atlas` is
 * not installed, its provider has not booted, or the connection named is not
 * one. Raised on the first count, with the original failure as `cause`.
 */
export class E_BLACKHOLE_DATABASE_UNAVAILABLE extends Error {
	readonly code = "E_BLACKHOLE_DATABASE_UNAVAILABLE";
	readonly status = 500;

	constructor(reason: string, cause?: unknown) {
		super(`[blackhole] ${reason}.`, { cause });
		this.name = "E_BLACKHOLE_DATABASE_UNAVAILABLE";
	}
}

/** The database limiter store was given a database it cannot count in. */
export class E_BLACKHOLE_UNSUPPORTED_DATABASE extends Error {
	readonly code = "E_BLACKHOLE_UNSUPPORTED_DATABASE";
	readonly status = 500;
	readonly dialect: string;

	constructor(dialect: string) {
		super(
			`[blackhole] Unsupported database ${JSON.stringify(dialect)}: the database limiter store works with PostgreSQL, MySQL and SQLite.`,
		);
		this.name = "E_BLACKHOLE_UNSUPPORTED_DATABASE";
		this.dialect = dialect;
	}
}
