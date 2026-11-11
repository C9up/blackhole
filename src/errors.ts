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
