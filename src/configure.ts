/**
 * `ream configure @c9up/blackhole` — wire the security filter in one command.
 *
 * Registering the provider is not enough, and that is the trap: the provider
 * binds the instance into the container, and the middleware is what actually
 * puts headers on the wire. Miss the middleware line and everything looks
 * configured — `config/blackhole.ts` complete, provider listed — while the
 * response carries no security header at all. Nothing fails; nothing is
 * protected either.
 *
 * AdonisJS avoids this by having shield's `configure()` call
 * `codemods.registerMiddleware(...)` for you. This is the same hook.
 */

import { stubsRoot } from "./stubs.js";

interface Codemods {
	addProvider(importPath: string): Promise<void>;
	registerMiddleware(
		importPath: string,
		options?: { tier?: "server" | "router"; position?: "before" | "after" },
	): Promise<void>;
	writeFile(
		filePath: string,
		content: string,
		options?: { force?: boolean },
	): Promise<void>;
	makeUsingStub(
		stubsRoot: string,
		stubPath: string,
		state?: Record<string, string | number | boolean>,
		options?: { force?: boolean },
	): Promise<{ path: string; contents: string }>;
}

export async function configure(codemods: Codemods): Promise<void> {
	await codemods.addProvider("@c9up/blackhole/provider");

	// Two halves. The server tier sees every request, a 404 included: rate
	// limit, shield, CORS, protective headers. The CSRF check reads the parsed
	// body, so it runs on the router tier, after the body parser.
	await codemods.registerMiddleware("@c9up/blackhole/server_middleware", {
		tier: "server",
	});
	// At the END of the router tier: CSRF tokens are bound to the session,
	// so this half runs after the session middleware. Inserted first, it would
	// find no session, and with a session configured every request is refused
	// (`E_BLACKHOLE_SESSION_NOT_READY`).
	await codemods.registerMiddleware("@c9up/blackhole/middleware", {
		tier: "router",
		position: "after",
	});

	await codemods.makeUsingStub(stubsRoot, "config/blackhole.stub");
}
