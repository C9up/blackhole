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
		options?: { tier?: "server" | "router" },
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

	// Router tier, not server: the XSS filter reads `request.body()`, so it has
	// to run after the body parser. On the server tier it would inspect a body
	// that has not been parsed yet.
	await codemods.registerMiddleware("@c9up/blackhole/middleware", {
		tier: "router",
	});

	await codemods.makeUsingStub(stubsRoot, "config/blackhole.stub");
}
