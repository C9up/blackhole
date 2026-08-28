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
}

export async function configure(codemods: Codemods): Promise<void> {
	await codemods.addProvider("@c9up/blackhole/provider");

	// Router tier, not server: the XSS filter reads `request.body()`, so it has
	// to run after the body parser. On the server tier it would inspect a body
	// that has not been parsed yet.
	await codemods.registerMiddleware("@c9up/blackhole/middleware", {
		tier: "router",
	});

	await codemods.writeFile(
		"config/blackhole.ts",
		`import { defineConfig } from '@c9up/blackhole'
import env from '#start/env'

export default defineConfig({
  // Signs the CSRF double-submit token. Required once \`csrf\` is on.
  secret: env.get('APP_KEY'),

  // Off until the app has a form to protect. Turn it on with the first one:
  // the same-origin guard covers a lot, but it is not a CSRF token.
  csrf: false,

  securityHeaders: {
    // The default policy names \`@nonce\`, substituted per request. A view
    // layer reads it from \`response.nonce\` and stamps its inline scripts —
    // \`@c9up/aurora\` does this on its own. Serving inline scripts from
    // another renderer means stamping them the same way, or the browser
    // blocks them and the page never hydrates.
    //
    // Widen it here rather than removing it: a policy that is turned off
    // protects nothing.
  },
})
`,
	);
}
