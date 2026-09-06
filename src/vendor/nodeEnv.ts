// Generated from scripts/vendor/nodeEnv.ts — do not edit.
//
// This package is published and built from its own repository, so the file
// has to exist here rather than be imported. `pnpm vendor:sync` rewrites it,
// and `pnpm vendor:check` fails if this copy has drifted from the original.

/**
 * `NODE_ENV`, read the way every runtime actually spells it.
 *
 * `NODE_ENV=prod` is ordinary in a Dockerfile or a platform dashboard, and a
 * bare `=== "production"` answers "not production" for it. What that costs
 * differs per package, so the consequence is stated where the decision is
 * taken, not here.
 *
 * The tables mirror the framework's (`@c9up/ream`, src/env/nodeEnv.ts), which
 * is the origin rather than a peer: it formats to different rules and exposes
 * `currentNodeEnv()` instead of `inProduction()`.
 */

const DEV_ENVS = ["dev", "develop", "development"];
const PROD_ENVS = ["prod", "production"];
const TEST_ENVS = ["test", "testing"];

/** The canonical name for whatever `NODE_ENV` holds. */
export function normalizeNodeEnv(value: string | undefined): string {
	if (!value || typeof value !== "string") return "unknown";
	const env = value.toLowerCase();
	if (DEV_ENVS.includes(env)) return "development";
	if (PROD_ENVS.includes(env)) return "production";
	if (TEST_ENVS.includes(env)) return "test";
	return env;
}

/** Whether this process is running in production, under any spelling. */
export function inProduction(): boolean {
	return normalizeNodeEnv(process.env.NODE_ENV) === "production";
}
