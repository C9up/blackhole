/**
 * Reading `NODE_ENV`, with the aliases people actually set.
 *
 * `NODE_ENV=prod` is ordinary in a Dockerfile or a platform dashboard, and a
 * bare `=== "production"` reads it as "not production" — which here means the
 * CSRF cookie ships without `Secure`, over plain HTTP, in production.
 *
 * The tables mirror the framework's. Deliberately duplicated rather than
 * imported: blackhole depends on no other package in this workspace, and a
 * security decision that only holds when an optional peer is installed is not
 * a decision.
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
