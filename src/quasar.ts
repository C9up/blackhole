/**
 * Resolving a Redis connection by name, from `@c9up/quasar`.
 *
 * Blackhole does not depend on quasar: it is an optional peer, and this module
 * never imports it statically — the specifier is built at runtime so the
 * TypeScript build stays free of it too.
 *
 * The connection is duck-typed before use rather than asserted: a client
 * missing a command would otherwise fail on the first limited request, far
 * from the cause.
 */

import type { RateLimitRedisClient } from "./stores.js";

interface ConnectionSource {
	connection(name?: string): unknown;
}

/** The commands the counter issues. */
const REQUIRED = ["incr", "expire", "ttl"] as const;

function isConnectionSource(value: unknown): value is ConnectionSource {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof Reflect.get(value, "connection") === "function"
	);
}

function missingCommands(value: unknown): string[] {
	if (typeof value !== "object" || value === null) return [...REQUIRED];
	return REQUIRED.filter(
		(command) => typeof Reflect.get(value, command) !== "function",
	);
}

/** Resolve the named quasar connection, or say precisely what is missing. */
export async function quasarConnection(
	name?: string,
): Promise<RateLimitRedisClient> {
	const specifier = "@c9up/quasar/services/main";
	let loaded: unknown;
	try {
		loaded = await import(/* @vite-ignore */ specifier);
	} catch (cause) {
		throw new Error(
			`[blackhole] the rate limiter asks for the quasar connection "${name ?? "default"}", but @c9up/quasar is not installed.\n` +
				"  pnpm add @c9up/quasar, or pass a client instead of a connection name.",
			{ cause },
		);
	}

	const manager = isConnectionSource(loaded)
		? loaded
		: Reflect.get(Object(loaded), "default");
	if (!isConnectionSource(manager)) {
		throw new Error(
			"[blackhole] @c9up/quasar/services/main did not expose a connection() manager",
		);
	}

	const connection = manager.connection(name);
	const missing = missingCommands(connection);
	if (missing.length > 0) {
		throw new Error(
			`[blackhole] the quasar connection${name ? ` '${name}'` : ""} is missing ${missing.join(", ")}, which the rate-limit counter issues.`,
		);
	}
	return connection as RateLimitRedisClient;
}
