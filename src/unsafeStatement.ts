/**
 * Turning a refused SQL statement into a decision about a person.
 *
 * The query builder binds every value, so an injection payload arriving as a
 * value is compared and never parsed. What reaches here is the other vector:
 * user input that landed where a value cannot go — a column name, a sort
 * direction, a SELECT expression — and the statement was refused.
 *
 * Two things have to be true before that becomes a block, and neither is the
 * database layer's to know:
 *
 *   - WHO. The refusal happens deep inside a query builder that has never heard
 *     of a request. `keyFor` is where the host answers, typically from the
 *     ambient HTTP context.
 *   - WHETHER. A static string passed to `select()` fails the same way every
 *     time, so it is caught the first time the code runs. For a refusal to
 *     appear in production, on code a test suite has exercised, the string must
 *     have CHANGED — and what changes between two runs of the same code came in
 *     with the request. While developing, the same refusal is usually the code
 *     being written. So the environment decides: a notification there, a block
 *     in production.
 *
 * The event is described structurally rather than imported, the same way
 * {@link RateLimitContext} describes ream's `HttpContext`: this package does
 * not depend on the database layer, and must not.
 */

import type { RateLimitStore } from "./index.js";
import { inProduction } from "./nodeEnv.js";

/** The shape `@c9up/atlas`'s `db:unsafe` event has. Structural on purpose. */
export interface UnsafeStatementLike {
	/**
	 * How strong the signal is.
	 *
	 * `injection-pattern` — the fragment carries `;`, `--`, a nested `SELECT`,
	 * `UNION`, or a quote inside an identifier. Nobody writes that by hand.
	 *
	 * `invalid-shape` — an unknown function, a column name with a space. An
	 * attack looks like this too, but so does a legacy schema, so it counts
	 * towards a threshold instead of deciding on its own.
	 */
	kind: "injection-pattern" | "invalid-shape";
	code: string;
	message: string;
	connection?: string;
}

export interface UnsafeStatementPolicy {
	/**
	 * Who the refusal is charged against — an id, an IP, a tenant. Return
	 * `undefined` when there is nobody to charge (a migration, a background job)
	 * and the refusal is recorded without a verdict.
	 */
	keyFor: () => string | undefined;
	/** Where the count lives. Share the rate limiter's store to survive restarts. */
	store: RateLimitStore;
	/** How long a count survives. Default one hour. */
	windowSeconds?: number;
	/**
	 * How many refusals of each kind before the key is blocked.
	 *
	 * An injection pattern defaults to `1`: it is not the sort of thing that
	 * happens twice by accident. An invalid shape defaults to `5`, because a
	 * report builder or a tenant's custom field name produces the same refusal
	 * and blocking on the first one would lock out an innocent user.
	 */
	thresholds?: { injectionPattern?: number; invalidShape?: number };
	/** Called when the threshold is reached and the environment says block. */
	onBlock: (decision: UnsafeStatementDecision) => void | Promise<void>;
	/**
	 * Called instead of `onBlock` outside production, and for every refusal
	 * under the threshold. Default: nothing.
	 */
	onNotify?: (decision: UnsafeStatementDecision) => void | Promise<void>;
	/**
	 * Override the environment check. Provided so a test — or a staging box that
	 * wants production behaviour — can say so explicitly.
	 */
	blocking?: () => boolean;
}

export interface UnsafeStatementDecision {
	/** Who it was charged against, when the host could name them. */
	key?: string;
	/** How many refusals this key has accumulated in the window. */
	count: number;
	/** The threshold that applied to this kind. */
	threshold: number;
	/** Whether the count reached it. */
	blocked: boolean;
	/** The refusal itself. */
	event: UnsafeStatementLike;
}

const DEFAULT_WINDOW_SECONDS = 3_600;

/**
 * Build the `db:unsafe` listener.
 *
 * ```ts
 * emitter.on('db:unsafe', onUnsafeStatement({
 *   store,
 *   keyFor: () => HttpContext.get()?.request.ip(),
 *   onBlock: ({ key }) => bans.add(key),
 * }))
 * ```
 *
 * Never throws: it is called from inside a statement that is already failing,
 * and a reporter that throws would replace the refusal with its own error.
 */
export function onUnsafeStatement(
	policy: UnsafeStatementPolicy,
): (event: UnsafeStatementLike) => Promise<void> {
	const windowSeconds = policy.windowSeconds ?? DEFAULT_WINDOW_SECONDS;
	const injectionThreshold = policy.thresholds?.injectionPattern ?? 1;
	const shapeThreshold = policy.thresholds?.invalidShape ?? 5;
	const isBlocking = policy.blocking ?? inProduction;

	return async (event: UnsafeStatementLike): Promise<void> => {
		try {
			const key = policy.keyFor();
			const threshold =
				event.kind === "injection-pattern"
					? injectionThreshold
					: shapeThreshold;

			// No key means no verdict: a migration or a queue worker has nobody to
			// charge, and counting them under a shared key would eventually block
			// a person for something a job did.
			let count = 0;
			if (key !== undefined) {
				const result = await policy.store.increment(
					`unsafe-sql:${key}`,
					windowSeconds,
				);
				count = result.count;
			}

			const decision: UnsafeStatementDecision = {
				key,
				count,
				threshold,
				blocked: key !== undefined && count >= threshold && isBlocking(),
				event,
			};

			if (decision.blocked) await policy.onBlock(decision);
			else await policy.onNotify?.(decision);
		} catch {
			/* the statement's own refusal is what the caller must see */
		}
	};
}
