/**
 * The decision a refused statement leads to.
 *
 * Two things the database layer cannot know: who made the request, and whether
 * this refusal is an attack or the code being written. The first is `keyFor`;
 * the second is the environment.
 */
import { describe, expect, it, vi } from "vitest";
import type { RateLimitStore } from "../../src/index.js";
import {
	onUnsafeStatement,
	type UnsafeStatementDecision,
	type UnsafeStatementLike,
} from "../../src/unsafeStatement.js";

/** An in-memory store, so a count is observable. */
function store(): RateLimitStore & { counts: Map<string, number> } {
	const counts = new Map<string, number>();
	return {
		counts,
		async increment(key) {
			const next = (counts.get(key) ?? 0) + 1;
			counts.set(key, next);
			return { count: next, resetSeconds: 60 };
		},
	};
}

const injection: UnsafeStatementLike = {
	kind: "injection-pattern",
	code: "E_INJECTION_PATTERN",
	message: "E_INJECTION_PATTERN: ... name; DROP TABLE users --",
};
const shape: UnsafeStatementLike = {
	kind: "invalid-shape",
	code: "E_UNSAFE_EXPRESSION",
	message: "E_UNSAFE_EXPRESSION: my_func(name)",
};

function policy(over: Partial<Parameters<typeof onUnsafeStatement>[0]> = {}) {
	const blocked: UnsafeStatementDecision[] = [];
	const notified: UnsafeStatementDecision[] = [];
	const s = store();
	const listener = onUnsafeStatement({
		store: s,
		keyFor: () => "10.0.0.1",
		blocking: () => true,
		onBlock: (d) => {
			blocked.push(d);
		},
		onNotify: (d) => {
			notified.push(d);
		},
		...over,
	});
	return { listener, blocked, notified, store: s };
}

describe("blackhole > what a refused statement leads to", () => {
	it("blocks on the first injection pattern", async () => {
		const { listener, blocked } = policy();
		await listener(injection);
		expect(blocked).toHaveLength(1);
		expect(blocked[0]).toMatchObject({
			key: "10.0.0.1",
			count: 1,
			blocked: true,
		});
	});

	it("counts an invalid shape instead of deciding on it", async () => {
		// A report builder or a tenant's custom field name produces this exact
		// refusal; blocking on the first would lock out an innocent user.
		const { listener, blocked, notified } = policy();
		for (let i = 0; i < 4; i++) await listener(shape);
		expect(blocked).toHaveLength(0);
		expect(notified).toHaveLength(4);

		await listener(shape);
		expect(blocked).toHaveLength(1);
		expect(blocked[0]?.count).toBe(5);
	});

	it("notifies instead of blocking outside production", async () => {
		const { listener, blocked, notified } = policy({ blocking: () => false });
		await listener(injection);
		expect(blocked).toHaveLength(0);
		expect(notified[0]).toMatchObject({ blocked: false, count: 1 });
	});

	it("charges nobody when the host cannot name one", async () => {
		// A migration or a queue worker. Counting those under a shared key would
		// eventually block a person for something a job did.
		const { listener, blocked, store: s } = policy({ keyFor: () => undefined });
		await listener(injection);
		expect(blocked).toHaveLength(0);
		expect(s.counts.size).toBe(0);
	});

	it("keeps counts apart per key", async () => {
		const { listener, blocked } = policy({
			keyFor: vi
				.fn<() => string | undefined>()
				.mockReturnValueOnce("a")
				.mockReturnValueOnce("b"),
			thresholds: { injectionPattern: 2 },
		});
		await listener(injection);
		await listener(injection);
		expect(blocked).toHaveLength(0);
	});

	it("never throws — the statement's own refusal is what the caller must see", async () => {
		const { listener } = policy({
			onBlock: () => {
				throw new Error("the ban list is down");
			},
		});
		await expect(listener(injection)).resolves.toBeUndefined();
	});
});
