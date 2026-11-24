/**
 * `penalize()` counts the attempt BEFORE the callback runs and clears the
 * count on success: requests sent together cannot all read "attempts left"
 * before the first one has failed. With a budget of 5, at most 5 callbacks
 * run for one key however many requests arrive at once, in every store.
 */
import { setTimeout as sleep } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import {
	DatabaseLimiterStore,
	Limiter,
	type LimiterStore,
	MemoryLimiterStore,
	MultiLimiter,
	RedisLimiterStore,
} from "../../src/limiter.js";
import { fakeRedis, sqliteClient } from "./support/stores.js";

const STORES: [string, () => LimiterStore][] = [
	["memory", () => new MemoryLimiterStore()],
	["database", () => new DatabaseLimiterStore(sqliteClient())],
	["redis", () => new RedisLimiterStore(fakeRedis())],
];

/** A password check: slow (a hash), and wrong. */
async function wrongPassword(counter: { ran: number }): Promise<never> {
	counter.ran += 1;
	await sleep(20);
	throw new Error("E_INVALID_CREDENTIALS");
}

describe.each(STORES)(
	"blackhole > Limiter.penalize() (%s store)",
	(_, store) => {
		const login = () =>
			new Limiter(store(), {
				requests: 5,
				duration: "1 minute",
				blockDuration: "20 mins",
			});

		it("100 guesses sent together run the check 5 times, then the key is blocked", async () => {
			const limiter = login();
			const counter = { ran: 0 };
			const outcomes = await Promise.allSettled(
				Array.from({ length: 100 }, () =>
					limiter.penalize("login_victim", () => wrongPassword(counter)),
				),
			);
			expect(counter.ran).toBe(5);
			const refused = outcomes.filter(
				(o) =>
					o.status === "fulfilled" &&
					o.value[0]?.code === "E_TOO_MANY_REQUESTS",
			);
			expect(refused).toHaveLength(95);
			expect(await limiter.isBlocked("login_victim")).toBe(true);
			// Blocked for the block duration, not the window.
			expect(await limiter.availableIn("login_victim")).toBeGreaterThan(60);
		});

		it("sequentially, the 6th guess is refused without running", async () => {
			const limiter = login();
			const counter = { ran: 0 };
			for (let i = 0; i < 10; i++) {
				await limiter
					.penalize("login_victim", () => wrongPassword(counter))
					.catch(() => undefined);
			}
			expect(counter.ran).toBe(5);
			const [error, result] = await limiter.penalize(
				"login_victim",
				() => "ok",
			);
			expect(error?.code).toBe("E_TOO_MANY_REQUESTS");
			expect(error?.response.remaining).toBe(0);
			expect(result).toBeNull();
		});

		it("a success clears the failures before it, and returns the result", async () => {
			const limiter = login();
			const counter = { ran: 0 };
			for (let i = 0; i < 4; i++) {
				await limiter
					.penalize("login_alice", () => wrongPassword(counter))
					.catch(() => undefined);
			}
			const [error, user] = await limiter.penalize("login_alice", () => ({
				id: 1,
			}));
			expect(error).toBeNull();
			expect(user).toEqual({ id: 1 });
			expect(await limiter.get("login_alice")).toBeNull();
			expect(await limiter.remaining("login_alice")).toBe(5);
		});

		it("a failure is re-thrown as it came, and counted", async () => {
			const limiter = login();
			const failure = new Error("wrong password");
			await expect(
				limiter.penalize("login_bob", () => {
					throw failure;
				}),
			).rejects.toBe(failure);
			expect((await limiter.get("login_bob"))?.consumed).toBe(1);
		});

		it("without a blockDuration, a key out of attempts is refused for the rest of the window", async () => {
			const limiter = new Limiter(store(), { requests: 2, duration: 60 });
			const counter = { ran: 0 };
			await Promise.allSettled(
				Array.from({ length: 10 }, () =>
					limiter.penalize("k", () => wrongPassword(counter)),
				),
			);
			expect(counter.ran).toBe(2);
			expect(await limiter.availableIn("k")).toBeLessThanOrEqual(60);
		});

		it("an attempt worth several points is admitted while the key had one left", async () => {
			const limiter = new Limiter(store(), { requests: 5, duration: 60 });
			const counter = { ran: 0 };
			await limiter
				.penalize("k", () => wrongPassword(counter), 3)
				.catch(() => undefined);
			await limiter
				.penalize("k", () => wrongPassword(counter), 3)
				.catch(() => undefined);
			const [error] = await limiter.penalize("k", () => "ok", 3);
			expect(counter.ran).toBe(2);
			expect(error?.code).toBe("E_TOO_MANY_REQUESTS");
		});
	},
);

describe.each(STORES)(
	"blackhole > MultiLimiter.penalize() (%s store)",
	(_, store) => {
		const multi = () =>
			new MultiLimiter([
				{
					key: "login_victim",
					limiter: new Limiter(store(), {
						requests: 5,
						duration: "1 minute",
						blockDuration: "20 mins",
					}),
				},
				{
					key: "login_ip_203.0.113.9",
					limiter: new Limiter(store(), { requests: 20, duration: "1 hour" }),
				},
			]);

		it("100 guesses sent together run the check 5 times: the tightest budget holds", async () => {
			const limits = multi();
			const counter = { ran: 0 };
			await Promise.allSettled(
				Array.from({ length: 100 }, () =>
					limits.penalize(() => wrongPassword(counter)),
				),
			);
			expect(counter.ran).toBe(5);
			const [perUser] = limits.list();
			expect(await perUser?.limiter.isBlocked("login_victim")).toBe(true);
		});

		it("a success clears every key", async () => {
			const limits = multi();
			const counter = { ran: 0 };
			await limits
				.penalize(() => wrongPassword(counter))
				.catch(() => undefined);
			const [error, result] = await limits.penalize(() => "signed in");
			expect(error).toBeNull();
			expect(result).toBe("signed in");
			expect(await limits.get()).toEqual([null, null]);
		});
	},
);
