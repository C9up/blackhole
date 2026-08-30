/**
 * Resolving the rate limiter's Redis connection out of quasar.
 *
 * quasar is an optional peer, so this module builds its specifier at runtime
 * and never imports it. Nothing exercised that path, which means each of its
 * failures — absent package, wrong shape, a connection missing a command —
 * first appears on a limited request in production, far from its cause.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

const SPECIFIER = "@c9up/quasar/services/main";

/** The commands the counter issues. */
const commands = ["incr", "expire", "ttl"];

const client = (omit?: string) =>
	Object.fromEntries(
		commands.filter((c) => c !== omit).map((c) => [c, () => {}]),
	);

/**
 * A mocked namespace throws on any export the factory did not declare, unlike
 * a real one — so both shapes the bridge probes are always declared.
 */
const mockQuasar = (shape: { connection?: unknown; default?: unknown }) => {
	vi.doMock(SPECIFIER, () => ({
		connection: shape.connection,
		default: shape.default,
	}));
};

const load = async () => (await import("../../src/quasar.js")).quasarConnection;

afterEach(() => {
	vi.doUnmock(SPECIFIER);
	vi.resetModules();
});

describe("blackhole > the quasar bridge", () => {
	it("hands back the named connection", async () => {
		const connection = client();
		const manager = { connection: vi.fn(() => connection) };
		mockQuasar({ default: manager });

		expect(await (await load())("limiter")).toBe(connection);
		expect(manager.connection).toHaveBeenCalledWith("limiter");
	});

	it("takes the manager on the namespace as well as on the default export", async () => {
		const connection = client();
		mockQuasar({ connection: () => connection });

		expect(await (await load())()).toBe(connection);
	});

	it("says the package is missing, and offers the alternative", async () => {
		// A bare module-not-found reads as a blackhole bug rather than as a
		// missing optional peer.
		vi.doMock(SPECIFIER, () => {
			throw new Error("Cannot find module");
		});

		await expect((await load())("limiter")).rejects.toThrow(
			/@c9up\/quasar is not installed[\s\S]*pass a client instead/,
		);
	});

	it("names the connection that was asked for", async () => {
		vi.doMock(SPECIFIER, () => {
			throw new Error("Cannot find module");
		});
		const resolve = await load();

		await expect(resolve("limiter")).rejects.toThrow(/"limiter"/);
		await expect(resolve()).rejects.toThrow(/"default"/);
	});

	it("refuses a module that is not a connection manager", async () => {
		mockQuasar({ default: { somethingElse: () => {} } });

		await expect((await load())()).rejects.toThrow(
			/did not expose a connection\(\) manager/,
		);
	});

	it("names every command the connection is missing", async () => {
		mockQuasar({ default: { connection: () => ({}) } });

		// Naming them is the point: "does not work" sends the reader to the
		// wrong package.
		await expect((await load())("limiter")).rejects.toThrow(
			/'limiter' is missing incr, expire, ttl/,
		);
	});

	it("names just the one that is missing", async () => {
		for (const missing of commands) {
			vi.resetModules();
			mockQuasar({ default: { connection: () => client(missing) } });

			await expect((await load())("limiter"), missing).rejects.toThrow(
				new RegExp(`is missing ${missing},? ?`),
			);
		}
	});

	it("says it without a name when none was given", async () => {
		mockQuasar({ default: { connection: () => ({}) } });

		await expect((await load())()).rejects.toThrow(
			/connection is missing incr/,
		);
	});
});
