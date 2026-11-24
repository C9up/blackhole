/**
 * Where the engine comes from: the local build in a checkout, the platform
 * package `@c9up/blackhole-<suffix>` in an install, and a coded refusal naming
 * the package when neither loads.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * A stand-in engine whose constructor says it ran: reaching it proves this
 * binary, and not another, is the one `createBlackhole` uses.
 */
const standIn = () => ({
	Blackhole: class {
		constructor() {
			throw new Error("stand-in engine constructed");
		}
	},
});

/** The host the loader is told it runs on, stubbed so the suite runs anywhere. */
const HOST = { platform: "linux", arch: "x64", suffix: "linux-x64-gnu" };

/** The platform package this host installs. */
const PLATFORM_PACKAGE = `@c9up/blackhole-${HOST.suffix}`;

/** What `require` throws for a module that is not there. */
function notFound(id: string): Error {
	return Object.assign(new Error(`Cannot find module '${id}'`), {
		code: "MODULE_NOT_FOUND",
	});
}

/** Load blackhole with `require` running `load` for every module it asks for. */
async function withRequire(
	load: (id: string) => unknown,
	host: { platform: string; arch: string } = HOST,
) {
	vi.resetModules();
	vi.doMock("node:process", async (importOriginal) => ({
		...(await importOriginal<typeof import("node:process")>()),
		platform: host.platform,
		arch: host.arch,
	}));
	vi.doMock("node:module", async (importOriginal) => ({
		...(await importOriginal<typeof import("node:module")>()),
		createRequire: () => load,
	}));
	return import("../../src/index.js");
}

/** What `createBlackhole` throws, or `undefined` when it returns. */
function refusalOf(blackhole: typeof import("../../src/index.js")) {
	try {
		blackhole.createBlackhole({ csrf: false });
		return undefined;
	} catch (error) {
		return error;
	}
}

afterEach(() => {
	vi.doUnmock("node:process");
	vi.doUnmock("node:module");
	vi.resetModules();
});

describe("blackhole > the engine comes from the local build or the platform package", () => {
	it("loads the platform package when no local binary is built", async () => {
		const asked: string[] = [];
		const blackhole = await withRequire((id) => {
			asked.push(id);
			if (id === PLATFORM_PACKAGE) return standIn();
			throw notFound(id);
		});

		expect(refusalOf(blackhole)).toMatchObject({
			message: "stand-in engine constructed",
		});
		expect(asked).toHaveLength(2);
		expect(asked[0]).toMatch(/[\\/]index\.linux-x64-gnu\.node$/);
		expect(asked[1]).toBe(PLATFORM_PACKAGE);
	});

	it("prefers the local build, and never asks for the package then", async () => {
		const asked: string[] = [];
		const blackhole = await withRequire((id) => {
			asked.push(id);
			return standIn();
		});

		expect(refusalOf(blackhole)).toMatchObject({
			message: "stand-in engine constructed",
		});
		expect(asked).toHaveLength(1);
		expect(asked[0]).toMatch(/index\.linux-x64-gnu\.node$/);
	});

	it("names the platform package to install when neither is there", async () => {
		const blackhole = await withRequire((id) => {
			throw notFound(id);
		});

		const refusal = refusalOf(blackhole);

		expect(refusal).toBeInstanceOf(blackhole.errors.E_BLACKHOLE_NAPI_REQUIRED);
		expect(String(refusal)).toContain(
			`Fix: install ${PLATFORM_PACKAGE} at the exact version of @c9up/blackhole`,
		);
		expect(String(refusal)).toContain("pnpm build:napi");
		// The load error travels as the cause, not in the message.
		expect(refusal).toMatchObject({ cause: { code: "MODULE_NOT_FOUND" } });
		expect(String(refusal)).not.toContain("Cannot find module");
	});

	it("reports a local build that fails to load, instead of falling back to the package", async () => {
		const asked: string[] = [];
		const blackhole = await withRequire((id) => {
			asked.push(id);
			throw new Error("invalid ELF header");
		});

		const refusal = refusalOf(blackhole);

		expect(asked).toHaveLength(1);
		expect(refusal).toBeInstanceOf(blackhole.errors.E_BLACKHOLE_NAPI_REQUIRED);
		expect(String(refusal)).toContain(
			"Fix: index.linux-x64-gnu.node failed to load. Rebuild it: cd packages/blackhole && pnpm build:napi",
		);
		expect(refusal).toMatchObject({ cause: { message: "invalid ELF header" } });
		expect(String(refusal)).not.toContain("invalid ELF header");
	});

	it("rejects a platform package from another version, naming it", async () => {
		const blackhole = await withRequire((id) => {
			if (id === PLATFORM_PACKAGE) return {};
			throw notFound(id);
		});

		const refusal = refusalOf(blackhole);

		expect(refusal).toBeInstanceOf(blackhole.errors.E_BLACKHOLE_NAPI_REQUIRED);
		expect(String(refusal)).toContain(`Fix: install ${PLATFORM_PACKAGE}`);
		expect(refusal).toMatchObject({
			cause: {
				message: expect.stringContaining(
					`${PLATFORM_PACKAGE} loaded, but it lacks Blackhole.`,
				),
			},
		});
	});

	it("lists the supported targets on a host no binary is built for", async () => {
		const asked: string[] = [];
		const blackhole = await withRequire(
			(id) => {
				asked.push(id);
				return standIn();
			},
			{ platform: "linux", arch: "riscv64" },
		);

		const refusal = refusalOf(blackhole);

		expect(asked).toHaveLength(0);
		expect(refusal).toBeInstanceOf(blackhole.errors.E_BLACKHOLE_NAPI_REQUIRED);
		expect(String(refusal)).toContain(
			"Fix: no prebuilt binary for linux-riscv64; blackhole ships one for linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64.",
		);
		expect(refusal).not.toHaveProperty("cause");
	});
});
