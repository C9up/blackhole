// Generated from scripts/vendor/nativeBinary.ts — do not edit.
//
// This package is published and built from its own repository, so the file
// has to exist here rather than be imported. `pnpm vendor:sync` rewrites it,
// and `pnpm vendor:check` fails if this copy has drifted from the original.

/**
 * Finding the NAPI binary a package ships beside itself.
 *
 * Every package with a Rust engine repeats the same table: napi-rs names its
 * artefacts `index.<platform>-<arch>-<abi>.node`, and the mapping from Node's
 * `platform`/`arch` to that suffix is the part that must never differ between
 * packages. Adding a target means adding it everywhere, and a package that
 * missed the edit fails only on that platform — which is exactly the failure
 * nobody reproduces.
 *
 * What is NOT here is the policy. Some packages degrade when the binary is
 * absent and answer `undefined`; others refuse loudly with build instructions.
 * Both are right for their package, so the loader reports what happened and
 * the caller decides.
 */

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { arch, platform } from "node:process";
import { fileURLToPath } from "node:url";

/** Node's `platform-arch` → the suffix napi-rs builds under. */
const TARGETS: Record<string, string> = {
	"linux-x64": "linux-x64-gnu",
	"linux-arm64": "linux-arm64-gnu",
	"darwin-x64": "darwin-x64",
	"darwin-arm64": "darwin-arm64",
	"win32-x64": "win32-x64-msvc",
};

/**
 * Every `platform-arch` a binary is built for.
 *
 * For the message a package raises when it refuses: "no binary for
 * linux-riscv64" is only actionable next to the list of what there IS.
 */
export function supportedTargets(): readonly string[] {
	return Object.keys(TARGETS);
}

/** The suffix a given `platform-arch` builds under, or `undefined`. */
export function nativeTargetSuffix(target: string): string | undefined {
	return TARGETS[target];
}

/** The suffix for THIS platform, or `undefined` where no binary is built. */
export function nativeBinarySuffix(): string | undefined {
	return nativeTargetSuffix(`${platform}-${arch}`);
}

/**
 * Why the binary is not there, phrased for whoever has to fix it.
 *
 * "not found" and "not built for your platform" call for different actions,
 * and a single "unavailable" leaves the reader to guess which one they are
 * looking at.
 */
export function unavailableReason(cause?: unknown): string {
	if (cause !== undefined) {
		return `failed to load (${cause instanceof Error ? cause.message : String(cause)})`;
	}
	const target = `${platform}-${arch}`;
	return nativeTargetSuffix(target) !== undefined
		? "binary not found"
		: `no prebuilt binary for ${target}`;
}

/**
 * `musl` builds under a different suffix, and the failure is otherwise
 * baffling: the file is there, and `require` still refuses it. Worth saying so
 * in a message rather than leaving a reader to discover glibc.
 */
export function muslHint(): string {
	return platform === "linux"
		? " On Alpine/musl, the gnu binary will not load — build the musl target."
		: "";
}

/** What a load attempt did, so the caller can apply its own policy. */
export type NativeBinaryResult<T> =
	| { loaded: true; binary: T }
	| { loaded: false; suffix: string | undefined; cause?: unknown };

/** Whether `value` carries a function under `name` (a napi class is one too). */
function hasFunction(value: object, name: string): boolean {
	const member: unknown = Reflect.get(value, name);
	return typeof member === "function";
}

/**
 * Whether `value` carries every one of `names` as a function.
 *
 * The building block of the guard a package hands to `loadNativeBinary`: it
 * lists what the package actually calls on its binary, functions and classes
 * alike.
 */
export function hasFunctions(
	value: unknown,
	names: readonly string[],
): value is object {
	if (typeof value !== "object" || value === null) return false;
	return names.every((name) => hasFunction(value, name));
}

/**
 * Load `<package root>/index.<suffix>.node`, and check it is the binary the
 * package calls.
 *
 * The path is fixed rather than passed: this file is generated into
 * `<package>/src/vendor/`, so the package root is always two levels up, from
 * `src` and from `dist` alike.
 *
 * `isBinary` is the package's own check of what it calls. A declaration only
 * says what the Rust promises: a stale build, or one from another version,
 * loads just as well and then fails on the first missing call, far from here.
 * A rejected module is reported as a failed load, so the package's policy
 * (degrade or refuse) applies to it unchanged.
 */
export function loadNativeBinary<T>(
	isBinary: (value: unknown) => value is T,
): NativeBinaryResult<T> {
	const suffix = nativeBinarySuffix();
	if (suffix === undefined) return { loaded: false, suffix };
	const here = dirname(fileURLToPath(import.meta.url));
	let loaded: unknown;
	try {
		const nodeRequire = createRequire(import.meta.url);
		loaded = nodeRequire(join(here, `../../index.${suffix}.node`));
	} catch (cause) {
		return { loaded: false, suffix, cause };
	}
	if (isBinary(loaded)) return { loaded: true, binary: loaded };
	// The guard answers yes or no; what the binary does export is what lets a
	// reader see which call it lacks.
	const exported =
		typeof loaded === "object" && loaded !== null
			? Object.keys(loaded).filter((name) => hasFunction(loaded, name))
			: [];
	return {
		loaded: false,
		suffix,
		cause: new Error(
			`index.${suffix}.node loaded, but it lacks functions this package calls ` +
				`(it exports: ${exported.length > 0 ? exported.join(", ") : "none"}). ` +
				"The binary is stale or from another version: rebuild it.",
		),
	};
}
