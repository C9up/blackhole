import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { Secret } from "@c9up/ream";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { createBlackhole } from "../../src/index.js";
import { stubsRoot } from "../../src/stubs.js";

const KEY = "test-app-key-32-bytes-long-aaaaaa";

/** A POST that echoes `token` the way a browser does (cookie + header). */
function postWith(token: string) {
	return {
		method: "POST",
		path: "/orders",
		headers: { "x-xsrf-token": token, cookie: `XSRF-TOKEN=${token}` },
	};
}

describe("blackhole > secret given as a Secret", () => {
	it("signs and verifies with anything that releases a string", () => {
		const bh = createBlackhole({
			csrf: true,
			secret: { release: () => KEY },
		});
		const token = bh.generateCsrfToken();
		expect(bh.csrfTokenIsValid(token)).toBe(true);
		expect(bh.check(postWith(token)).allowed).toBe(true);
	});

	it("signs with the released value of ream's Secret, not its redacted text", () => {
		// A token minted under the plain key must verify under the Secret: the
		// HMAC key is the released value, never `String(secret)` ('[redacted]').
		const plain = createBlackhole({ csrf: true, secret: KEY });
		const wrapped = createBlackhole({ csrf: true, secret: new Secret(KEY) });
		const token = plain.generateCsrfToken();
		expect(wrapped.csrfTokenIsValid(token)).toBe(true);
		expect(wrapped.check(postWith(token)).allowed).toBe(true);

		const redacted = createBlackhole({
			csrf: true,
			secret: "[redacted]-padding-to-16",
		});
		expect(redacted.csrfTokenIsValid(wrapped.generateCsrfToken())).toBe(false);
	});

	it("still refuses a forged token when the secret is a Secret", () => {
		const bh = createBlackhole({ csrf: true, secret: new Secret(KEY) });
		const forged = `${"a".repeat(43)}.${"b".repeat(43)}`;
		expect(bh.csrfTokenIsValid(forged)).toBe(false);
		expect(bh.check(postWith(forged)).allowed).toBe(false);
	});

	it("fails closed on a Secret that wraps an empty string", () => {
		expect(() =>
			createBlackhole({ csrf: true, secret: new Secret("") }),
		).toThrow(/no `secret` was provided/);
		expect(() =>
			createBlackhole({ csrf: true, secret: { release: () => "" } }),
		).toThrow(/no `secret` was provided/);
	});

	it("applies the placeholder and length checks to the released value", () => {
		expect(() =>
			createBlackhole({
				csrf: true,
				secret: new Secret("change-me-to-a-unique-32+-byte-secret!!"),
			}),
		).toThrow(/placeholder/);
		expect(() =>
			createBlackhole({ csrf: true, secret: new Secret("short") }),
		).toThrow(/too short/);
	});

	it("refuses a Secret that does not release a string", () => {
		// What an untyped (JavaScript) config can hand over: the type guard,
		// not the compiler, is what stands between it and the HMAC key.
		const untyped = (secret: unknown, csrf: boolean) => () =>
			Reflect.apply(createBlackhole, undefined, [{ csrf, secret }]);
		expect(untyped(new Secret(KEY.length), true)).toThrow(TypeError);
		expect(untyped(new Secret(undefined), false)).toThrow(TypeError);
		expect(untyped({ release: "not-a-function" }, true)).toThrow(TypeError);
		expect(untyped(42, true)).toThrow(TypeError);
	});
});

/**
 * Type-check the configure stub as a new app receives it.
 *
 * The files live only in this host, under the package root so `@c9up/ream`
 * and `@c9up/blackhole` resolve exactly as in an app. `start/env.ts` is the
 * one a new app is scaffolded with: APP_KEY is `Env.schema.secret()`.
 */
function stubDiagnostics(): string[] {
	const pkgRoot = resolve(import.meta.dirname, "..", "..");
	const appRoot = join(pkgRoot, ".stub-app");
	const raw = readFileSync(join(stubsRoot, "config", "blackhole.stub"), "utf8");
	const [, front = "", body = ""] = raw.split(/^---\r?\n/m, 3);
	const to = /^to:\s*(.+)$/m.exec(front)?.[1]?.trim() ?? "";
	const configFile = join(appRoot, to);
	const envFile = join(appRoot, "start", "env.ts");
	const files = new Map<string, string>([
		[configFile, body],
		[
			envFile,
			[
				"import { Env } from '@c9up/ream'",
				"export default await Env.create(new URL('../', import.meta.url), {",
				"  APP_KEY: Env.schema.secret(),",
				"})",
			].join("\n"),
		],
	]);
	const options: ts.CompilerOptions = {
		target: ts.ScriptTarget.ES2022,
		module: ts.ModuleKind.ESNext,
		moduleResolution: ts.ModuleResolutionKind.Bundler,
		strict: true,
		noEmit: true,
		skipLibCheck: true,
		experimentalDecorators: true,
		types: ["node"],
		typeRoots: [join(pkgRoot, "node_modules", "@types")],
		paths: { "#start/env": [envFile] },
	};
	const host = ts.createCompilerHost(options);
	const fileExists = host.fileExists.bind(host);
	const readFile = host.readFile.bind(host);
	const getSourceFile = host.getSourceFile.bind(host);
	host.fileExists = (name) => files.has(name) || fileExists(name);
	host.readFile = (name) => files.get(name) ?? readFile(name);
	host.directoryExists = (name) =>
		name === appRoot || [...files.keys()].some((f) => dirname(f) === name)
			? true
			: ts.sys.directoryExists(name);
	host.getSourceFile = (name, version, onError, create) => {
		const text = files.get(name);
		return text === undefined
			? getSourceFile(name, version, onError, create)
			: ts.createSourceFile(name, text, version);
	};
	const program = ts.createProgram([configFile], options, host);
	const source = program.getSourceFile(configFile);
	if (source === undefined) return ["the rendered stub was not loaded"];
	return [
		...program.getSyntacticDiagnostics(source),
		...program.getSemanticDiagnostics(source),
	].map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
}

describe("blackhole > configure stub", () => {
	it("type-checks against an env whose APP_KEY is a Secret", () => {
		expect(stubDiagnostics()).toEqual([]);
	}, 60_000);
});
