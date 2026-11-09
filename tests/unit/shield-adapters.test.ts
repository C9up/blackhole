/**
 * The shield (path traversal, parameter pollution) on every adapter.
 *
 * Both guards only work on what the request actually carried: the path as
 * the client wrote it, before any URL parser resolves `..` away, and every
 * key of the query, the first one included.
 */
import { describe, expect, it } from "vitest";
import { queryOf, rawPathOf } from "../../src/core.js";
import { type BlackholeOptions, createBlackhole } from "../../src/index.js";
import { ADAPTERS, viaAdapter } from "./support/adapters.js";

const OPTIONS: BlackholeOptions = { csrf: false };

describe("blackhole > parameter pollution", () => {
	it("refuses a duplicate of the FIRST query key", () => {
		// The search string arrives with its `?`; read literally, the first key
		// was `?role` and never matched its duplicate.
		const bh = createBlackhole(OPTIONS);
		const result = bh.check({
			method: "GET",
			path: "/",
			query: "?role=user&role=admin",
			headers: {},
		});
		expect(result.allowed).toBe(false);
		expect(result.status).toBe(400);
		expect(result.body).toContain("E_BLACKHOLE_PARAMETER_POLLUTION");
	});

	it("hands the engine the query without its leading `?`", () => {
		expect(queryOf("/users?role=user&role=admin")).toBe("role=user&role=admin");
		expect(queryOf("http://app.test/x?a=1")).toBe("a=1");
		expect(queryOf("/x")).toBe("");
	});

	for (const adapter of ADAPTERS) {
		describe(`on ${adapter}`, () => {
			for (const query of [
				"role=user&role=admin",
				"a[]=1&a=2",
				"a[0]=1&a=2",
				"a+b=1&a%20b=2",
				"a.b=1&a[b]=2",
			]) {
				it(`refuses ?${query}`, async () => {
					const res = await viaAdapter(adapter, OPTIONS, {
						target: `/search?${query}`,
					});
					expect(res.status).toBe(400);
					expect(res.routeRan).toBe(false);
				});
			}

			it("lets a list through", async () => {
				const res = await viaAdapter(adapter, OPTIONS, {
					target: "/search?tags[]=a&tags[]=b&page=2",
				});
				expect(res.status).toBe(200);
				expect(res.routeRan).toBe(true);
			});
		});
	}
});

describe("blackhole > path traversal", () => {
	it("reads the raw path of a request target", () => {
		expect(rawPathOf("/files/../../etc/passwd?x=1")).toBe(
			"/files/../../etc/passwd",
		);
		expect(rawPathOf("/files/%2e%2e/x#frag")).toBe("/files/%2e%2e/x");
		expect(rawPathOf("http://app.test/a/../b")).toBe("/a/../b");
		expect(rawPathOf("http://app.test")).toBe("/");
	});

	for (const adapter of ADAPTERS) {
		describe(`on ${adapter}`, () => {
			for (const target of [
				"/files/../../etc/passwd",
				"/files/%2e%2e/%2e%2e/etc/passwd",
				"/files/%2E%2E/secret",
				"/files/%252e%252e/%252e%252e/etc/passwd",
				"/files/..%5c..%5cwindows",
				"/files/..\\..\\windows",
				"/files/.%2e/secret",
			]) {
				it(`refuses ${target}`, async () => {
					const res = await viaAdapter(adapter, OPTIONS, {
						target,
						// Fastify 4 used to hand over this pattern instead of the path.
						routePattern: "/files/*",
					});
					expect(res.status).toBe(400);
					expect(res.routeRan).toBe(false);
				});
			}

			it("serves an ordinary file path", async () => {
				const res = await viaAdapter(adapter, OPTIONS, {
					target: "/files/report.pdf",
					routePattern: "/files/*",
				});
				expect(res.status).toBe(200);
				expect(res.routeRan).toBe(true);
			});
		});
	}
});
