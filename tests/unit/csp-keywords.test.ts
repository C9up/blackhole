/**
 * CSP keywords (bug 041): `@word` sources a resolver fills in per request,
 * registered through `cspKeywords` — and an `@word` nothing resolves refused
 * when the policy is built instead of reaching the browser as a host name.
 */
import { describe, expect, it } from "vitest";
import {
	CspKeywords,
	createBlackhole,
	cspKeywords,
	E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE,
	E_BLACKHOLE_UNKNOWN_CSP_KEYWORD,
} from "../../src/index.js";
import { blackholeMiddleware } from "../../src/middleware.js";
import { ADAPTERS, viaAdapter } from "./support/adapters.js";
import { reamContext } from "./support/ream.js";

const CSP = "content-security-policy";

describe("blackhole > CSP keyword registry", () => {
	it("refuses an `@keyword` no resolver knows, at createBlackhole", () => {
		const build = (csp: Parameters<typeof createBlackhole>[0]) => () =>
			createBlackhole({ csrf: false, ...csp });
		for (const make of [
			build({ csp: { directives: { scriptSrc: ["'self'", "@viteDevUrl"] } } }),
			build({ csp: { policy: "default-src 'self'; script-src @viteDevUrl" } }),
		]) {
			expect(make).toThrow(E_BLACKHOLE_UNKNOWN_CSP_KEYWORD);
			expect(make).toThrow(/@viteDevUrl/);
		}
	});

	it("resolves a registered keyword per request, with the framework's objects", () => {
		const seen: unknown[] = [];
		cspKeywords.register("@assetsUrl", (request, response, nonce) => {
			seen.push([request, response, nonce]);
			return `https://cdn-${seen.length}.example`;
		});
		const bh = createBlackhole({
			csrf: false,
			csp: {
				useDefaults: false,
				directives: {
					defaultSrc: ["'self'"],
					scriptSrc: ["'self'", "@nonce", "@assetsUrl"],
				},
			},
		});
		const request = { id: "req" };
		const response = { id: "res" };
		expect(bh.securityHeaders("abc", { request, response })[CSP]).toBe(
			"default-src 'self'; script-src 'self' 'nonce-abc' https://cdn-1.example",
		);
		expect(bh.securityHeaders("def")[CSP]).toBe(
			"default-src 'self'; script-src 'self' 'nonce-def' https://cdn-2.example",
		);
		expect(seen).toEqual([
			[request, response, "abc"],
			[undefined, undefined, "def"],
		]);
	});

	it("matches a keyword as a whole token, not as a prefix of another", () => {
		cspKeywords.register("@cdn", () => "https://a.example");
		cspKeywords.register("@cdnImages", () => "https://b.example");
		const bh = createBlackhole({
			csrf: false,
			csp: { policy: "default-src 'self' @cdnImages; img-src @cdn" },
		});
		expect(bh.securityHeaders()[CSP]).toBe(
			"default-src 'self' https://b.example; img-src https://a.example",
		);
	});

	it("drops a keyword its resolver answers empty, and `@nonce` with no nonce", () => {
		cspKeywords.register("@devServer", () => "");
		const bh = createBlackhole({
			csrf: false,
			csp: {
				policy: "default-src 'self'; script-src 'self' @nonce @devServer",
			},
		});
		expect(bh.securityHeaders()[CSP]).toBe(
			"default-src 'self'; script-src 'self'",
		);
	});

	it("refuses a resolved value that would end the directive", () => {
		cspKeywords.register("@evil", () => "https://x.example; script-src *");
		const bh = createBlackhole({
			csrf: false,
			csp: { policy: "default-src 'self' @evil" },
		});
		expect(() => bh.securityHeaders()).toThrow(
			E_BLACKHOLE_INVALID_CSP_KEYWORD_VALUE,
		);
	});

	it("refuses a keyword registered under an invalid name", () => {
		const registry = new CspKeywords();
		expect(() => registry.register("vite", () => "")).toThrow(
			E_BLACKHOLE_UNKNOWN_CSP_KEYWORD,
		);
		expect(() => registry.register("@a b", () => "")).toThrow(
			E_BLACKHOLE_UNKNOWN_CSP_KEYWORD,
		);
		expect(registry.register("@ok-name_2", () => "").has("@ok-name_2")).toBe(
			true,
		);
	});

	it("captures the resolvers when the policy is built", () => {
		cspKeywords.register("@pinned", () => "https://first.example");
		const bh = createBlackhole({
			csrf: false,
			csp: { policy: "default-src 'self' @pinned" },
		});
		cspKeywords.register("@pinned", () => "https://second.example");
		expect(bh.securityHeaders()[CSP]).toBe(
			"default-src 'self' https://first.example",
		);
	});

	it("hands the Ream middleware's request and response to the resolver", async () => {
		const received: unknown[] = [];
		cspKeywords.register("@reamProbe", (request, response) => {
			received.push(request, response);
			return "https://probe.example";
		});
		const built = reamContext({
			bh: createBlackhole({
				csrf: false,
				csp: { policy: "default-src 'self'; script-src @reamProbe" },
			}),
		});
		await blackholeMiddleware(built.ctx, async () => {});
		expect(built.spy.headers[CSP]).toBe(
			"default-src 'self'; script-src https://probe.example",
		);
		expect(received[0]).toBe(built.ctx.request);
		expect(received[1]).toBe(built.ctx.response);
	});

	it("resolves it through every adapter", async () => {
		cspKeywords.register("@everywhere", () => "https://all.example");
		for (const adapter of ADAPTERS) {
			const res = await viaAdapter(
				adapter,
				{
					csrf: false,
					csp: { policy: "default-src 'self'; img-src @everywhere" },
				},
				{ target: "/" },
			);
			expect(res.headers[CSP], adapter).toBe(
				"default-src 'self'; img-src https://all.example",
			);
		}
	});
});
