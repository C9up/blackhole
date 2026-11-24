/**
 * The CSRF decision is taken on the method the request came in with. A
 * `_method` field — or any other override — can add a guarded method, never
 * take a request out of the guarded set: a POST on the wire is checked
 * whatever verb the framework reports afterwards.
 */
import {
	Container,
	createHttpKernel,
	type HttpContext,
	MiddlewareRegistry,
	Router,
} from "@c9up/ream";
import BodyParserMiddleware from "@c9up/ream/bodyparser_middleware";
import { describe, expect, it } from "vitest";
import { BLACKHOLE_KEY } from "../../src/BlackholeProvider.js";
import { csrfBodyString } from "../../src/core.js";
import { createBlackhole } from "../../src/index.js";
import { blackholeMiddleware } from "../../src/middleware.js";
import { ADAPTERS, viaAdapter } from "./support/adapters.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";
const bh = createBlackhole({ csrf: true, secret: SECRET });

function kernel(
	allowMethodSpoofing: boolean,
	blackhole: ReturnType<typeof createBlackhole> = bh,
) {
	const ran: string[] = [];
	const router = new Router();
	router.get("/transfer", (ctx) => {
		ran.push("GET");
		ctx.response.json({ ran: "GET /transfer" });
	});
	router.post("/transfer", (ctx) => {
		ran.push("POST");
		ctx.response.json({
			ran: "POST /transfer",
			csrfProtected: Reflect.get(ctx.request, "csrfProtected"),
		});
	});
	const bodyParser = new BodyParserMiddleware({});
	const container = new Container();
	container.singleton(BLACKHOLE_KEY, () => blackhole);
	const handle = createHttpKernel({
		router,
		middleware: new MiddlewareRegistry(),
		container,
		routerMiddleware: [
			// The order a new application is scaffolded with: body parser first.
			(ctx: HttpContext, next: () => Promise<void>) =>
				bodyParser.handle(ctx, next),
			(ctx: HttpContext, next: () => Promise<void>) =>
				blackholeMiddleware(ctx, next),
		],
		allowMethodSpoofing,
	});
	return { handle, ran };
}

function post(
	body: string,
	extra: Record<string, string> = {},
	contentType = "application/x-www-form-urlencoded",
) {
	return {
		method: "POST",
		path: "/transfer",
		query: "",
		headers: {
			host: "bank.example",
			origin: "https://evil.example",
			referer: "https://evil.example/attack.html",
			"content-type": contentType,
			"content-length": String(Buffer.byteLength(body)),
			accept: "application/json",
			...extra,
		},
		body,
	};
}

describe("blackhole > CSRF > a body `_method` under allowMethodSpoofing", () => {
	it("a same-origin POST with a valid token pair runs the handler, guarded", async () => {
		const k = kernel(true);
		const token = bh.generateCsrfToken();
		const res = await k.handle(
			post("_method=GET&amount=1", {
				// The test kernel speaks plain http: same scheme, same host.
				origin: "http://bank.example",
				referer: "http://bank.example/form",
				cookie: `XSRF-TOKEN=${token}`,
				"x-xsrf-token": token,
			}),
		);
		expect(res.status).toBe(200);
		expect(k.ran).toEqual(["POST"]);
		expect(JSON.parse(res.body).csrfProtected).toBe(true);
	});

	it.each(["GET", "HEAD", "OPTIONS", "X"])(
		"a forged POST whose body says `_method=%s` is refused, handler not run",
		async (verb) => {
			const k = kernel(true);
			const res = await k.handle(post(`_method=${verb}&amount=1000`));
			expect(res.status).toBe(403);
			expect(k.ran).toEqual([]);
		},
	);

	it("the same field in a JSON body is refused too", async () => {
		const k = kernel(true);
		const res = await k.handle(
			post('{"_method":"GET","amount":1000}', {}, "application/json"),
		);
		expect(res.status).toBe(403);
		expect(k.ran).toEqual([]);
	});

	it("with no cross-site header at all, the missing token still refuses it", async () => {
		const k = kernel(true);
		const res = await k.handle(
			post("_method=GET&amount=1000", { origin: "", referer: "" }),
		);
		expect(res.status).toBe(403);
		expect(res.body).toContain("E_BAD_CSRF_TOKEN");
		expect(k.ran).toEqual([]);
	});

	it("spoofing off: the field changes nothing", async () => {
		const k = kernel(false);
		const res = await k.handle(post("_method=GET&amount=1000"));
		expect(res.status).toBe(403);
		expect(k.ran).toEqual([]);
	});
});

describe.each(ADAPTERS)(
	"blackhole > CSRF > the wire method decides (%s)",
	(adapter) => {
		const forged = {
			origin: "https://evil.example",
			host: "bank.example",
		};

		it.each(["GET", "HEAD", "OPTIONS", "X"])(
			"a POST the framework reports as %s is still guarded",
			async (reported) => {
				const res = await viaAdapter(
					adapter,
					{ csrf: true, secret: SECRET },
					{
						method: reported,
						wireMethod: "POST",
						target: "/transfer",
						headers: forged,
					},
				);
				expect(res.status).toBe(403);
				expect(res.routeRan).toBe(false);
			},
		);

		it("a POST reported as GET passes with the double-submitted token", async () => {
			const token = createBlackhole({ secret: SECRET }).generateCsrfToken();
			const res = await viaAdapter(
				adapter,
				{ csrf: true, secret: SECRET },
				{
					method: "GET",
					wireMethod: "POST",
					target: "/transfer",
					headers: {
						host: "bank.example",
						origin: "http://bank.example",
						cookie: `XSRF-TOKEN=${token}`,
						"x-xsrf-token": token,
					},
				},
			);
			expect(res.status).toBe(200);
			expect(res.routeRan).toBe(true);
		});

		it("an override INTO the guarded set is guarded: POST reported as DELETE, `methods: ['DELETE']`", async () => {
			const options = {
				csrf: { methods: ["DELETE"] },
				secret: SECRET,
			};
			const overridden = await viaAdapter(adapter, options, {
				method: "DELETE",
				wireMethod: "POST",
				target: "/transfer",
				headers: forged,
			});
			expect(overridden.status).toBe(403);
			expect(overridden.routeRan).toBe(false);
			// The plain POST is outside this application's guarded set.
			const plain = await viaAdapter(adapter, options, {
				method: "POST",
				target: "/transfer",
				headers: forged,
			});
			expect(plain.status).toBe(200);
			expect(plain.routeRan).toBe(true);
		});

		it("a GET stays unguarded", async () => {
			const res = await viaAdapter(
				adapter,
				{ csrf: true, secret: SECRET },
				{ method: "GET", target: "/transfer", headers: forged },
			);
			expect(res.status).toBe(200);
			expect(res.routeRan).toBe(true);
		});
	},
);

describe("blackhole > CSRF > a `_csrf` field that cannot be encoded", () => {
	const loneSurrogate = "\ud800";

	it("counts as an absent token, where any other string is rebuilt", () => {
		expect(csrfBodyString({ _csrf: loneSurrogate })).toBeUndefined();
		expect(csrfBodyString({ _csrf: `abc${loneSurrogate}` })).toBeUndefined();
		expect(csrfBodyString({ _csrf: "a b&c" })).toBe("_csrf=a%20b%26c");
		expect(csrfBodyString({ _csrf: 12 })).toBeUndefined();
	});

	it.each(["ream", "express", "fastify"] as const)(
		"%s: 403 E_BAD_CSRF_TOKEN with CSRF on, the handler with CSRF off",
		async (adapter) => {
			const request = {
				method: "POST",
				target: "/orders",
				headers: { host: "app.example" },
				body: { _csrf: loneSurrogate },
			};
			const guarded = await viaAdapter(
				adapter,
				{ csrf: true, secret: SECRET },
				request,
			);
			expect(guarded.status).toBe(403);
			expect(guarded.routeRan).toBe(false);
			expect(guarded.body).toMatchObject({
				error: { code: "E_BAD_CSRF_TOKEN" },
			});
			const open = await viaAdapter(adapter, { csrf: false }, request);
			expect(open.status).toBe(200);
			expect(open.routeRan).toBe(true);
		},
	);

	it("through the kernel and its body parser: a 403, then a 200 with CSRF off", async () => {
		const json = '{"_csrf":"\\ud800"}';
		const on = kernel(true);
		const refused = await on.handle(
			post(json, { origin: "", referer: "" }, "application/json"),
		);
		expect(refused.status).toBe(403);
		expect(refused.body).toContain("E_BAD_CSRF_TOKEN");
		expect(on.ran).toEqual([]);
		const off = kernel(true, createBlackhole({ csrf: false }));
		const passed = await off.handle(post(json, {}, "application/json"));
		expect(passed.status).toBe(200);
		expect(off.ran).toEqual(["POST"]);
	});
});
