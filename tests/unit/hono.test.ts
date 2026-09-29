/**
 * `blackholeHono` against the real Hono: what reaches the route, what is
 * refused before it, and what every response — a refusal, a thrown route —
 * carries.
 */
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { type BlackholeHonoOptions, blackholeHono } from "../../src/hono.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";

function app(options: BlackholeHonoOptions = {}) {
	const hono = new Hono();
	hono.use(
		blackholeHono({ secret: SECRET, clientIp: () => "1.2.3.4", ...options }),
	);
	hono.get("/token", (c) => c.json({ token: c.get("csrfToken") }));
	hono.get("/page", (c) => c.html("<p>hi</p><script>alert(1)</script>"));
	hono.get("/boom", () => {
		throw new Error("boom");
	});
	hono.post("/orders", (c) => c.json({ ok: true }));
	return hono;
}

/** A token and the cookie it came in, from a GET. */
async function tokenFor(
	hono: Hono,
): Promise<{ token: string; cookie: string }> {
	const res = await hono.request("http://app.test/token");
	const body: unknown = await res.json();
	const token: unknown = Reflect.get(Object(body), "token");
	if (typeof token !== "string") throw new Error("no token");
	const cookie = res.headers.get("set-cookie") ?? "";
	expect(cookie).toContain(`XSRF-TOKEN=${token}`);
	return { token, cookie: `XSRF-TOKEN=${token}` };
}

describe("blackhole > blackholeHono", () => {
	it("seeds the token for the route and the cookie on the response", async () => {
		const hono = app();
		const { token } = await tokenFor(hono);
		expect(token).toMatch(/\./);
	});

	it("refuses a POST without a token, with the protective headers", async () => {
		const res = await app().request("http://app.test/orders", {
			method: "POST",
		});
		expect(res.status).toBe(403);
		expect(await res.json()).toMatchObject({
			error: { code: "E_BAD_CSRF_TOKEN" },
		});
		expect(res.headers.get("x-content-type-options")).toBe("nosniff");
		expect(res.headers.get("content-security-policy")).not.toBeNull();
	});

	it("lets a POST through with the double-submitted token", async () => {
		const hono = app();
		const { token, cookie } = await tokenFor(hono);
		const res = await hono.request("http://app.test/orders", {
			method: "POST",
			headers: { cookie, "x-xsrf-token": token },
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true });
	});

	it("reads the token from an urlencoded form, and leaves the body to the route", async () => {
		const hono = new Hono();
		hono.use(blackholeHono({ secret: SECRET, clientIp: () => "1.2.3.4" }));
		hono.get("/token", (c) => c.json({ token: c.get("csrfToken") }));
		hono.post("/form", async (c) => c.json(await c.req.parseBody()));
		const { token, cookie } = await tokenFor(hono);
		const res = await hono.request("http://app.test/form", {
			method: "POST",
			headers: {
				cookie,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: `name=ada&_csrf=${encodeURIComponent(token)}`,
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ name: "ada" });
	});

	it("refuses an http Origin on an https request", async () => {
		const hono = app();
		const { token, cookie } = await tokenFor(hono);
		const res = await hono.request("https://app.test/orders", {
			method: "POST",
			headers: {
				host: "app.test",
				origin: "http://app.test",
				cookie,
				"x-xsrf-token": token,
			},
		});
		expect(res.status).toBe(403);
		expect(await res.json()).toMatchObject({
			error: { code: "E_BLACKHOLE_CSRF_ORIGIN_MISMATCH" },
		});
	});

	it("sanitizes an HTML fragment and sets the headers on it", async () => {
		const res = await app().request("http://app.test/page");
		const html = await res.text();
		expect(html).toContain("<p>hi</p>");
		expect(html).not.toContain("<script>");
		expect(res.headers.get("x-content-type-options")).toBe("nosniff");
	});

	it("sets the headers on the error response of a route that throws", async () => {
		const res = await app().request("http://app.test/boom");
		expect(res.status).toBe(500);
		expect(res.headers.get("x-content-type-options")).toBe("nosniff");
	});

	it("rate-limits, with the budget and Retry-After", async () => {
		const hono = app({ csrf: false, rateLimit: { max: 1, windowSeconds: 60 } });
		const first = await hono.request("http://app.test/token");
		expect(first.headers.get("x-ratelimit-remaining")).toBe("0");
		const second = await hono.request("http://app.test/token");
		expect(second.status).toBe(429);
		expect(second.headers.get("retry-after")).not.toBeNull();
		expect(await second.json()).toMatchObject({
			error: { code: "E_BLACKHOLE_RATE_LIMITED" },
		});
	});

	it("answers a CORS preflight before the route", async () => {
		const hono = app({
			cors: { origin: ["https://front.test"], methods: ["POST"] },
		});
		const res = await hono.request("http://app.test/orders", {
			method: "OPTIONS",
			headers: {
				origin: "https://front.test",
				"access-control-request-method": "POST",
			},
		});
		expect(res.status).toBe(204);
		expect(res.headers.get("access-control-allow-origin")).toBe(
			"https://front.test",
		);
		expect(res.headers.get("x-content-type-options")).toBe("nosniff");
	});
});
