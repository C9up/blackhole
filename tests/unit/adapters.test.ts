import { describe, expect, it } from "vitest";
import { blackholeExpress } from "../../src/express.js";
import { blackholeFastify } from "../../src/fastify.js";
import { createBlackhole } from "../../src/index.js";

// ── Express adapter ──────────────────────────────────────────

interface ExpressReqLike {
	method: string;
	originalUrl?: string;
	url: string;
	path?: string;
	headers: Record<string, string | string[] | undefined>;
	body?: unknown;
	ip?: string;
	socket?: { remoteAddress?: string };
	csrfToken?: string;
}

interface ExpressResLike {
	headersSent: boolean;
	getHeader(name: string): number | string | string[] | undefined;
	setHeader(name: string, value: string): unknown;
	status(code: number): ExpressResLike;
	json(body: unknown): unknown;
	send(body?: unknown): unknown;
	nonce?: string;
}

interface ExpressSpy {
	status?: number;
	json?: unknown;
	sent?: unknown;
}

function mockExpress(opts: {
	method?: string;
	url?: string;
	headers?: Record<string, string>;
	body?: unknown;
}): { req: ExpressReqLike; res: ExpressResLike; spy: ExpressSpy } {
	const headers: Record<string, string> = {};
	const spy: ExpressSpy = {};
	const res: ExpressResLike = {
		headersSent: false,
		getHeader(name) {
			return headers[name.toLowerCase()];
		},
		setHeader(name, value) {
			headers[name.toLowerCase()] = value;
		},
		status(code) {
			spy.status = code;
			return this;
		},
		json(body) {
			spy.json = body;
		},
		send(body) {
			spy.sent = body;
		},
	};
	const req: ExpressReqLike = {
		method: opts.method ?? "GET",
		url: opts.url ?? "/orders",
		path: opts.url ?? "/orders",
		headers: opts.headers ?? {},
		body: opts.body,
		ip: "1.2.3.4",
	};
	return { req, res, spy };
}

describe("blackhole > blackholeExpress", () => {
	it("allows a GET and seeds the XSRF-TOKEN cookie + req.csrfToken", () => {
		const mw = blackholeExpress({ csrf: true });
		const { req, res } = mockExpress({ method: "GET" });
		let nextCalled = false;
		mw(req, res, () => {
			nextCalled = true;
		});
		expect(nextCalled).toBe(true);
		expect(typeof req.csrfToken).toBe("string");
		const cookie = res.getHeader("set-cookie");
		expect(String(cookie)).toMatch(/^XSRF-TOKEN=/);
	});

	it("rejects a POST without a CSRF token (403) and does not call next", () => {
		const mw = blackholeExpress({ csrf: true });
		const { req, res, spy } = mockExpress({ method: "POST" });
		let nextCalled = false;
		mw(req, res, () => {
			nextCalled = true;
		});
		expect(nextCalled).toBe(false);
		expect(spy.status).toBe(403);
		expect(spy.json).toBeDefined();
	});

	it("allows a POST when the XSRF-TOKEN cookie matches the X-XSRF-TOKEN header", () => {
		const token = createBlackhole().generateCsrfToken();
		const mw = blackholeExpress({ csrf: true });
		const { req, res } = mockExpress({
			method: "POST",
			headers: { cookie: `XSRF-TOKEN=${token}`, "x-xsrf-token": token },
		});
		let nextCalled = false;
		mw(req, res, () => {
			nextCalled = true;
		});
		expect(nextCalled).toBe(true);
	});

	it("sanitizes a text/html response + sets security headers via the send wrapper", () => {
		const mw = blackholeExpress({ csrf: false });
		const { req, res, spy } = mockExpress({ method: "GET" });
		mw(req, res, () => {
			res.setHeader("content-type", "text/html");
			res.send("<p>ok</p><script>alert(1)</script>");
		});
		expect(String(spy.sent)).not.toMatch(/<script/i);
		expect(String(spy.sent)).toContain("<p>ok</p>");
		expect(res.getHeader("x-content-type-options")).toBe("nosniff");
	});

	it("answers a CORS preflight with 204", () => {
		const mw = blackholeExpress({
			csrf: false,
			cors: { origin: ["https://app.test"] },
		});
		const { req, res, spy } = mockExpress({
			method: "OPTIONS",
			headers: { origin: "https://app.test" },
		});
		mw(req, res, () => {
			throw new Error("next must not run for preflight");
		});
		expect(spy.status).toBe(204);
		expect(res.getHeader("access-control-allow-origin")).toBe(
			"https://app.test",
		);
	});
});

// ── Fastify adapter ──────────────────────────────────────────

interface FastifyReqLike {
	method: string;
	url: string;
	routerPath?: string;
	headers: Record<string, string | string[] | undefined>;
	body?: unknown;
	ip?: string;
	csrfToken?: string;
}

interface FastifyReplyLike {
	code(statusCode: number): FastifyReplyLike;
	header(name: string, value: string): FastifyReplyLike;
	getHeader(name: string): number | string | string[] | undefined;
	send(payload?: unknown): FastifyReplyLike;
	nonce?: string;
}

/** Superset signature both hooks satisfy (onRequest ignores `payload`). */
type FastifyHook = (
	request: FastifyReqLike,
	reply: FastifyReplyLike,
	payload: unknown,
) => Promise<unknown>;

interface FastifyInstanceLike {
	addHook(name: string, hook: FastifyHook): unknown;
}

async function registerFastify(
	plugin: (fastify: FastifyInstanceLike) => Promise<void>,
): Promise<{ onRequest?: FastifyHook; onSend?: FastifyHook }> {
	const hooks: Array<{ name: string; fn: FastifyHook }> = [];
	await plugin({
		addHook(name, hook) {
			hooks.push({ name, fn: hook });
		},
	});
	return {
		onRequest: hooks.find((h) => h.name === "onRequest")?.fn,
		onSend: hooks.find((h) => h.name === "onSend")?.fn,
	};
}

function mockReply(): {
	reply: FastifyReplyLike;
	spy: { code?: number; sent?: unknown };
} {
	const headers: Record<string, string> = {};
	const spy: { code?: number; sent?: unknown } = {};
	const reply: FastifyReplyLike = {
		code(statusCode) {
			spy.code = statusCode;
			return this;
		},
		header(name, value) {
			headers[name.toLowerCase()] = value;
			return this;
		},
		getHeader(name) {
			return headers[name.toLowerCase()];
		},
		send(payload) {
			spy.sent = payload;
			return this;
		},
	};
	return { reply, spy };
}

describe("blackhole > blackholeFastify", () => {
	it("rejects a POST without a CSRF token in onRequest", async () => {
		const { onRequest } = await registerFastify(
			blackholeFastify({ csrf: true }),
		);
		const { reply, spy } = mockReply();
		const request: FastifyReqLike = {
			method: "POST",
			url: "/orders",
			headers: {},
			ip: "1.2.3.4",
		};
		await onRequest?.(request, reply, undefined);
		expect(spy.code).toBe(403);
		expect(spy.sent).toBeDefined();
	});

	it("seeds request.csrfToken + the XSRF-TOKEN cookie on a GET", async () => {
		const { onRequest } = await registerFastify(
			blackholeFastify({ csrf: true }),
		);
		const { reply } = mockReply();
		const request: FastifyReqLike = {
			method: "GET",
			url: "/orders",
			headers: {},
			ip: "1.2.3.4",
		};
		await onRequest?.(request, reply, undefined);
		expect(typeof request.csrfToken).toBe("string");
		expect(String(reply.getHeader("set-cookie"))).toMatch(/^XSRF-TOKEN=/);
	});

	it("sanitizes a text/html payload + sets security headers in onSend", async () => {
		const { onSend } = await registerFastify(blackholeFastify({ csrf: false }));
		const { reply } = mockReply();
		reply.header("content-type", "text/html");
		const request: FastifyReqLike = { method: "GET", url: "/", headers: {} };
		const out = await onSend?.(
			request,
			reply,
			"<p>ok</p><script>alert(1)</script>",
		);
		expect(String(out)).not.toMatch(/<script/i);
		expect(String(out)).toContain("<p>ok</p>");
		expect(reply.getHeader("x-content-type-options")).toBe("nosniff");
	});
});
