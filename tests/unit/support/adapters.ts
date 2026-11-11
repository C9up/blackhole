/**
 * One request, through each adapter — so a guard is asserted on Ream,
 * Express, Fastify and Hono alike instead of on whichever one a test
 * happened to pick.
 *
 * Express and Fastify are driven through the structural shapes the adapters
 * read (no framework installed here); Hono is the real thing; Ream is the
 * router-tier middleware on a context built field by field.
 */
import { Hono } from "hono";
import { blackholeExpress } from "../../../src/express.js";
import { blackholeFastify } from "../../../src/fastify.js";
import { blackholeHono } from "../../../src/hono.js";
import { type BlackholeOptions, createBlackhole } from "../../../src/index.js";
import { blackholeMiddleware } from "../../../src/middleware.js";
import { reamContext } from "./ream.js";

export interface AdapterRequest {
	method?: string;
	/** Path and query, exactly as sent on the request line. */
	target: string;
	headers?: Record<string, string>;
	/** `host[:port]` the framework resolved (trust-proxy aware). */
	resolvedHost?: string;
	protocol?: string;
	/** The matched route pattern, where the framework has one. */
	routePattern?: string;
	/** Headers the route handler sets on its response. */
	routeHeaders?: Record<string, string>;
	/** An HTML body the route sends as `text/html` (`ok` as text otherwise). */
	routeBody?: string;
}

export interface AdapterResult {
	status: number;
	headers: Record<string, string>;
	body: unknown;
	routeRan: boolean;
	/** The body that went out, when the route answered with text. */
	sentBody?: string;
}

export type AdapterName = "ream" | "express" | "fastify" | "hono";

export const ADAPTERS: AdapterName[] = ["ream", "express", "fastify", "hono"];

function splitTarget(target: string): { path: string; query: string } {
	const at = target.indexOf("?");
	return at === -1
		? { path: target, query: "" }
		: { path: target.slice(0, at), query: target.slice(at + 1) };
}

async function viaReam(
	options: BlackholeOptions,
	req: AdapterRequest,
): Promise<AdapterResult> {
	const { path, query } = splitTarget(req.target);
	const built = reamContext({
		bh: createBlackhole(options),
		method: req.method,
		path,
		query,
		headers: req.headers,
		protocol: req.protocol,
		host: req.resolvedHost,
		route: req.routePattern ? { pattern: req.routePattern } : undefined,
	});
	let routeRan = false;
	await blackholeMiddleware(built.ctx, async () => {
		routeRan = true;
		for (const [name, value] of Object.entries(req.routeHeaders ?? {})) {
			built.ctx.response.header(name, value);
		}
		if (req.routeBody !== undefined) {
			built.ctx.response.header("content-type", "text/html; charset=utf-8");
			built.ctx.response.send(req.routeBody);
		}
	});
	return {
		status: built.spy.status,
		headers: built.spy.headers,
		body: built.spy.json,
		routeRan,
		sentBody: built.ctx.response.getBody(),
	};
}

async function viaExpress(
	options: BlackholeOptions,
	req: AdapterRequest,
): Promise<AdapterResult> {
	const headers: Record<string, string> = {};
	let status = 200;
	let body: unknown;
	let sentBody: string | undefined;
	let routeRan = false;
	const res = {
		headersSent: false,
		getHeader: (name: string) => headers[name.toLowerCase()],
		setHeader(name: string, value: string) {
			headers[name.toLowerCase()] = value;
		},
		append(name: string, value: string | string[]) {
			headers[name.toLowerCase()] = String(value);
		},
		status(code: number) {
			status = code;
			return res;
		},
		json(data: unknown) {
			body = data;
		},
		send(data?: unknown): unknown {
			body = data;
			if (typeof data === "string") sentBody = data;
			return undefined;
		},
	};
	const requestHeaders = req.headers ?? {};
	const host = req.resolvedHost ?? requestHeaders.host;
	await blackholeExpress(options)(
		{
			method: req.method ?? "GET",
			url: req.target,
			originalUrl: req.target,
			path: splitTarget(req.target).path,
			headers: requestHeaders,
			ip: "203.0.113.7",
			protocol: req.protocol ?? "http",
			hostname: host?.split(":")[0],
		},
		res,
		() => {
			routeRan = true;
			for (const [name, value] of Object.entries(req.routeHeaders ?? {})) {
				res.setHeader(name, value);
			}
			if (req.routeBody !== undefined) {
				res.setHeader("content-type", "text/html; charset=utf-8");
			}
			res.send(req.routeBody ?? "ok");
		},
	);
	return { status, headers, body, routeRan, sentBody };
}

type FastifyHook = (
	request: FastifyRequestLike,
	reply: FastifyReplyLike,
	payload: unknown,
) => Promise<unknown>;

interface FastifyRequestLike {
	method: string;
	url: string;
	raw: { url: string };
	routeOptions?: { url?: string };
	headers: Record<string, string>;
	ip: string;
	protocol: string;
	host?: string;
}

interface FastifyReplyLike {
	code(statusCode: number): FastifyReplyLike;
	header(name: string, value: string | string[]): FastifyReplyLike;
	getHeader(name: string): string | string[] | undefined;
	send(payload?: unknown): FastifyReplyLike;
}

async function viaFastify(
	options: BlackholeOptions,
	req: AdapterRequest,
): Promise<AdapterResult> {
	const hooks = new Map<string, FastifyHook>();
	await blackholeFastify(options)({
		addHook(name: string, hook: FastifyHook) {
			hooks.set(name, hook);
		},
	});
	const headers: Record<string, string> = {};
	let status = 200;
	let body: unknown;
	let sent = false;
	const reply: FastifyReplyLike = {
		code(statusCode) {
			status = statusCode;
			return reply;
		},
		header(name, value) {
			headers[name.toLowerCase()] = String(value);
			return reply;
		},
		getHeader: (name) => headers[name.toLowerCase()],
		send(payload) {
			sent = true;
			body = payload;
			return reply;
		},
	};
	const request: FastifyRequestLike = {
		method: req.method ?? "GET",
		url: req.target,
		raw: { url: req.target },
		routeOptions: req.routePattern ? { url: req.routePattern } : undefined,
		headers: req.headers ?? {},
		ip: "203.0.113.7",
		protocol: req.protocol ?? "http",
		host: req.resolvedHost ?? req.headers?.host,
	};
	await hooks.get("preValidation")?.(request, reply, undefined);
	const routeRan = !sent;
	if (routeRan) {
		for (const [name, value] of Object.entries(req.routeHeaders ?? {})) {
			reply.header(name, value);
		}
		if (req.routeBody !== undefined) {
			reply.header("content-type", "text/html; charset=utf-8");
		}
	}
	const answered = await hooks.get("onSend")?.(
		request,
		reply,
		routeRan ? (req.routeBody ?? "ok") : body,
	);
	return {
		status,
		headers,
		body,
		routeRan,
		sentBody: typeof answered === "string" ? answered : undefined,
	};
}

async function viaHono(
	options: BlackholeOptions,
	req: AdapterRequest,
): Promise<AdapterResult> {
	const app = new Hono();
	let routeRan = false;
	app.use(
		blackholeHono({
			...options,
			clientIp: () => "203.0.113.7",
			protocol: () => req.protocol ?? "http",
			host: (c) => req.resolvedHost ?? c.req.header("host") ?? "",
		}),
	);
	app.all("*", (c) => {
		routeRan = true;
		for (const [name, value] of Object.entries(req.routeHeaders ?? {})) {
			c.header(name, value);
		}
		return req.routeBody === undefined ? c.text("ok") : c.html(req.routeBody);
	});
	const response = await app.request(
		`http://localhost${req.target}`,
		{ method: req.method ?? "GET", headers: req.headers ?? {} },
		// What `@hono/node-server` hands the app: the raw request target.
		{ incoming: { url: req.target } },
	);
	const headers: Record<string, string> = {};
	response.headers.forEach((value, name) => {
		headers[name] = value;
	});
	const text = await response.text();
	let body: unknown = text;
	try {
		body = JSON.parse(text);
	} catch {
		// A plain-text body stays as it is.
	}
	return { status: response.status, headers, body, routeRan, sentBody: text };
}

/** Send `req` through `adapter` configured with `options`. */
export function viaAdapter(
	adapter: AdapterName,
	options: BlackholeOptions,
	req: AdapterRequest,
): Promise<AdapterResult> {
	switch (adapter) {
		case "ream":
			return viaReam(options, req);
		case "express":
			return viaExpress(options, req);
		case "fastify":
			return viaFastify(options, req);
		case "hono":
			return viaHono(options, req);
	}
}
