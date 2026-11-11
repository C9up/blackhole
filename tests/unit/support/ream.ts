/**
 * A Ream HTTP context built field by field — what `blackholeMiddleware` reads
 * and writes, and nothing it does not — with every write recorded.
 */
import { BLACKHOLE_KEY } from "../../../src/BlackholeProvider.js";
import type { Blackhole } from "../../../src/index.js";
import type { ReamContext } from "../../../src/middleware.js";

/**
 * A session that keeps what is put in it, and records flashes. Like the host's,
 * `regenerate()` gives it a new id and keeps its data.
 */
export class FakeSession {
	readonly data = new Map<string, unknown>();
	readonly flashes: unknown[][] = [];
	#generation = 0;
	readonly #prefix = Math.random().toString(36).slice(2);

	get sessionId(): string {
		return `${this.#prefix}-${this.#generation}`;
	}

	regenerate(): void {
		this.#generation += 1;
	}

	get(key: string): unknown {
		return this.data.get(key);
	}

	put(key: string, value: unknown): void {
		this.data.set(key, value);
	}

	flash(...args: unknown[]): void {
		this.flashes.push(["flash", ...args]);
	}

	flashExcept(...args: unknown[]): void {
		this.flashes.push(["flashExcept", ...args]);
	}

	flashErrors(...args: unknown[]): void {
		this.flashes.push(["flashErrors", ...args]);
	}
}

export interface ReamSpy {
	status: number;
	json?: unknown;
	headers: Record<string, string>;
	cookies: Record<string, string>;
	redirectedBack: boolean;
	nextCalled: boolean;
}

export interface ReamOptions {
	bh: Blackhole;
	method?: string;
	path?: string;
	query?: string;
	headers?: Record<string, string>;
	body?: unknown;
	ip?: string;
	protocol?: string;
	host?: string | null;
	route?: { pattern: string };
	session?: FakeSession;
	i18n?: { t(key: string, data: object, fallback: string): string };
	/** What the route handler sends back. */
	responseBody?: string;
	responseType?: string;
}

/** The context, and what the middleware did to it. */
export function reamContext(options: ReamOptions): {
	ctx: ReamContext;
	spy: ReamSpy;
} {
	const spy: ReamSpy = {
		status: 200,
		headers: {},
		cookies: {},
		redirectedBack: false,
		nextCalled: false,
	};
	const requestHeaders = options.headers ?? {};
	let body = options.responseBody ?? "";
	if (options.responseType !== undefined) {
		spy.headers["content-type"] = options.responseType;
	}
	const response = {
		status(code: number) {
			spy.status = code;
			return response;
		},
		json(data: unknown) {
			spy.json = data;
		},
		send(data: unknown) {
			body = String(data);
		},
		header(name: string, value: string) {
			spy.headers[name.toLowerCase()] = value;
			return response;
		},
		cookie(name: string, value: string) {
			spy.cookies[name] = value;
			return response;
		},
		plainCookie(name: string, value: string) {
			spy.cookies[name] = value;
			return response;
		},
		getBody: () => body,
		getHeader: (name: string): string | undefined =>
			spy.headers[name.toLowerCase()],
		setBody(next: string) {
			body = next;
		},
		redirect: () => ({
			back() {
				spy.redirectedBack = true;
			},
		}),
	};
	const path = options.path ?? "/";
	const ctx: ReamContext & {
		session?: FakeSession;
		i18n?: ReamOptions["i18n"];
	} = {
		containerResolver: {
			async make(token: string) {
				if (token === BLACKHOLE_KEY) return options.bh;
				throw new Error(`No binding for ${token}`);
			},
		},
		route: options.route,
		session: options.session,
		i18n: options.i18n,
		request: {
			method: () => options.method ?? "GET",
			url: (full?: boolean) =>
				full && options.query ? `${path}?${options.query}` : path,
			path: () => path,
			header: (name: string) => requestHeaders[name.toLowerCase()],
			headers: () => requestHeaders,
			body: () => options.body,
			ip: () => options.ip ?? "127.0.0.1",
			protocol: () => options.protocol ?? "http",
			host: () =>
				options.host === undefined
					? (requestHeaders.host ?? null)
					: options.host,
		},
		store: { set() {} },
		response,
	};
	return { ctx, spy };
}

/** Run the router-tier middleware, recording whether the route ran. */
export async function runRoute(
	middleware: (ctx: ReamContext, next: () => Promise<void>) => Promise<void>,
	built: { ctx: ReamContext; spy: ReamSpy },
	handler: (ctx: ReamContext) => void = () => {},
): Promise<ReamSpy> {
	await middleware(built.ctx, async () => {
		built.spy.nextCalled = true;
		handler(built.ctx);
	});
	return built.spy;
}
