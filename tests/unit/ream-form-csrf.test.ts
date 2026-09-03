/**
 * The `_csrf` form field, through the Ream middleware.
 *
 * A server-rendered form submits its token as a body field, not a header —
 * that is what `csrfField()` exists for. By the time a middleware runs, Ream's
 * body parser has turned an `application/x-www-form-urlencoded` body into an
 * object, so the field only reaches the engine if the adapter reconstructs it.
 * The Express and Fastify adapters do; this asserts the Ream one does too,
 * which is the adapter every Ream app actually uses.
 */

import { describe, expect, it } from "vitest";
import { BLACKHOLE_KEY } from "../../src/BlackholeProvider.js";
import { createBlackhole } from "../../src/index.js";
import { blackholeMiddleware, type ReamContext } from "../../src/middleware.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";
const bh = createBlackhole({ csrf: true, secret: SECRET });

/** Minimal Ream-shaped context: only what the CSRF path reads. */
function contextFor(body: unknown, token: string) {
	const headers: Record<string, string> = { cookie: `XSRF-TOKEN=${token}` };
	let status: number | undefined;
	const response = {
		status(code: number) {
			status = code;
			return response;
		},
		json() {},
		send() {},
		cookie() {
			return response;
		},
		plainCookie() {
			return response;
		},
		header() {
			return response;
		},
		getBody: () => "",
		getHeader: () => undefined,
		setBody() {},
	};
	const ctx: ReamContext = {
		containerResolver: {
			async make(token_) {
				if (token_ === BLACKHOLE_KEY) return bh;
				throw new Error(`No binding for ${String(token_)}`);
			},
		},
		request: {
			method: () => "POST",
			url: () => "/orders",
			path: () => "/orders",
			header: (name) => headers[name],
			headers: () => headers,
			body: () => body,
			ip: () => "127.0.0.1",
		},
		store: { set() {} },
		response,
	};
	return { ctx, statusOf: () => status };
}

describe("blackhole > Ream middleware > _csrf form field", () => {
	// The shape Ream hands a middleware: `request.body()` is the PARSED body,
	// so the token arrives as a property, never as the raw urlencoded string.
	it("accepts a form POST whose parsed body carries a valid _csrf", async () => {
		const token = bh.generateCsrfToken();
		const { ctx, statusOf } = contextFor(
			{ name: "widget", _csrf: token },
			token,
		);

		let reached = false;
		await blackholeMiddleware(ctx, () => {
			reached = true;
		});

		expect(statusOf()).not.toBe(403);
		expect(reached).toBe(true);
	});

	// Same shape, wrong token — the field must be READ, not merely tolerated.
	it("still rejects a form POST whose _csrf does not match the cookie", async () => {
		const token = bh.generateCsrfToken();
		const other = bh.generateCsrfToken();
		const { ctx, statusOf } = contextFor({ _csrf: other }, token);

		let reached = false;
		await blackholeMiddleware(ctx, () => {
			reached = true;
		});

		expect(statusOf()).toBe(403);
		expect(reached).toBe(false);
	});
});
