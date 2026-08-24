/**
 * What a rejected CSRF token does, checked against `@adonisjs/shield`.
 *
 * Shield raises ONE error — `E_BAD_CSRF_TOKEN`, 403, "Invalid or expired CSRF
 * token" — and its handler, for a session-backed request, flashes the form back
 * (minus `_csrf`, `_method` and any password), flashes the message, then
 * redirects to the previous page. It does NOT distinguish a missing token from
 * a mismatched one, and neither do we.
 *
 * The check runs in Rust, before the JS pipeline, so the rejection cannot reach
 * a session there — the browser branch lives in the middleware, which has the
 * context.
 */
import { describe, expect, it, vi } from "vitest";
import { BLACKHOLE_KEY } from "../../src/BlackholeProvider.js";
import { createBlackhole } from "../../src/index.js";
import { blackholeMiddleware, type ReamContext } from "../../src/middleware.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";
const bh = createBlackhole({ secret: SECRET, csrf: true });

function makeContext(accept: string, withSession = true) {
	const back = vi.fn();
	const session = {
		flash: vi.fn(),
		flashExcept: vi.fn(),
		flashErrors: vi.fn(),
	};
	const json = vi.fn();
	const status = vi.fn();

	const ctx = {
		containerResolver: {
			async make(token: unknown) {
				if (token === BLACKHOLE_KEY) return bh;
				throw new Error(`No binding for ${String(token)}`);
			},
		},
		request: {
			method: () => "POST",
			url: () => "/orders",
			path: () => "/orders",
			header: (name: string) =>
				name.toLowerCase() === "accept" ? accept : undefined,
			headers: () => ({ accept }),
			// No `_csrf` field and no cookie: the token cannot validate.
			body: () => "name=widget",
			ip: () => "127.0.0.1",
		},
		store: { set: vi.fn() },
		response: {
			status,
			json,
			send: vi.fn(),
			header: vi.fn(),
			cookie: vi.fn(),
			redirect: () => ({ back }),
		},
	};
	if (withSession) Reflect.set(ctx, "session", session);
	return { ctx: ctx as unknown as ReamContext, session, back, json, status };
}

describe("blackhole > CSRF rejection (AdonisJS Shield parity)", () => {
	it("redirects a browser back and re-flashes the form", async () => {
		const { ctx, session, back, json } = makeContext("text/html");

		await blackholeMiddleware(ctx, async () => {});

		expect(session.flashExcept).toHaveBeenCalledWith([
			"_csrf",
			"_method",
			"password",
			"password_confirmation",
		]);
		expect(session.flash).toHaveBeenCalledWith(
			"error",
			"Invalid or expired CSRF token",
		);
		expect(session.flashErrors).toHaveBeenCalledWith({
			E_BAD_CSRF_TOKEN: "Invalid or expired CSRF token",
		});
		expect(back).toHaveBeenCalled();
		// The form is not answered with a JSON body it cannot render.
		expect(json).not.toHaveBeenCalled();
	});

	it("still answers a JSON client with the error body", async () => {
		const { ctx, back, json, status } = makeContext("application/json");

		await blackholeMiddleware(ctx, async () => {});

		expect(back).not.toHaveBeenCalled();
		expect(status).toHaveBeenCalledWith(403);
		expect(json).toHaveBeenCalledWith({
			error: {
				code: "E_BAD_CSRF_TOKEN",
				message: "Invalid or expired CSRF token",
			},
		});
	});

	it("falls back to JSON when the host has no session", async () => {
		// blackhole is agnostic: a host without a session must not crash here.
		const { ctx, back, json } = makeContext("text/html", false);

		await blackholeMiddleware(ctx, async () => {});

		expect(back).not.toHaveBeenCalled();
		expect(json).toHaveBeenCalled();
	});
});
