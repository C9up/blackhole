import { Exception } from "@c9up/flare";
import { describe, expect, it, vi } from "vitest";

import { errors, LimiterResponse } from "../../src/index.js";

describe("errors", () => {
	it("the entry exports the errors namespace, each a flare Exception", () => {
		const error = new errors.E_BLACKHOLE_INVALID_TABLE_NAME(['"a b"']);
		expect(error).toBeInstanceOf(Exception);
		expect(error).toBeInstanceOf(errors.E_BLACKHOLE_INVALID_TABLE_NAME);
		expect(error).toMatchObject({
			code: "E_BLACKHOLE_INVALID_TABLE_NAME",
			status: 500,
			message:
				'[blackhole] the database limiter store\'s tableName "a b" is not a table name.',
		});
	});

	it("a class that carries data keeps it next to the code", () => {
		const error = new errors.E_BLACKHOLE_UNSUPPORTED_DATABASE("oracle");
		expect(error).toBeInstanceOf(Exception);
		expect(error).toMatchObject({
			code: "E_BLACKHOLE_UNSUPPORTED_DATABASE",
			status: 500,
			dialect: "oracle",
		});
		expect(error.message).toContain('Unsupported database "oracle"');
	});

	it("E_TOO_MANY_REQUESTS is ThrottleException, a 429", () => {
		expect(errors.E_TOO_MANY_REQUESTS).toBe(errors.ThrottleException);
		const error = new errors.E_TOO_MANY_REQUESTS(
			new LimiterResponse({
				limit: 1,
				remaining: 0,
				consumed: 2,
				availableIn: 30,
			}),
		);
		expect(error).toBeInstanceOf(Exception);
		expect(error).toMatchObject({
			code: "E_TOO_MANY_REQUESTS",
			status: 429,
			message: "Too many requests",
		});
	});

	it("E_BAD_CSRF_TOKEN has upstream's shape: 403, its message, its identifier", () => {
		const error = new errors.E_BAD_CSRF_TOKEN();
		expect(error).toBeInstanceOf(Exception);
		expect(error).toBeInstanceOf(errors.InvalidCSRFToken);
		expect(error).toMatchObject({
			code: "E_BAD_CSRF_TOKEN",
			status: 403,
			message: "Invalid or expired CSRF token",
			identifier: "errors.E_BAD_CSRF_TOKEN",
		});
	});

	it("E_BAD_CSRF_TOKEN translates its message through ctx.i18n", () => {
		const error = new errors.E_BAD_CSRF_TOKEN();
		const t = vi.fn(() => "Jeton CSRF invalide");
		expect(error.getResponseMessage(error, { i18n: { t } })).toBe(
			"Jeton CSRF invalide",
		);
		expect(t).toHaveBeenCalledWith(
			"errors.E_BAD_CSRF_TOKEN",
			{},
			"Invalid or expired CSRF token",
		);
		expect(error.getResponseMessage(error, {})).toBe(
			"Invalid or expired CSRF token",
		);
	});

	it("E_BAD_CSRF_TOKEN renders itself: a 403 JSON body when there is no session", async () => {
		const error = new errors.E_BAD_CSRF_TOKEN();
		const status = vi.fn();
		const json = vi.fn();
		await error.handle(error, {
			request: {
				header: (name) => (name === "accept" ? "text/html" : undefined),
			},
			response: { status, json },
		});
		expect(status).toHaveBeenCalledWith(403);
		expect(json).toHaveBeenCalledWith({
			error: {
				code: "E_BAD_CSRF_TOKEN",
				message: "Invalid or expired CSRF token",
			},
		});
	});

	it("E_BAD_CSRF_TOKEN does not re-flash an Inertia visit's form", async () => {
		const error = new errors.E_BAD_CSRF_TOKEN();
		const back = vi.fn();
		const session = {
			flashExcept: vi.fn(),
			flash: vi.fn(),
			flashErrors: vi.fn(),
		};
		const json = vi.fn();
		const ctx = {
			request: {
				header: (name: string) => (name === "x-inertia" ? "true" : undefined),
			},
			response: { status: vi.fn(), json, redirect: () => ({ back }) },
			session,
		};
		await error.handle(error, ctx);
		expect(session.flashExcept).not.toHaveBeenCalled();
		expect(session.flash).toHaveBeenCalledWith(
			"error",
			"Invalid or expired CSRF token",
		);
		expect(back).toHaveBeenCalled();
		expect(json).not.toHaveBeenCalled();
	});

	it("E_TOO_MANY_REQUESTS shapes its body with the host's content negotiation", async () => {
		const error = new errors.E_TOO_MANY_REQUESTS(
			new LimiterResponse({
				limit: 1,
				remaining: 0,
				consumed: 2,
				availableIn: 30,
			}),
		);
		const send = vi.fn();
		const offered: string[][] = [];
		const accepts = <T extends string>(types: T[]): T | null => {
			offered.push(types);
			return types.find((type) => type === "application/vnd.api+json") ?? null;
		};
		await error.handle(error, {
			// The raw header says JSON; the negotiation decides.
			request: { header: () => "application/json", accepts },
			response: { header: vi.fn(), status: vi.fn(), send },
		});
		expect(offered).toEqual([["html", "application/vnd.api+json", "json"]]);
		expect(send).toHaveBeenCalledWith({
			errors: [
				{
					code: "E_TOO_MANY_REQUESTS",
					title: "Too many requests",
					meta: { retryAfter: 30 },
				},
			],
		});
	});

	it("E_TOO_MANY_REQUESTS answers text when the negotiation matches nothing", async () => {
		const error = new errors.E_TOO_MANY_REQUESTS(
			new LimiterResponse({
				limit: 1,
				remaining: 0,
				consumed: 2,
				availableIn: 30,
			}),
		);
		const send = vi.fn();
		await error.handle(error, {
			request: { header: () => "image/png", accepts: () => null },
			response: { header: vi.fn(), status: vi.fn(), send },
		});
		expect(send).toHaveBeenCalledWith("Too many requests");
	});
});
