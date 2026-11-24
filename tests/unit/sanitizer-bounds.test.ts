/**
 * The sanitizer's parse is not linear in its input: misnested formatting
 * elements are re-created in every new block, deep nesting rescans the open
 * elements. Its input is bounded — length, nesting depth, and how much markup
 * it may build — and an input past a bound is refused, never passed through.
 *
 * SMALL inputs only: a few KB prove the bound. Unbounded, the shapes below
 * took hundreds of MB at 30 KB.
 */
import {
	Container,
	createHttpKernel,
	type HttpContext,
	MiddlewareRegistry,
	Router,
} from "@c9up/ream";
import { describe, expect, it } from "vitest";
import { BLACKHOLE_KEY } from "../../src/BlackholeProvider.js";
import { createBlackhole, errors } from "../../src/index.js";
import { blackholeMiddleware } from "../../src/middleware.js";

const bh = createBlackhole({ csrf: false });

/** `<font size=i><p>`: paragraph k holds k re-created `<font>`s. */
const distinct = (n: number) =>
	Array.from({ length: n }, (_, i) => `<font size=${i}><p>`).join("");
/** The same with an element the sanitizer keeps: the output grew with it. */
const allowListed = (n: number) =>
	Array.from({ length: n }, (_, i) => `<b title=${i}><p>`).join("");
/** Open `<b>`s re-created by every `<p>x`, at a depth the default accepts. */
const reopened = (open: number, paragraphs: number) =>
	`<p>${Array.from({ length: open }, (_, i) => `<b title=${i}>`).join("")}${"<p>x".repeat(paragraphs)}`;

function refusal(run: () => unknown): unknown {
	try {
		run();
	} catch (error) {
		return error;
	}
	throw new Error("expected a refusal");
}

describe("blackhole > sanitizer > bounds", () => {
	it("the default depth bound is 512 nested elements", () => {
		const atBound = "<div>".repeat(512);
		expect(bh.sanitizeResponse(atBound, "text/html")).toContain(atBound);
		const error = refusal(() =>
			bh.sanitizeResponse("<div>".repeat(513), "text/html"),
		);
		expect(error).toBeInstanceOf(errors.E_BLACKHOLE_HTML_TOO_DEEP);
		expect(error).toMatchObject({ code: "E_BLACKHOLE_HTML_TOO_DEEP" });
	});

	it("refuses markup that builds far more than it holds, below the depth bound", () => {
		for (const input of [
			distinct(300),
			distinct(800),
			allowListed(300),
			reopened(400, 400),
		]) {
			expect(
				refusal(() => bh.sanitizeResponse(input, "text/html")),
			).toBeInstanceOf(errors.E_BLACKHOLE_HTML_TOO_COMPLEX);
		}
	});

	it("the output of an accepted input stays within four times its size, plus 64 KiB", () => {
		// The largest re-creation the allowance takes: kept, and bounded.
		const input = reopened(10, 200);
		const output = bh.sanitizeResponse(input, "text/html");
		expect(output).toContain('<b title="9">x</b>');
		expect(output.length).toBeLessThan(input.length * 4 + 64 * 1024);
	});

	it("a refusal costs about what the bound allows, not the square of the input", () => {
		const time = (input: string) => {
			const started = performance.now();
			for (let i = 0; i < 5; i++) {
				refusal(() => bh.sanitizeResponse(input, "text/html"));
			}
			return performance.now() - started;
		};
		const small = distinct(1_000);
		const large = distinct(4_000);
		time(small);
		const smallTime = time(small);
		const largeTime = time(large);
		// Four times the input: linear is x4, the unbounded parse was x16.
		expect(largeTime).toBeLessThan(Math.max(smallTime, 1) * 10);
	});

	it("ordinary markup is untouched by the bounds", () => {
		const input = `<ul>${"<li><b>item</b> <i>note</i>".repeat(2_000)}</ul>`;
		const output = bh.sanitizeResponse(input, "text/html");
		expect(output.startsWith("<ul><li><b>item</b> <i>note</i></li>")).toBe(
			true,
		);
		expect(
			bh.sanitizeResponse("&nbsp;".repeat(5_000), "text/html"),
		).toHaveLength(5_000 * "&nbsp;".length);
	});

	it("`xss.maxInputBytes` bounds a text/html body before it is parsed", () => {
		const tight = createBlackhole({ csrf: false, xss: { maxInputBytes: 10 } });
		expect(tight.sanitizeResponse("<b>12</b>a", "text/html")).toBe(
			"<b>12</b>a",
		);
		const error = refusal(() =>
			tight.sanitizeResponse("<b>12</b>ab", "text/html"),
		);
		expect(error).toBeInstanceOf(errors.E_BLACKHOLE_HTML_TOO_LARGE);
		expect(String(error)).toContain("11 bytes, over xss.maxInputBytes (10)");
		// The length is counted in UTF-8 bytes, not UTF-16 units.
		expect(
			refusal(() => tight.sanitizeResponse("ééééé!", "text/html")),
		).toBeInstanceOf(errors.E_BLACKHOLE_HTML_TOO_LARGE);
		// Only `text/html` is parsed, so only `text/html` is bounded.
		expect(tight.sanitizeResponse("x".repeat(50), "text/plain")).toBe(
			"x".repeat(50),
		);
	});

	it("the default input bound is 1 MiB", () => {
		const atBound = "a".repeat(1024 * 1024);
		expect(bh.sanitizeResponse(atBound, "text/html")).toHaveLength(
			atBound.length,
		);
		expect(
			refusal(() => bh.sanitizeResponse(`${atBound}a`, "text/html")),
		).toBeInstanceOf(errors.E_BLACKHOLE_HTML_TOO_LARGE);
	});

	it("`xss.maxDepth` bounds the nesting, counted on the tree the parser builds", () => {
		const shallow = createBlackhole({ csrf: false, xss: { maxDepth: 5 } });
		expect(shallow.sanitizeResponse("<div>".repeat(5), "text/html")).toBe(
			`${"<div>".repeat(5)}${"</div>".repeat(5)}`,
		);
		for (const input of [
			"<div>".repeat(6),
			// One tag, several levels: the parser implies the ancestors.
			"<table><tr><td>".repeat(2),
			// A comment a reading of the markup would take as unterminated.
			"<!--><div>".repeat(6),
			// Blocks left open by a formatting element closed over them.
			"<b><div><div><div></b>".repeat(2),
		]) {
			expect(
				refusal(() => shallow.sanitizeResponse(input, "text/html")),
			).toBeInstanceOf(errors.E_BLACKHOLE_HTML_TOO_DEEP);
		}
	});

	it.each([0, -1, 1.5, Number.NaN, 2 ** 32])(
		"refuses %s as a bound when the filter is built",
		(value) => {
			for (const xss of [{ maxInputBytes: value }, { maxDepth: value }]) {
				expect(() => createBlackhole({ csrf: false, xss })).toThrow(
					errors.E_BLACKHOLE_INVALID_XSS_LIMIT,
				);
			}
		},
	);

	it("with `xss` on, a response past a bound is refused, never sent as it came", async () => {
		const router = new Router();
		router.get("/", (ctx) => {
			ctx.response.header("content-type", "text/html; charset=utf-8");
			ctx.response.send(`<script>alert(1)</script>${distinct(800)}`);
		});
		const container = new Container();
		container.singleton(BLACKHOLE_KEY, () =>
			createBlackhole({ csrf: false, xss: true }),
		);
		const handle = createHttpKernel({
			router,
			middleware: new MiddlewareRegistry(),
			container,
			routerMiddleware: [
				(ctx: HttpContext, next: () => Promise<void>) =>
					blackholeMiddleware(ctx, next),
			],
		});
		const res = await handle({
			method: "GET",
			path: "/",
			query: "",
			headers: { host: "app.example", accept: "text/html" },
			body: "",
		});
		expect(res.status).toBe(500);
		expect(res.body).not.toContain("<script>");
		expect(res.body).not.toContain("<font");
	});
});
