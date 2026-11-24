/**
 * The engine's refusals reach JavaScript coded: each starts its message with
 * its code, and the boundary rethrows the matching `errors` class.
 */
import { describe, expect, it } from "vitest";
import {
	createBlackhole,
	type EngineCheck,
	errors,
	type XssOptInAttribute,
} from "../../src/index.js";
import {
	hasFunctions,
	loadNativeBinary,
} from "../../src/vendor/nativeBinary.js";

function engine() {
	const attempt = loadNativeBinary(
		(
			value,
		): value is Pick<
			typeof import("../../src/native/generated.js"),
			"Blackhole"
		> => hasFunctions(value, ["Blackhole"]),
	);
	if (!attempt.loaded) throw new Error("the engine binary is not built");
	return attempt.binary;
}

function caught(run: () => unknown): unknown {
	try {
		run();
	} catch (error) {
		return error;
	}
	throw new Error("expected a throw");
}

const REQUEST = {
	method: "GET",
	path: "/",
	headers: {},
	remoteAddr: "127.0.0.1",
};

describe("blackhole > engine errors", () => {
	it("an attribute outside the opt-in list is E_BLACKHOLE_INVALID_XSS_ATTRIBUTE", () => {
		// A config written in JavaScript is not held to the type.
		const allowAttributes: XssOptInAttribute[] = [];
		Reflect.set(allowAttributes, 0, "onclick");
		const error = caught(() =>
			createBlackhole({ csrf: false, xss: { allowAttributes } }),
		);
		expect(error).toBeInstanceOf(errors.E_BLACKHOLE_INVALID_XSS_ATTRIBUTE);
		expect(error).toMatchObject({
			code: "E_BLACKHOLE_INVALID_XSS_ATTRIBUTE",
			message: expect.stringMatching(
				/^\[blackhole\] xss\.allowAttributes: 'onclick' cannot be allowed/,
			),
		});
		expect(Reflect.get(Object(error), "cause")).toBeInstanceOf(Error);
	});

	it("an unknown check is E_BLACKHOLE_UNKNOWN_CHECK", () => {
		const checks: EngineCheck[] = [];
		Reflect.set(checks, 0, "firewall");
		const bh = createBlackhole({ csrf: false });
		const error = caught(() => bh.check({ ...REQUEST, checks }));
		expect(error).toBeInstanceOf(errors.E_BLACKHOLE_UNKNOWN_CHECK);
		expect(error).toMatchObject({
			code: "E_BLACKHOLE_UNKNOWN_CHECK",
			message:
				"[blackhole] unknown check 'firewall' (expected rateLimit, shield or csrf)",
		});
	});

	it("headers that are not strings are E_BLACKHOLE_INVALID_HEADERS", () => {
		const headers: Record<string, string> = {};
		Reflect.set(headers, "accept", ["text/html", "application/json"]);
		const bh = createBlackhole({ csrf: false });
		const error = caught(() => bh.check({ ...REQUEST, headers }));
		expect(error).toBeInstanceOf(errors.E_BLACKHOLE_INVALID_HEADERS);
		expect(error).toMatchObject({
			code: "E_BLACKHOLE_INVALID_HEADERS",
			message: expect.stringMatching(/^\[blackhole\] invalid headers JSON: /),
		});
	});

	it("a zero rate limit is refused by the engine itself, coded", () => {
		// The TypeScript side refuses it first; a direct engine call still may not.
		const { Blackhole } = engine();
		expect(
			() => new Blackhole(false, 0, 60, true, true, [], [], undefined, [], []),
		).toThrow(
			/^E_BLACKHOLE_INVALID_RATE_LIMIT: rate limit max and window must be greater than 0$/,
		);
	});

	it("a request the engine accepts is returned unchanged", () => {
		const bh = createBlackhole({ csrf: false });
		expect(bh.check(REQUEST)).toMatchObject({ allowed: true });
	});
});
