/**
 * The relay handshake, through the CSRF guard.
 *
 * `@c9up/relay` auto-mounts `POST /__relay/subscribe` and `/__relay/unsubscribe`,
 * and aurora's client posts to them from the browser. Two packages, two
 * repositories, one request — and nothing exercised the join: a change to the
 * header this package expects, or to the one that client sends, would be found
 * by whoever next opened a realtime page.
 *
 * They are NOT exempted from the guard, and must not be: a subscribe is a
 * state-changing POST that names a channel, which is exactly what the
 * double-submit check exists to protect. The client carries the token instead.
 */
import { describe, expect, it } from "vitest";
import { createBlackhole } from "../../src/index.js";

const SECRET = "test-app-key-32-bytes-long-aaaaaa";
const bh = createBlackhole({ secret: SECRET });

/** What aurora's relay client sends: the cookie, echoed as the header. */
function handshake(
	path: string,
	headers: Record<string, string>,
): ReturnType<typeof bh.check> {
	return bh.check({
		method: "POST",
		path,
		headers: {
			"content-type": "application/json",
			host: "app.test",
			origin: "https://app.test",
			...headers,
		},
		body: JSON.stringify({ uid: "uid-1", channel: "users/1/notifications" }),
	});
}

const withToken = (token: string) => ({
	cookie: `XSRF-TOKEN=${encodeURIComponent(token)}`,
	"x-xsrf-token": token,
});

describe("blackhole > the relay handshake", () => {
	it("accepts a subscribe carrying the token the client read from the cookie", () => {
		const token = bh.generateCsrfToken();
		expect(handshake("/__relay/subscribe", withToken(token))).toMatchObject({
			allowed: true,
			csrfEnforced: true,
		});
	});

	it("accepts an unsubscribe the same way", () => {
		const token = bh.generateCsrfToken();
		expect(handshake("/__relay/unsubscribe", withToken(token))).toMatchObject({
			allowed: true,
		});
	});

	it("refuses a subscribe with no token at all", () => {
		// The route is not exempt, and must not be: a subscribe names a channel.
		expect(handshake("/__relay/subscribe", {})).toMatchObject({
			allowed: false,
			status: 403,
		});
	});

	it("refuses a header that does not match the cookie", () => {
		// The whole point of double-submit: an attacker can make the browser send
		// the cookie, but cannot read it to echo it back.
		const token = bh.generateCsrfToken();
		expect(
			handshake("/__relay/subscribe", {
				cookie: `XSRF-TOKEN=${encodeURIComponent(token)}`,
				"x-xsrf-token": bh.generateCsrfToken(),
			}),
		).toMatchObject({ allowed: false });
	});

	it("refuses a token nobody signed", () => {
		expect(
			handshake("/__relay/subscribe", {
				cookie: "XSRF-TOKEN=forged",
				"x-xsrf-token": "forged",
			}),
		).toMatchObject({ allowed: false });
	});

	it("leaves the SSE stream alone — it is a GET", () => {
		expect(
			bh.check({
				method: "GET",
				path: "/__relay/events",
				headers: { host: "app.test" },
			}),
		).toMatchObject({ allowed: true });
	});
});
