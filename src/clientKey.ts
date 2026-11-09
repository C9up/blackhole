/**
 * The key a client IP is counted under by the rate limits.
 */

import { isIPv4, isIPv6 } from "node:net";

/**
 * The key a client IP counts under: an IPv4 address as is, an IPv6 address by
 * its /64 network.
 *
 * A /64 is what a single subscriber — one host, often — is handed, and it
 * holds 2^64 addresses: keyed one by one, a client rotating through them gets
 * a fresh budget on every request and the limit means nothing. An IPv4 address
 * written as IPv6 (`::ffff:192.0.2.1`) counts as that IPv4 address.
 */
export function clientKey(ip: string): string {
	const zoneless = ip.split("%")[0] ?? ip;
	if (!isIPv6(zoneless)) return ip;
	const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(zoneless)?.[1];
	if (mapped !== undefined && isIPv4(mapped)) return mapped;
	const groups = expandIpv6(zoneless);
	return `${groups.slice(0, 4).join(":")}::/64`;
}

/** The eight 16-bit groups of a valid IPv6 address, lower-case, unpadded. */
function expandIpv6(address: string): string[] {
	// A trailing dotted quad is the last two groups written in IPv4 form.
	let text = address.toLowerCase();
	const quad = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
	if (quad) {
		const [a, b, c, d] = quad.slice(1).map(Number);
		const high = (((a ?? 0) << 8) | (b ?? 0)).toString(16);
		const low = (((c ?? 0) << 8) | (d ?? 0)).toString(16);
		text = `${text.slice(0, quad.index)}${high}:${low}`;
	}
	const [head = "", tail] = text.split("::");
	const left = head.length > 0 ? head.split(":") : [];
	const right = tail === undefined || tail.length === 0 ? [] : tail.split(":");
	const fill =
		tail === undefined
			? []
			: Array.from({ length: 8 - left.length - right.length }, () => "0");
	return [...left, ...fill, ...right].map((group) =>
		Number.parseInt(group, 16).toString(16),
	);
}
