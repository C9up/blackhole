/**
 * @c9up/blackhole — Rust-native security filter for any Node.js framework.
 *
 * Provides XSS response sanitization, CSRF token management, and sliding-window
 * rate limiting. All security checks run in Rust via NAPI — rejected requests
 * never reach JavaScript. Works standalone (Express, Fastify, Hono) or as a
 * Ream provider.
 *
 * @example
 *   import { createBlackhole } from '@c9up/blackhole'
 *   import { blackholeExpress } from '@c9up/blackhole/middleware'
 *
 *   // Express adapter — handles request filtering AND response sanitization
 *   app.use(blackholeExpress({ csrf: true, rateLimit: { max: 100, windowSeconds: 60 } }))
 *
 *   // Or low-level usage — note: result.body may not always be valid JSON,
 *   // so wrap JSON.parse in try/catch (or use the express/fastify adapters which do this for you).
 */

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { arch, platform } from "node:process";
import { fileURLToPath } from "node:url";

const nodeRequire = createRequire(import.meta.url);
const currentDir = dirname(fileURLToPath(import.meta.url));

const platformMap: Record<string, string> = {
	"linux-x64": "linux-x64-gnu",
	"linux-arm64": "linux-arm64-gnu",
	"darwin-x64": "darwin-x64",
	"darwin-arm64": "darwin-arm64",
	"win32-x64": "win32-x64-msvc",
};

interface NativeBlackhole {
	generateCsrfToken(): string;
	check(
		method: string,
		path: string,
		query: string,
		headersJson: string,
		body: string,
		remoteAddr: string,
	): { allowed: boolean; status?: number; body?: string };
	sanitizeResponse(body: string, contentType: string): string;
}

interface NativeModule {
	Blackhole: new (
		xssEnabled?: boolean,
		csrfEnabled?: boolean,
		rateLimitMax?: number,
		rateLimitWindow?: number,
	) => NativeBlackhole;
}

let native: NativeModule | undefined;

try {
	const suffix = platformMap[`${platform}-${arch}`];
	if (suffix) {
		native = nodeRequire(join(currentDir, `../index.${suffix}.node`));
	}
} catch {
	// Binary not available — createBlackhole will throw.
}

export interface BlackholeOptions {
	/** Enable XSS response sanitization (default: true). */
	xss?: boolean;
	/** Enable CSRF token validation (default: true). */
	csrf?: boolean;
	/** Rate limiting configuration. */
	rateLimit?: { max: number; windowSeconds: number };
}

export interface CheckResult {
	allowed: boolean;
	status?: number;
	body?: string;
}

export interface Blackhole {
	/** Run all security checks against an incoming request. */
	check(req: {
		method: string;
		path: string;
		query?: string;
		headers: Readonly<Record<string, string>>;
		body?: string;
		remoteAddr?: string;
	}): CheckResult;
	/** Generate a new CSRF token. */
	generateCsrfToken(): string;
	/** Sanitize an outgoing response body based on content type. */
	sanitizeResponse(body: string, contentType: string): string;
}

/**
 * Create a Blackhole security filter instance.
 *
 * @throws If the NAPI binary is not available.
 */
export function createBlackhole(options: BlackholeOptions = {}): Blackhole {
	if (!native) {
		throw new Error(
			"[BLACKHOLE_NAPI_REQUIRED] The Blackhole Rust engine is required but not loaded.\n" +
				"  Fix: cd packages/blackhole && pnpm build:napi",
		);
	}

	const filter = new native.Blackhole(
		options.xss ?? true,
		options.csrf ?? true,
		options.rateLimit?.max,
		options.rateLimit?.windowSeconds,
	);

	return {
		check(req) {
			const headersJson = JSON.stringify(req.headers);
			return filter.check(
				req.method,
				req.path,
				req.query ?? "",
				headersJson,
				req.body ?? "",
				req.remoteAddr ?? "",
			);
		},
		generateCsrfToken() {
			return filter.generateCsrfToken();
		},
		sanitizeResponse(body: string, contentType: string) {
			return filter.sanitizeResponse(body, contentType);
		},
	};
}
