import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Alias the optional `@c9up/ream` peer to a local stub so the middleware
		// suite runs standalone (agnostic). Runtime resolves the real peer only
		// when blackhole actually runs inside Ream.
		alias: {
			"@c9up/ream/services/app": fileURLToPath(
				new URL("./tests/stubs/ream-app.ts", import.meta.url),
			),
		},
		coverage: {
			provider: "v8",
			include: ["src/**"],
			exclude: ["src/**/*.d.ts"],
			reporter: ["text-summary", "json-summary"],
			thresholds: {
				lines: 89,
				statements: 87,
				branches: 81,
				functions: 90,
			},
		},
	},
});
