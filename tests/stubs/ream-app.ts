/**
 * Local stand-in for `@c9up/ream/services/app`, aliased in vitest.config so
 * blackhole's middleware test runs standalone — without the optional
 * `@c9up/ream` peer. Exposes the slice the Ream middleware touches: a default
 * `app` with a live IoC container (`singleton` / `resolve`) plus `_setApp`.
 */
class StubContainer {
	readonly #factories = new Map<unknown, () => unknown>();
	singleton(token: unknown, factory: () => unknown): void {
		this.#factories.set(token, factory);
	}
	resolve(token: unknown): unknown {
		const factory = this.#factories.get(token);
		if (!factory) throw new Error(`not registered: ${String(token)}`);
		return factory();
	}
}

const app = { container: new StubContainer() };

/** No-op: the stub container is already live (real Ream seeds it via Ignitor). */
export function setApp(): void {}

export default app;
