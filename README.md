# @c9up/blackhole

> Rust-native security filter (XSS, CSRF, rate-limiting, CORS, security headers) for any Node.js framework.

Part of **[Ream](https://github.com/C9up/ream)** — a Rust-powered, AdonisJS-compatible Node.js framework. Independent, publishable package.

## Installation

```bash
pnpm add @c9up/blackhole
ream configure @c9up/blackhole
```

## Usage

**Ream** — register the middleware:

```ts
// start/kernel.ts
router.use([() => import('@c9up/blackhole/middleware')])
```

**Express / Fastify** — standalone adapters:

```ts
import { blackholeExpress } from '@c9up/blackhole/express'

// `secret` is REQUIRED when CSRF is on (signed double-submit, fail-closed).
// The Ream provider defaults it from APP_KEY; the standalone adapters do not,
// so pass your app key explicitly here.
app.use(blackholeExpress({
  secret: process.env.APP_KEY,
  csrf: true,
  rateLimit: { max: 100, windowSeconds: 60 },
}))
```

## Entry points

- `@c9up/blackhole` — main API
- `@c9up/blackhole/middleware` — Ream middleware
- `@c9up/blackhole/provider` — Ream IoC provider
- `@c9up/blackhole/config` — `defineConfig()` helper
- `@c9up/blackhole/express` — Express adapter
- `@c9up/blackhole/fastify` — Fastify adapter

## License

MIT
