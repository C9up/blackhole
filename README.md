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

## Rate limiting

Without a store, counting happens in the Rust core — one process, so N
instances each allow the limit. Name a store and the count is shared:

```ts
// config/blackhole.ts
import { defineConfig, stores } from '@c9up/blackhole'
import env from '#start/env'

export default defineConfig({
  rateLimit: {
    max: 100,
    windowSeconds: 60,
    default: env.get('RATE_LIMIT_STORE'),
    stores: {
      memory: stores.memory(),
      redis:  stores.redis({ connection: 'main' }),
    },
  },
})
```

| Store | Counts in | Reach |
| --- | --- | --- |
| *(none)* | the Rust core | one process |
| `stores.memory()` | this process's memory | one process |
| `stores.redis({ connection })` | Redis | every process |

`stores.redis` takes a `@c9up/quasar` connection name, resolved at first use so
blackhole never imports quasar, which stays an optional peer. Pass a client (or
a function answering one) to use any other ioredis-shaped client.

The Redis counter sets the window's expiry once, on the first hit — refreshing
it on every request would push the window forward for ever, and a client
hitting steadily would never be limited.

Only the selected store is built, and a `default` naming nothing throws: an
application that meant to share its counter and silently got the in-process one
would allow N times its limit without a sign.

## Entry points

- `@c9up/blackhole` — main API
- `@c9up/blackhole/middleware` — Ream middleware
- `@c9up/blackhole/provider` — Ream IoC provider
- `@c9up/blackhole/config` — `defineConfig()` helper
- `stores` — rate-limit store factories, exported from the main entry
- `@c9up/blackhole/express` — Express adapter
- `@c9up/blackhole/fastify` — Fastify adapter

## License

MIT
