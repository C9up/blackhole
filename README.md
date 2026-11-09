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

## CSRF

On by default (`csrf: true` in the generated config). A `POST`, `PUT`,
`PATCH` or `DELETE` needs both:

- an `Origin` (or, without one, a `Referer`) from the host the request was
  addressed to — or from `trustedOrigins`. The host and the scheme come from the
  framework's trust-proxy resolution (`request.host()` / `request.protocol()` on
  Ream, `req.hostname` / `req.protocol` on Express, `request.host` on Fastify,
  the `host` / `protocol` options on Hono). An empty `Origin` counts as absent.
- a token: the `XSRF-TOKEN` cookie echoed in `X-XSRF-TOKEN` / `X-CSRF-TOKEN`,
  or the `_csrf` form field. Tokens are HMAC-signed with `secret` (your
  `APP_KEY`). On Ream with a session, they are also bound to a per-session
  secret (`csrf-secret` in the session): a token issued to one session is
  refused for any other, and dies with its session. Without a session (the
  standalone adapters), the token is signed but bound to nothing.

Both checks belong to the `csrf` switch: `csrf: false` turns both off.

`exceptRoutes` skips the check:

```ts
csrf: {
  // The matched route's pattern (Ream, Fastify), or the path —
  // exact, or by prefix with a trailing `*` (every adapter).
  exceptRoutes: ['/webhooks/:provider', '/api/hooks/*'],
  // …or a predicate over the request context (the HTTP context on Ream).
  // exceptRoutes: (ctx) => ctx.request.url().startsWith('/webhooks/'),
}
```

A rejected token answers `E_BAD_CSRF_TOKEN` (403). On Ream, a browser form or
an Inertia visit (`X-Inertia`) is redirected back with the message flashed
(the form fields too, except for Inertia); a JSON client gets the JSON body.
With an `i18n` on the context, the message is translated under
`errors.E_BAD_CSRF_TOKEN`.

## Security headers

Each protective header has its own top-level key, `{ enabled, ... }`, and is
**on with a hardened default when the key is omitted** — turn one off with
`{ enabled: false }`:

| Key | Header | Default |
| --- | --- | --- |
| `xFrame` (`action`, `domain`) | `X-Frame-Options` | `SAMEORIGIN` |
| `hsts` (`maxAge`, `includeSubDomains`, `preload`) | `Strict-Transport-Security` | 180 days, subdomains |
| `contentTypeSniffing` | `X-Content-Type-Options: nosniff` | on |
| `csp` (`directives`, `useDefaults`, `policy`, `reportOnly`) | `Content-Security-Policy` | see below |
| `referrerPolicy` (`policy`) | `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `permissionsPolicy` (`policy`) | `Permissions-Policy` | camera, microphone, geolocation denied |

They are set before the route runs and added afterwards only where missing, so
a route that sets its own `X-Frame-Options` or CSP keeps it. An unknown key
inside one of these objects throws, and so does the former `securityHeaders`
option.

```ts
export default defineConfig({
  xFrame: { enabled: true, action: 'DENY' },
  hsts: { enabled: true, maxAge: '180 days', includeSubDomains: true }, // seconds, or a duration
  csp: {
    enabled: true,
    directives: {
      scriptSrc: ["'self'", '@nonce'],  // camelCase or 'script-src'
      imgSrc: ["'self'", 'data:'],
    },
    reportOnly: false,
  },
  referrerPolicy: { enabled: true, policy: 'no-referrer' },
})
```

Without `directives` or `policy`, the CSP is
`default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'; script-src 'self' @nonce`.
`directives` merge a hardened baseline under yours (`useDefaults: false` to
start from nothing); `policy` takes the whole header as a string instead. Both
are validated when the filter is created: an unquoted keyword (`self`, `none`,
`nonce-…`, `sha256-…`…), a directive given twice, or — for `directives` — a `;`
or `,` inside a source, or a policy without `default-src` throws. A directive
set to `null` is dropped; `default-src` only through
`dangerouslyDisableDefaultSrc`. `@nonce` is replaced per request with
`'nonce-…'`, available as `response.nonce`.

## CORS

```ts
cors: {
  origin: ['https://app.example'],   // true reflects any origin, '*' is the wildcard,
                                      // or (origin, ctx) => boolean | string | string[]
  methods: ['GET', 'POST'],
  headers: true,                      // false, a list, a string, or (headers, ctx) => …
  exposeHeaders: ['X-Total'],
  credentials: true,
  maxAge: 90,
  enabled: true,                      // or (ctx) => boolean
}
```

`origin: true` or `'*'` together with `credentials: true` is refused at boot,
and so is an unknown option — a misspelt key would otherwise drop its setting
without a word.

## XSS

`text/html` fragments are sanitized on the way out (full documents are left
alone). Untrusted markup loses `id`, `is`, `slot`, `part` and `data-*` — DOM
clobbering, customized elements, framework bindings, shadow DOM. Opt back in
only when nothing reads them from untrusted markup:

```ts
xss: { allowAttributes: ['id', 'data-*'] }
```

## Rate limiting

The in-process counter is a sliding window in constant memory per key (two
counters, whatever the limit). The default key is the client IP — an IPv6
client by its /64, since one host holds the whole /64. `keyFor(ctx)` picks
another key.

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

## Per-route limits

A limit defined once by name, attached to the routes it belongs to:

```ts
// start/limiter.ts
import limiter from '@c9up/blackhole/services/limiter'

export const throttle = limiter.define('api', (ctx) =>
  limiter.allowRequests(60).every('1 minute').usingKey(ctx.auth?.user?.id),
)

export const loginThrottle = limiter.define('login', () =>
  limiter.allowRequests(5).every('1 minute').blockFor('20 mins'),
)

// start/routes.ts
router.post('/login', [AuthController, 'login']).use(loginThrottle)
```

The key is `<name>_<usingKey>`, or `<name>_ip_<client IP>` (IPv6 by /64). Over
the limit, the middleware throws `ThrottleException` (`E_TOO_MANY_REQUESTS`,
429), rendered with `X-RateLimit-*` and `Retry-After` as text, JSON or JSON:API
depending on `Accept`; `limitExceeded((error) => …)` adjusts it first. A
builder returning `limiter.noLimit()` lets the request through uncounted.

By hand:

```ts
const login = limiter.use({ requests: 5, duration: '1 minute', blockDuration: '20 mins' })

// Count failures only: a wrong password costs an attempt, a right one clears them.
const [error, user] = await login.penalize(`login_${email}`, () => verify(email, password))

await login.attempt(key, () => sendResetMail())   // runs only while there is budget
await login.consume(key)                           // throws once over
```

`Limiter` also has `increment`, `decrement`, `get`, `set`, `block`, `delete`,
`remaining`, `availableIn`, `isBlocked` and `clear`. Counting is a fixed window
per key, opened by its first request.

The stores live under `limiter` in `config/blackhole.ts` (default: one memory
store):

```ts
import { defineConfig, limiterStores } from '@c9up/blackhole'

export default defineConfig({
  limiter: {
    default: env.get('LIMITER_STORE', 'memory'),
    stores: {
      memory: limiterStores.memory(),
      redis: limiterStores.redis({ connection: 'main' }),
    },
  },
})
```

The Redis store's `clear()` deletes its own keys (by prefix), not the database.

## Entry points

- `@c9up/blackhole` — main API
- `@c9up/blackhole/middleware` — Ream middleware
- `@c9up/blackhole/provider` — Ream IoC provider
- `@c9up/blackhole/config` — `defineConfig()` helper
- `stores` — rate-limit store factories, exported from the main entry
- `@c9up/blackhole/express` — Express adapter
- `@c9up/blackhole/fastify` — Fastify adapter
- `@c9up/blackhole/hono` — Hono adapter
- `@c9up/blackhole/limiter` — `Limiter`, `LimiterManager`, `ThrottleException`, stores
- `@c9up/blackhole/services/limiter` — the application's limiter (`define`, `allowRequests`, `use`)

## License

MIT
