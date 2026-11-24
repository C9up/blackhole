#!/usr/bin/env node
/**
 * The per-platform npm packages that carry blackhole's native engine.
 *
 * A consumer installs `@c9up/blackhole` and, through its optionalDependencies, the
 * one `@c9up/blackhole-<suffix>` whose `os`/`cpu`/`libc` match the host: one
 * binary instead of all five. Those packages are published by this
 * repository's own publish job, from `npm/<suffix>/`, right before the main
 * package.
 *
 * Their manifests and the main package's optionalDependencies are written by
 * this script, never by hand: every version is the main package's, exactly,
 * because a platform package from another version is a binary from other
 * Rust. Run it after a version bump; `--check` fails when anything is stale.
 *
 *   node scripts/platform-packages.mjs          rewrite the manifests
 *   node scripts/platform-packages.mjs --check  fail if any is stale
 *   node scripts/platform-packages.mjs --list   print the suffixes, one a line
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * Every target the CI matrix builds, by napi-rs suffix. Same list as the
 * matrix in .github/workflows and the table in scripts/copy-napi.mjs.
 */
const TARGETS = [
  { suffix: 'linux-x64-gnu', os: 'linux', cpu: 'x64', libc: 'glibc' },
  { suffix: 'linux-arm64-gnu', os: 'linux', cpu: 'arm64', libc: 'glibc' },
  { suffix: 'darwin-x64', os: 'darwin', cpu: 'x64' },
  { suffix: 'darwin-arm64', os: 'darwin', cpu: 'arm64' },
  { suffix: 'win32-x64-msvc', os: 'win32', cpu: 'x64' },
]

/** The binaries one platform package carries: `<stem>.<suffix>.node`. */
const STEMS = ['index']

/**
 * The licence files one platform package carries beside its binaries. npm
 * never looks above a package root, and the publish job copies each of these
 * in from the repository root.
 */
const LICENSES = ['LICENSE', 'THIRD-PARTY-NOTICES.md']

const manifestPath = join(root, 'package.json')
const main = JSON.parse(readFileSync(manifestPath, 'utf8'))

/** JSON as the repository writes it: two spaces, a final newline. */
const render = (value) => `${JSON.stringify(value, null, 2)}\n`

function platformManifest(target) {
  for (const field of ['name', 'version', 'license', 'engines']) {
    if (main[field] === undefined) throw new Error(`[platform-packages] package.json has no "${field}"`)
  }
  if (typeof main.repository?.url !== 'string') {
    // npm provenance matches the signature against repository.url.
    throw new Error('[platform-packages] package.json has no repository.url')
  }
  const binaries = STEMS.map((stem) => `${stem}.${target.suffix}.node`)
  return {
    name: `${main.name}-${target.suffix}`,
    version: main.version,
    description: `The ${target.suffix} native engine of ${main.name}, installed by it as an optional dependency.`,
    os: [target.os],
    cpu: [target.cpu],
    ...(target.libc === undefined ? {} : { libc: [target.libc] }),
    main: binaries[0],
    files: [...binaries, ...LICENSES],
    license: main.license,
    repository: {
      type: main.repository.type ?? 'git',
      url: main.repository.url,
      directory: `npm/${target.suffix}`,
    },
    engines: main.engines,
    publishConfig: { access: 'public' },
  }
}

/** The main manifest with its optionalDependencies pinned, placed after `dependencies`. */
function mainManifest() {
  const pins = Object.fromEntries(TARGETS.map((t) => [`${main.name}-${t.suffix}`, main.version]))
  const others = Object.fromEntries(
    Object.entries(main.optionalDependencies ?? {}).filter(([name]) => !name.startsWith(`${main.name}-`)),
  )
  const optionalDependencies = { ...others, ...pins }
  const out = {}
  let placed = false
  for (const [key, value] of Object.entries(main)) {
    if (key === 'optionalDependencies') continue
    out[key] = value
    if (key === 'dependencies') {
      out.optionalDependencies = optionalDependencies
      placed = true
    }
  }
  if (!placed) out.optionalDependencies = optionalDependencies
  return out
}

const files = [
  { path: manifestPath, text: render(mainManifest()) },
  ...TARGETS.map((target) => ({
    path: join(root, 'npm', target.suffix, 'package.json'),
    text: render(platformManifest(target)),
  })),
]

if (process.argv.includes('--list')) {
  for (const target of TARGETS) console.log(target.suffix)
} else if (process.argv.includes('--check')) {
  const stale = files.filter(({ path, text }) => !existsSync(path) || readFileSync(path, 'utf8') !== text)
  if (stale.length > 0) {
    console.error('[platform-packages] stale, run `node scripts/platform-packages.mjs`:')
    for (const { path } of stale) console.error(`  ${path.slice(root.length + 1)}`)
    process.exit(1)
  }
  console.log(`[platform-packages] ok: ${TARGETS.length} platform packages at ${main.version}`)
} else {
  for (const { path, text } of files) {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, text)
  }
  console.log(`[platform-packages] ${TARGETS.length} platform packages at ${main.version}`)
}
