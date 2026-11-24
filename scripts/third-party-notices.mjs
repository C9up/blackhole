#!/usr/bin/env node
/**
 * THIRD-PARTY-NOTICES.md: the licence and copyright notices of everything
 * compiled into the native binaries this package ships.
 *
 * A Rust binary statically links every crate of its dependency graph, and
 * MIT, BSD and ISC ask for their notice to travel with every copy, binaries
 * included. The file goes into the main package and into every platform
 * package (scripts/platform-packages.mjs lists it).
 *
 * The crates come from cargo-about, run on the crates that build the shipped
 * binaries, for the targets they are built for, without dev or build
 * dependencies. `about.toml` holds the licences accepted: anything else, a
 * copyleft licence included, fails the generation, and so does a crate whose
 * licence cannot be read. C and C++ code compiled in by a `-sys` crate is not
 * described by cargo metadata: BUNDLED below names it, with its own notice.
 *
 * cargo-about is pinned (CARGO_ABOUT): another version may read licence files
 * differently, and the file would change without the dependencies changing.
 *
 *   node scripts/third-party-notices.mjs          rewrite the file
 *   node scripts/third-party-notices.mjs --check  fail if it is stale
 */

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const TAG = '[third-party-notices]'
const OUTPUT = 'THIRD-PARTY-NOTICES.md'
const CARGO_ABOUT = '0.9.3'

/** The targets the CI matrix builds the `.node` binaries for. */
const NATIVE = [
  'x86_64-unknown-linux-gnu',
  'aarch64-unknown-linux-gnu',
  'x86_64-apple-darwin',
  'aarch64-apple-darwin',
  'x86_64-pc-windows-msvc',
]

/** The crates whose builds are shipped, the targets each is built for, and what it ships as. */
const BINARIES = [{ crate: 'crates/blackhole-engine-napi', targets: NATIVE, ships: '`.node`' }]

/**
 * C and C++ code a crate of the graph compiles into the binary. `crate` must
 * be in the graph: an entry outlives its crate only as an error. The notice is
 * read from `file` inside that crate's source (`excerpt` cuts it from the
 * first `from` to the end of the first `to` after it, less the `comment`
 * marker, and the space after it, opening each line), or given as `text` when
 * the source is fetched at build time; `pinnedIn` then names the file that
 * pins that source, which must still name the same commit.
 */
const BUNDLED = []

/**
 * Crates fetched from this project's own repositories are its own code, under
 * the LICENSE the package already ships, like the workspace's path crates.
 */
const OWN_GIT = 'git+https://github.com/C9up/'

const main = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))

function cargo(args) {
  try {
    return execFileSync('cargo', args, {
      cwd: root,
      encoding: 'utf8',
      maxBuffer: 1 << 30,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  } catch (error) {
    const stderr = typeof error?.stderr === 'string' ? error.stderr : ''
    throw new Error(`${TAG} cargo ${args.join(' ')} failed\n${stderr}`)
  }
}

function checkTool() {
  let version
  try {
    version = cargo(['about', '--version']).trim()
  } catch {
    version = 'none'
  }
  if (version !== `cargo-about ${CARGO_ABOUT}`) {
    throw new Error(
      `${TAG} needs cargo-about ${CARGO_ABOUT}, found ${version}: ` +
        `cargo install cargo-about --locked --version ${CARGO_ABOUT} --features cli`,
    )
  }
}

/** Licence text as written, with line endings and trailing spaces evened out. */
function normalize(text) {
  return text
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map((line) => line.trimEnd())
    .join('\n')
    .trim()
}

const isOwn = (krate) => krate.source === null || krate.source.startsWith(OWN_GIT)
const label = (krate) => `${krate.name} ${krate.version}`
const byLabel = (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)

function collect() {
  /** Third-party crates by id: their name, version, declared licence, source directory. */
  const crates = new Map()
  /** Licence texts by id and text, with the crates they cover. */
  const texts = new Map()
  for (const { crate, targets } of BINARIES) {
    const manifest = join(crate, 'Cargo.toml')
    if (!existsSync(join(root, manifest))) throw new Error(`${TAG} ${manifest} does not exist`)
    const args = ['about', 'generate', '--format', 'json', '--frozen', '-c', 'about.toml', '-m', manifest]
    for (const target of targets) args.push('--target', target)
    const report = JSON.parse(cargo(args))
    const resolved = new Set()
    for (const licence of report.licenses) {
      const users = licence.used_by.map((use) => use.crate).filter((krate) => !isOwn(krate))
      if (users.length === 0) continue
      const text = normalize(licence.text)
      const key = `${licence.id}\n${text}`
      const entry = texts.get(key) ?? {
        id: licence.id,
        name: licence.name,
        text,
        packaged: licence.source_path !== null,
        users: new Map(),
      }
      for (const krate of users) {
        entry.users.set(krate.id, krate)
        resolved.add(krate.id)
      }
      texts.set(key, entry)
    }
    for (const { package: krate, license } of report.crates) {
      if (isOwn(krate)) continue
      if (!resolved.has(krate.id)) {
        throw new Error(`${TAG} no licence text resolved for ${label(krate)} (declared: ${license})`)
      }
      crates.set(krate.id, {
        name: krate.name,
        version: krate.version,
        license,
        dir: dirname(krate.manifest_path),
      })
    }
  }
  return { crates: [...crates.values()].sort(byLabel), texts: [...texts.values()] }
}

function excerpt(content, entry) {
  if (entry.excerpt === undefined) return content
  const start = content.indexOf(entry.excerpt.from)
  const end = start === -1 ? -1 : content.indexOf(entry.excerpt.to, start)
  if (end === -1) throw new Error(`${TAG} the notice of ${entry.name} is no longer in ${entry.crate}/${entry.file}`)
  const text = content.slice(start, end + entry.excerpt.to.length)
  // A notice cut out of a source file loses that file's comment markers.
  const marker = entry.excerpt.comment
  if (marker === undefined) return text
  return text
    .split('\n')
    .map((line, index) => (index > 0 && line.startsWith(marker) ? line.slice(marker.length).replace(/^ /, '') : line))
    .join('\n')
}

function bundled(crates) {
  return BUNDLED.map((entry) => {
    const krate = crates.find((candidate) => candidate.name === entry.crate)
    if (krate === undefined) {
      throw new Error(`${TAG} ${entry.name} is compiled in by ${entry.crate}, which is no longer in the graph`)
    }
    if (entry.pinnedIn !== undefined) {
      const pin = readFileSync(join(root, entry.pinnedIn.file), 'utf8')
      if (!pin.includes(entry.pinnedIn.commit)) {
        throw new Error(`${TAG} ${entry.pinnedIn.file} no longer pins ${entry.name} at ${entry.pinnedIn.commit}`)
      }
    }
    const text = entry.text ?? excerpt(readFileSync(join(krate.dir, entry.file), 'utf8'), entry)
    return { ...entry, by: label(krate), text: normalize(text) }
  })
}

/** A fence longer than any run of backticks in the text. */
function fenced(text) {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length))
  const fence = '`'.repeat(Math.max(3, longest + 1))
  return `${fence}text\n${text}\n${fence}`
}

function render({ crates, texts }) {
  const counts = new Map()
  for (const entry of texts) {
    for (const krate of entry.users.values()) {
      const seen = counts.get(entry.id) ?? new Set()
      seen.add(krate.id)
      counts.set(entry.id, seen)
    }
  }
  const sortedTexts = texts
    .map((entry) => ({ ...entry, users: [...entry.users.values()].sort(byLabel) }))
    .sort((a, b) => a.id.localeCompare(b.id) || byLabel(a.users[0], b.users[0]))
  const extra = bundled(crates)
  const kinds = [...new Set(BINARIES.map(({ ships }) => ships))].join(' and ')

  const out = [
    '# Third-party notices',
    '',
    `The binaries of \`${main.name}\` (${kinds}) are compiled from the Rust crates below` +
      (extra.length > 0 ? ' and the C code they bundle' : '') +
      '. Their licences ask for these notices to accompany every copy, binaries included.',
    '',
    `Generated by \`node scripts/third-party-notices.mjs\` from \`Cargo.lock\` with cargo-about ${CARGO_ABOUT}. Do not edit by hand.`,
    '',
    '## Licences',
    '',
    '| Licence | Crates |',
    '| --- | ---: |',
    ...[...counts.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([id, seen]) => `| ${id} | ${seen.size} |`),
    '',
    '## Crates',
    '',
    '| Crate | Version | Declared licence |',
    '| --- | --- | --- |',
    ...crates.map((krate) => `| ${krate.name} | ${krate.version} | ${krate.license} |`),
    '',
  ]
  if (extra.length > 0) {
    out.push('## Bundled C code', '')
    for (const entry of extra) {
      out.push(`### ${entry.name} (${entry.license})`, '', `Compiled in by ${entry.by}. ${entry.origin}`, '')
      out.push(fenced(entry.text), '')
    }
  }
  out.push('## Licence texts', '')
  for (const entry of sortedTexts) {
    out.push(`### ${entry.id}`, '', `Used by: ${entry.users.map(label).join(', ')}.`, '')
    if (!entry.packaged) {
      // The crate ships no licence file: the standard text stands in for it,
      // and its authors are the copyright holders it does not name.
      out.push(
        'These crates ship no licence file, so the standard text is given. Their authors:',
        '',
        ...entry.users.map((krate) => `- ${label(krate)}: ${krate.authors.join(', ') || 'not declared'}`),
        '',
      )
    }
    if (entry.id.startsWith('MPL-')) {
      // MPL-2.0 is file-level: a binary may carry these files under any
      // licence, provided its recipients are told where their source is.
      out.push(
        'These crates are compiled in unmodified. Their source code is available at:',
        '',
        ...entry.users.map(
          (krate) =>
            `- ${label(krate)}: https://crates.io/crates/${krate.name}/${krate.version}` +
            (krate.repository ? ` (${krate.repository})` : ''),
        ),
        '',
      )
    }
    out.push(fenced(entry.text), '')
  }
  return `${out.join('\n').trimEnd()}\n`
}

checkTool()
cargo(['fetch', '--locked'])
const text = render(collect())
const path = join(root, OUTPUT)

if (process.argv.includes('--check')) {
  if (!existsSync(path) || readFileSync(path, 'utf8') !== text) {
    console.error(`${TAG} ${OUTPUT} is stale, run \`node scripts/third-party-notices.mjs\``)
    process.exit(1)
  }
  console.log(`${TAG} ok: ${OUTPUT} is up to date`)
} else {
  writeFileSync(path, text)
  console.log(`${TAG} wrote ${OUTPUT}`)
}
