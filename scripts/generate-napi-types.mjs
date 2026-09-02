#!/usr/bin/env node
/**
 * Generate the TypeScript surface of the native module FROM the Rust.
 *
 * `napi-derive`'s `type-def` feature emits one JSON line per exported item
 * while cargo compiles. Those lines are the source of truth: they are derived
 * from the `#[napi]` items themselves, so a signature cannot drift from the
 * Rust without this file changing.
 *
 * Hand-written interfaces are what this replaces, and they do drift — nothing
 * on the TypeScript side notices when a `pub fn` gains a parameter or stops
 * being `async`.
 *
 * One thing napi-rs cannot infer: the shape of a `JsFunction` callback. It
 * emits `(...args: any[]) => any`. Any such parameter is refined below, by
 * name, and the script fails if a refinement no longer matches anything — so
 * the table cannot rot either.
 *
 *   TYPE_DEF_TMP_PATH=<file> cargo build -p <crate>
 *   node scripts/generate-napi-types.mjs <file> <out.d.ts>
 */

import { readFileSync, writeFileSync } from 'node:fs'

/**
 * Callback signatures napi-rs erases to `any`, restored here.
 *
 * Keyed by `<owner>.<method>`; the value replaces the whole parameter. Every
 * entry must match, or the script fails: a stale refinement is how a hand
 * annotation quietly stops describing the Rust.
 *
 * Empty while this crate exposes no `JsFunction` parameter — add an entry the
 * day one appears, rather than letting an `any` through.
 */
const CALLBACK_REFINEMENTS = {}

const [input, output] = process.argv.slice(2)
if (!input || !output) {
  console.error('usage: generate-napi-types.mjs <type-def file> <out.d.ts>')
  process.exit(2)
}

const entries = readFileSync(input, 'utf8')
  .split('\n')
  .map((l) => l.trim())
  .filter(Boolean)
  .map((l) => JSON.parse(l))

const used = new Set()

/** Apply the refinements that belong to `owner`, tracking which ones matched. */
function refine(owner, body) {
  let out = body
  for (const [key, { from, to }] of Object.entries(CALLBACK_REFINEMENTS)) {
    const [entryOwner] = key.split('.')
    if (entryOwner !== owner) continue
    if (out.includes(from)) {
      out = out.replace(from, to)
      used.add(key)
    }
  }
  return out
}

/**
 * JSDoc as emitted by napi-derive, indented to sit above its member.
 *
 * `*` followed by `/` inside the text closes the comment early — a Rust doc
 * example holding a cron expression (`0 *​/5 * * *`) is enough to do it, and
 * the generated file then fails to parse. Escaped rather than stripped, so the
 * example still reads correctly.
 */
function docBlock(doc, indent = '') {
  if (!doc) return ''
  // Escape every `*/` EXCEPT the one that closes the block. A Rust doc example
  // holding a cron expression (`0 */5 * * *`) closes the comment early
  // otherwise, and the generated file stops parsing — but escaping the closer
  // too breaks it just as thoroughly, whether the block spans one line or many.
  const closer = doc.lastIndexOf('*/')
  const escaped =
    closer === -1
      ? doc
      : doc.slice(0, closer).replaceAll('*/', '*\\/') + doc.slice(closer)
  return (
    escaped
      .split('\n')
      .filter((l) => l.length > 0)
      .map((l) => `${indent}${l}`)
      .join('\n') + '\n'
  )
}

const interfaces = entries.filter((e) => e.kind === 'interface')
const structs = entries.filter((e) => e.kind === 'struct')
const impls = new Map(entries.filter((e) => e.kind === 'impl').map((e) => [e.name, e]))
const fns = entries.filter((e) => e.kind === 'fn')

const out = [
  '// GENERATED FROM THE RUST — do not edit.',
  '//',
  "// Produced by scripts/generate-napi-types.mjs from napi-derive's type-def",
  '// output. Editing this file by hand puts it back where it started: a',
  '// description that can disagree with the code it describes.',
  '',
]

for (const iface of interfaces) {
  out.push(docBlock(iface.js_doc))
  out.push(`export interface ${iface.name} {`)
  for (const line of iface.def.split('\n')) {
    out.push(line ? `  ${line.trim()}` : '')
  }
  out.push('}', '')
}

for (const struct of structs) {
  const impl = impls.get(struct.name)
  out.push(docBlock(struct.js_doc))
  out.push(`export declare class ${struct.name} {`)
  if (impl) {
    for (const line of refine(struct.name, impl.def).split('\n')) {
      out.push(line ? `  ${line.trim()}` : '')
    }
  }
  out.push('}', '')
}

for (const fn of fns) {
  out.push(docBlock(fn.js_doc))
  // napi-derive emits the whole declaration for a function, unlike a struct
  // where `def` holds only the members.
  const declaration = fn.def.trim()
  // napi-derive 3 emits a bare `function name(...)` where 2 emitted the
  // signature after the name; concatenating onto the former produced
  // `function xfunction x(...)`.
  const rendered = declaration.startsWith('export declare function')
    ? declaration
    : declaration.startsWith('function ')
      ? `export declare ${declaration}`
      : `export declare function ${fn.name}${declaration}`
  out.push(`${rendered};`, '')
}

const stale = Object.keys(CALLBACK_REFINEMENTS).filter((k) => !used.has(k))
if (stale.length > 0) {
  console.error(
    `[napi-types] refinement(s) that matched nothing: ${stale.join(', ')}\n` +
      '[napi-types] the Rust changed under them — update or remove the entry.',
  )
  process.exit(1)
}

writeFileSync(output, out.join('\n'))
console.log(
  `[napi-types] ${output} — ${interfaces.length} interface(s), ${structs.length} class(es), ${fns.length} function(s)`,
)
