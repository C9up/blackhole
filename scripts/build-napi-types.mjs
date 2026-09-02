#!/usr/bin/env node
/**
 * Regenerate `src/native/generated.ts` from the Rust.
 *
 * Node rather than a shell script because this runs inside `build:napi`, and
 * that runs on the Windows prebuild runner too: a bash `mktemp` there hands
 * cargo a `/tmp/...` path the native proc-macro cannot write to, so the
 * type-def file comes back empty and the build fails for no visible reason.
 *
 * One crate at a time on purpose: with napi-derive 2 the writes all went to a
 * single `TYPE_DEF_TMP_PATH` and a parallel build interleaved them
 * while cargo compiles, and a parallel build interleaves the writes —
 * definitions go missing, silently, and the generated file comes out short.
 */

import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CRATES = ['blackhole-engine-napi']

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const output = join('src', 'native', 'generated.ts')
const scratch = mkdtempSync(join(tmpdir(), 'napi-types-'))

try {
  const lines = []
  for (const crate of CRATES) {
    const perCrate = join(scratch, crate)
    writeFileSync(perCrate, '')
    execFileSync('cargo', ['build', '-p', crate], {
      cwd: packageRoot,
      env: { ...process.env, NAPI_TYPE_DEF_TMP_FOLDER: scratch },
      stdio: ['ignore', 'ignore', 'inherit'],
    })
    const emitted = readFileSync(perCrate, 'utf8').split('\n').filter(Boolean)
    if (emitted.length === 0) {
      throw new Error(
        `[napi-types] ${crate} emitted nothing — is napi-derive's "type-def" feature on?`,
      )
    }
    lines.push(...emitted)
  }

  const combined = join(scratch, 'combined.jsonl')
  writeFileSync(combined, `${lines.join('\n')}\n`)

  execFileSync(
    process.execPath,
    [join('scripts', 'generate-napi-types.mjs'), combined, output],
    { cwd: packageRoot, stdio: 'inherit' },
  )

  // Formatted here rather than excluded from the linter: the file is checked
  // in, so it should read like the rest of the tree — and formatting it at
  // generation means it never shows up as a diff someone has to fix by hand.
  // Resolved through the package entry rather than `node_modules/.bin`, whose
  // shim is a shell script the Windows runner cannot execute directly.
  const biome = createRequire(import.meta.url).resolve('@biomejs/biome/bin/biome')
  execFileSync(process.execPath, [biome, 'format', '--write', output], {
    cwd: packageRoot,
    stdio: ['ignore', 'ignore', 'inherit'],
  })
} finally {
  rmSync(scratch, { recursive: true, force: true })
}
