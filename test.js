const {buildSync} = require('esbuild')
const {mkdtempSync, rmSync} = require('node:fs')
const {tmpdir} = require('node:os')
const {join} = require('node:path')
const {spawnSync} = require('node:child_process')

const directory = mkdtempSync(join(tmpdir(), 'nos2x-tests-'))
try {
  const outfile = join(directory, 'tests.mjs')
  buildSync({
    entryPoints: ['tests/signer.test.js'],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile
  })
  const result = spawnSync(process.execPath, ['--test', outfile], {
    stdio: 'inherit'
  })
  process.exitCode = result.status ?? 1
} finally {
  rmSync(directory, {recursive: true, force: true})
}
