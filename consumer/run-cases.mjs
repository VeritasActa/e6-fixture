// Runs every case in cases/ through the reference consumer and compares its result with the case's expected
// result: the verdict, every claim and the reference codes. One line per case; exit 1 if any case differs.
//
//   node consumer/run-cases.mjs                                  (finds @veritasacta/verify@0.10.21 through npx)
//   VERIFY_CLI=/path/to/verify/cli.js node consumer/run-cases.mjs (a local copy of 0.10.21)
import { readdirSync, readFileSync, existsSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { checkBill, caseInputs, pinnedVerifier, CLAIMS } from './check.mjs'

const CASES = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'cases')
const cli = pinnedVerifier()
console.log(`verifier: @veritasacta/verify 0.10.21, ${cli}\n`)
const same = (a = [], b = []) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort())
let total = 0
let differing = 0
let paymentReady = 0
for (const name of readdirSync(CASES).sort()) {
  const dir = join(CASES, name)
  if (!existsSync(join(dir, 'case.json'))) continue
  total++
  const { expected } = JSON.parse(readFileSync(join(dir, 'case.json'), 'utf8'))
  const got = checkBill(caseInputs(dir, cli))
  const diffs = []
  if (got.verdict !== expected.verdict) diffs.push(`verdict ${got.verdict}`)
  if (got.payment_ready !== false) { diffs.push('payment_ready'); paymentReady++ }
  for (const k of CLAIMS) {
    if (got.claims[k].result !== expected.claims[k]) diffs.push(`${k} ${got.claims[k].result}`)
    else if (!same(got.claims[k].codes, (expected.codes || {})[k])) diffs.push(`${k} codes ${(got.claims[k].codes || []).join('+') || 'none'}`)
  }
  if (diffs.length) differing++
  const decisive = expected.decisive.map((k) => `${k} ${got.claims[k].result}${got.claims[k].codes ? ` (${got.claims[k].codes.join(', ')})` : ''}`).join('; ')
  console.log(`${diffs.length ? 'DIFFERS' : 'ok     '}  ${name.padEnd(42)} ${got.verdict.padEnd(7)} expected ${expected.verdict.padEnd(7)}  ${decisive || 'all evidence claims PASS'}${diffs.length ? `\n         differs: ${diffs.join(', ')}` : ''}`)
}
console.log(`\n${total - differing} of ${total} cases as expected; payment_ready was ${paymentReady ? `true in ${paymentReady}` : 'false in every'} case.`)
process.exitCode = differing || !total ? 1 : 0
