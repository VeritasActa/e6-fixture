// Case 12 of the E6 fixture, added in v1.1.0: the period manifest with one hex digit of its signature changed, and the matching
// bill re-pointed at the altered manifest's record hash. Every hash link still holds, so only a signature check fails. The case is
// derived from the pinned manifest.json and bill.json alone, with the reference consumer's own record hash, so it gives the same
// bytes every time it runs.
//
//   node producer/case-12.mjs            writes cases/12-manifest-signature-altered/
//   node producer/case-12.mjs --check    exits 1 unless the files there are exactly the ones it would write
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { recordHash, CLAIMS } from '../consumer/check.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const NAME = '12-manifest-signature-altered'
const DIR = join(ROOT, 'cases', NAME)
const DASHES = /[\u2013\u2014]/
const read = (p) => readFileSync(join(ROOT, p), 'utf8')
const pretty = (v) => JSON.stringify(v, null, 2) + '\n'
const once = (text, s) => text.split(s).length - 1 === 1

// The manifest exactly as pinned, with the first hex digit of its signature moved on by one. Nothing else in it changes.
const manifestText = read('manifest.json'), manifest = JSON.parse(manifestText), sig = manifest.signature.sig
const from = sig[0], to = ((parseInt(from, 16) + 1) % 16).toString(16), field = '"sig":"' + sig + '"'
if (!once(manifestText, field)) throw new Error('manifest.json does not hold its signature exactly once')
const manifestOut = manifestText.replace(field, '"sig":"' + to + sig.slice(1) + '"')
const alteredId = recordHash(JSON.parse(manifestOut))

// The matching bill, pointing at the altered manifest instead of the pinned one. Nothing else in it changes.
const billText = read('bill.json'), pinnedId = recordHash(manifest)
if (JSON.parse(billText).manifest !== pinnedId || !once(billText, pinnedId)) throw new Error('bill.json does not name manifest.json exactly once')
const billOut = billText.replace(pinnedId, alteredId)

// The case, in the same form as cases 01 to 11.
const base = JSON.parse(read('cases/01-matching-bill/case.json'))
const claims = Object.fromEntries(CLAIMS.map((k) => [k, k === 'signatures' ? 'FAIL' : k === 'keys' || k === 'scope' ? 'PASS' : 'NOT_EVALUATED']))
const caseOut = pretty({
  format: base.format,
  case: NAME,
  title: 'An altered manifest signature',
  additional: 'Added in v1.1.0, from the first independent run: the one case that only a signature check catches.',
  change: `manifest.json is the pinned period statement with the first hex digit of its signature changed from ${from} to ${to}; nothing else in it changed. bill.json is the matching bill, re-pointed at the altered statement's record hash (${alteredId}) instead of the pinned one.`,
  why: 'Signatures: the statement no longer verifies under the pinned meter key. Every hash link still holds: the receipts, their head and their root are the ones the statement names, and the bill names the statement it was cut from. So a consumer that checked the links but never a signature would pass this bill. In cases 01 to 11, what a signature check catches is also caught by a link (07) or by the key a record names (08); this case is caught by the signature alone.',
  inputs: { ...base.inputs, manifest: 'manifest.json', bill: 'bill.json' },
  expected: { verdict: 'FAIL', decisive: ['signatures'], claims, codes: { signatures: ['manifest_signature_invalid'] }, payment_ready: false }
})

const out = { 'manifest.json': manifestOut, 'bill.json': billOut, 'case.json': caseOut }
for (const [f, text] of Object.entries(out)) if (DASHES.test(text)) throw new Error(`${f} holds an en or em dash`)
if (process.argv.includes('--check')) {
  const differ = Object.entries(out).filter(([f, text]) => !existsSync(join(DIR, f)) || readFileSync(join(DIR, f), 'utf8') !== text).map(([f]) => f)
  if (differ.length) { console.error(`cases/${NAME}: ${differ.join(', ')} differ from what this script writes`); process.exitCode = 1 }
  else console.log(`cases/${NAME}: all three files are exactly what this script writes`)
} else {
  mkdirSync(DIR, { recursive: true })
  for (const [f, text] of Object.entries(out)) writeFileSync(join(DIR, f), text)
  console.log(`wrote cases/${NAME}: manifest signature digit ${from} -> ${to}, bill re-pointed to ${alteredId}`)
}
