// Cases 13 and 14 of the E6 fixture, added in v1.2.0, one for each of two rules the README states. Case 13: within a claim a
// failure outranks a check that could not be decided. Case 14: a key's validity window runs from valid_from, included, to
// valid_until, excluded.
//
// Case 13 is a case.json alone. It names case 08's bundle and the pinned keys document, and no verifier, as case 10 does.
//
// Case 14 needs a meter key whose window ends at a record's issued_at. The pinned meter key's window has no end, and the private
// half of every key in the fixture was discarded, so this script derives two new DEMO keys, a root key and a meter key, from
// published seeds: the SHA-256 of the labels in SEEDS below. Anyone can sign anything under them; they demonstrate only the window
// rule. The script re-signs the pinned August receipts and period statement under the case meter key, changing only issuer_id and
// the hashes that follow from it, re-points the matching bill at the re-signed records, and writes a keys document whose meter key
// carries a certificate, signed by the case root key, that ends the window at the statement's issued_at. Ed25519 signing is
// deterministic and every input is a pinned file, so it writes the same bytes every time it runs. Every hash is the reference
// consumer's own.
//
//   node producer/case-13-14.mjs            writes cases/13-unexpected-signer-no-verifier/ and cases/14-record-issued-at-valid-until/
//   node producer/case-13-14.mjs --check    exits 1 unless the files there are exactly the ones it would write
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { jcs, recordHash, fingerprintOf, rangeRoot, CLAIMS } from '../consumer/check.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const DASHES = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`)
const read = (p) => readFileSync(join(ROOT, p), 'utf8')
const records = (text) => text.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
const pretty = (v) => JSON.stringify(v, null, 2) + '\n'
const once = (text, s) => text.split(s).length - 1 === 1
const must = (ok, message) => { if (!ok) throw new Error(message) }
const base = JSON.parse(read('cases/01-matching-bill/case.json'))
const pinnedKeys = JSON.parse(read('keys.json'))
const pinnedMeter = pinnedKeys.keys[0]
must(pinnedKeys.keys.length === 1 && pinnedMeter.role === 'meter' && pinnedMeter.valid_until === null, 'keys.json does not hold one meter key with no end to its window')
const out = {}

// ------------------------------------------------------------------ case 13: an unexpected signer, with no verifier

const C13 = '13-unexpected-signer-no-verifier'
const C08 = '../08-unexpected-signer'
const bundle08 = [...records(read('cases/08-unexpected-signer/chain.jsonl')), JSON.parse(read('cases/08-unexpected-signer/manifest.json'))]
const kid08 = bundle08[0].signature.kid
must(kid08 !== pinnedMeter.kid && bundle08.every((r) => r.signature.kid === kid08 && r.payload.issuer_id === kid08), 'case 08 is not signed throughout by one key other than the pinned meter key')
out[`cases/${C13}/case.json`] = pretty({
  format: base.format,
  case: C13,
  title: 'An unexpected signer, with no verifier',
  additional: 'Added in v1.2.0, for a rule the README now states: within a claim a failure outranks a check that could not be decided.',
  change: `The inputs are case 08's, read where case 08 keeps them: the bundle signed by a different demo key (kid ${kid08}) and the pinned keys document (../../keys.json). As in case 10, the consumer runs with no verifier it can use (here a path that does not exist). No file is copied or changed.`,
  why: 'Keys: every record names a key the pinned keys document does not hold, and comparing a kid needs no verifier, so that check fails. The certificate check cannot be decided without a verifier, but within a claim a failure outranks a check that could not be decided, so keys is FAIL with unexpected_signer, not ABSTAIN. Signatures: no signature can be established and no check of that claim fails, so it abstains, as in case 10. Scope needs no verifier and passes, as in case 08. The verdict is FAIL because a claim failed. A consumer that let an undecided check outrank a failure would report keys ABSTAIN and the verdict ABSTAIN.',
  inputs: { ...base.inputs, receipts: `${C08}/chain.jsonl`, manifest: `${C08}/manifest.json`, bill: `${C08}/bill.json`, verifier: 'unavailable' },
  expected: {
    verdict: 'FAIL',
    decisive: ['keys'],
    claims: { keys: 'FAIL', signatures: 'ABSTAIN', scope: 'PASS', coverage_bill_to_receipts: 'NOT_EVALUATED', coverage_receipts_to_bill: 'NOT_EVALUATED', uniqueness: 'NOT_EVALUATED', quantities: 'NOT_EVALUATED', amount: 'NOT_EVALUATED' },
    codes: { keys: ['unexpected_signer'], signatures: ['verifier_unavailable'] },
    payment_ready: false
  }
})

// ------------------------------------------------------------------ case 14: a record issued exactly at valid_until

const C14 = '14-record-issued-at-valid-until'

// The seeds are published, here and in the case's keys.json: anyone can derive these two private keys and sign under them.
const SEEDS = {
  root: 'VeritasActa/e6-fixture case 14 root key (DEMO). This seed is published, so anyone can sign under this key.',
  meter: 'VeritasActa/e6-fixture case 14 meter key (DEMO). This seed is published, so anyone can sign under this key.'
}
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex')
function seededKey (role) {
  const seed = createHash('sha256').update(SEEDS[role], 'utf8').digest()
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' })
  const publicKeyHex = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  const fingerprint = fingerprintOf(publicKeyHex)
  const kid = `demo:e6-fixture:case-14:${role}:${fingerprint.slice(7, 23)}`
  return {
    kid,
    publicKeyHex,
    fingerprint,
    seed: { label: SEEDS[role], derivation: 'SHA-256 of the UTF-8 bytes of the label, used as the 32-byte Ed25519 private key (RFC 8032, section 5.1.5)', hex: seed.toString('hex') },
    envelope: (payload) => ({ payload, signature: { alg: 'EdDSA', kid, sig: sign(null, Buffer.from(jcs(payload), 'utf8'), privateKey).toString('hex') } })
  }
}
const caseRoot = seededKey('root')
const caseMeter = seededKey('meter')

// Each pinned payload with only issuer_id and the hashes that follow from re-signing changed. The first receipt keeps its link to
// the pinned July statement, which is outside the period, as in every case.
const leaves = (v, at = '') => (v !== null && typeof v === 'object' ? Object.entries(v).flatMap(([k, x]) => leaves(x, at ? `${at}.${k}` : k)) : [[at, JSON.stringify(v)]])
const changed = (a, b) => {
  const A = new Map(leaves(a))
  const B = new Map(leaves(b))
  return [...new Set([...A.keys(), ...B.keys()])].filter((k) => A.get(k) !== B.get(k)).sort().join(' ')
}
const pinnedReceipts = records(read('receipts/chain.jsonl'))
const pinnedStatement = JSON.parse(read('manifest.json'))
must([...pinnedReceipts, pinnedStatement].every((r) => r.signature.kid === pinnedMeter.kid && r.payload.issuer_id === pinnedMeter.kid), 'a pinned record does not name the pinned meter key')
const receipts = []
for (const r of pinnedReceipts) {
  const payload = structuredClone(r.payload)
  payload.issuer_id = caseMeter.kid
  if (receipts.length) payload.previousReceiptHash = recordHash(receipts.at(-1))
  must(changed(r.payload, payload) === (receipts.length ? 'issuer_id previousReceiptHash' : 'issuer_id'), `receipt ${r.payload.sequence} changed in more than its issuer and its link`)
  receipts.push(caseMeter.envelope(payload))
}
const ids = receipts.map(recordHash)
const sp = structuredClone(pinnedStatement.payload)
sp.issuer_id = caseMeter.kid
sp.previousReceiptHash = ids.at(-1)
sp.range.head = ids.at(-1)
sp.range.root = rangeRoot(ids)
must(changed(pinnedStatement.payload, sp) === 'issuer_id previousReceiptHash range.head range.root', 'the statement changed in more than its issuer, link, head and root')
const statement = caseMeter.envelope(sp)
const statementId = recordHash(statement)

// The window ends at the statement's issued_at. The statement is the last record the meter key signs for the period and no record
// was issued after it, so the records issued at that instant are the only ones outside the window, and a consumer that counted
// valid_until as inside would find every record inside. An earlier end would put later records after it, outside under either reading.
const VALID_FROM = pinnedMeter.valid_from
const VALID_UNTIL = sp.issued_at
const t = (r) => Date.parse(r.payload.issued_at)
const last = receipts.at(-1)
must([...receipts, statement].every((r) => t(r) >= Date.parse(VALID_FROM) && t(r) <= Date.parse(VALID_UNTIL)), 'a record was issued before valid_from or after the statement')
const atEnd = [...receipts, statement].filter((r) => t(r) === Date.parse(VALID_UNTIL))
must(atEnd.length === 2 && atEnd[0] === last && atEnd[1] === statement, 'the records issued at valid_until are not exactly the last receipt and the statement')

const certificate = caseRoot.envelope({
  type: pinnedMeter.certificate.payload.type,
  spec: pinnedMeter.certificate.payload.spec,
  issuer_id: caseRoot.kid,
  issued_at: pinnedMeter.certificate.payload.issued_at,
  subject: { kid: caseMeter.kid, public_key_hex: caseMeter.publicKeyHex, fingerprint: caseMeter.fingerprint, role: 'meter', signs: pinnedMeter.signs, valid_from: VALID_FROM, valid_until: VALID_UNTIL },
  statement: `DEMO, FROM PUBLISHED SEEDS. The E6 fixture's case 14 root demo key certifies this demo key to sign outcome receipts and period statements for the simulated Harbor Sandbox Co. engagement from ${VALID_FROM}, included, until ${VALID_UNTIL}, excluded. Both seeds are published, so anyone can sign under either key; they demonstrate only the validity window rule. Neither key is a production key.`,
  demo: true
})
const caseKeys = {
  format: pinnedKeys.format,
  demo: true,
  notice: 'DEMO KEYS FROM PUBLISHED SEEDS, for case 14 of the E6 fixture only. Each key is derived from the SHA-256 of the label given with it, so anyone can sign anything under either key, and a signature under them shows nothing about who signed. They demonstrate only the validity window rule. Neither is a ScopeBlind production key, any other real key, or a key of the fixture\'s pinned keys document (../../keys.json).',
  root: {
    role: 'root',
    label: 'E6 fixture case 14 root key (DEMO, published seed)',
    kid: caseRoot.kid,
    alg: 'Ed25519',
    public_key_hex: caseRoot.publicKeyHex,
    fingerprint: caseRoot.fingerprint,
    seed: caseRoot.seed,
    established: 'Derived by producer/case-13-14.mjs from the published seed above, so anyone can derive its private half. In this fixture it signs only the meter key\'s certificate below. Case 14 pins this fingerprint in its case.json, in place of the fixture\'s root.'
  },
  keys: [{
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(caseMeter.publicKeyHex, 'hex').toString('base64url'),
    kid: caseMeter.kid,
    alg: 'EdDSA',
    use: 'sig',
    role: 'meter',
    label: 'E6 fixture case 14 meter key (DEMO, published seed)',
    public_key_hex: caseMeter.publicKeyHex,
    fingerprint: caseMeter.fingerprint,
    signs: pinnedMeter.signs,
    valid_from: VALID_FROM,
    valid_until: VALID_UNTIL,
    status: pinnedMeter.status,
    seed: caseMeter.seed,
    established: `Derived by producer/case-13-14.mjs from the published seed above, so anyone can derive its private half. In this fixture it signs case 14's copy of the August 2026 records: the pinned outcome receipts and period statement, re-signed with only issuer_id and the hashes that follow from it changed. Certified by the case 14 root key; the certificate is below. Its window ends at ${VALID_UNTIL}, the period statement's issued_at, so the statement and the last receipt, both issued at that instant, fall outside it.`,
    certificate
  }],
  history: [{ at: certificate.payload.issued_at, event: `meter key certified by the root key, valid from ${VALID_FROM.slice(0, 10)} until ${VALID_UNTIL}, that instant excluded`, kid: caseMeter.kid, certificate: recordHash(certificate) }],
  referenced_only: pinnedKeys.referenced_only,
  times: 'Every issued_at, valid_from, valid_until and history time in this document and in case 14\'s records is a simulated time of the sandbox (June to September 2026). Ed25519 signing is deterministic, so producer/case-13-14.mjs makes these same signatures each time it runs.',
  obtained_by_paying_side: 'Placeholder for this test, as in ../../keys.json. Case 14 gives the consumer this document as its keys input and pins its root fingerprint in case.json. The seeds are published, so pinning it shows only the window rule at work, never anyone\'s identity.',
  generated: { release: 'v1.2.0', by: 'producer/case-13-14.mjs' }
}

// The matching bill with each receipt ID and the manifest's record hash replaced by the re-signed ones. Nothing else in it changes.
let billOut = read('bill.json')
for (const [from, to] of [[recordHash(pinnedStatement), statementId], ...pinnedReceipts.map((r, i) => [recordHash(r), ids[i]])]) {
  must(once(billOut, from), `bill.json does not name ${from} exactly once`)
  billOut = billOut.replace(from, to)
}
const bill = JSON.parse(billOut)
const named = [...bill.lines.flatMap((l) => l.receipts), ...bill.exclusions.map((x) => x.receipt)]
must(bill.manifest === statementId && [...named].sort().join() === [...ids].sort().join(), 'the re-pointed bill does not name each re-signed record once')

out[`cases/${C14}/chain.jsonl`] = receipts.map((r) => JSON.stringify(r) + '\n').join('')
out[`cases/${C14}/manifest.json`] = JSON.stringify(statement) + '\n'
out[`cases/${C14}/bill.json`] = billOut
out[`cases/${C14}/keys.json`] = pretty(caseKeys)
out[`cases/${C14}/case.json`] = pretty({
  format: base.format,
  case: C14,
  title: 'A record issued exactly at the meter key\'s valid_until',
  additional: 'Added in v1.2.0, for a rule the README now states: the validity window includes valid_from and excludes valid_until.',
  notice: 'DEMO KEYS FROM PUBLISHED SEEDS. This case\'s root and meter keys are derived from the SHA-256 of labels published in its keys.json and in producer/case-13-14.mjs, so anyone can sign anything under them. They demonstrate only the window rule, and a signature under them shows nothing about who signed. The case pins its own root fingerprint, not the fixture\'s.',
  change: `chain.jsonl and manifest.json are the pinned August receipts and period statement, re-signed under this case's meter key (kid ${caseMeter.kid}). Each payload changes only in issuer_id and in the hashes that follow from re-signing: previousReceiptHash, and in the statement also range.head and range.root. The first receipt still links to the pinned July statement, outside the period. bill.json is the matching bill with each receipt ID replaced by the re-signed one, and its manifest by the re-signed statement's record hash (${statementId}). keys.json is the keys document the paying side pins for this case, under its own root: the meter key's certificate, signed by that root, gives valid_from ${VALID_FROM} and valid_until ${VALID_UNTIL}, the statement's issued_at.`,
  why: `Keys: the window is [valid_from, valid_until), so a record issued at valid_until is outside it. valid_until is the statement's issued_at because the statement is the last record signed for the period and no record was issued after it; the last receipt (sequence ${last.payload.sequence}) was issued at the same instant. So exactly those two records fall outside the window, both at valid_until and none after it, and the other ${receipts.length - 1} receipts fall inside. An earlier valid_until would put later records after it, outside under either reading, and the case would no longer test the boundary. Every signature verifies under the case meter key, every link, head and root holds, and the bill matches the receipts, so a consumer that counted valid_until as inside the window would pass this bill.`,
  inputs: { ...base.inputs, receipts: 'chain.jsonl', manifest: 'manifest.json', bill: 'bill.json', keys: 'keys.json', root_fingerprint: caseRoot.fingerprint },
  expected: {
    verdict: 'FAIL',
    decisive: ['keys'],
    claims: { keys: 'FAIL', signatures: 'PASS', scope: 'PASS', coverage_bill_to_receipts: 'NOT_EVALUATED', coverage_receipts_to_bill: 'NOT_EVALUATED', uniqueness: 'NOT_EVALUATED', quantities: 'NOT_EVALUATED', amount: 'NOT_EVALUATED' },
    codes: { keys: ['outside_key_window'] },
    payment_ready: false
  }
})

for (const [f, text] of Object.entries(out)) {
  must(!DASHES.test(text), `${f} holds an en or em dash`)
  if (f.endsWith('/case.json')) must(JSON.stringify(Object.keys(JSON.parse(text).expected.claims)) === JSON.stringify(CLAIMS), `${f} does not give the eight claims in order`)
}
if (process.argv.includes('--check')) {
  const differ = Object.entries(out).filter(([f, text]) => !existsSync(join(ROOT, f)) || readFileSync(join(ROOT, f), 'utf8') !== text).map(([f]) => f)
  if (differ.length) { console.error(`${differ.join(', ')} differ from what this script writes`); process.exitCode = 1 }
  else console.log(`cases/${C13} and cases/${C14}: all ${Object.keys(out).length} files are exactly what this script writes`)
} else {
  for (const [f, text] of Object.entries(out)) {
    mkdirSync(dirname(join(ROOT, f)), { recursive: true })
    writeFileSync(join(ROOT, f), text)
  }
  console.log(`wrote cases/${C13} and cases/${C14}: case 14 root ${caseRoot.fingerprint}, meter valid_until ${VALID_UNTIL}, manifest ${statementId}`)
}
