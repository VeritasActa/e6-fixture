// producer/generate.mjs: how this fixture was made. It is kept for transparency; it cannot reproduce the pinned bytes.
//
// It drives the outcome meter (an unpublished prototype; OUTCOME_METER names its source directory, which it only
// reads) over the meter's sandbox company, Harbor Sandbox Co. (fictional), at small scale for July and August 2026,
// with demo keys made in this process: a root key, a meter key, a second meter key and root for the unexpected
// signer of case 08, and two keys whose fingerprints the simulated engagement names. Every private key and the
// engagement secret exist only in this process's memory: nothing secret is written or printed. Running it again
// makes new keys, so new bytes; the pinned fixture is the one SHA256SUMS lists.
//
//   OUTCOME_METER=/path/to/outcome-meter node producer/generate.mjs --out <new or empty directory>
import { randomBytes, createPrivateKey, createPublicKey, sign as edSign, createHash } from 'node:crypto'
import { mkdirSync, writeFileSync, readdirSync, existsSync, readFileSync, statSync } from 'node:fs'
import { join, dirname, resolve, relative, sep } from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import assert from 'node:assert/strict'
import { jcs, recordHash, fingerprintOf, rangeRoot } from '../consumer/check.mjs'

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const argv = process.argv.slice(2)
const OM = process.env.OUTCOME_METER
if (!OM || !argv.includes('--out')) {
  console.error('usage: OUTCOME_METER=<outcome meter source> node producer/generate.mjs --out <new or empty directory>')
  process.exit(2)
}
const OUT = resolve(argv[argv.indexOf('--out') + 1])
if (existsSync(OUT) && readdirSync(OUT).length) { console.error(`refused: ${OUT} is not empty`); process.exit(2) }

const om = (p) => import(pathToFileURL(join(OM, p)).href)
const { generateCompany } = await om('src/sandbox/company.js')
const { openMeter } = await om('src/meter/meter.js')
const { openMemoryStore } = await om('src/meter/store-memory.js')
const { kidOf } = await om('src/core/kid.js')
const { receiptHash } = await om('src/core/envelope.js')
const { parseIso } = await om('src/core/time.js')
const git = (...a) => execFileSync('git', ['-C', OM, ...a], { encoding: 'utf8' }).trim()
const OM_COMMIT = git('rev-parse', 'HEAD')
const OM_CLEAN = git('status', '--porcelain') === ''
const GENERATED_ON = new Date().toISOString().slice(0, 10)
const ON = `${GENERATED_ON} (UTC)`

// ------------------------------------------------------------------ demo keys (private halves in memory only)

const DASHES = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`)
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex')
function demoKey () {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, randomBytes(32)]), format: 'der', type: 'pkcs8' })
  const publicKeyHex = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  return { publicKeyHex, fingerprint: fingerprintOf(publicKeyHex), sign: async (bytes) => new Uint8Array(edSign(null, Buffer.from(bytes), privateKey)) }
}
const K = { root: demoKey(), meter: demoKey(), otherRoot: demoKey(), otherMeter: demoKey(), buyer: demoKey(), certifier: demoKey() }
for (const r of ['root', 'otherRoot']) K[r].kid = `demo:e6-fixture:root:${K[r].fingerprint.slice(7, 23)}`
for (const m of ['meter', 'otherMeter']) K[m].kid = kidOf(K[m].publicKeyHex)
const ENGAGEMENT_SECRET = randomBytes(32).toString('hex')

// ------------------------------------------------------------------ the outcome meter, July and August 2026

const CLOSE = '2026-09-01T02:00:00.000Z'
const PERIOD = '2026-08'
const config = structuredClone(generateCompany({ scale: 'small' }).config)
config.buyer_key_fingerprint = K.buyer.fingerprint
config.certifier = { ...config.certifier, key_fingerprint: K.certifier.fingerprint, name: 'Demonstration certifier (simulated, E6 fixture)' }

async function meterChain (signer) {
  const company = generateCompany({ scale: 'small' })
  const classifier = company.vendorB.classifier
  const store = openMemoryStore()
  const meter = await openMeter({
    store,
    signer,
    engagement: config,
    secret: ENGAGEMENT_SECRET,
    classifier: ({ record, episode, candidates }) => classifier.claimsFor({ conversationId: record.conversation_id, k: episode.k, candidates }),
    classifierId: classifier.id,
    vendorName: company.vendorB.name,
    buyerName: 'Harbor Sandbox Co. (fictional)',
    clock: () => parseIso(CLOSE)
  })
  const r = await meter.replayExport({ exportDoc: company.exportDoc, tags: company.vendorB.tags, until: CLOSE })
  assert.equal(r.refused.length + r.blocked.length, 0)
  assert.deepEqual(r.closed.map((c) => c.period), ['2026-07', PERIOD])
  return store.chainLines().map((l) => {
    const env = JSON.parse(l.text)
    assert.equal(recordHash(env), l.hash)
    assert.equal(receiptHash(env), l.hash)
    return { text: l.text, env, hash: l.hash }
  })
}

/** The August range of a meter chain, its closing statement and the July statement before it. */
function periodOf (lines) {
  const at = (id) => lines.findIndex((l) => l.env.payload.type === 'ocs:period_statement.v0' && l.env.payload.period.id === id)
  const j = at('2026-07')
  const a = at(PERIOD)
  const receipts = lines.slice(j + 1, a)
  const statement = lines[a]
  const p = statement.env.payload
  assert.ok(receipts.every((l) => l.env.payload.type === 'ocs:outcome.v0' && l.env.payload.period === PERIOD))
  assert.ok(receipts.every((l) => l.env.payload.times.final_at >= '2026-08-01' && l.env.payload.times.final_at < '2026-09-01'))
  assert.equal(p.range.correction_receipts, 0)
  assert.equal(receipts.length, p.range.outcome_receipts)
  assert.equal(receipts[0].env.payload.sequence, p.range.first_sequence)
  assert.equal(receipts.at(-1).env.payload.sequence, p.range.last_sequence)
  assert.equal(receipts.at(-1).hash, p.range.head)
  assert.equal(p.previousReceiptHash, p.range.head)
  assert.equal(rangeRoot(receipts.map((l) => l.hash)), p.range.root)
  return { july: lines[j], receipts, statement }
}

const P = periodOf(await meterChain(K.meter))
const Q = periodOf(await meterChain(K.otherMeter))
assert.equal(P.receipts.length, Q.receipts.length)

// ------------------------------------------------------------------ keys

const META = {
  signs: ['ocs:outcome.v0', 'ocs:period_statement.v0'],
  valid_from: '2026-07-01T00:00:00.000Z',
  certified_at: '2026-06-25T09:00:00.000Z'
}
async function certificate (root, meter, statement) {
  const payload = {
    type: 'e6-fixture:key_certificate.v1',
    spec: 'draft-farley-acta-signed-receipts-03',
    issuer_id: root.kid,
    issued_at: META.certified_at,
    subject: { kid: meter.kid, public_key_hex: meter.publicKeyHex, fingerprint: meter.fingerprint, role: 'meter', signs: META.signs, valid_from: META.valid_from, valid_until: null },
    statement,
    demo: true
  }
  const sig = Buffer.from(await root.sign(Buffer.from(jcs(payload), 'utf8'))).toString('hex')
  return { payload, signature: { alg: 'EdDSA', kid: root.kid, sig } }
}
const TIMES_NOTE = `Every issued_at, valid_from and history time in this fixture is a simulated time of the sandbox (June to September 2026). Every signature in it was made on ${ON}.`
const made = (what) => `Generated on ${ON} by producer/generate.mjs from 32 random bytes (node:crypto). Its private half existed only in that process's memory, where ${what}; it was then discarded, and nobody holds it.`

function keysDocument ({ root, meter, cert, notice, rootLabel, meterLabel, meterUse, obtained, referenced }) {
  return {
    format: 'e6-fixture.keys.v1',
    demo: true,
    notice,
    root: {
      role: 'root',
      label: rootLabel,
      kid: root.kid,
      alg: 'Ed25519',
      public_key_hex: root.publicKeyHex,
      fingerprint: root.fingerprint,
      established: made('it signed the meter key\'s certificate below') + ' The paying side pins this fingerprint before it reads any bundle.'
    },
    keys: [{
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(meter.publicKeyHex, 'hex').toString('base64url'),
      kid: meter.kid,
      alg: 'EdDSA',
      use: 'sig',
      role: 'meter',
      label: meterLabel,
      public_key_hex: meter.publicKeyHex,
      fingerprint: meter.fingerprint,
      signs: META.signs,
      valid_from: META.valid_from,
      valid_until: null,
      status: 'active',
      established: made(meterUse) + ' Certified by the root key; the certificate is below. The kid follows the outcome meter\'s convention, "sb:issuer:" and the first 12 base58 characters of the public key; it names a format, not a ScopeBlind production issuer.',
      certificate: cert
    }],
    history: [{ at: META.certified_at, event: 'meter key certified by the root key, valid from 2026-07-01, no end set', kid: meter.kid, certificate: recordHash(cert) }],
    ...(referenced ? { referenced_only: referenced } : {}),
    times: TIMES_NOTE,
    obtained_by_paying_side: obtained,
    generated: { on: GENERATED_ON, by: 'producer/generate.mjs' }
  }
}

const certMeter = await certificate(K.root, K.meter, 'DEMO. The E6 fixture root demo key certifies this demo key to sign outcome receipts and period statements for the simulated Harbor Sandbox Co. engagement. Neither key is a production key.')
const keys = keysDocument({
  root: K.root,
  meter: K.meter,
  cert: certMeter,
  notice: `DEMO KEYS, made fresh for the E6 interoperability fixture on ${ON}. None is a ScopeBlind production key or any other real key. A signature under them shows only that the signed bytes have not changed since they were signed; it shows nothing about any real party.`,
  rootLabel: 'E6 fixture root key (DEMO)',
  meterLabel: 'E6 fixture meter key (DEMO)',
  meterUse: 'the outcome meter used it to sign the simulated engagement\'s July and August 2026 records (outcome receipts and period statements)',
  obtained: 'Placeholder for this test. A real paying side takes the root fingerprint from its contract or another channel the producer does not control, and pins it before it reads any bundle. Here the keys document travels with the bundle, so pinning it shows the mechanism, not anyone\'s identity. The consumer is given this document as an input of its own and never uses keys that arrive inside a bundle (case 08).',
  referenced: [
    { role: 'buyer (simulated)', fingerprint: K.buyer.fingerprint, appears_in: 'manifest.json, payload.engagement.buyer_key_fingerprint', established: `A demo key generated on ${ON} only so that the simulated engagement names a buyer, as the outcome meter requires. Its private half was discarded at once. It signs nothing in this fixture and no E6 check reads it.` },
    { role: 'certifier (simulated)', fingerprint: K.certifier.fingerprint, appears_in: 'the engagement configuration, which the records name only by digest (payload.engagement.config in manifest.json)', established: `A demo key generated on ${ON} only so that the simulated engagement names a certifier, as the outcome meter requires. Its private half was discarded at once. It signs nothing in this fixture and no E6 check reads it.` }
  ]
})
const certOther = await certificate(K.otherRoot, K.otherMeter, 'DEMO. This root demo key certifies this demo key to sign outcome receipts and period statements. Neither key is a production key.')
const suppliedKeys = keysDocument({
  root: K.otherRoot,
  meter: K.otherMeter,
  cert: certOther,
  notice: `DEMO KEYS, made for case 08 of the E6 fixture on ${ON}. This is the keys document that arrived inside case 08's bundle, naming the key that signed it. It is not the paying side's pinned keys document (../../keys.json); a consumer that trusted it would pass case 08.`,
  rootLabel: 'Unexpected signer\'s root key (DEMO, case 08)',
  meterLabel: 'Unexpected signer\'s meter key (DEMO, case 08)',
  meterUse: 'the outcome meter used it to sign case 08\'s copy of the same July and August 2026 records',
  obtained: 'This document came with the bundle it describes; nothing establishes it independently.'
})

// ------------------------------------------------------------------ bills

const PRICE = config.pricing.unit_prices.resolution
const HALF = '2026-08-16'
const BILL_ID = 'HARBOR-DEMO-2026-08-001'
const total = (lines) => lines.reduce((a, l) => a + l.amount_minor, 0)
function bill ({ bill_id = BILL_ID, issued_on = '2026-09-10', period = PERIOD, manifest, lines, exclusions }) {
  return {
    format: 'e6-fixture.bill.v1',
    demo: true,
    notice: 'SIMULATED BILL for the E6 interoperability fixture. Not a real invoice: the vendor, the buyer and the work are fictional.',
    bill_id,
    issued_on,
    vendor: 'Vendor B (fictional)',
    buyer: 'Harbor Sandbox Co. (fictional)',
    period,
    manifest,
    currency: 'USD',
    lines,
    exclusions,
    total_minor: total(lines)
  }
}
const line = (line_id, description, receipts) => ({ line_id, description, billing_class: 'resolution', unit_price_minor: PRICE, quantity: receipts.length, amount_minor: receipts.length * PRICE, receipts })
/** The bill that matches a period exactly: billable receipts on two lines by final date, every other receipt excluded. */
function matchingBill (period) {
  const billable = period.receipts.filter((l) => l.env.payload.outcome.billable)
  assert.ok(billable.every((l) => l.env.payload.outcome.billing_class === 'resolution'))
  const first = billable.filter((l) => l.env.payload.times.final_at < HALF).map((l) => l.hash)
  const second = billable.filter((l) => l.env.payload.times.final_at >= HALF).map((l) => l.hash)
  return bill({
    manifest: period.statement.hash,
    lines: [line('L1', 'Resolved conversations, final 1 to 15 August 2026', first), line('L2', 'Resolved conversations, final 16 to 31 August 2026', second)],
    exclusions: period.receipts.filter((l) => !l.env.payload.outcome.billable).map((l) => ({ receipt: l.hash, reason: 'not_billable', state: l.env.payload.outcome.state }))
  })
}
const raise = (b, lineId, id) => {
  const l = b.lines.find((x) => x.line_id === lineId)
  l.receipts.push(id)
  l.quantity = l.receipts.length
  l.amount_minor = l.quantity * l.unit_price_minor
  b.total_minor = total(b.lines)
  return b
}
const BILL = matchingBill(P)
const statementAmount = P.statement.env.payload.amount

// ------------------------------------------------------------------ files

const files = {}
const put = (rel, text) => { files[rel] = text }
const pretty = (v) => JSON.stringify(v, null, 2) + '\n'
const jsonl = (ls) => ls.map((l) => l.text + '\n').join('')
const seq = (l) => String(l.env.payload.sequence).padStart(4, '0')

put('receipts/chain.jsonl', jsonl(P.receipts))
for (const l of P.receipts) put(`receipts/${seq(l)}.json`, l.text + '\n')
put('manifest.json', P.statement.text + '\n')
put('bill.json', pretty(BILL))
put('keys.json', pretty(keys))

// ------------------------------------------------------------------ cases

const ROOT = { receipts: '../../receipts/chain.jsonl', manifest: '../../manifest.json', bill: '../../bill.json', keys: '../../keys.json', root_fingerprint: K.root.fingerprint, earlier_bills: [], verifier: '@veritasacta/verify@0.10.21' }
const PASSING = { keys: 'PASS', signatures: 'PASS', scope: 'PASS', coverage_bill_to_receipts: 'PASS', coverage_receipts_to_bill: 'PASS', uniqueness: 'PASS', quantities: 'PASS', amount: 'NOT_EVALUATED' }
const REFUSED = { coverage_bill_to_receipts: 'NOT_EVALUATED', coverage_receipts_to_bill: 'NOT_EVALUATED', uniqueness: 'NOT_EVALUATED', quantities: 'NOT_EVALUATED' }
const cases = []
function addCase (name, { title, change, why, inputs = {}, verdict, decisive, claims, codes = {}, own = {}, additional = false }) {
  const c = {
    format: 'e6-fixture.case.v1',
    case: name,
    title,
    ...(additional ? { additional: 'Beyond the ten core cases; it shows what the manifest is for.' } : {}),
    change,
    why,
    inputs: { ...ROOT, ...inputs },
    expected: { verdict, decisive, claims: { ...PASSING, ...claims }, codes, payment_ready: false }
  }
  put(`cases/${name}/case.json`, pretty(c))
  for (const [f, text] of Object.entries(own)) put(`cases/${name}/${f}`, text)
  cases.push(c)
}
const short = (h) => h.slice(0, 19) + '...'
const seqOf = (period, hash) => period.receipts.find((l) => l.hash === hash).env.payload.sequence

addCase('01-matching-bill', {
  title: 'The matching bill',
  change: 'Nothing: the receipts, manifest, bill and keys as supplied.',
  why: 'Every claim of the evidence layer holds, so the verdict is PASS. payment_ready stays false: price and amount are a separate claim against the contract.',
  verdict: 'PASS',
  decisive: [],
  claims: {}
})

const invented = 'sha256:' + createHash('sha256').update('E6 fixture: a receipt ID with no receipt behind it').digest('hex')
addCase('02-missing-receipt', {
  title: 'A missing receipt',
  change: `bill.json bills one more receipt on line L2, ${invented}, with the line's quantity and amount raised to match. No receipt has that ID.`,
  why: 'Bill to receipts coverage: a billed item with no signed receipt behind it is an invented line.',
  inputs: { bill: 'bill.json' },
  own: { 'bill.json': pretty(raise(structuredClone(BILL), 'L2', invented)) },
  verdict: 'FAIL',
  decisive: ['coverage_bill_to_receipts'],
  claims: { coverage_bill_to_receipts: 'FAIL' },
  codes: { coverage_bill_to_receipts: ['unknown_receipt'] }
})

const dup = BILL.lines[0].receipts[0]
addCase('03-receipt-billed-twice-across-lines', {
  title: 'A receipt billed twice across lines',
  change: `bill.json bills receipt ${seqOf(P, dup)} (${dup}) on line L2 as well as on line L1, with L2's quantity and amount raised to match.`,
  why: 'Uniqueness within the bill: each receipt is billed at most once. Every other claim holds, quantities included, since each line\'s quantity still equals the receipts it names.',
  inputs: { bill: 'bill.json' },
  own: { 'bill.json': pretty(raise(structuredClone(BILL), 'L2', dup)) },
  verdict: 'FAIL',
  decisive: ['uniqueness'],
  claims: { uniqueness: 'FAIL' },
  codes: { uniqueness: ['listed_twice_in_bill'] }
})

const again = BILL.lines[1].receipts[0]
const later = bill({
  bill_id: 'HARBOR-DEMO-2026-08-002',
  issued_on: '2026-09-24',
  manifest: P.statement.hash,
  lines: [line('L1', 'Resolved conversation, late adjustment for August 2026', [again])],
  exclusions: P.receipts.filter((l) => l.hash !== again).map((l) => (l.env.payload.outcome.billable
    ? { receipt: l.hash, reason: 'billed_on_earlier_bill', bill_id: BILL_ID }
    : { receipt: l.hash, reason: 'not_billable', state: l.env.payload.outcome.state }))
})
addCase('04-receipt-billed-again-on-later-bill', {
  title: 'A receipt billed again on a later bill',
  change: `bill.json here is a second bill for August (HARBOR-DEMO-2026-08-002), cut from the same manifest. It bills a single receipt, receipt ${seqOf(P, again)} (${again}), and excludes every other receipt, as billed on the first bill or as not billable. The first bill (../../bill.json) is given as an earlier bill, and it already billed receipt ${seqOf(P, again)}.`,
  why: 'Uniqueness against earlier bills: a receipt is billed at most once across the bills the paying side is given. Taken alone, this bill passes every other claim.',
  inputs: { bill: 'bill.json', earlier_bills: ['../../bill.json'] },
  own: { 'bill.json': pretty(later) },
  verdict: 'FAIL',
  decisive: ['uniqueness'],
  claims: { uniqueness: 'FAIL' },
  codes: { uniqueness: ['billed_on_earlier_bill'] }
})

const dropped = BILL.exclusions.find((x) => x.state === 'escalation_requested') || BILL.exclusions[0]
const b5 = structuredClone(BILL)
b5.exclusions = b5.exclusions.filter((x) => x.receipt !== dropped.receipt)
addCase('05-receipt-neither-billed-nor-excluded', {
  title: 'An in-scope receipt neither billed nor excluded',
  change: `bill.json drops the exclusion of receipt ${seqOf(P, dropped.receipt)} (${dropped.receipt}, signed state ${dropped.state}), so it is neither billed nor excluded.`,
  why: 'Receipts to bill coverage: every receipt in the manifest\'s set is billed or explicitly excluded, so a bill cannot quietly leave one out.',
  inputs: { bill: 'bill.json' },
  own: { 'bill.json': pretty(b5) },
  verdict: 'FAIL',
  decisive: ['coverage_receipts_to_bill'],
  claims: { coverage_receipts_to_bill: 'FAIL' },
  codes: { coverage_receipts_to_bill: ['unaccounted_receipt'] }
})

addCase('06-bill-cut-from-different-manifest', {
  title: 'A bill cut from a different manifest',
  change: `bill.json names the July 2026 period statement (${P.july.hash}, in other-manifest.json) as its manifest instead of the August one supplied. Its period and lines are unchanged.`,
  why: 'Scope binding: the consumer refuses a bill whose manifest is not the one supplied and does not compare across scopes, so the bill is never compared with the receipts.',
  inputs: { bill: 'bill.json' },
  own: { 'bill.json': pretty({ ...BILL, manifest: P.july.hash }), 'other-manifest.json': P.july.text + '\n' },
  verdict: 'FAIL',
  decisive: ['scope'],
  claims: { scope: 'FAIL', ...REFUSED },
  codes: { scope: ['manifest_mismatch'] }
})

const victim = P.receipts.find((l) => !l.env.payload.outcome.billable && l.env.payload.outcome.state === 'no_substantive_answer' && l !== P.receipts.at(-1)) ||
  P.receipts.find((l) => !l.env.payload.outcome.billable && l !== P.receipts.at(-1))
const altered = structuredClone(victim.env)
altered.payload.outcome = { ...altered.payload.outcome, basis: 'assumed', billable: true, billing_class: 'resolution', rule: 'J12', state: 'resolved_assumed' }
const alteredLine = { text: JSON.stringify(altered), env: altered, hash: recordHash(altered) }
const P7 = { ...P, receipts: P.receipts.map((l) => (l === victim ? alteredLine : l)) }
const b7 = matchingBill(P7)
addCase('07-altered-receipt', {
  title: 'An altered receipt',
  change: `chain.jsonl alters receipt ${victim.env.payload.sequence} after signing: its outcome is changed from not billable (${victim.env.payload.outcome.state}) to billable (resolved_assumed, rule J12) and its signature is left as it was. bill.json bills it under its new ID (${alteredLine.hash}) on line ${b7.lines.find((x) => x.receipts.includes(alteredLine.hash)).line_id} instead of excluding it.`,
  why: 'Signatures: the verifier finds the altered receipt invalid and the next link broken, and the receipts no longer match the manifest\'s root. The bill and the altered receipts agree with each other, so a consumer that checked neither the signatures nor the manifest would pass this bill.',
  inputs: { receipts: 'chain.jsonl', bill: 'bill.json' },
  own: { 'chain.jsonl': jsonl(P7.receipts), 'bill.json': pretty(b7) },
  verdict: 'FAIL',
  decisive: ['signatures'],
  claims: { signatures: 'FAIL', scope: 'FAIL', ...REFUSED },
  codes: { signatures: ['invalid_signature', 'chain_break'], scope: ['root_mismatch'] }
})

addCase('08-unexpected-signer', {
  title: 'An unexpected signer',
  change: `chain.jsonl, manifest.json and bill.json are a complete, self-consistent bundle for the same August outcomes, signed by a different demo key (kid ${K.otherMeter.kid}, fingerprint ${K.otherMeter.fingerprint}). supplied-keys.json is the keys document that came with that bundle, naming that key. The consumer is given the pinned keys document (../../keys.json), as in every case.`,
  why: 'Keys: the records name a key the pinned keys document does not hold. Every record verifies under the self-supplied key and none under the pinned one, so a consumer that took the bundle\'s own keys document would pass this bundle.',
  inputs: { receipts: 'chain.jsonl', manifest: 'manifest.json', bill: 'bill.json' },
  own: { 'chain.jsonl': jsonl(Q.receipts), 'manifest.json': Q.statement.text + '\n', 'bill.json': pretty(matchingBill(Q)), 'supplied-keys.json': pretty(suppliedKeys) },
  verdict: 'FAIL',
  decisive: ['keys'],
  claims: { keys: 'FAIL', signatures: 'FAIL', ...REFUSED },
  codes: { keys: ['unexpected_signer'], signatures: ['invalid_signature', 'manifest_signature_invalid'] }
})

addCase('09-period-mismatch', {
  title: 'A period mismatch',
  change: 'bill.json states period 2026-09 while naming the August 2026 manifest.',
  why: 'Scope binding: the bill\'s period must equal the manifest\'s; the consumer refuses a mismatch and does not compare the bill with the receipts.',
  inputs: { bill: 'bill.json' },
  own: { 'bill.json': pretty({ ...BILL, period: '2026-09' }) },
  verdict: 'FAIL',
  decisive: ['scope'],
  claims: { scope: 'FAIL', ...REFUSED },
  codes: { scope: ['period_mismatch'] }
})

addCase('10-verifier-unavailable', {
  title: 'The verifier is unavailable',
  change: 'The inputs are the matching ones; the consumer runs with no verifier it can use (here a path that does not exist).',
  why: 'With no verifier no signature can be established, so the consumer abstains rather than passing or failing. Nor is a missing verifier a FAIL: under Node a missing script also exits 1, but with no JSON.',
  inputs: { verifier: 'unavailable' },
  verdict: 'ABSTAIN',
  decisive: ['signatures'],
  claims: { keys: 'ABSTAIN', signatures: 'ABSTAIN', ...REFUSED },
  codes: { keys: ['verifier_unavailable'], signatures: ['verifier_unavailable'] }
})

const last = P.receipts.at(-1)
const P11 = { ...P, receipts: P.receipts.slice(0, -1) }
addCase('11-export-truncated', {
  title: 'An export that leaves out its last receipt',
  additional: true,
  change: `chain.jsonl leaves out the period's last receipt (${last.env.payload.sequence}, ${last.hash}, signed ${last.env.payload.outcome.billable ? 'billable' : `not billable, ${last.env.payload.outcome.state}`}), and bill.json leaves it out too (${last.env.payload.outcome.billable ? 'its line\'s quantity and amount lowered to match' : 'its exclusion removed'}). The manifest is the real one.`,
  why: 'Every remaining receipt verifies and links, and the bill matches the export exactly, so a consumer without the manifest would pass it. The signed manifest\'s count, last sequence, head and root show that a receipt is missing.',
  inputs: { receipts: 'chain.jsonl', bill: 'bill.json' },
  own: { 'chain.jsonl': jsonl(P11.receipts), 'bill.json': pretty(matchingBill(P11)) },
  verdict: 'FAIL',
  decisive: ['scope'],
  claims: { scope: 'FAIL', ...REFUSED },
  codes: { scope: ['count_mismatch', 'sequence_mismatch', 'head_mismatch', 'root_mismatch'] }
})

// ------------------------------------------------------------------ README, code, digests

const V = {
  n: P.receipts.length,
  billable: P.receipts.filter((l) => l.env.payload.outcome.billable).length,
  first: P.receipts[0].env.payload.sequence,
  last: P.receipts.at(-1).env.payload.sequence,
  manifest: P.statement.hash,
  head: P.statement.env.payload.range.head,
  root: P.statement.env.payload.range.root,
  standard: P.statement.env.payload.standard,
  july: P.july.hash
}
put('README.md', readme())
for (const f of ['consumer/check.mjs', 'consumer/run-cases.mjs', 'producer/generate.mjs']) put(f, readFileSync(join(SRC, f), 'utf8'))
for (const [rel, text] of Object.entries(files)) {
  assert.ok(!DASHES.test(text), `${rel} holds an en or em dash`)
  mkdirSync(dirname(join(OUT, rel)), { recursive: true })
  writeFileSync(join(OUT, rel), text)
}
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]))
const sums = walk(OUT).map((p) => relative(OUT, p).split(sep).join('/')).filter((p) => p !== 'SHA256SUMS').sort()
  .map((p) => `${createHash('sha256').update(readFileSync(join(OUT, p))).digest('hex')}  ${p}\n`).join('')
writeFileSync(join(OUT, 'SHA256SUMS'), sums)
console.log(JSON.stringify({
  out: OUT,
  outcome_meter: { commit: OM_COMMIT, clean: OM_CLEAN },
  receipts: V.n,
  billable: V.billable,
  sequences: [V.first, V.last],
  manifest: V.manifest,
  bill_total_minor: BILL.total_minor,
  statement_amount: statementAmount,
  root: { kid: K.root.kid, fingerprint: K.root.fingerprint },
  meter: { kid: K.meter.kid, public_key_hex: K.meter.publicKeyHex, fingerprint: K.meter.fingerprint },
  unexpected_meter: { kid: K.otherMeter.kid, fingerprint: K.otherMeter.fingerprint },
  cases: cases.length,
  files: sums.split('\n').filter(Boolean).length,
  sha256sums_digest: 'sha256:' + createHash('sha256').update(sums).digest('hex')
}, null, 2))

function readme () {
  const m = K.meter.publicKeyHex
  const caseRows = cases.map((c) => {
    const d = c.expected.decisive.length
      ? c.expected.decisive.map((k) => `${k} ${c.expected.claims[k]}${c.expected.codes[k] ? ` (${c.expected.codes[k].join(', ')})` : ''}`).join('; ')
      : 'all seven evidence claims PASS'
    return `| \`${c.case}\`${c.additional ? ' (additional)' : ''} | ${c.title} | **${c.expected.verdict}** | ${d} |`
  }).join('\n')
  return `# E6 producer fixture: Acta receipts for one billing period, a signed period manifest and a bill

**DEMO FIXTURE. Demo keys, simulated outcomes, fictional companies. Not production evidence and not a real bill.**

This is a pinned producer fixture for edge E6 of [aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177): Veritas Acta signed receipts consumed by a paying-side check. It follows the input contract proposed on that issue on 3 October 2026, so that a consumer it did not come from, such as the one in [arian-gogani/nobulex#24](https://github.com/arian-gogani/nobulex/pull/24), can be run against it.

It holds:

- the receipts of one billing period, August 2026: ${V.n} signed outcome receipts, hash-chained (${V.billable} billable, ${V.n - V.billable} not);
- the signed period manifest that fixed that receipt set before the bill was cut: period, chain head, count and a Merkle root over the set;
- a bill, supplied separately, whose lines name the receipts they bill, with every other receipt explicitly excluded;
- a keys document with stated provenance, given to the consumer apart from the bundle;
- ${cases.length} cases, each one change with its expected result, and a small reference consumer that runs them.

## What this is not

- **Demo keys.** Every key here was made for this fixture on ${ON} and is labelled DEMO. None is a ScopeBlind production key or any other real key. Each private half existed only in the memory of the process that made the fixture and was then discarded, so nobody can sign anything more under these keys. A valid signature here shows only that the bytes have not changed since they were signed; it shows nothing about any real party.
- **Simulated outcomes.** The receipts record simulated customer support conversations of Harbor Sandbox Co., a fictional retailer, answered by the AI agent of a fictional vendor, "Vendor B". Each outcome was decided by the outcome meter, an unpublished prototype, under its draft counting standard ${V.standard.id} ${V.standard.version} (not frozen; digest \`${V.standard.digest}\`). The sandbox plants deliberate errors in the vendor's claims; the E6 checks do not, and cannot, detect them.
- **Simulated times.** Every \`issued_at\` in the fixture is a simulated time between June and September 2026. Every signature was made on ${ON}.
- **Not independent.** The Veritas Acta draft, the verifier \`@veritasacta/verify\`, the outcome meter and this fixture are all the work of one author (Tom Farley). Only a consumer written by someone else tests the contract.
- **The evidence layer only.** A PASS says the bill agrees with the signed receipts under the pinned keys. It says nothing about whether the work was good, whether the price is the contracted price, or whether anyone should pay. Price and amount are a separate claim against the contract, which this fixture does not carry, so \`payment_ready\` is always false.
- **One channel.** The keys document travels with the bundle here, so pinning it shows the mechanism, not anyone's identity.

Three more limits: the bill is unsigned, so the fixture does not establish who issued it; uniqueness is checked by receipt ID, so a second receipt signed for the same work under a new ID would not be caught by these checks; and the reasons given for exclusions are the producer's statements, which no check tests.

## Pins

- **Verifier:** \`@veritasacta/verify@0.10.21\` from npm, unmodified. Tarball integrity \`sha512-48roJsv+GsS9v5KiQA7RKL9qCqZ13e8ohQYJhM9Alr6xCB0U7MRy+zXiYeQC2aop9ve0Uage4kN/TlwrqgPi5A==\`, shasum \`4b66003131f63567f05a1550bfdc30e230162b7a\`.
- **Root demo key:** fingerprint \`${K.root.fingerprint}\`. The paying side pins this before it reads any bundle.
- **Meter demo key** (signs the receipts and the manifest): kid \`${K.meter.kid}\`, public key \`${m}\`, fingerprint \`${K.meter.fingerprint}\`.
- **Manifest** (its record hash, which the bill names): \`${V.manifest}\`.
- **Every file:** \`SHA256SUMS\`. The SHA-256 of \`SHA256SUMS\` itself identifies this version of the fixture; it is published beside the fixture, since it cannot be inside it.

## Files

| Path | What it is |
|---|---|
| \`receipts/chain.jsonl\` | The ${V.n} outcome receipts of August 2026 (sequences ${V.first} to ${V.last} of the meter's chain), one envelope per line, in chain order. This file is the consumer's receipts input. |
| \`receipts/${String(V.first).padStart(4, '0')}.json\` to \`receipts/${String(V.last).padStart(4, '0')}.json\` | The same receipts, one per file, named by sequence, for verifying one at a time. |
| \`manifest.json\` | The signed period manifest: the outcome meter's period statement for August 2026 (\`ocs:period_statement.v0\`), on one line. |
| \`bill.json\` | The bill, \`${BILL_ID}\`, supplied separately from the receipts. |
| \`keys.json\` | The keys document: the root demo key, the meter demo key with its root-signed certificate and validity window, the key history and the provenance. It is also a JWKS, so the verifier can take it with \`--jwks\`. |
| \`cases/\` | One directory per case: \`case.json\` (inputs and expected result) and the files the case changes. |
| \`consumer/check.mjs\`, \`consumer/run-cases.mjs\` | The reference consumer and the case runner. |
| \`producer/generate.mjs\` | How the fixture was made. It needs the unpublished outcome meter and cannot reproduce these bytes. |
| \`SHA256SUMS\` | The SHA-256 of every other file. |

Every record is an envelope of draft-farley-acta-signed-receipts-03: \`{"payload": {...}, "signature": {"alg": "EdDSA", "kid": "...", "sig": "..."}}\`, an Ed25519 signature over the JCS (RFC 8785) bytes of the payload, and, after the first record of the meter's chain, a \`previousReceiptHash\` holding \`sha256:\` and the hex SHA-256 of the JCS of the whole previous envelope, signature included (section 6.7). The first August receipt links to the July statement, which is not part of this period; \`cases/06-bill-cut-from-different-manifest/other-manifest.json\` is that July statement.

## Verify the receipts with the public verifier

From this directory, with Node 18 or later:

\`\`\`sh
# Every file against its pinned digest (on Linux: sha256sum -c SHA256SUMS)
shasum -a 256 -c SHA256SUMS

# Each receipt on its own, under the pinned meter key: ${V.n} invocations, each must exit 0
for f in receipts/0*.json; do npx --yes @veritasacta/verify@0.10.21 "$f" --key ${m} --json > /dev/null || echo "NOT VALID: $f"; done

# The receipts as a chain: every signature and every link
npx --yes @veritasacta/verify@0.10.21 --replay-chain receipts/chain.jsonl --key ${m}

# The chain closed by the manifest, which links to the last receipt
cat receipts/chain.jsonl manifest.json | npx --yes @veritasacta/verify@0.10.21 --replay-chain /dev/stdin --key ${m}

# The manifest on its own
npx --yes @veritasacta/verify@0.10.21 manifest.json --key ${m}

# A receipt with the keys document as its key source, applying the key's validity window
npx --yes @veritasacta/verify@0.10.21 receipts/${String(V.first).padStart(4, '0')}.json --jwks keys.json --require-key-window

# The meter key's certificate, under the root demo key
node -e 'process.stdout.write(JSON.stringify(require("./keys.json").keys[0].certificate))' | npx --yes @veritasacta/verify@0.10.21 --stdin --key ${K.root.publicKeyHex}
\`\`\`

Each command exits 0. The two replays report ${V.n} and ${V.n + 1} records verified with no chain breaks. The verifier checks signatures and links; it knows nothing of periods, bills or coverage, which is what the consumer adds. Use \`--replay-chain\` for the links: the \`chain explore\` subcommand of 0.10.21 looks ancestors up by an unprefixed base64url hash rather than the section 6.7 value, so it does not walk these chains.

## The input contract

The five points of the 3 October comment, and where each one lives here:

1. **Each billed unit names its receipt:** every line lists its receipt IDs (\`lines[].receipts\`), so \`uniqueness\` can check each receipt is billed at most once, in this bill and against the earlier bills given.
2. **Coverage both ways:** \`coverage_bill_to_receipts\` and \`coverage_receipts_to_bill\`, measured against the receipt set that the signed manifest fixed before the bill was cut (period, chain head, count, Merkle root).
3. **Scope binding:** the bill states its \`period\` and the \`manifest\` it was cut from; \`scope\` refuses a mismatch, and nothing is compared across scopes.
4. **Key provenance as its own input:** \`keys.json\` and a root fingerprint pinned out of band, kept apart from the bundle, with key history and a statement of how each key was made (\`keys\`).
5. **Per-claim results:** seven evidence claims reported separately; price and amount left as a separate claim against the contract; \`payment_ready\` always false.

### Inputs

A consumer takes these, each as bytes:

1. \`receipts\`: the period's receipts, JSONL in chain order.
2. \`manifest\`: the signed period manifest.
3. \`bill\`: the bill under check, supplied separately from the receipts.
4. \`keys\` with \`root_fingerprint\`: the pinned keys document and the root fingerprint pinned out of band. Never keys that arrive inside a bundle.
5. \`earlier_bills\`: zero or more bills the paying side has already accepted.
6. The verifier: \`@veritasacta/verify\` 0.10.21, unmodified.

### Constructions

- **Receipt ID** (and the manifest's record hash): \`sha256:\` and the lowercase hex SHA-256 of the UTF-8 JCS of the whole envelope, signature included. It is the value the next record's \`previousReceiptHash\` holds.
- **Range root:** the RFC 6962 Merkle tree over the receipt IDs in sequence order: each leaf SHA-256(0x00 and the 32 bytes of the ID), each node SHA-256(0x01, left, right), split at the largest power of two below the count.
- **Key fingerprint:** \`sha256:\` and the hex SHA-256 of the 32-byte public key.

### Fields the checks read

- **Receipt** (\`ocs:outcome.v0\`): \`signature.kid\`, \`payload.issuer_id\`, \`payload.issued_at\`, \`payload.sequence\`, \`payload.previousReceiptHash\`, \`payload.period\`, \`payload.outcome.billable\`, \`payload.outcome.billing_class\`.
- **Manifest** (\`ocs:period_statement.v0\`): \`signature.kid\`, \`payload.issuer_id\`, \`payload.issued_at\`, \`payload.previousReceiptHash\`, \`payload.period.id\`, and \`payload.range\`: \`first_sequence\`, \`last_sequence\`, \`head\`, \`outcome_receipts\`, \`correction_receipts\`, \`root\`.
- **Bill:** \`period\`, \`manifest\`, \`lines[].quantity\`, \`lines[].billing_class\`, \`lines[].receipts\`, \`exclusions[].receipt\`. The rest (\`unit_price_minor\`, \`amount_minor\`, \`total_minor\`, names, descriptions, exclusion reasons) is for people and for the separate price and amount claim.
- **Keys:** \`root\` (\`kid\`, \`public_key_hex\`, \`fingerprint\`) and the meter key (\`kid\`, \`public_key_hex\`, \`x\`, \`fingerprint\`, \`valid_from\`, \`valid_until\`, \`certificate\`).

Everything else in the records belongs to the outcome meter's data model and plays no part in these checks.

### Claims

| Claim | PASS means |
|---|---|
| \`keys\` | The keys document's root matches the pinned fingerprint. The meter key carries a certificate that the verifier finds signed by the root and whose subject matches the entry. Every receipt and the manifest name that key (\`signature.kid\` and \`payload.issuer_id\`) and were issued inside its validity window. |
| \`signatures\` | Under the pinned meter key, the verifier's \`--replay-chain\` finds every receipt valid and every link intact, every receipt after the first carries a link, and the manifest verifies. |
| \`scope\` | The bill's \`period\` equals the manifest's \`period.id\` and its \`manifest\` equals the manifest's record hash. The receipts are exactly the set the manifest fixed: the count (\`outcome_receipts + correction_receipts\`), the sequences from \`first_sequence\` to \`last_sequence\`, the \`head\` (the last receipt's ID, which the manifest's own \`previousReceiptHash\` also names), the \`root\`, and each receipt's \`period\`. |
| \`coverage_bill_to_receipts\` | Every receipt ID the bill names, on a line or as an exclusion, is in that set. |
| \`coverage_receipts_to_bill\` | Every receipt in that set is billed on a line or explicitly excluded. |
| \`uniqueness\` | No receipt ID appears twice in the bill, across lines and exclusions, and no receipt it bills was billed on an earlier bill given. |
| \`quantities\` | Each line's quantity equals the number of receipts it names, and each of them is signed \`outcome.billable: true\` in the line's \`billing_class\`. One receipt is one unit. |
| \`amount\` | Not evaluated: price and amount are a separate claim against the contract. |

### Results

Each claim is \`PASS\`, \`FAIL\`, \`ABSTAIN\` (could not be decided, for example with no verifier) or \`NOT_EVALUATED\`. The bill is compared with the receipts (the coverage, uniqueness and quantities claims) only when \`keys\`, \`signatures\` and \`scope\` have all passed; otherwise those four are \`NOT_EVALUATED\`, so a consumer never compares across scopes or against receipts it could not establish. The verdict is \`FAIL\` when any claim fails, \`PASS\` when all seven evidence claims pass, and \`ABSTAIN\` otherwise. \`payment_ready\` is always false. A verifier's exit code counts only with its \`--json\` output: a missing verifier script also exits 1 under Node.

Next to Nobulex's PR #24: each line here names the receipts it bills rather than one fill ID; a receipt listed twice is a \`uniqueness\` FAIL, since the bill is well formed and the double billing is the finding (the PR reports a duplicate line as INDETERMINATE); and \`ABSTAIN\` corresponds to the PR's INDETERMINATE.

## The cases

| Case | What it tests | Expected verdict | Decisive claim (reference codes) |
|---|---|---|---|
${caseRows}

Each \`case.json\` says what changed, why the result follows, and the inputs, as paths relative to its directory. A consumer agrees with a case when its verdict and its result for each decisive claim match \`expected\` and \`payment_ready\` is false. The full claim vector and the codes in \`expected\` are what the reference consumer reports, given for comparison.

Run them all:

\`\`\`sh
node consumer/run-cases.mjs
\`\`\`

It finds \`@veritasacta/verify@0.10.21\` through \`npx\` (or the \`cli.js\` named by \`VERIFY_CLI\`), refuses any other version, runs every case and prints one line each. \`node consumer/check.mjs --case cases/07-altered-receipt\` prints one case's full result. The reference consumer shows that the cases are decidable; it is not offered as a product.

## How it was made

\`producer/generate.mjs\` ran the outcome meter (an unpublished prototype; commit \`${OM_COMMIT.slice(0, 12)}\`) over its sandbox at small scale for July and August 2026, closing each month with a signed period statement, and wrote August's range, the August statement, the bills and the cases. A second run of the same simulation under another demo key made case 08's bundle. The keys, and the engagement secret behind the receipts' unit references, existed only in that process's memory. Running the script again makes new keys and different bytes.
`
}
