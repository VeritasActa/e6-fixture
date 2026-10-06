// The reference consumer for the E6 producer fixture. It exists to show that every case is decidable; it is
// not a product. Every signature is checked by the pinned public verifier (@veritasacta/verify 0.10.21, run
// unmodified as a child process); this file computes only hashes and comparisons.
//
//   node consumer/check.mjs --case cases/02-missing-receipt
//   node consumer/check.mjs --receipts R --manifest M --bill B --keys K --root-fingerprint sha256:... [--earlier-bill B0 ...]
//
// The verifier is the npm package @veritasacta/verify@0.10.21, found through npx, or the cli.js that VERIFY_CLI or
// --verifier names (refused unless its package.json says 0.10.21). Prints the result as JSON.
// Exit 0 PASS, 1 FAIL, 2 ABSTAIN.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

export const CLAIMS = ['keys', 'signatures', 'scope', 'coverage_bill_to_receipts', 'coverage_receipts_to_bill', 'uniqueness', 'quantities', 'amount']
const GATED = ['coverage_bill_to_receipts', 'coverage_receipts_to_bill', 'uniqueness', 'quantities']
const VERSION = '0.10.21'

// RFC 8785 (JCS) for the values these files hold: strings, safe integers, booleans, null, arrays and objects.
export function jcs (v) {
  if (v === null || typeof v !== 'object') {
    if (typeof v === 'number' && !Number.isSafeInteger(v)) throw new Error('number is not a safe integer')
    return JSON.stringify(v)
  }
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}'
}
const sha256 = (bytes) => createHash('sha256').update(bytes).digest()
const hex = (h) => 'sha256:' + h.toString('hex')

/** Receipt ID: "sha256:" + hex SHA-256 of JCS(the whole envelope, signature included), the draft's section 6.7 link. */
export const recordHash = (env) => hex(sha256(Buffer.from(jcs(env), 'utf8')))
/** Key fingerprint: "sha256:" + hex SHA-256 of the 32-byte raw public key. */
export const fingerprintOf = (publicKeyHex) => hex(sha256(Buffer.from(publicKeyHex, 'hex')))

/** RFC 6962 Merkle root over record hashes in order: leaf SHA-256(0x00 || 32 bytes), node SHA-256(0x01 || l || r). */
export function rangeRoot (hashes) {
  const root = (a) => {
    if (a.length === 0) return sha256(Buffer.alloc(0))
    if (a.length === 1) return a[0]
    let k = 1
    while (k * 2 < a.length) k *= 2
    return sha256(Buffer.concat([Buffer.from([1]), root(a.slice(0, k)), root(a.slice(k))]))
  }
  return hex(root(hashes.map((h) => sha256(Buffer.concat([Buffer.from([0]), Buffer.from(h.slice(7), 'hex')])))))
}

/** The pinned verifier's cli.js: VERIFY_CLI, or the npm package through npx. Throws unless it is version 0.10.21. */
export function pinnedVerifier (given = process.env.VERIFY_CLI) {
  let cli = given
  if (!cli) {
    const r = spawnSync('npx', ['--yes', '-p', `@veritasacta/verify@${VERSION}`, 'sh', '-c', 'command -v verify'], { encoding: 'utf8' })
    const bin = (r.stdout || '').trim().split('\n').pop()
    if (r.status !== 0 || !bin) throw new Error(`could not install @veritasacta/verify@${VERSION} through npx`)
    cli = realpathSync(bin)
  }
  const pkg = join(dirname(cli), 'package.json')
  const version = existsSync(pkg) ? JSON.parse(readFileSync(pkg, 'utf8')).version : undefined
  if (version !== VERSION) throw new Error(`refused: ${cli} is not @veritasacta/verify ${VERSION} (found ${version})`)
  return cli
}

/** One verifier call. Only parseable JSON with a matching exit code counts; anything else is undecided. */
function verify (cli, args) {
  if (typeof cli !== 'string' || !existsSync(cli)) return { status: 'undecided' }
  const run = spawnSync(process.execPath, [cli, ...args, '--json'], { encoding: 'utf8', timeout: 120000, maxBuffer: 64 * 1024 * 1024 })
  let json
  try { json = JSON.parse(run.stdout) } catch { return { status: 'undecided' } }
  if (run.status === 0 && json.valid === true) return { status: 'valid', json }
  if (run.status === 1 && json.valid === false) return { status: 'invalid', json }
  return { status: 'undecided', json }
}

const inWindow = (at, k) => {
  const t = Date.parse(at)
  return Number.isFinite(t) && t >= Date.parse(k.valid_from) && (k.valid_until === null || t < Date.parse(k.valid_until))
}
const uniq = (a) => [...new Set(a)]
const verdictOf = (codes, undecided) => (codes.length ? 'FAIL' : undecided ? 'ABSTAIN' : 'PASS')

export function checkBill ({ receiptsBytes, manifestBytes, billBytes, keysBytes, rootFingerprint, earlierBillsBytes = [], verifierCli }) {
  const claims = {}
  const set = (name, result, codes = [], extra = {}) => { claims[name] = { result, ...(codes.length ? { codes: uniq(codes) } : {}), ...extra } }
  const finish = () => {
    const r = CLAIMS.filter((c) => c !== 'amount').map((c) => claims[c].result)
    const verdict = r.includes('FAIL') ? 'FAIL' : r.every((x) => x === 'PASS') ? 'PASS' : 'ABSTAIN'
    return { verdict, claims: Object.fromEntries(CLAIMS.map((c) => [c, claims[c]])), payment_ready: false }
  }
  set('amount', 'NOT_EVALUATED', [], { detail: 'Price and amount are a separate claim against the contract; this fixture carries no contract.' })

  let receipts, manifest, bill, keys, earlier, ids, manifestId
  const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
  try {
    receipts = receiptsBytes.toString('utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
    manifest = JSON.parse(manifestBytes)
    bill = JSON.parse(billBytes)
    keys = JSON.parse(keysBytes)
    earlier = earlierBillsBytes.map((b) => JSON.parse(b))
    if (![...receipts, manifest, bill, keys, ...earlier].every(isObject)) throw new Error('not a JSON object')
    ids = receipts.map(recordHash)
    manifestId = recordHash(manifest)
  } catch {
    for (const c of CLAIMS.slice(0, -1)) set(c, 'ABSTAIN', ['input_unreadable'])
    return finish()
  }
  const meterKeys = Array.isArray(keys.keys) ? keys.keys.filter((k) => k && k.role === 'meter') : []
  const mk = meterKeys.length === 1 ? meterKeys[0] : undefined
  const root = keys.root || {}
  const dir = mkdtempSync(join(tmpdir(), 'e6-consumer-'))
  try {
    // The verifier reads private copies of the exact bytes this function compares.
    const receiptsFile = join(dir, 'receipts.jsonl')
    const manifestFile = join(dir, 'manifest.json')
    writeFileSync(receiptsFile, receiptsBytes)
    writeFileSync(manifestFile, manifestBytes)

    // keys: the pinned root, a root-signed certificate behind the meter key, and every record signed by that
    // key inside its validity window. The keys document is an input of its own, never taken from the bundle.
    let codes = []
    let undecided = false
    if (typeof root.public_key_hex !== 'string' || root.fingerprint !== rootFingerprint || fingerprintOf(root.public_key_hex) !== rootFingerprint) codes.push('root_not_pinned')
    if (!mk) codes.push('no_single_meter_key')
    if (!codes.length) {
      const c = mk.certificate || {}
      const s = (c.payload && c.payload.subject) || {}
      if (c.payload?.type !== 'e6-fixture:key_certificate.v1' || c.signature?.kid !== root.kid || c.payload?.issuer_id !== root.kid ||
          s.kid !== mk.kid || s.public_key_hex !== mk.public_key_hex || s.role !== mk.role || s.valid_from !== mk.valid_from ||
          s.valid_until !== mk.valid_until || fingerprintOf(mk.public_key_hex) !== mk.fingerprint ||
          Buffer.from(String(mk.x), 'base64url').toString('hex') !== mk.public_key_hex) {
        codes.push('certificate_mismatch')
      } else {
        const certFile = join(dir, 'certificate.json')
        writeFileSync(certFile, JSON.stringify(c))
        const v = verify(verifierCli, [certFile, '--key', root.public_key_hex])
        if (v.status === 'invalid') codes.push('certificate_invalid')
        if (v.status === 'undecided') undecided = true
      }
      for (const r of [...receipts, manifest]) {
        if (r?.signature?.kid !== mk.kid || r?.payload?.issuer_id !== mk.kid) codes.push('unexpected_signer')
        else if (!inWindow(r.payload.issued_at, mk)) codes.push('outside_key_window')
      }
    }
    set('keys', verdictOf(codes, undecided), codes.length ? codes : undecided ? ['verifier_unavailable'] : [])

    // signatures: every receipt and every link between receipts (one --replay-chain call), and the manifest,
    // under the pinned meter key, by the public verifier. A link the verifier would skip (no
    // previousReceiptHash after the first record) is refused here.
    codes = []
    undecided = false
    if (!mk) codes.push('no_pinned_key')
    else {
      const chain = verify(verifierCli, ['--replay-chain', receiptsFile, '--key', mk.public_key_hex])
      if (chain.status === 'undecided') undecided = true
      else {
        const j = chain.json
        if (j.total !== receipts.length) codes.push('verifier_read_other_records')
        if ((j.receipts || []).some((x) => x.valid !== true)) codes.push('invalid_signature')
        if (j.chainBreaks > 0) codes.push('chain_break')
        if (chain.status === 'invalid' && !codes.length) codes.push('chain_invalid')
      }
      if (receipts.slice(1).some((r) => typeof r?.payload?.previousReceiptHash !== 'string')) codes.push('missing_link')
      const man = verify(verifierCli, [manifestFile, '--key', mk.public_key_hex])
      if (man.status === 'undecided') undecided = true
      if (man.status === 'invalid') codes.push('manifest_signature_invalid')
    }
    set('signatures', verdictOf(codes, undecided), codes.length ? codes : undecided ? ['verifier_unavailable'] : [])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }

  // scope: the bill names this manifest and its period, and the receipts are exactly the set the manifest
  // fixed (count, sequences, head, Merkle root). Hashes and comparisons only, so it needs no verifier.
  const codes = []
  const mp = (manifest && manifest.payload) || {}
  const range = mp.range || {}
  if (mp.type !== 'ocs:period_statement.v0' || !mp.period || !mp.range) codes.push('not_a_period_statement')
  else {
    if (bill.period !== mp.period.id) codes.push('period_mismatch')
    if (bill.manifest !== manifestId) codes.push('manifest_mismatch')
    if (receipts.length !== range.outcome_receipts + range.correction_receipts) codes.push('count_mismatch')
    if (!receipts.every((r, i) => r?.payload?.sequence === range.first_sequence + i) || receipts.at(-1)?.payload?.sequence !== range.last_sequence) codes.push('sequence_mismatch')
    if (ids.at(-1) !== range.head) codes.push('head_mismatch')
    if (mp.previousReceiptHash !== range.head) codes.push('manifest_link_mismatch')
    if (rangeRoot(ids) !== range.root) codes.push('root_mismatch')
    if (receipts.some((r) => r?.payload?.period !== mp.period.id)) codes.push('receipt_period_mismatch')
  }
  set('scope', verdictOf(codes, false), codes)

  // The bill is compared with the receipts only when keys, signatures and scope have all passed.
  if (!['keys', 'signatures', 'scope'].every((c) => claims[c].result === 'PASS')) {
    for (const c of GATED) set(c, 'NOT_EVALUATED', [], { detail: 'Refused: keys, signatures and scope must pass before the bill is compared with the receipts.' })
    return finish()
  }
  const inScope = new Map(ids.map((id, i) => [id, receipts[i]]))
  const lines = Array.isArray(bill.lines) ? bill.lines : []
  const billed = lines.flatMap((l) => (Array.isArray(l.receipts) ? l.receipts : []))
  const named = [...billed, ...(Array.isArray(bill.exclusions) ? bill.exclusions : []).map((x) => x && x.receipt)]

  const unknown = uniq(named.filter((id) => !inScope.has(id)))
  set('coverage_bill_to_receipts', unknown.length ? 'FAIL' : 'PASS', unknown.length ? ['unknown_receipt'] : [], unknown.length ? { receipts: unknown } : {})

  const namedSet = new Set(named)
  const unaccounted = ids.filter((id) => !namedSet.has(id))
  set('coverage_receipts_to_bill', unaccounted.length ? 'FAIL' : 'PASS', unaccounted.length ? ['unaccounted_receipt'] : [], unaccounted.length ? { receipts: unaccounted } : {})

  const seen = new Set()
  const twice = named.filter((id) => (seen.has(id) ? true : (seen.add(id), false)))
  const earlierBilled = new Set(earlier.flatMap((b) => (Array.isArray(b.lines) ? b.lines : []).flatMap((l) => (Array.isArray(l.receipts) ? l.receipts : []))))
  const again = billed.filter((id) => earlierBilled.has(id))
  const ucodes = [...(twice.length ? ['listed_twice_in_bill'] : []), ...(again.length ? ['billed_on_earlier_bill'] : [])]
  set('uniqueness', ucodes.length ? 'FAIL' : 'PASS', ucodes, ucodes.length ? { receipts: uniq([...twice, ...again]) } : {})

  const qcodes = []
  for (const l of lines) {
    const rs = Array.isArray(l.receipts) ? l.receipts : []
    if (!Number.isSafeInteger(l.quantity) || l.quantity !== rs.length) qcodes.push('quantity_mismatch')
    for (const id of rs) {
      const o = inScope.get(id)?.payload?.outcome
      if (o && !(o.billable === true && o.billing_class === l.billing_class)) qcodes.push('receipt_not_billable_in_class')
    }
  }
  set('quantities', qcodes.length ? 'FAIL' : 'PASS', qcodes)
  return finish()
}

/** The inputs a case names, read relative to its directory. The case's expected result is never read here. */
export function caseInputs (caseDir, verifierCli) {
  const c = JSON.parse(readFileSync(join(caseDir, 'case.json'), 'utf8'))
  const at = (p) => readFileSync(resolve(caseDir, p))
  return {
    receiptsBytes: at(c.inputs.receipts),
    manifestBytes: at(c.inputs.manifest),
    billBytes: at(c.inputs.bill),
    keysBytes: at(c.inputs.keys),
    rootFingerprint: c.inputs.root_fingerprint,
    earlierBillsBytes: (c.inputs.earlier_bills || []).map(at),
    verifierCli: c.inputs.verifier === 'unavailable' ? '/nonexistent/veritasacta-verify/cli.js' : verifierCli
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2)
  const one = (f) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : undefined }
  const many = (f) => argv.flatMap((a, i) => (a === f ? [argv[i + 1]] : []))
  const verifierCli = pinnedVerifier(one('--verifier') || process.env.VERIFY_CLI)
  const input = one('--case')
    ? caseInputs(resolve(one('--case')), verifierCli)
    : {
        receiptsBytes: readFileSync(one('--receipts')),
        manifestBytes: readFileSync(one('--manifest')),
        billBytes: readFileSync(one('--bill')),
        keysBytes: readFileSync(one('--keys')),
        rootFingerprint: one('--root-fingerprint'),
        earlierBillsBytes: many('--earlier-bill').map((p) => readFileSync(p)),
        verifierCli
      }
  const out = checkBill(input)
  console.log(JSON.stringify(out, null, 2))
  process.exitCode = out.verdict === 'PASS' ? 0 : out.verdict === 'FAIL' ? 1 : 2
}
