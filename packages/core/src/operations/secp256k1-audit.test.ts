import { createHash } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import {
  auditSecp256k1, createDefaultOperationRegistry, MemoryByteSource, BitcoinParser,
  SECP256K1_AUDIT_RECIPE, SECP256K1_AUDIT_MAX_BYTES,
  SECP256K1_GX as GX, SECP256K1_GY as GY, SECP256K1_N as N,
  SECP256K1_P as P, runRecipe, validateRecipe,
} from '../index'
import type { Secp256k1AuditInput, Secp256k1AuditResult } from './secp256k1-audit'

const be = (value: bigint) => Uint8Array.from(Buffer.from(value.toString(16).padStart(64, '0'), 'hex'))
const pubkey = Uint8Array.from([2, ...be(GX)])
function der(r: bigint, s: bigint): Uint8Array {
  const integer = (value: bigint) => {
    let hex = value.toString(16)
    if (hex.length % 2) hex = `0${hex}`
    if (parseInt(hex.slice(0, 2), 16) >= 128) hex = `00${hex}`
    const bytes = Buffer.from(hex, 'hex')
    return [2, bytes.length, ...bytes]
  }
  const payload = [...integer(r), ...integer(s)]
  return Uint8Array.from([0x30, payload.length, ...payload])
}
function compactSize(length: number): number[] {
  if (length < 253) return [length]
  if (length <= 65535) return [253, length & 255, length >>> 8]
  return [254, length & 255, length >>> 8 & 255, length >>> 16 & 255, length >>> 24]
}
const push = (bytes: Uint8Array, mode: 'direct' | 'p1' | 'p2' | 'p4' = 'direct') => Uint8Array.from([
  ...(mode === 'direct' ? [bytes.length] : mode === 'p1' ? [0x4c, bytes.length] : mode === 'p2' ? [0x4d, bytes.length, 0] : [0x4e, bytes.length, 0, 0, 0]), ...bytes,
])
function tx(options: {
  scriptSig?: Uint8Array
  scriptPubKey?: Uint8Array
  witness?: Uint8Array[]
  values?: bigint[]
  inputs?: number
  coinbase?: boolean
} = {}): Uint8Array {
  const scriptSig = options.scriptSig ?? new Uint8Array()
  const scriptPubKey = options.scriptPubKey ?? new Uint8Array()
  const values = options.values ?? [1n]
  const inputs = options.inputs ?? 1
  const input: number[] = [
    ...new Uint8Array(32).fill(options.coinbase ? 0 : 1),
    ...(options.coinbase ? [255, 255, 255, 255] : [0, 0, 0, 0]),
    ...compactSize(scriptSig.length), ...scriptSig, 255, 255, 255, 255,
  ]
  const outputs = values.flatMap(value => {
    const amount = new Uint8Array(8)
    new DataView(amount.buffer).setBigUint64(0, value, true)
    return [...amount, ...compactSize(scriptPubKey.length), ...scriptPubKey]
  })
  const witness = options.witness
  const stack = witness ? [...compactSize(witness.length), ...witness.flatMap(item => [...compactSize(item.length), ...item])] : []
  return Uint8Array.from([
    2, 0, 0, 0, ...(witness ? [0, 1] : []), ...compactSize(inputs),
    ...Array.from({ length: inputs }, () => input).flat(), ...compactSize(values.length), ...outputs,
    ...Array.from({ length: inputs }, () => stack).flat(), 0, 0, 0, 0,
  ])
}

describe('secp256k1.audit raw input findings', () => {
  it('is registered as a deterministic read-only crypto operation and exposed in capabilities', () => {
    const registry = createDefaultOperationRegistry()
    expect(registry.get('secp256k1.audit')).toMatchObject({ category: 'crypto', deterministic: true, readOnly: true })
    expect(registry.generateCapabilityManifest().supportedOperations).toContainEqual(expect.objectContaining({ id: 'secp256k1.audit', category: 'crypto' }))
  })
  it.each([pubkey, be(GX), Uint8Array.from([4, ...be(GX), ...be(GY)])])('detects and inspects a public key', key => {
    const result = auditSecp256k1(key)
    expect(result.format).toBe('pubkey')
    expect(result.findings).toEqual([])
    expect(result.inspections[0]?.inspection).toMatchObject({ isValid: true, x: GX.toString() })
    expect(result.cryptographicSignaturesVerified).toBe(false)
    expect(() => JSON.stringify(result)).not.toThrow()
  })
  it('detects DER and compact ECDSA without narrowing scalar values', () => {
    const signature = der(N - 1n, 1n)
    expect(auditSecp256k1(signature)).toMatchObject({ format: 'der', findings: [] })
    const result = auditSecp256k1(Uint8Array.from([...be(N - 1n), ...be(1n)]))
    expect(result.format).toBe('compact')
    expect(result.inspections[0]?.inspection).toMatchObject({ r: (N - 1n).toString(), s: '1' })
  })
  it('recognizes a valid x-only public key whose first byte equals the DER sequence tag', () => {
    // OpenSSL's compressed public key for scalar 102, without its SEC prefix.
    const key = Uint8Array.from(Buffer.from('3049f7ffc71d744bd9bed6f42dc6a28974e3a1b9d30671f800e5d46389103c7e', 'hex'))
    expect(auditSecp256k1(key)).toMatchObject({ format: 'pubkey', findings: [] })
  })
  it('flags high-S with the required warning', () => {
    expect(auditSecp256k1(der(1n, N - 1n)).findings).toEqual([{
      severity: 'warning', code: 'high-s', message: 'Malleable signature detected (BIP-62/146 violation)', location: 'input',
    }])
  })
  it.each([be(P), Uint8Array.from([2, ...be(P)]), Uint8Array.from([4, ...be(GX), ...be(P)])])('flags field overflow as critical', key => {
    expect(auditSecp256k1(key).findings[0]).toMatchObject({ severity: 'critical', code: 'field-overflow' })
  })
  it.each([der(N, 1n), der(1n, N), Uint8Array.from([...be(N), ...be(N)])])('flags scalar overflow as critical without classifying it as malleability', signature => {
    const result = auditSecp256k1(signature)
    expect(result.findings.some(f => f.code === 'scalar-overflow' && f.message === 'Scalar overflow (k ≥ n)')).toBe(true)
    expect(result.findings.some(f => f.code === 'high-s')).toBe(false)
  })
  it('flags an invalid curve point', () => {
    expect(auditSecp256k1(be(0n)).findings[0]).toMatchObject({ severity: 'critical', code: 'invalid-point', message: 'Point not on secp256k1 curve' })
  })
  it('rejects zero scalars, malformed DER, invalid key prefixes and unrecognized inputs', () => {
    for (const bytes of [der(0n, 1n), Uint8Array.from([0x30, 6, 3, 1, 1, 2, 1, 1]), new Uint8Array(33), new Uint8Array(3)]) {
      expect(auditSecp256k1(bytes).findings[0]?.severity).toBe('critical')
    }
  })
  it('allows explicit format selection for ambiguous 64-byte encodings', () => {
    const bytes = new Uint8Array(64)
    bytes.set([0x30, 62, 2, 28, 1])
    bytes.set([2, 30, 1], 32)
    expect(auditSecp256k1(bytes).format).toBe('der')
    expect(auditSecp256k1(bytes, 'compact').format).toBe('compact')
    bytes.fill(0)
    bytes[0] = 0x30
    expect(auditSecp256k1(bytes).format).toBe('compact')
    expect(auditSecp256k1(bytes, 'der').findings[0]?.code).toBe('invalid-encoding')
  })
})

describe('secp256k1 audit Bitcoin framing and invariant checks', () => {
  it('prioritizes fully framed 64-byte transactions over compact signatures', () => {
    const raw = tx({ scriptSig: Uint8Array.from([0x51, 0x51, 0x51, 0x51]) })
    expect(raw.length).toBe(64)
    expect(auditSecp256k1(raw).format).toBe('bitcoin-tx')
  })
  it.each(['direct', 'p1', 'p2', 'p4'] as const)('extracts DER with sighash from scriptSig %s pushes', mode => {
    const scriptSig = Uint8Array.from([...push(Uint8Array.from([...der(1n, N - 1n), 1]), mode), ...push(pubkey)])
    const result = auditSecp256k1(tx({ scriptSig }))
    expect(result.format).toBe('bitcoin-tx')
    expect(result.inspections.map(i => i.kind)).toEqual(['der', 'pubkey'])
    expect(result.findings[0]?.code).toBe('high-s')
    expect(result.findings[0]?.location).toContain('transaction.inputs[0].scriptSig@')
  })
  it('inspects P2WPKH-shaped witness signatures with trailing sighash', () => {
    const raw = tx({ witness: [Uint8Array.from([...der(1n, N - 1n), 0x81]), pubkey] })
    const result = auditSecp256k1(raw)
    expect(result.transaction?.isSegWit).toBe(true)
    expect(result.findings[0]).toMatchObject({ code: 'high-s', location: 'transaction.inputs[0].witness[0]' })
    expect(result.inspections).toHaveLength(2)
    const legacy = tx()
    const expectedHash = createHash('sha256').update(createHash('sha256').update(legacy).digest()).digest('hex').toUpperCase()
    expect(result.transaction?.txidWire).toBe(expectedHash)
    expect(result.transaction?.weightUnits).toBe(legacy.length * 3 + raw.length)
    expect(result.transaction?.vsizeBytes).toBe(Math.ceil((legacy.length * 3 + raw.length) / 4))
  })
  it('does not apply ECDSA low-S policy to Taproot-shaped 64 or 65-byte witnesses', () => {
    for (const item of [Uint8Array.from([...be(1n), ...be(N - 1n)]), Uint8Array.from([...be(1n), ...be(N - 1n), 1])]) {
      const result = auditSecp256k1(tx({ witness: [item] }))
      expect(result.findings).toEqual([])
      expect(result.inspections).toEqual([])
      expect(result.uninspectedLocations).toContain('transaction.inputs[0].witness[0]')
    }
  })
  it('inspects exact P2PK and Taproot output key templates', () => {
    const overflow = auditSecp256k1(tx({ scriptPubKey: Uint8Array.from([33, 2, ...be(P), 0xac]) }))
    expect(overflow.findings[0]).toMatchObject({ code: 'field-overflow', message: 'Field element overflow (x ≥ p)' })
    expect(auditSecp256k1(tx({ scriptPubKey: Uint8Array.from([0x51, 32, ...be(GX)]) })).inspections[0]?.kind).toBe('pubkey')
  })
  it('does not infer keys from unrelated pushed data or coinbase metadata', () => {
    const data = Uint8Array.from([0x6a, 32, ...be(P)])
    expect(auditSecp256k1(tx({ scriptPubKey: data })).inspections).toEqual([])
    const result = auditSecp256k1(tx({ coinbase: true, scriptSig: Uint8Array.from([...push(der(1n, N - 1n)), ...push(pubkey)]) }))
    expect(result.inspections).toEqual([])
    expect(result.findings).toEqual([])
  })
  it.each([Uint8Array.from([0x4c]), Uint8Array.from([0x4d, 1]), Uint8Array.from([0x4e, 1, 0]), Uint8Array.from([5, 1])])('reports truncated script pushes', scriptSig => {
    expect(auditSecp256k1(tx({ scriptSig })).findings[0]?.message).toContain('Truncated script push')
  })
  it('detects output amounts and sums beyond MAX_MONEY with exact arithmetic', () => {
    const maxMoney = 2_100_000_000_000_000n
    for (const values of [[maxMoney + 1n], [maxMoney, 1n], [2n ** 64n - 1n]]) {
      const result = auditSecp256k1(tx({ values }))
      expect(result.transaction?.totalOutputSatoshis).toBe(values.reduce((sum, n) => sum + n, 0n).toString())
      expect(result.findings.some(f => f.message.includes('MAX_MONEY'))).toBe(true)
    }
    expect(auditSecp256k1(tx({ values: [maxMoney] })).findings).toEqual([])
  })
  it('detects duplicate inputs, empty outputs and malformed coinbase scripts', () => {
    expect(auditSecp256k1(tx({ inputs: 2 })).findings[0]?.message).toContain('Duplicate')
    expect(auditSecp256k1(tx({ values: [] })).findings[0]?.message).toBe('Transaction has no outputs')
    expect(auditSecp256k1(tx({ coinbase: true })).findings[0]?.message).toContain('Coinbase scriptSig')
  })
  it('detects empty inputs and null prevouts outside coinbase transactions', () => {
    expect(auditSecp256k1(tx({ inputs: 0, values: [] })).findings[0]?.message).toBe('Transaction has no inputs')
    expect(auditSecp256k1(tx({ inputs: 2, coinbase: true })).findings[0]?.message).toBe('Null prevout in a non-coinbase transaction')
  })
  it('rejects trailing bytes, unsupported flags, truncated counts and superfluous witness records', () => {
    const trailing = Uint8Array.from([...tx(), 0])
    const unknownFlag = tx({ witness: [new Uint8Array(0)] })
    unknownFlag[5] = 3
    const excessiveCount = tx()
    excessiveCount[4] = 100
    for (const bytes of [trailing, unknownFlag, excessiveCount, tx({ witness: [] })]) {
      expect(() => BitcoinParser.parseTransaction(bytes)).toThrow()
      expect(auditSecp256k1(bytes, 'bitcoin-tx').findings[0]?.code).toBe('invalid-encoding')
    }
  })
  it('retains a witness containing one empty item, which is not a superfluous witness record', () => {
    expect(BitcoinParser.parseTransaction(tx({ witness: [new Uint8Array(0)] })).inputs[0]?.witness).toHaveLength(1)
  })
  it('rejects noncanonical CompactSize and every truncated transaction', () => {
    const raw = tx()
    const noncanonical = Uint8Array.from([...raw.subarray(0, 4), 0xfd, 1, 0, ...raw.subarray(5)])
    expect(() => BitcoinParser.parseTransaction(noncanonical)).toThrow('Non-canonical CompactSize')
    for (let length = 0; length < raw.length; length++) expect(() => BitcoinParser.parseTransaction(raw.subarray(0, length))).toThrow()
  })
})

describe('audit operation and executable recipe integration', () => {
  const execute = (input: Secp256k1AuditInput, source?: MemoryByteSource, signal?: AbortSignal) =>
    createDefaultOperationRegistry().execute<Secp256k1AuditInput, Secp256k1AuditResult>('secp256k1.audit', input, { source, signal })
  it('returns identical JSON-safe results for direct bytes, hex, and ByteSource', async () => {
    const expected = auditSecp256k1(pubkey)
    for (const actual of [await execute(pubkey), await execute({ bytes: pubkey }), await execute({ rawHex: Buffer.from(pubkey).toString('hex') }), await execute({}, new MemoryByteSource(pubkey))]) {
      expect(actual).toEqual(expected)
      expect(JSON.parse(JSON.stringify(actual))).toEqual(actual)
    }
  })
  it('rejects missing, conflicting, invalid and oversized input', async () => {
    await expect(execute({})).rejects.toThrow('required')
    await expect(execute({ bytes: pubkey, rawHex: '00' })).rejects.toThrow('either')
    await expect(execute({ rawHex: '0xgg' })).rejects.toThrow()
    await expect(execute({ rawHex: '1' })).rejects.toThrow()
    const large = new Uint8Array(SECP256K1_AUDIT_MAX_BYTES + 1)
    expect(() => auditSecp256k1(large)).toThrow('1 MiB')
    await expect(execute({}, new MemoryByteSource(large))).rejects.toThrow('1 MiB')
    await expect(execute({ rawHex: ' '.repeat(SECP256K1_AUDIT_MAX_BYTES * 3 + 1) })).rejects.toThrow('size limit')
  })
  it('rejects incomplete source reads and already-aborted operations', async () => {
    const source = new MemoryByteSource(pubkey)
    vi.spyOn(source, 'read').mockResolvedValue(pubkey.subarray(0, 1))
    await expect(execute({}, source)).rejects.toThrow('Incomplete')
    await expect(execute(pubkey, undefined, AbortSignal.abort())).rejects.toThrow('aborted')
  })
  it('validates and runs the built-in audit recipe without mutating bytes', () => {
    expect(validateRecipe(SECP256K1_AUDIT_RECIPE).ok).toBe(true)
    const before = pubkey.slice()
    const result = runRecipe(SECP256K1_AUDIT_RECIPE, { input: pubkey }, { dryRun: true })
    expect(result.ok).toBe(true)
    expect(result.stepResults[0]?.outputValue).toEqual(auditSecp256k1(pubkey))
    expect(pubkey).toEqual(before)
    expect(() => JSON.stringify(result)).not.toThrow()
  })
  it('honors recipe ranges and explicit input formats', () => {
    const container = Uint8Array.from([255, ...pubkey, 255])
    const recipe = { ...SECP256K1_AUDIT_RECIPE, steps: [{ ...SECP256K1_AUDIT_RECIPE.steps[0]!, range: { start: 1, end: 34 }, parameters: { format: 'pubkey' } }] }
    expect(runRecipe(recipe, { input: container }).stepResults[0]?.outputValue).toEqual(auditSecp256k1(pubkey, 'pubkey'))
    recipe.steps[0]!.parameters.format = 'unsupported'
    expect(runRecipe(recipe, { input: container }).ok).toBe(false)
  })
})
