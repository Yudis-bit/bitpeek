import { createECDH, createHash } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as crypto from '../crypto'
import { unsignedBigEndian } from '../bytes'
import { auditBip375Shares, BIP375_MAX_SIGNERS, BIP375_MAX_OUTPUTS, type Bip375AuditParams } from './bip375'
import { SECP256K1_GX, SECP256K1_GY, SECP256K1_N as N, Secp256k1Engine, scalarMul, compressedPoint, pointAdd } from './secp256k1'
import { referenceScalarMul, referencePointAdd } from './secp256k1-diff-oracle'

const G = { x: SECP256K1_GX, y: SECP256K1_GY }
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex')
const be = (value: bigint) => Uint8Array.from(Buffer.from(value.toString(16).padStart(64, '0'), 'hex'))
function nativeKey(scalar: bigint): Uint8Array {
  const native = createECDH('secp256k1'); native.setPrivateKey(be(scalar))
  return Uint8Array.from(native.getPublicKey(undefined, 'compressed'))
}
function taggedHash(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const digest = createHash('sha256').update(tag).digest(), hash = createHash('sha256').update(digest).update(digest)
  for (const part of parts) hash.update(part)
  return hash.digest()
}
const scan = scalarMul(5n, G)!, spend = nativeKey(7n), outpoint = new Uint8Array(36).fill(3)
function signer(d: bigint, xOnly = false) {
  const point = scalarMul(d, G)!
  if (xOnly && (point.y & 1n) !== 0n) d = N - d
  const input = scalarMul(d, G)!, share = scalarMul(d, scan)!
  return { inputPubkey: xOnly ? be(input.x) : nativeKey(d), ecdhShare: nativeKey(d * 5n % N),
    dleqProof: Secp256k1Engine.proveDLEQ(d, G, input, scan, share, be(11n)) }
}
const a = signer(3n), b = signer(11n), xOnlySigner = signer(9n, true)
const base: Bip375AuditParams = { signers: [a, b], scanPubkey: nativeKey(5n), spendPubkey: spend,
  outpointSmallest: outpoint, allInputPubkeys: [a.inputPubkey, b.inputPubkey], outputCount: 2 }
afterEach(() => vi.restoreAllMocks())

describe('BIP-375 extracted signer-share audit and scalar folding', () => {
  it.each(['specification', 'published-bip'] as const)('verifies multiple signer proofs, aggregation and outputs under %s', profile => {
    const audit = auditBip375Shares({ ...base, profile })
    expect(audit).toMatchObject({ valid: true, signerCount: 2, verifiedSigners: [true, true], profile })
    expect(audit.aggregatedShareHex).toBe(hex(nativeKey(70n)))
    const expectedHash = profile === 'specification' ? taggedHash('BIP0352/Inputs', outpoint, ...base.allInputPubkeys.slice().sort((left, right) => Buffer.compare(left, right)))
      : taggedHash('BIP0352/Inputs', outpoint, nativeKey(14n))
    expect(audit.inputHashHex).toBe(hex(expectedHash))
    const S = referenceScalarMul(unsignedBigEndian(expectedHash), referenceScalarMul(70n, G))!
    expect(audit.scalarFoldTweakHex).toBe(hex(compressedPoint(S)))
    for (let k = 0; k < 2; k++) {
      const index = new Uint8Array(4); new DataView(index.buffer).setUint32(0, k, false)
      const tweak = unsignedBigEndian(taggedHash('BIP0352/SharedSecret', compressedPoint(S), index))
      const output = referencePointAdd(referenceScalarMul(7n, G), referenceScalarMul(tweak, G))!
      expect(audit.expectedOutputKeysHex?.[k]).toBe(output.x.toString(16).padStart(64, '0'))
    }
  })
  it('accepts a single signer and a valid x-only normalized input key', () => {
    expect(auditBip375Shares({ ...base, signers: [xOnlySigner], allInputPubkeys: [xOnlySigner.inputPubkey] })).toMatchObject({ valid: true, verifiedSigners: [true] })
  })
  it('preserves multiset coverage for repeated eligible keys', () => {
    const repeated = auditBip375Shares({ ...base, signers: [a, a], allInputPubkeys: [a.inputPubkey, a.inputPubkey] })
    expect(repeated.valid).toBe(true)
    expect(repeated.aggregatedShareHex).toBe(hex(nativeKey(30n)))
  })
  it('is independent of signer and eligible-key order in both profiles', () => {
    for (const profile of ['specification', 'published-bip'] as const) {
      const original = auditBip375Shares({ ...base, profile })
      expect(auditBip375Shares({ ...base, signers: [b, a], allInputPubkeys: [b.inputPubkey, a.inputPubkey], profile })).toEqual(original)
    }
  })
  it('checks observed scalar fold and multiple x-only recipient outputs', () => {
    const original = auditBip375Shares(base)
    const expectedScalarFold = Uint8Array.from(Buffer.from(original.scalarFoldTweakHex!, 'hex'))
    const expectedOutputs = original.expectedOutputKeysHex!.map(output => Uint8Array.from(Buffer.from(output, 'hex')))
    expect(auditBip375Shares({ ...base, expectedScalarFold, expectedOutputs })).toMatchObject({ valid: true, verifiedOutputs: [true, true] })
  })
  it('uses zero outputs when requested and defaults to one when omitted', () => {
    expect(auditBip375Shares({ ...base, outputCount: 0 }).expectedOutputKeysHex).toEqual([])
    expect(auditBip375Shares({ ...base, outputCount: undefined }).expectedOutputKeysHex).toHaveLength(1)
  })
  it('derives output count from the observed output list', () => {
    const original = auditBip375Shares({ ...base, outputCount: 1 })
    const expectedOutputs = [Uint8Array.from(Buffer.from(original.expectedOutputKeysHex![0], 'hex'))]
    expect(auditBip375Shares({ ...base, outputCount: undefined, expectedOutputs }).valid).toBe(true)
  })
  it.each([[], [a, a], [b], [a, b, a]].map((signers, index) => ({ signers, index })))('rejects empty, missing or duplicate coverage (case $index)', ({ signers }) => {
    expect(auditBip375Shares({ ...base, signers }).valid).toBe(false)
  })
  it('rejects a rogue signer whose valid proof belongs to another eligible-key set', () => {
    expect(auditBip375Shares({ ...base, signers: [a, xOnlySigner] })).toMatchObject({ valid: false, verifiedSigners: [true, false],
      rejectionReason: expect.stringContaining('rogue') })
  })
  it('rejects a substituted ECDH share even when it is an on-curve compressed point', () => {
    expect(auditBip375Shares({ ...base, signers: [{ ...a, ecdhShare: b.ecdhShare }, b] }).rejectionReason).toContain('DLEQ')
  })
  it('rejects a share/proof replay under another recipient scan key', () => {
    expect(auditBip375Shares({ ...base, scanPubkey: nativeKey(6n) }).rejectionReason).toContain('DLEQ')
  })
  it.each([0, 15, 31, 32, 47, 63])('detects DLEQ proof corruption at byte %s', offset => {
    const proof = a.dleqProof.slice(); proof[offset] ^= 1
    expect(auditBip375Shares({ ...base, signers: [{ ...a, dleqProof: proof }, b] }).valid).toBe(false)
  })
  it.each([0, 32, 63, 65])('rejects a %s-byte proof', length => {
    expect(auditBip375Shares({ ...base, signers: [{ ...a, dleqProof: new Uint8Array(length) }, b] }).rejectionReason).toContain('64 bytes')
  })
  it.each([0, 32, 34, 65])('rejects a %s-byte ECDH share', length => {
    expect(auditBip375Shares({ ...base, signers: [{ ...a, ecdhShare: new Uint8Array(length) }, b] }).rejectionReason).toContain('compressed ECDH share')
  })
  it.each(['scanPubkey', 'spendPubkey'] as const)('rejects invalid %s', property => {
    expect(auditBip375Shares({ ...base, [property]: be(0n) }).valid).toBe(false)
  })
  it('rejects invalid signer and eligible public keys', () => {
    expect(auditBip375Shares({ ...base, signers: [{ ...a, inputPubkey: be(0n) }, b] }).rejectionReason).toContain('input public key')
    expect(auditBip375Shares({ ...base, allInputPubkeys: [be(0n), b.inputPubkey] }).rejectionReason).toContain('eligible input')
  })
  it.each([0, 35, 37])('requires a 36-byte serialized smallest outpoint (%s)', length => {
    expect(auditBip375Shares({ ...base, outpointSmallest: new Uint8Array(length) }).rejectionReason).toContain('36 bytes')
  })
  it.each([-1, 1.5, BIP375_MAX_OUTPUTS + 1])('bounds output count %s', outputCount => {
    expect(auditBip375Shares({ ...base, outputCount }).valid).toBe(false)
  })
  it('bounds signer/input counts and checks output list consistency', () => {
    expect(auditBip375Shares({ ...base, signers: Array.from({ length: BIP375_MAX_SIGNERS + 1 }, () => a) }).valid).toBe(false)
    expect(auditBip375Shares({ ...base, allInputPubkeys: [] }).valid).toBe(false)
    expect(auditBip375Shares({ ...base, allInputPubkeys: Array.from({ length: BIP375_MAX_SIGNERS + 1 }, () => a.inputPubkey) }).valid).toBe(false)
    expect(auditBip375Shares({ ...base, expectedOutputs: [] }).rejectionReason).toContain('length must equal')
  })
  it('rejects mismatched and malformed expected scalar-fold points', () => {
    expect(auditBip375Shares({ ...base, expectedScalarFold: nativeKey(1n) }).rejectionReason).toContain('Scalar fold mismatch')
    expect(auditBip375Shares({ ...base, expectedScalarFold: be(1n) }).valid).toBe(false)
  })
  it('rejects recipient output mismatches and invalid x-only encodings', () => {
    expect(auditBip375Shares({ ...base, expectedOutputs: [be(0n), be(1n)] })).toMatchObject({ valid: false, verifiedOutputs: [false, false] })
  })
  it.each([0n, N, N + 1n])('rejects input-hash scalar %s without silently reducing it', value => {
    const original = crypto.taggedHash
    vi.spyOn(crypto, 'taggedHash').mockImplementation((tag, ...parts) => tag === 'BIP0352/Inputs' ? be(value) : original(tag, ...parts))
    expect(auditBip375Shares(base).rejectionReason).toContain('input_hash')
  })
  it.each([0n, N, N + 1n])('rejects derived output tweak %s', value => {
    const original = crypto.taggedHash
    vi.spyOn(crypto, 'taggedHash').mockImplementation((tag, ...parts) => tag === 'BIP0352/SharedSecret' ? be(value) : original(tag, ...parts))
    expect(auditBip375Shares(base).rejectionReason).toContain('tweak')
  })
  it('rejects cancellation of eligible public-key sums at infinity', () => {
    const inverse = nativeKey(N - 3n)
    expect(pointAdd(scalarMul(3n, G), scalarMul(N - 3n, G))).toBeNull()
    expect(auditBip375Shares({ ...base, allInputPubkeys: [a.inputPubkey, inverse] }).rejectionReason).toContain('input public key is point at infinity')
  })
  it('rejects a derived recipient key at infinity', () => {
    const original = crypto.taggedHash
    vi.spyOn(crypto, 'taggedHash').mockImplementation((tag, ...parts) => tag === 'BIP0352/SharedSecret' ? be(N - 7n) : original(tag, ...parts))
    expect(auditBip375Shares(base).rejectionReason).toContain('derived key is point at infinity')
  })
  it('binds the outpoint in the input hash and leaves every caller buffer unchanged', () => {
    const buffers = [outpoint, base.scanPubkey, spend, ...base.signers.flatMap(item => [item.inputPubkey, item.ecdhShare, item.dleqProof])]
    const copies = buffers.map(buffer => buffer.slice())
    const original = auditBip375Shares(base)
    expect(auditBip375Shares({ ...base, outpointSmallest: new Uint8Array(36).fill(4) }).scalarFoldTweakHex).not.toBe(original.scalarFoldTweakHex)
    expect(buffers).toEqual(copies)
  })
})
