import { createECDH, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as crypto from '../crypto'
import {
  Secp256k1Engine as Engine, SECP256K1_N as N, SECP256K1_P as P,
  SECP256K1_GX as GX, SECP256K1_GY as GY, unsignedBigEndian,
} from '../index'
import type {
  Point, Secp256k1PublicKeyAggregationResult, SilentPaymentTweakResult,
  SilentPaymentOutputKeyResult, SilentPaymentTweakVerificationResult,
} from '../index'

const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'))
const be = (value: bigint) => hex(value.toString(16).padStart(64, '0'))
const G = { x: GX, y: GY }

interface ReferenceOutput {
  comment: string
  spendPubKey: string
  tweak: string
  outputKey: string
  parity: number
}

const vectors = JSON.parse(readFileSync(new URL('./fixtures/bip352-reference.json', import.meta.url), 'utf8')) as {
  aggregation: Array<{ comment: string; pubkeys: string[]; compressed: string }>
  outputs: ReferenceOutput[]
  labels: Array<{ comment: string; scanPrivKey: string; index: number; tweak: string; spendPubKey: string; labeledSpendPubKey: string; parity: number }>
}

function nativePubkey(scalar: bigint): Uint8Array {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(be(scalar))
  return new Uint8Array(ecdh.getPublicKey(undefined, 'compressed'))
}

function nativeTaggedHash(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const tagHash = createHash('sha256').update(tag).digest()
  const hash = createHash('sha256').update(tagHash).update(tagHash)
  for (const part of parts) hash.update(part)
  return new Uint8Array(hash.digest())
}

function indexBytes(index: number): Uint8Array {
  const bytes = new Uint8Array(4)
  new DataView(bytes.buffer).setUint32(0, index, false)
  return bytes
}

afterEach(() => vi.restoreAllMocks())

describe('Silent Payments public key aggregation', () => {
  it('exports all result contracts through the core API', () => {
    const aggregate: Secp256k1PublicKeyAggregationResult = Engine.aggregatePublicKeys([nativePubkey(1n)])
    const tweak: SilentPaymentTweakResult = Engine.createSilentPaymentTweak(G, new Uint8Array(32))
    const output: SilentPaymentOutputKeyResult = Engine.deriveSilentPaymentOutputKey(nativePubkey(1n), 1n)
    const verified: SilentPaymentTweakVerificationResult = Engine.verifySilentPaymentTweak(nativePubkey(1n), 1n, output.outputKey32!)
    expect([aggregate.valid, tweak.valid, output.valid, verified.valid]).toEqual([true, true, true, true])
  })

  it.each(vectors.aggregation)('matches the published input aggregate: $comment', vector => {
    const result = Engine.aggregatePublicKeys(vector.pubkeys.map(hex))
    expect(result.valid).toBe(true)
    expect(result.compressed).toEqual(hex(vector.compressed))
    const point = Engine.inspectPubKey(hex(vector.compressed))
    expect(result.point).toEqual({ x: point.x, y: point.y })
  })

  it.each([1, 2, 5])('matches independent OpenSSL aggregation of %s inputs', count => {
    const scalars = Array.from({ length: count }, (_, index) => BigInt(index + 1))
    const result = Engine.aggregatePublicKeys(scalars.map(nativePubkey))
    expect(result.compressed).toEqual(nativePubkey(scalars.reduce((sum, scalar) => sum + scalar, 0n)))
  })

  it('accepts one compressed or x-only key and preserves compressed odd parity', () => {
    const odd = nativePubkey(6n)
    expect(odd[0]).toBe(3)
    expect(Engine.aggregatePublicKeys([odd]).compressed).toEqual(odd)
    const even = Engine.aggregatePublicKeys([odd.subarray(1)])
    expect(even.compressed).toEqual(Uint8Array.from([2, ...odd.subarray(1)]))
    expect(even.point!.y & 1n).toBe(0n)
  })

  it('rejects empty aggregates and final sums at infinity', () => {
    expect(Engine.aggregatePublicKeys([])).toEqual({ valid: false, point: null, reason: 'Empty public key list' })
    expect(Engine.aggregatePublicKeys([nativePubkey(1n), nativePubkey(N - 1n)])).toEqual({ valid: false, point: null, reason: 'Aggregated public key is point at infinity' })
    const odd = nativePubkey(6n)
    expect(Engine.aggregatePublicKeys([odd, odd.subarray(1)]).reason).toBe('Aggregated public key is point at infinity')
  })

  it('allows an intermediate infinity when the final sum is finite', () => {
    expect(Engine.aggregatePublicKeys([nativePubkey(1n), nativePubkey(N - 1n), nativePubkey(1n)]).compressed).toEqual(nativePubkey(1n))
  })

  it.each([
    new Uint8Array(0), new Uint8Array(31), new Uint8Array(34),
    hex(`04${GX.toString(16)}`), hex(`02${P.toString(16)}`), new Uint8Array(32),
    hex(`04${GX.toString(16)}${GY.toString(16)}`),
  ])('rejects invalid lengths, SEC prefixes and curve points (%s)', pubkey => {
    expect(Engine.aggregatePublicKeys([nativePubkey(1n), pubkey])).toEqual({ valid: false, point: null, reason: 'Invalid public key in aggregation' })
  })
})

describe('directive shared-secret tweak transcript', () => {
  // The directive deliberately includes outpointsHash32 in this transcript.
  // This differs from the published BIP-352 shared-secret hash; official vector
  // coverage below verifies aggregation, output addition and labels directly.
  it.each([0, 1, 256, 0x01020304, 0xffffffff])('matches native SHA-256 with uint32 big-endian index %s', index => {
    const outpoints = nativeTaggedHash('BIP0352/Inputs', hex('11'.repeat(32) + '00000000'), nativePubkey(1n))
    const expected = nativeTaggedHash('BIP0352/SharedSecret', nativePubkey(1n), outpoints, indexBytes(index))
    expect(Engine.createSilentPaymentTweak(G, outpoints, index)).toEqual({ valid: true, tweak: unsignedBigEndian(expected), tweakBytes: expected })
  })

  it('defaults to index zero and binds the hash to Q parity, outpoints and index', () => {
    const outpoints = new Uint8Array(32)
    const defaultTweak = Engine.createSilentPaymentTweak(G, outpoints)
    expect(defaultTweak).toEqual(Engine.createSilentPaymentTweak(G, outpoints, 0))
    expect(Engine.createSilentPaymentTweak({ x: GX, y: P - GY }, outpoints).tweak).not.toBe(defaultTweak.tweak)
    expect(Engine.createSilentPaymentTweak(G, new Uint8Array(32).fill(1)).tweak).not.toBe(defaultTweak.tweak)
    expect(Engine.createSilentPaymentTweak(G, outpoints, 1).tweak).not.toBe(defaultTweak.tweak)
  })

  it.each([
    null, { x: 0n, y: 0n }, { x: -1n, y: GY }, { x: GX + P, y: GY },
    { x: GX, y: -GY }, { x: GX, y: GY + P }, { x: GX, y: GY + 1n },
  ] as Point[])('rejects infinity, off-curve and noncanonical ECDH points (%s)', point => {
    expect(Engine.createSilentPaymentTweak(point, new Uint8Array(32))).toEqual({ valid: false, tweak: 0n, reason: 'ECDH point is null or invalid' })
  })

  it.each([0, 31, 33])('rejects an outpoints hash of %s bytes', length => {
    expect(Engine.createSilentPaymentTweak(G, new Uint8Array(length))).toEqual({ valid: false, tweak: 0n, reason: 'Outpoints hash must be 32 bytes' })
  })

  it.each([-1, 0.5, 2 ** 32, Number.MAX_SAFE_INTEGER, NaN, Infinity])('rejects uint32 index coercion (%s)', index => {
    expect(Engine.createSilentPaymentTweak(G, new Uint8Array(32), index)).toEqual({ valid: false, tweak: 0n, reason: 'Output index must be a uint32' })
  })

  it.each([[0n, 'Tweak scalar is zero'], [N, 'Tweak scalar >= n'], [N + 1n, 'Tweak scalar >= n']] as const)('rejects hash scalar %s without reducing it', (scalar, reason) => {
    vi.spyOn(crypto, 'taggedHash').mockReturnValue(be(scalar))
    expect(Engine.createSilentPaymentTweak(G, new Uint8Array(32))).toEqual({ valid: false, tweak: 0n, reason })
  })

  it('accepts the largest canonical hash scalar', () => {
    vi.spyOn(crypto, 'taggedHash').mockReturnValue(be(N - 1n))
    expect(Engine.createSilentPaymentTweak(G, new Uint8Array(32))).toEqual({ valid: true, tweak: N - 1n, tweakBytes: be(N - 1n) })
  })

  it('derives and verifies a full directive transcript against independent OpenSSL', () => {
    const outpoints = new Uint8Array(32).fill(42)
    const tweak = Engine.createSilentPaymentTweak(G, outpoints, 3)
    const expectedHash = nativeTaggedHash('BIP0352/SharedSecret', nativePubkey(1n), outpoints, indexBytes(3))
    const expected = nativePubkey((17n + unsignedBigEndian(expectedHash)) % N)
    expect(tweak.tweakBytes).toEqual(expectedHash)
    expect(Engine.deriveSilentPaymentOutputKey(nativePubkey(17n), tweak.tweak)).toEqual({ valid: true, outputKey32: expected.subarray(1), parity: expected[0]! & 1 })
    expect(Engine.verifySilentPaymentTweak(nativePubkey(17n), tweak.tweakBytes!, expected.subarray(1))).toEqual({ valid: true, parity: expected[0]! & 1 })
  })
})

describe('Silent Payments output key addition and verification', () => {
  it.each(vectors.outputs)('derives and verifies the published output: $comment ($outputKey)', vector => {
    const spendKey = hex(vector.spendPubKey)
    for (const tweak of [hex(vector.tweak), BigInt(`0x${vector.tweak}`)]) {
      expect(Engine.deriveSilentPaymentOutputKey(spendKey, tweak)).toEqual({ valid: true, outputKey32: hex(vector.outputKey), parity: vector.parity })
      expect(Engine.verifySilentPaymentTweak(spendKey, tweak, hex(vector.outputKey))).toEqual({ valid: true, parity: vector.parity })
    }
    if (spendKey[0] === 2) expect(Engine.verifySilentPaymentTweak(spendKey.subarray(1), hex(vector.tweak), hex(vector.outputKey))).toEqual({ valid: true, parity: vector.parity })
  })

  it.each([[1n, 1n], [1n, 2n], [3n, 7n], [42n, 17n], [N - 1n, 2n], [2n, N - 1n]])('matches native addition for spend scalar %s and tweak %s', (spendScalar, tweak) => {
    const spendKey = nativePubkey(spendScalar)
    const expected = nativePubkey((spendScalar + tweak) % N)
    expect(Engine.deriveSilentPaymentOutputKey(spendKey, tweak)).toEqual({ valid: true, outputKey32: expected.subarray(1), parity: expected[0]! & 1 })
    const evenScalar = spendKey[0] === 2 ? spendScalar : N - spendScalar
    const evenExpected = nativePubkey((evenScalar + tweak) % N)
    expect(Engine.deriveSilentPaymentOutputKey(spendKey.subarray(1), be(tweak))).toEqual({ valid: true, outputKey32: evenExpected.subarray(1), parity: evenExpected[0]! & 1 })
  })

  it('preserves spend-key compressed parity instead of silently lifting to even Y', () => {
    const odd = nativePubkey(6n)
    const compressed = Engine.deriveSilentPaymentOutputKey(odd, 1n)
    const xOnly = Engine.deriveSilentPaymentOutputKey(odd.subarray(1), 1n)
    expect(compressed.outputKey32).not.toEqual(xOnly.outputKey32)
    expect(compressed.outputKey32).toEqual(nativePubkey(7n).subarray(1))
  })

  it.each([-1n, 0n, N, N + 1n, 2n ** 256n])('rejects noncanonical scalar %s before multiplication', tweak => {
    expect(Engine.deriveSilentPaymentOutputKey(nativePubkey(1n), tweak)).toEqual({ valid: false, reason: 'Tweak scalar outside valid range (0 < t < n)' })
  })

  it.each([0n, N, N + 1n])('rejects noncanonical byte scalar %s before multiplication', tweak => {
    expect(Engine.verifySilentPaymentTweak(nativePubkey(1n), be(tweak), nativePubkey(2n).subarray(1))).toEqual({ valid: false, parity: -1, reason: 'Tweak scalar outside valid range (0 < t < n)' })
  })

  it.each([0, 31, 33, 64])('rejects a scalar encoding of %s bytes', length => {
    expect(Engine.deriveSilentPaymentOutputKey(nativePubkey(1n), new Uint8Array(length))).toEqual({ valid: false, reason: 'Tweak scalar must be 32 bytes' })
  })

  it.each([new Uint8Array(31), new Uint8Array(32), be(P), hex(`04${GX.toString(16)}`), hex(`02${P.toString(16)}`), hex(`04${GX.toString(16)}${GY.toString(16)}`)])('rejects an invalid spend public key (%s)', key => {
    expect(Engine.deriveSilentPaymentOutputKey(key, 1n)).toEqual({ valid: false, reason: 'Invalid spend public key' })
    expect(Engine.verifySilentPaymentTweak(key, 1n, new Uint8Array(32))).toEqual({ valid: false, parity: -1, reason: 'Invalid spend public key' })
  })

  it('rejects the tweaked point at infinity for both parity encodings', () => {
    for (const [spend, tweak] of [[nativePubkey(1n), N - 1n], [nativePubkey(N - 1n), 1n]] as const) {
      expect(Engine.deriveSilentPaymentOutputKey(spend, tweak)).toEqual({ valid: false, reason: 'Tweaked point is point at infinity' })
      expect(Engine.verifySilentPaymentTweak(spend, tweak, be(GX))).toEqual({ valid: false, parity: -1, reason: 'Tweaked point is point at infinity' })
    }
  })

  it.each([0, 31, 33, 64])('rejects an expected output encoding of %s bytes', length => {
    expect(Engine.verifySilentPaymentTweak(nativePubkey(1n), 1n, new Uint8Array(length))).toEqual({ valid: false, parity: -1, reason: 'Expected output key must be 32 bytes' })
  })

  it('retains derived parity when the expected output mismatches', () => {
    const expected = nativePubkey(2n)
    const damaged = expected.subarray(1).slice()
    damaged[31] ^= 1
    expect(Engine.verifySilentPaymentTweak(nativePubkey(1n), 1n, damaged)).toEqual({ valid: false, parity: expected[0]! & 1, reason: 'Output key mismatch' })
    expect(Engine.verifySilentPaymentTweak(nativePubkey(1n), 1n, be(P)).reason).toBe('Output key mismatch')
  })
})

describe('Silent Payments labeled address tweaks', () => {
  it.each(vectors.labels)('matches the published labeled spend point: $comment ($index)', vector => {
    const label = Engine.deriveSilentPaymentLabelTweak(hex(vector.scanPrivKey), vector.index)
    expect(label).toEqual({ valid: true, tweak: BigInt(`0x${vector.tweak}`), tweakBytes: hex(vector.tweak) })
    expect(Engine.deriveSilentPaymentOutputKey(hex(vector.spendPubKey), label.tweak)).toEqual({ valid: true, outputKey32: hex(vector.labeledSpendPubKey).subarray(1), parity: vector.parity })
  })

  it.each([0, 1, 256, 0x01020304, 0xffffffff])('uses scan private bytes and big-endian label index %s', index => {
    const scan = be(17n)
    const expected = nativeTaggedHash('BIP0352/Label', scan, indexBytes(index))
    expect(Engine.deriveSilentPaymentLabelTweak(scan, index)).toEqual({ valid: true, tweak: unsignedBigEndian(expected), tweakBytes: expected })
  })

  it.each([0, 31, 33])('rejects a scan key encoding of %s bytes', length => {
    expect(Engine.deriveSilentPaymentLabelTweak(new Uint8Array(length), 0)).toEqual({ valid: false, tweak: 0n, reason: 'Scan private key must be 32 bytes' })
  })

  it.each([0n, N, N + 1n])('rejects a noncanonical scan private scalar %s', scalar => {
    expect(Engine.deriveSilentPaymentLabelTweak(be(scalar), 0)).toEqual({ valid: false, tweak: 0n, reason: 'Scan private key outside valid range (0 < b_scan < n)' })
  })

  it.each([-1, 0.5, 2 ** 32, NaN, Infinity])('rejects a noncanonical label index %s', index => {
    expect(Engine.deriveSilentPaymentLabelTweak(be(1n), index)).toEqual({ valid: false, tweak: 0n, reason: 'Label index must be a uint32' })
  })

  it.each([[0n, 'Tweak scalar is zero'], [N, 'Tweak scalar >= n'], [N + 1n, 'Tweak scalar >= n']] as const)('rejects noncanonical label hash %s without reduction', (scalar, reason) => {
    vi.spyOn(crypto, 'taggedHash').mockReturnValue(be(scalar))
    expect(Engine.deriveSilentPaymentLabelTweak(be(1n), 0)).toEqual({ valid: false, tweak: 0n, reason })
  })

  it('binds label hash to the private scan scalar and label index', () => {
    const label = Engine.deriveSilentPaymentLabelTweak(be(1n), 1)
    expect(label.tweak).not.toBe(Engine.deriveSilentPaymentLabelTweak(be(2n), 1).tweak)
    expect(label.tweak).not.toBe(Engine.deriveSilentPaymentLabelTweak(be(1n), 2).tweak)
    expect(Engine.deriveSilentPaymentLabelTweak(be(N - 1n), 0).valid).toBe(true)
  })
})

it('preserves all caller-owned points, key bytes, hashes and tweaks', () => {
  const point = { ...G }
  const keys = [nativePubkey(1n), nativePubkey(2n)]
  const keysBefore = keys.map(key => key.slice())
  const outpoints = new Uint8Array(32).fill(7)
  const outpointsBefore = outpoints.slice()
  const scalar = be(1n)
  const scalarBefore = scalar.slice()
  const expectedOutput = nativePubkey(2n).subarray(1).slice()
  const expectedBefore = expectedOutput.slice()
  Engine.aggregatePublicKeys(keys)
  Engine.createSilentPaymentTweak(point, outpoints)
  const derived = Engine.deriveSilentPaymentOutputKey(keys[0], scalar)
  Engine.verifySilentPaymentTweak(keys[0], scalar, expectedOutput)
  const label = Engine.deriveSilentPaymentLabelTweak(scalar, 1)
  derived.outputKey32!.fill(0)
  label.tweakBytes!.fill(0)
  expect(point).toEqual(G)
  expect(keys).toEqual(keysBefore)
  expect(outpoints).toEqual(outpointsBefore)
  expect(scalar).toEqual(scalarBefore)
  expect(expectedOutput).toEqual(expectedBefore)
})
