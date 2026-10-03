import { createECDH, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as crypto from '../crypto'
import { unsignedBigEndian } from '../bytes'
import { Secp256k1Engine as Engine, SECP256K1_N as N, SECP256K1_GX as GX, SECP256K1_GY as GY } from './secp256k1'
import type { Bip340NonceResult, Bip340SignResult, Bip340AuxAuditResult } from '../index'

interface SigningVector {
  index: number
  secretKey: string
  publicKey: string
  auxRand: string
  message: string
  signature: string
}

const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/bip340-signing-vectors.json', import.meta.url), 'utf8')) as { vectors: SigningVector[] }
const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'))
const be = (value: bigint) => hex(value.toString(16).padStart(64, '0'))
const zero = new Uint8Array(32)
const key = be(3n)
const signature = hex(vectors[0]!.signature)
const G = { x: GX, y: GY }

function nativeTaggedHash(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const tagHash = createHash('sha256').update(tag).digest()
  const hash = createHash('sha256').update(tagHash).update(tagHash)
  for (const part of parts) hash.update(part)
  return hash.digest()
}

afterEach(() => vi.restoreAllMocks())

describe('BIP-340 reference signing and synthetic nonce derivation', () => {
  it.each(vectors)('reproduces published signing vector $index byte for byte', vector => {
    const result: Bip340SignResult = Engine.bip340Sign(hex(vector.secretKey), hex(vector.message), hex(vector.auxRand))
    const expected = hex(vector.signature)
    expect(result).toEqual({ valid: true, signature64: expected, publicKey32: hex(vector.publicKey),
      rx: unsignedBigEndian(expected.subarray(0, 32)), s: unsignedBigEndian(expected.subarray(32)) })
    expect(Engine.verifySchnorr(result.publicKey32!, hex(vector.message), result.signature64!)).toEqual({ valid: true })
  })

  it.each(vectors)('derives the normalized nonce implied by published vector $index', vector => {
    const secret = hex(vector.secretKey)
    const publicKey = hex(vector.publicKey)
    const msg = hex(vector.message)
    const expected = hex(vector.signature)
    const nativeKey = createECDH('secp256k1')
    nativeKey.setPrivateKey(secret)
    const dPrime = unsignedBigEndian(secret)
    const d = nativeKey.getPublicKey(undefined, 'compressed')[0] === 2 ? dPrime : N - dPrime
    const e = unsignedBigEndian(nativeTaggedHash('BIP0340/challenge', expected.subarray(0, 32), publicKey, msg)) % N
    const expectedK = ((unsignedBigEndian(expected.subarray(32)) - e * d) % N + N) % N
    const nonce: Bip340NonceResult = Engine.bip340DeriveNonce(secret, msg, hex(vector.auxRand))
    expect(nonce).toEqual({ valid: true, k: expectedK, rx: unsignedBigEndian(expected.subarray(0, 32)) })
    const commitment = Engine.scalarMul(nonce.k!, G)!
    expect(commitment.x).toBe(nonce.rx)
    expect(commitment.y & 1n).toBe(0n)
  })

  it('uses zero aux when omitted, reproducing published vector 0', () => {
    expect(Engine.bip340Sign(key, zero).signature64).toEqual(signature)
    expect(Engine.bip340Sign(key, zero, zero).signature64).toEqual(signature)
    expect(Engine.bip340DeriveNonce(key, zero)).toEqual(Engine.bip340DeriveNonce(key, zero, zero))
  })

  it('normalizes inverse secret keys to the same x-only signing key', () => {
    for (const vector of vectors) {
      const inverseKey = be(N - unsignedBigEndian(hex(vector.secretKey)))
      expect(Engine.bip340Sign(inverseKey, hex(vector.message), hex(vector.auxRand)).signature64).toEqual(hex(vector.signature))
    }
  })

  it.each([0n, N, N + 1n])('rejects out-of-range secret scalar %s without reducing it', scalar => {
    expect(Engine.bip340DeriveNonce(be(scalar), zero)).toEqual({ valid: false, reason: 'Secret key outside range 0 < d < n' })
    expect(Engine.bip340Sign(be(scalar), zero)).toEqual({ valid: false, reason: 'Secret key outside range 0 < d < n' })
  })

  it.each([0, 31, 33])('rejects %s-byte keys, messages and aux data', length => {
    const malformed = new Uint8Array(length)
    expect(Engine.bip340DeriveNonce(malformed, zero).valid).toBe(false)
    expect(Engine.bip340Sign(key, malformed).valid).toBe(false)
    expect(Engine.bip340Sign(key, zero, malformed)).toEqual({ valid: false, reason: 'auxRand must be 32 bytes when supplied' })
  })

  it.each([0n, N])('rejects a nonce hash that reduces to zero (%s)', nonceHash => {
    const original = crypto.taggedHash
    vi.spyOn(crypto, 'taggedHash').mockImplementation((tag, ...parts) => tag === 'BIP0340/nonce' ? be(nonceHash) : original(tag, ...parts))
    expect(Engine.bip340DeriveNonce(key, zero)).toEqual({ valid: false, reason: 'Derived nonce is zero' })
    expect(Engine.bip340Sign(key, zero)).toEqual({ valid: false, reason: 'Derived nonce is zero' })
  })

  it('reduces an overflowing nonce hash modulo n', () => {
    const original = crypto.taggedHash
    vi.spyOn(crypto, 'taggedHash').mockImplementation((tag, ...parts) => tag === 'BIP0340/nonce' ? be(N + 1n) : original(tag, ...parts))
    expect(Engine.bip340DeriveNonce(key, zero)).toEqual({ valid: true, k: 1n, rx: GX })
    expect(Engine.bip340Sign(key, zero).valid).toBe(true)
  })

  it('withholds the signature if its mandatory self-verification fails', () => {
    vi.spyOn(Engine, 'verifySchnorr').mockReturnValue({ valid: false, reason: 'Injected verification failure' })
    expect(Engine.bip340Sign(key, zero)).toEqual({ valid: false, reason: 'Signature self-verification failed: Injected verification failure' })
  })

  it('does not modify secret, message or auxiliary input buffers', () => {
    const vector = vectors[2]!
    const inputs = [hex(vector.secretKey), hex(vector.message), hex(vector.auxRand)] as const
    const copies = inputs.map(bytes => bytes.slice())
    Engine.bip340DeriveNonce(...inputs)
    Engine.bip340Sign(...inputs)
    expect(inputs).toEqual(copies)
  })
})

describe('BIP-340 auxiliary-randomness invariant audit', () => {
  it('identifies the zero-aux default with an omitted or zero candidate', () => {
    const audit: Bip340AuxAuditResult = Engine.bip340AuditSignatureAux(key, zero, signature)
    expect(audit).toMatchObject({ valid: true, matchesAux: true, isDeterministicDefault: true, expectedSignature: signature })
    expect(audit.candidateSignature).toBeUndefined()
    expect(Engine.bip340AuditSignatureAux(key, zero, signature, zero)).toMatchObject({ valid: true,
      matchesAux: true, isDeterministicDefault: true, candidateSignature: signature })
  })

  it.each(vectors.slice(1))('matches the nonzero aux in published vector $index', vector => {
    const audit = Engine.bip340AuditSignatureAux(hex(vector.secretKey), hex(vector.message), hex(vector.signature), hex(vector.auxRand))
    expect(audit).toMatchObject({ valid: true, matchesAux: true, isDeterministicDefault: false, candidateSignature: hex(vector.signature) })
    expect(audit.expectedSignature).not.toEqual(audit.candidateSignature)
  })

  it('keeps the deterministic-default flag independent of a wrong candidate aux', () => {
    expect(Engine.bip340AuditSignatureAux(key, zero, signature, be(1n))).toMatchObject({ valid: true,
      matchesAux: false, isDeterministicDefault: true, expectedSignature: signature })
  })

  it('reports a nondefault signature without a candidate as an unmatched comparison', () => {
    const vector = vectors[1]!
    expect(Engine.bip340AuditSignatureAux(hex(vector.secretKey), hex(vector.message), hex(vector.signature)))
      .toMatchObject({ valid: true, matchesAux: false, isDeterministicDefault: false })
  })

  it('does not mistake an unrelated 64-byte signature or changed message for either transcript', () => {
    for (const [msg, sig] of [[zero, new Uint8Array(64)], [be(1n), signature]]) {
      expect(Engine.bip340AuditSignatureAux(key, msg!, sig!, be(1n)))
        .toMatchObject({ valid: true, matchesAux: false, isDeterministicDefault: false })
    }
  })

  it.each([0, 63, 65])('rejects a %s-byte observed signature', length => {
    expect(Engine.bip340AuditSignatureAux(key, zero, new Uint8Array(length))).toEqual({ valid: false,
      matchesAux: false, isDeterministicDefault: false, reason: 'Signature must be 64 bytes' })
  })

  it.each([0, 31, 33])('rejects a %s-byte candidate aux even when the signature matches zero aux', length => {
    expect(Engine.bip340AuditSignatureAux(key, zero, signature, new Uint8Array(length))).toEqual({ valid: false,
      matchesAux: false, isDeterministicDefault: false, reason: 'auxRand must be 32 bytes when supplied' })
  })

  it('propagates invalid signing inputs through the audit', () => {
    expect(Engine.bip340AuditSignatureAux(be(N), zero, signature)).toMatchObject({ valid: false, matchesAux: false, isDeterministicDefault: false })
    expect(Engine.bip340AuditSignatureAux(key, new Uint8Array(31), signature).valid).toBe(false)
  })
})
