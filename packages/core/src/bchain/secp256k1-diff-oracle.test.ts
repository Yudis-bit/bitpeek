import { createECDH } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  auditDifferentialExecution, auditSecp256k1BoundaryExecutions, generateSecp256k1Boundaries, referenceScalarMul, referencePointAdd,
  referenceFieldInverse, referenceJacobianToAffine, referenceSchnorrVerify, type Secp256k1DifferentialAdapter,
} from './secp256k1-diff-oracle'
import {
  SECP256K1_P as P, SECP256K1_N as N, SECP256K1_GX, SECP256K1_GY,
  Secp256k1Engine, compressedPoint, type Point,
} from './secp256k1'

const G = { x: SECP256K1_GX, y: SECP256K1_GY }
const be = (value: bigint) => Uint8Array.from(Buffer.from(value.toString(16).padStart(64, '0'), 'hex'))
const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'))
const hex = (data: Uint8Array) => Buffer.from(data).toString('hex')
const boundaries = generateSecp256k1Boundaries()
const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/bip340-signing-vectors.json', import.meta.url), 'utf8')) as {
  vectors: { index: number; publicKey: string; message: string; signature: string }[]
}
const nativeAdapter: Secp256k1DifferentialAdapter = { name: 'OpenSSL-secp256k1', mul(scalar, point) {
  if (point === null) return null
  // OpenSSL's public-key constructor gives an independent native result for G.
  if (point.x !== G.x || point.y !== G.y) throw new RangeError('Native fixture accepts only G')
  const reduced = (scalar % N + N) % N
  if (reduced === 0n) return null
  const native = createECDH('secp256k1'); native.setPrivateKey(be(reduced))
  const raw = native.getPublicKey(undefined, 'uncompressed')
  return { x: BigInt(`0x${raw.subarray(1, 33).toString('hex')}`), y: BigInt(`0x${raw.subarray(33).toString('hex')}`) }
} }

describe('secp256k1 boundary generation and independent arithmetic', () => {
  it('covers every requested scalar/field boundary and edge encoding with stable unique names', () => {
    expect(boundaries.filter(vector => vector.kind === 'scalar').map(vector => vector.value)).toEqual([0n, 1n, 2n, (N - 1n) / 2n, N - 1n, N, N + 1n, (1n << 256n) - 1n])
    expect(boundaries.filter(vector => vector.kind === 'field').map(vector => vector.value)).toEqual([0n, 1n, P - 1n, P, P + 1n, (1n << 256n) - 1n])
    expect(new Set(boundaries.map(vector => vector.name)).size).toBe(boundaries.length)
    expect(boundaries.map(vector => vector.name)).toEqual(expect.arrayContaining(['point-infinity', 'point-even-y', 'point-odd-y', 'point-jacobian', 'point-low-order-candidate', 'schnorr-overflow-s']))
  })
  it.each(boundaries.filter(vector => vector.kind === 'scalar'))('compares scalar $name against affine and native engines', vector => {
    const scalar = vector.value!
    expect(auditDifferentialExecution('mul', { scalar }).valid).toBe(true)
    expect(auditDifferentialExecution('mul', { scalar, adapter: nativeAdapter })).toMatchObject({ valid: true, candidateName: 'OpenSSL-secp256k1', divergenceCount: 0 })
    if (scalar === 0n || scalar === N) expect(referenceScalarMul(scalar, G)).toBeNull()
  })
  it.each(boundaries.filter(vector => vector.kind === 'field'))('enforces field boundary $name', vector => {
    if (!vector.canonical) expect(() => auditDifferentialExecution('inversion', { fieldElement: vector.value })).toThrow('canonical')
    else {
      const audit = auditDifferentialExecution('inversion', { fieldElement: vector.value })
      expect(audit.valid).toBe(true)
      if (vector.value === 0n) expect(audit.checks[0].referenceError).toContain('inverse does not exist')
      else expect(vector.value! * referenceFieldInverse(vector.value!) % P).toBe(1n)
    }
  })
  it.each(boundaries.filter(vector => vector.kind === 'encoding' && !vector.name.startsWith('schnorr')))('rejects public-key encoding $name', vector => {
    expect(Secp256k1Engine.inspectPubKey(bytes(vector.hex!)).isValid).toBe(false)
  })
  it('handles infinity, inverse points, odd/even Y, and cofactor-one low-order rejection', () => {
    expect(referencePointAdd(G, null)).toEqual(G)
    expect(referencePointAdd(null, G)).toEqual(G)
    expect(referencePointAdd(G, { x: G.x, y: P - G.y })).toBeNull()
    expect(referenceScalarMul(N, G)).toBeNull()
    expect(() => referencePointAdd({ x: 0n, y: 0n }, G)).toThrow('canonical secp256k1')
    expect(() => auditDifferentialExecution('mul', { point: { x: G.x + P, y: G.y } })).toThrow('canonical secp256k1')
  })
  it('normalizes Jacobian coordinates independently of repository affine functions', () => {
    const vector = boundaries.find(vector => vector.name === 'point-jacobian')!
    expect(referenceJacobianToAffine(vector.jacobian!)).toEqual(G)
    expect(referenceJacobianToAffine({ x: 0n, y: 1n, z: 0n })).toBeNull()
    expect(() => referenceJacobianToAffine({ x: P, y: 1n, z: 0n })).toThrow('canonical')
    expect(() => referenceJacobianToAffine({ x: 0n, y: 0n, z: 1n })).toThrow('canonical secp256k1')
  })
  it.each([-1n, -2n, N * 2n, N * 2n + 1n, (1n << 511n) - 1n])('agrees on algebraic scalar reduction for %s', scalar => {
    expect(auditDifferentialExecution('mul', { scalar }).valid).toBe(true)
  })
  it.each([-(1n << 512n) - 1n, 1n << 512n])('bounds excessively wide scalar %s', scalar => {
    expect(() => referenceScalarMul(scalar, G)).toThrow('512 bits')
    expect(() => auditDifferentialExecution('mul', { scalar })).toThrow('512 bits')
  })
  it.each([1n, 2n, 3n, 7n, 42n, N - 1n])('verifies all group identities for scalar %s', scalar => {
    const point = referenceScalarMul(scalar, G), otherPoint = referenceScalarMul(7n, G), thirdPoint = referenceScalarMul(11n, G)
    const audit = auditDifferentialExecution('identities', { scalar, scalar2: N - scalar, point, otherPoint, thirdPoint })
    expect(audit).toMatchObject({ valid: true, comparisons: 10, divergenceCount: 0, divergenceRate: 0 })
    expect(audit.checks.every(check => check.matches)).toBe(true)
  })
  it.each(['mul', 'add', 'doubling', 'identities'] as const)('handles infinity under %s', operation => {
    expect(auditDifferentialExecution(operation, { point: null, otherPoint: null, thirdPoint: null }).valid).toBe(true)
  })
  it('returns fresh boundary arrays and points without shared mutable vector state', () => {
    const first = generateSecp256k1Boundaries(), second = generateSecp256k1Boundaries()
    first[0].name = 'mutated'
    const point = first.find(vector => vector.name === 'point-even-y')!.point!
    point.x = 0n
    expect(second[0].name).toBe('scalar-zero')
    expect(second.find(vector => vector.name === 'point-even-y')!.point).toEqual(G)
  })
})

describe('secp256k1 mutant detection and differential Schnorr verification', () => {
  it('executes a complete automated reference/repository boundary campaign', () => {
    const campaign = auditSecp256k1BoundaryExecutions()
    expect(campaign).toMatchObject({ valid: true, comparisons: 41, divergenceCount: 0, skippedOperations: [], constantTimeProven: false })
    expect(campaign.cases).toHaveLength(14)
  })
  it('detects scalar mutants automatically and lists unavailable native operations', () => {
    const campaign = auditSecp256k1BoundaryExecutions({ name: 'zero-scalar-mutant', mul() { return null } })
    expect(campaign.valid).toBe(false)
    expect(campaign.divergenceCount).toBeGreaterThan(0)
    expect(campaign.skippedOperations).toEqual(['field-inversion', 'group-identities'])
    expect(auditSecp256k1BoundaryExecutions({ name: 'empty-adapter' }).valid).toBe(false)
  })
  it.each(vectors)('agrees with independent verification for published Schnorr vector $index', vector => {
    const pubkey32 = bytes(vector.publicKey), message32 = bytes(vector.message), signature64 = bytes(vector.signature)
    expect(referenceSchnorrVerify(pubkey32, message32, signature64)).toBe(true)
    expect(auditDifferentialExecution('schnorr', { pubkey32, message32, signature64 }).valid).toBe(true)
    const corrupted = signature64.slice(); corrupted[63] ^= 1
    const audit = auditDifferentialExecution('schnorr', { pubkey32, message32, signature64: corrupted })
    expect(audit.valid).toBe(true); expect(audit.checks[0].reference).toBe(false)
  })
  it.each(['schnorr-overflow-r', 'schnorr-overflow-s'])('rejects non-canonical $0 in both verifiers', name => {
    const vector = boundaries.find(vector => vector.name === name)!, fixture = vectors[0]
    const audit = auditDifferentialExecution('schnorr', { pubkey32: bytes(fixture.publicKey), message32: bytes(fixture.message), signature64: bytes(vector.hex!) })
    expect(audit.valid).toBe(true); expect(audit.checks[0].candidate).toBe(false)
  })
  it('detects a scalar-overflow mutant that clamps instead of reducing n+1', () => {
    const adapter: Secp256k1DifferentialAdapter = { name: 'clamped-scalar-mutant', mul(k, point) { return k >= N ? null : Secp256k1Engine.scalarMul(k, point) } }
    expect(auditDifferentialExecution('mul', { scalar: N + 1n, adapter })).toMatchObject({ valid: false, divergenceCount: 1, divergenceRate: 1 })
  })
  it('detects incorrect infinity handling, point negation and doubling mutants', () => {
    const adapter: Secp256k1DifferentialAdapter = { name: 'infinity-mutant',
      add(a, b) { return a === null || b === null ? null : G }, doubling() { return G }, mul: Secp256k1Engine.scalarMul }
    const audit = auditDifferentialExecution('identities', { adapter })
    expect(audit.valid).toBe(false)
    expect(audit.checks.filter(check => !check.matches).map(check => check.name)).toEqual(expect.arrayContaining(['right-infinity-identity', 'left-infinity-identity', 'inverse-identity', 'doubling-vs-addition']))
  })
  it('isolates native input mutation and snapshots results before later adapter calls', () => {
    const point = { ...G }, doubled = referenceScalarMul(2n, G)!
    const scratch = { ...G }
    const adapter: Secp256k1DifferentialAdapter = { name: 'mutating-native',
      add(left, right) {
        if (left && right === null) Object.assign(left, doubled)
        const result = referencePointAdd(left, right)
        if (result === null) return null
        Object.assign(scratch, result)
        return scratch
      }, doubling: p => referencePointAdd(p, p), mul: referenceScalarMul }
    const audit = auditDifferentialExecution('identities', { point, adapter })
    expect(audit.valid).toBe(false)
    expect(audit.checks[0]).toMatchObject({ name: 'right-infinity-identity', matches: false, reference: G, candidate: doubled })
    expect(point).toEqual(G)
  })
  it('detects non-canonical affine output instead of reducing coordinates', () => {
    const adapter: Secp256k1DifferentialAdapter = { name: 'overflow-point-mutant', mul() { return { x: G.x + P, y: G.y } } }
    expect(auditDifferentialExecution('mul', { adapter }).divergenceCount).toBe(1)
  })
  it('reports thrown native errors and missing adapter operations as divergences', () => {
    const adapter: Secp256k1DifferentialAdapter = { name: 'throwing-native', mul() { throw new Error('Native crash') } }
    expect(auditDifferentialExecution('mul', { adapter }).checks[0]).toMatchObject({ matches: false, candidateError: 'Native crash' })
    expect(auditDifferentialExecution('inversion', { fieldElement: 0n, adapter: { name: 'missing' } }).valid).toBe(false)
  })
  it('compares supplied observed infinity, point and inverse values', () => {
    expect(auditDifferentialExecution('mul', { scalar: 0n, observedResult: null }).valid).toBe(true)
    expect(auditDifferentialExecution('mul', { observedResult: G }).valid).toBe(true)
    expect(auditDifferentialExecution('mul', { observedResult: null }).valid).toBe(false)
    expect(auditDifferentialExecution('inversion', { fieldElement: 2n, observedResult: 2n }).valid).toBe(false)
  })
  it('detects a Schnorr verifier that erroneously accepts a corrupted signature', () => {
    const fixture = vectors[0], signature64 = bytes(fixture.signature); signature64[0] ^= 1
    const audit = auditDifferentialExecution('schnorr', { pubkey32: bytes(fixture.publicKey), message32: bytes(fixture.message), signature64, observedResult: true })
    expect(audit).toMatchObject({ valid: false, divergenceCount: 1 })
  })
  it('requires complete Schnorr inputs and a supported operation', () => {
    expect(() => auditDifferentialExecution('schnorr')).toThrow('requires')
    expect(() => auditDifferentialExecution('invalid' as 'mul')).toThrow('Unsupported')
    expect(referenceSchnorrVerify(be(0n), be(0n), new Uint8Array(64))).toBe(false)
    expect(referenceSchnorrVerify(be(P), be(0n), new Uint8Array(64))).toBe(false)
    expect(referenceSchnorrVerify(be(G.x), be(0n), new Uint8Array(63))).toBe(false)
  })
  it('does not claim constant-time execution from arithmetic agreement and reports scalar-dependent work', () => {
    const a = auditDifferentialExecution('mul', { scalar: 1n }), b = auditDifferentialExecution('mul', { scalar: 7n })
    expect(a).toMatchObject({ valid: true, constantTimeProven: false, referenceIsConstantTime: false, scalarSchedule: { bitLength: 1, conditionalAdditions: 1 } })
    expect(b.scalarSchedule).toEqual({ bitLength: 3, conditionalAdditions: 3 })
  })
  it('connects actual machine-code timing hazard inspection while keeping proof claims scoped', () => {
    const audit = auditDifferentialExecution('mul', { criticalCode: bytes('75029090') })
    expect(audit.timingAudit?.hasConditionalBranches).toBe(true)
    expect(audit.constantTimeProven).toBe(false)
    expect(() => auditDifferentialExecution('mul', { criticalCode: new Uint8Array(65537) })).toThrow('65536')
  })
  it('preserves caller points and yields correct independent compressed native output', () => {
    const point: Point = { ...G }, copy = { ...point }
    const audit = auditDifferentialExecution('doubling', { point })
    expect(point).toEqual(copy)
    expect(hex(compressedPoint(audit.checks[0].reference as NonNullable<Point>))).toBe(hex(nativeKey(2n)))
  })
})
function nativeKey(scalar: bigint): Uint8Array {
  const native = createECDH('secp256k1'); native.setPrivateKey(be(scalar))
  return native.getPublicKey(undefined, 'compressed')
}
