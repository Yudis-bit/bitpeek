/** Independent Jacobian BigInt oracle for defensive differential testing.
 * Reference and repository BigInt engines are variable-time; arithmetic agreement
 * cannot certify timing behavior or native code that has not been supplied.
 */
import { unsignedBigEndian } from '../bytes'
import { taggedHash } from '../crypto'
import { ConstantTimeAuditor, type ConstantTimeAuditResult } from '../native/constant-time'
import {
  SECP256K1_P as P, SECP256K1_N as N, SECP256K1_GX, SECP256K1_GY,
  Secp256k1Engine, isCurvePoint, compressedPoint, type Point,
} from './secp256k1'

const G = { x: SECP256K1_GX, y: SECP256K1_GY }
const mod = (value: bigint, modulus = P) => ((value % modulus) + modulus) % modulus
function pow(value: bigint, exponent: bigint): bigint {
  let result = 1n
  value = mod(value)
  while (exponent > 0n) {
    if (exponent & 1n) result = mod(result * value)
    value = mod(value * value); exponent >>= 1n
  }
  return result
}
export function referenceFieldInverse(value: bigint): bigint {
  if (mod(value) === 0n) throw new RangeError('Field inverse does not exist')
  return pow(value, P - 2n)
}
export interface Secp256k1JacobianPoint { x: bigint; y: bigint; z: bigint }
const O: Secp256k1JacobianPoint = { x: 0n, y: 1n, z: 0n }
function validatePoint(point: Point): void {
  if (point !== null && !isCurvePoint(point)) throw new RangeError('Expected infinity or a canonical secp256k1 curve point')
}
function project(point: Point): Secp256k1JacobianPoint { return point === null ? O : { ...point, z: 1n } }
export function referenceJacobianToAffine(point: Secp256k1JacobianPoint): Point {
  for (const coordinate of [point.x, point.y, point.z]) {
    if (typeof coordinate !== 'bigint' || coordinate < 0n || coordinate >= P) throw new RangeError('Jacobian coordinates must be canonical field elements')
  }
  if (point.z === 0n) return null
  const inverse = referenceFieldInverse(point.z), inverse2 = mod(inverse * inverse)
  const affine = { x: mod(point.x * inverse2), y: mod(point.y * inverse2 * inverse) }
  validatePoint(affine)
  return affine
}
function doubleJ(a: Secp256k1JacobianPoint): Secp256k1JacobianPoint {
  if (a.z === 0n || a.y === 0n) return O
  const yy = mod(a.y * a.y), S = mod(4n * a.x * yy), M = mod(3n * a.x * a.x)
  const x = mod(M * M - 2n * S)
  return { x, y: mod(M * (S - x) - 8n * yy * yy), z: mod(2n * a.y * a.z) }
}
function addJ(a: Secp256k1JacobianPoint, b: Secp256k1JacobianPoint): Secp256k1JacobianPoint {
  if (a.z === 0n) return b
  if (b.z === 0n) return a
  const z1z1 = mod(a.z * a.z), z2z2 = mod(b.z * b.z)
  const u1 = mod(a.x * z2z2), u2 = mod(b.x * z1z1)
  const s1 = mod(a.y * b.z * z2z2), s2 = mod(b.y * a.z * z1z1)
  if (u1 === u2) return s1 === s2 ? doubleJ(a) : O
  const h = mod(u2 - u1), r = mod(s2 - s1), hh = mod(h * h), hhh = mod(h * hh), v = mod(u1 * hh)
  const x = mod(r * r - hhh - 2n * v)
  return { x, y: mod(r * (v - x) - s1 * hhh), z: mod(h * a.z * b.z) }
}
export function referencePointAdd(left: Point, right: Point): Point {
  validatePoint(left); validatePoint(right)
  return referenceJacobianToAffine(addJ(project(left), project(right)))
}
export function referenceScalarMul(scalar: bigint, point: Point): Point {
  validatePoint(point)
  if (typeof scalar !== 'bigint' || scalar < -(1n << 512n) || scalar >= (1n << 512n)) throw new RangeError('Reference scalar must fit within 512 bits')
  const reduced = mod(scalar, N)
  let accumulator = O
  const base = project(point)
  // Independent left-to-right projective ladder; no affine repository helpers.
  for (let bit = 255; bit >= 0; bit--) {
    accumulator = doubleJ(accumulator)
    if (((reduced >> BigInt(bit)) & 1n) !== 0n) accumulator = addJ(accumulator, base)
  }
  return referenceJacobianToAffine(accumulator)
}
export function referenceSchnorrVerify(pubkey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (pubkey.length !== 32 || signature.length !== 64 || message.length !== 32) return false
  const x = unsignedBigEndian(pubkey), r = unsignedBigEndian(signature.subarray(0, 32)), s = unsignedBigEndian(signature.subarray(32))
  if (x >= P || r >= P || s >= N) return false
  const y = pow(mod(x * x * x + 7n), (P + 1n) / 4n)
  if (mod(y * y) !== mod(x * x * x + 7n)) return false
  const point = { x, y: (y & 1n) === 0n ? y : P - y }
  const e = unsignedBigEndian(taggedHash('BIP0340/challenge', signature.subarray(0, 32), pubkey, message)) % N
  const R = referencePointAdd(referenceScalarMul(s, G), referenceScalarMul(N - e, point))
  return R !== null && (R.y & 1n) === 0n && R.x === r
}

export interface Secp256k1BoundaryVector {
  name: string
  kind: 'scalar' | 'field' | 'point' | 'encoding'
  value?: bigint
  hex?: string
  point?: Point
  jacobian?: Secp256k1JacobianPoint
  canonical: boolean
  expected: string
}
const hex32 = (value: bigint) => value.toString(16).padStart(64, '0')
const hex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
export function generateSecp256k1Boundaries(): Secp256k1BoundaryVector[] {
  const scalars: [string, bigint][] = [['zero', 0n], ['one', 1n], ['two', 2n], ['half-order', (N - 1n) / 2n],
    ['order-minus-one', N - 1n], ['order', N], ['order-plus-one', N + 1n], ['uint256-max', (1n << 256n) - 1n]]
  const fields: [string, bigint][] = [['zero', 0n], ['one', 1n], ['prime-minus-one', P - 1n], ['prime', P],
    ['prime-plus-one', P + 1n], ['uint256-max', (1n << 256n) - 1n]]
  const inverseG = { x: G.x, y: P - G.y }
  return [
    ...scalars.map(([name, value]): Secp256k1BoundaryVector => ({ name: `scalar-${name}`, kind: 'scalar', value,
      hex: hex32(value), canonical: value < N, expected: value === 0n ? 'Canonical scalar; forbidden as a secret key' : value < N ? 'Canonical scalar' : 'Reject non-canonical scalar encoding; group arithmetic may reduce modulo n' })),
    ...fields.map(([name, value]): Secp256k1BoundaryVector => ({ name: `field-${name}`, kind: 'field', value,
      hex: hex32(value), canonical: value < P, expected: value < P ? 'Canonical field element; X still requires a curve lift' : 'Reject non-canonical field encoding' })),
    { name: 'point-infinity', kind: 'point', point: null, canonical: true, expected: 'Group identity; no finite SEC encoding' },
    { name: 'point-even-y', kind: 'point', point: { ...G }, hex: hex(compressedPoint(G)), canonical: true, expected: 'Finite curve point' },
    { name: 'point-odd-y', kind: 'point', point: inverseG, hex: hex(compressedPoint(inverseG)), canonical: true, expected: 'Negation of even-Y point' },
    { name: 'point-jacobian', kind: 'point', jacobian: { x: mod(G.x * 4n), y: mod(G.y * 8n), z: 2n }, canonical: true, expected: 'Same point as affine G' },
    { name: 'point-low-order-candidate', kind: 'point', point: { x: 0n, y: 0n }, canonical: false, expected: 'Reject: cofactor-one secp256k1 has no nontrivial low-order points' },
    { name: 'sec-infinity', kind: 'encoding', hex: '00', canonical: false, expected: 'Reject infinity SEC public key' },
    { name: 'sec-hybrid', kind: 'encoding', hex: `06${hex32(G.x)}${hex32(G.y)}`, canonical: false, expected: 'Reject hybrid public key' },
    { name: 'sec-truncated', kind: 'encoding', hex: `02${hex32(G.x).slice(2)}`, canonical: false, expected: 'Reject truncated public key' },
    { name: 'sec-overflow-x', kind: 'encoding', hex: `02${hex32(P)}`, canonical: false, expected: 'Reject X >= p' },
    { name: 'sec-invalid-prefix', kind: 'encoding', hex: `05${hex32(G.x)}`, canonical: false, expected: 'Reject unsupported SEC prefix' },
    { name: 'schnorr-overflow-r', kind: 'encoding', hex: `${hex32(P)}${hex32(1n)}`, canonical: false, expected: 'Reject Schnorr r >= p' },
    { name: 'schnorr-overflow-s', kind: 'encoding', hex: `${hex32(G.x)}${hex32(N)}`, canonical: false, expected: 'Reject Schnorr s >= n' },
  ]
}

export type Secp256k1DifferentialOperation = 'mul' | 'add' | 'doubling' | 'inversion' | 'schnorr' | 'identities'
/** Native/Wasm/C bindings can supply these callbacks. They must return canonical
 * affine points (null for infinity), canonical field values, or verification booleans.
 */
export interface Secp256k1DifferentialAdapter {
  name: string
  mul?: (scalar: bigint, point: Point) => Point
  add?: (left: Point, right: Point) => Point
  doubling?: (point: Point) => Point
  inversion?: (value: bigint) => bigint
  schnorr?: (pubkey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
}
export interface Secp256k1DifferentialInputs {
  scalar?: bigint
  scalar2?: bigint
  point?: Point
  otherPoint?: Point
  thirdPoint?: Point
  fieldElement?: bigint
  pubkey32?: Uint8Array
  message32?: Uint8Array
  signature64?: Uint8Array
  adapter?: Secp256k1DifferentialAdapter
  observedResult?: Point | bigint | boolean
  criticalCode?: Uint8Array
  arch?: 'x86_64' | 'aarch64'
}
export interface Secp256k1DifferentialCheck {
  name: string
  matches: boolean
  reference?: Point | bigint | boolean
  candidate?: Point | bigint | boolean
  referenceError?: string
  candidateError?: string
}
export interface Secp256k1DifferentialResult {
  valid: boolean
  operation: Secp256k1DifferentialOperation
  candidateName: string
  checks: Secp256k1DifferentialCheck[]
  comparisons: number
  divergenceCount: number
  divergenceRate: number
  boundariesGenerated: number
  constantTimeProven: false
  referenceIsConstantTime: false
  scalarSchedule: { bitLength: number; conditionalAdditions: number }
  timingAudit?: ConstantTimeAuditResult
  reason?: string
}

function extendedEuclid(value: bigint): bigint {
  let a = mod(value), b = P, x = 1n, y = 0n
  while (b !== 0n) {
    const quotient = a / b
    ;[a, b] = [b, a - quotient * b]
    ;[x, y] = [y, x - quotient * y]
  }
  if (a !== 1n) throw new RangeError('Field inverse does not exist')
  return mod(x)
}
function equal(a: Point | bigint | boolean | undefined, b: Point | bigint | boolean | undefined): boolean {
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return a === b
  return isCurvePoint(a) && isCurvePoint(b) && a.x === b.x && a.y === b.y
}
function copyPoint(point: Point): Point { return point === null ? null : { ...point } }
function snapshot(value: Point | bigint | boolean): Point | bigint | boolean {
  return value !== null && typeof value === 'object' ? { x: value.x, y: value.y } : value
}
export function auditDifferentialExecution(operation: Secp256k1DifferentialOperation, inputs: Secp256k1DifferentialInputs = {}): Secp256k1DifferentialResult {
  if (!['mul', 'add', 'doubling', 'inversion', 'schnorr', 'identities'].includes(operation)) throw new RangeError('Unsupported differential operation')
  if (operation === 'identities' && inputs.observedResult !== undefined) throw new RangeError('A single observed result cannot describe an identity campaign')
  const scalar = inputs.scalar ?? 1n, scalar2 = inputs.scalar2 ?? 2n
  const point = copyPoint(inputs.point === undefined ? G : inputs.point)
  const other = copyPoint(inputs.otherPoint === undefined ? G : inputs.otherPoint)
  const third = copyPoint(inputs.thirdPoint === undefined ? G : inputs.thirdPoint)
  validatePoint(point); validatePoint(other); validatePoint(third)
  for (const k of [scalar, scalar2]) if (typeof k !== 'bigint' || k < -(1n << 512n) || k >= (1n << 512n)) throw new RangeError('Differential scalars must fit within 512 bits')
  if (inputs.fieldElement !== undefined && (typeof inputs.fieldElement !== 'bigint' || inputs.fieldElement < 0n || inputs.fieldElement >= P)) {
    throw new RangeError('fieldElement must be canonical; overflow belongs to encoding rejection tests')
  }
  const adapter = inputs.adapter
  const nativeMul = adapter ? adapter.mul?.bind(adapter) : Secp256k1Engine.scalarMul
  const nativeAdd = adapter ? adapter.add?.bind(adapter) : Secp256k1Engine.pointAdd
  const nativeDouble = adapter ? adapter.doubling?.bind(adapter) : Secp256k1Engine.pointDouble
  const inversion = adapter ? adapter.inversion?.bind(adapter) : extendedEuclid
  const nativeSchnorr = adapter ? adapter.schnorr?.bind(adapter) : (key: Uint8Array, message: Uint8Array, signature: Uint8Array) => Secp256k1Engine.verifySchnorr(key, message, signature).valid
  const mul = nativeMul ? (k: bigint, p: Point) => nativeMul(k, copyPoint(p)) : undefined
  const add = nativeAdd ? (a: Point, b: Point) => nativeAdd(copyPoint(a), copyPoint(b)) : undefined
  const doubling = nativeDouble ? (p: Point) => nativeDouble(copyPoint(p)) : undefined
  const schnorr = nativeSchnorr ? (key: Uint8Array, message: Uint8Array, signature: Uint8Array) => nativeSchnorr(key.slice(), message.slice(), signature.slice()) : undefined
  const checks: Secp256k1DifferentialCheck[] = []
  const compare = (name: string, reference: () => Point | bigint | boolean, candidate: () => Point | bigint | boolean) => {
    const check: Secp256k1DifferentialCheck = { name, matches: false }
    try { check.reference = snapshot(reference()) } catch (error) { check.referenceError = error instanceof Error ? error.message : String(error) }
    try { check.candidate = snapshot(candidate()) } catch (error) { check.candidateError = error instanceof Error ? error.message : String(error) }
    check.matches = check.referenceError !== undefined ? check.candidateError === check.referenceError : check.candidateError === undefined && equal(check.reference, check.candidate)
    checks.push(check)
  }
  const missing = () => { throw new RangeError('Candidate adapter does not implement this operation') }
  const observed = <T extends Point | bigint | boolean>(run: () => T) => inputs.observedResult === undefined ? run() : inputs.observedResult
  if (operation === 'mul') compare('scalar-multiplication', () => referenceScalarMul(scalar, point), () => observed(() => (mul ?? missing)(scalar, point)))
  if (operation === 'add') compare('point-addition', () => referencePointAdd(point, other), () => observed(() => (add ?? missing)(point, other)))
  if (operation === 'doubling') compare('point-doubling', () => referencePointAdd(point, point), () => observed(() => (doubling ?? missing)(point)))
  if (operation === 'inversion') {
    const value = inputs.fieldElement ?? 1n
    compare('field-inversion', () => referenceFieldInverse(value), () => observed(() => (inversion ?? missing)(value)))
  }
  if (operation === 'schnorr') {
    if (!inputs.pubkey32 || !inputs.message32 || !inputs.signature64) throw new RangeError('Schnorr differential verification requires pubkey32, message32 and signature64')
    compare('schnorr-verification', () => referenceSchnorrVerify(inputs.pubkey32!, inputs.message32!, inputs.signature64!),
      () => observed(() => (schnorr ?? missing)(inputs.pubkey32!, inputs.message32!, inputs.signature64!)))
  }
  if (operation === 'identities') {
    const negate = point === null ? null : { x: point.x, y: mod(-point.y) }
    compare('right-infinity-identity', () => point, () => (add ?? missing)(point, null))
    compare('left-infinity-identity', () => point, () => (add ?? missing)(null, point))
    compare('inverse-identity', () => null, () => (add ?? missing)(point, negate))
    compare('doubling-vs-addition', () => referencePointAdd(point, point), () => (doubling ?? missing)(point))
    compare('addition-doubling', () => referencePointAdd(point, point), () => (add ?? missing)(point, point))
    compare('associativity-left', () => referencePointAdd(referencePointAdd(point, other), third), () => (add ?? missing)((add ?? missing)(point, other), third))
    compare('associativity-right', () => referencePointAdd(point, referencePointAdd(other, third)), () => (add ?? missing)(point, (add ?? missing)(other, third)))
    compare('distributivity-sum', () => referenceScalarMul(mod(scalar + scalar2, N), point), () => (mul ?? missing)(mod(scalar + scalar2, N), point))
    compare('distributivity-add', () => referenceScalarMul(mod(scalar + scalar2, N), point), () => (add ?? missing)((mul ?? missing)(scalar, point), (mul ?? missing)(scalar2, point)))
    compare('order-identity', () => null, () => (mul ?? missing)(N, point))
  }
  const reduced = mod(scalar, N), bits = reduced === 0n ? '' : reduced.toString(2)
  const divergenceCount = checks.filter(check => !check.matches).length
  if (inputs.criticalCode && inputs.criticalCode.length > 65536) throw new RangeError('criticalCode exceeds 65536-byte inspection limit')
  const timingAudit = inputs.criticalCode ? ConstantTimeAuditor.auditBytes(inputs.criticalCode, { arch: inputs.arch ?? 'x86_64', maxInstructions: 10000 }) : undefined
  return { valid: divergenceCount === 0, operation, candidateName: inputs.observedResult !== undefined ? 'supplied-observed-result' : adapter?.name ?? 'repository-affine-BigInt', checks,
    comparisons: checks.length, divergenceCount, divergenceRate: checks.length ? divergenceCount / checks.length : 0,
    boundariesGenerated: generateSecp256k1Boundaries().length, constantTimeProven: false, referenceIsConstantTime: false,
    scalarSchedule: { bitLength: bits.length, conditionalAdditions: Array.from(bits).filter(bit => bit === '1').length }, timingAudit,
    reason: divergenceCount ? `${divergenceCount} differential comparison(s) diverged` : undefined }
}

export interface Secp256k1BoundaryExecutionResult {
  valid: boolean
  cases: { name: string; audit: Secp256k1DifferentialResult }[]
  comparisons: number
  divergenceCount: number
  skippedOperations: string[]
  constantTimeProven: false
}
/** Deterministic boundary campaign for repository or caller-supplied native bindings.
 * Unsupported auxiliary adapter operations are listed explicitly; multiplication
 * is required, so an empty adapter cannot produce a successful campaign.
 */
export function auditSecp256k1BoundaryExecutions(adapter?: Secp256k1DifferentialAdapter): Secp256k1BoundaryExecutionResult {
  const vectors = generateSecp256k1Boundaries()
  const cases: Secp256k1BoundaryExecutionResult['cases'] = []
  const skippedOperations: string[] = []
  for (const vector of vectors.filter(vector => vector.kind === 'scalar')) {
    cases.push({ name: vector.name, audit: auditDifferentialExecution('mul', { scalar: vector.value!, adapter }) })
  }
  if (!adapter || adapter.inversion) {
    for (const vector of vectors.filter(vector => vector.kind === 'field' && vector.canonical)) {
      cases.push({ name: vector.name, audit: auditDifferentialExecution('inversion', { fieldElement: vector.value!, adapter }) })
    }
  } else skippedOperations.push('field-inversion')
  if (!adapter || (adapter.mul && adapter.add && adapter.doubling)) {
    for (const vector of vectors.filter(vector => vector.kind === 'point' && vector.canonical && vector.jacobian === undefined)) {
      cases.push({ name: vector.name, audit: auditDifferentialExecution('identities', { point: vector.point!, scalar: N - 1n, scalar2: 1n, adapter }) })
    }
  } else skippedOperations.push('group-identities')
  const comparisons = cases.reduce((count, entry) => count + entry.audit.comparisons, 0)
  const divergenceCount = cases.reduce((count, entry) => count + entry.audit.divergenceCount, 0)
  return { valid: divergenceCount === 0, cases, comparisons, divergenceCount, skippedOperations, constantTimeProven: false }
}
