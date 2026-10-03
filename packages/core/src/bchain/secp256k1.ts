import { unsignedBigEndian } from '../bytes'
import { taggedHash } from '../crypto'

export const SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
export const SECP256K1_HALF_N = SECP256K1_N / 2n
export const SECP256K1_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
export const SECP256K1_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n

export type Point = { x: bigint; y: bigint } | null
const GENERATOR = { x: SECP256K1_GX, y: SECP256K1_GY }

function mod(value: bigint, modulus = SECP256K1_P): bigint {
  return ((value % modulus) + modulus) % modulus
}

function inverse(value: bigint): bigint {
  let a = mod(value)
  let b = SECP256K1_P
  let x = 1n
  let y = 0n
  while (b !== 0n) {
    const quotient = a / b
    ;[a, b] = [b, a - quotient * b]
    ;[x, y] = [y, x - quotient * y]
  }
  if (a !== 1n) throw new RangeError('Field inverse does not exist')
  return mod(x)
}

export function pointDouble(point: Point): Point {
  if (point === null || point.y === 0n) return null
  const slope = mod(3n * point.x * point.x * inverse(2n * point.y))
  const x = mod(slope * slope - 2n * point.x)
  return { x, y: mod(slope * (point.x - x) - point.y) }
}

export function pointAdd(left: Point, right: Point): Point {
  if (left === null) return right
  if (right === null) return left
  if (left.x === right.x) return left.y === right.y ? pointDouble(left) : null
  const slope = mod((right.y - left.y) * inverse(right.x - left.x))
  const x = mod(slope * slope - left.x - right.x)
  return { x, y: mod(slope * (left.x - x) - left.y) }
}

export function scalarMul(scalar: bigint, point: Point): Point {
  let k = mod(scalar, SECP256K1_N)
  let result: Point = null
  let addend = point
  while (k > 0n) {
    if ((k & 1n) !== 0n) result = pointAdd(result, addend)
    addend = pointDouble(addend)
    k >>= 1n
  }
  return result
}

export function liftX(bytes: Uint8Array): Point {
  if (bytes.length !== 32) return null
  const x = unsignedBigEndian(bytes)
  if (x >= SECP256K1_P) return null
  const y = Secp256k1Engine.sqrtModP(mod(x * x * x + 7n))
  return y === null ? null : { x, y: (y & 1n) === 0n ? y : SECP256K1_P - y }
}

function isCurvePoint(point: Point): point is NonNullable<Point> {
  return point !== null && typeof point.x === 'bigint' && typeof point.y === 'bigint'
    && point.x >= 0n && point.x < SECP256K1_P && point.y >= 0n && point.y < SECP256K1_P
    && mod(point.y * point.y) === mod(point.x * point.x * point.x + 7n)
}

function compressedPoint(point: NonNullable<Point>): Uint8Array {
  const bytes = new Uint8Array(33)
  bytes[0] = 2 + Number(point.y & 1n)
  let x = point.x
  for (let index = 32; index > 0; index--) {
    bytes[index] = Number(x & 255n)
    x >>= 8n
  }
  return bytes
}

export type Secp256k1PubKeyFormat = 'compressed' | 'uncompressed' | 'x-only-bip340' | 'invalid'

export interface Secp256k1PubKeyInspection {
  format: Secp256k1PubKeyFormat
  isValid: boolean
  x: bigint
  y?: bigint
  rawHex: string
  rejectionReason?: string
}

export interface Secp256k1SignatureInspection {
  isDer: boolean
  isCompact64: boolean
  r: bigint
  s: bigint
  isLowS: boolean
  isCanonicalR: boolean
  isCanonicalS: boolean
  isStrictlyValid: boolean
  rejectionReason?: string
}

function signatureResult(
  r: bigint,
  s: bigint,
  isDer: boolean,
  isCompact64: boolean,
  encodingError?: string,
): Secp256k1SignatureInspection {
  const isCanonicalR = r > 0n && r < SECP256K1_N
  const isCanonicalS = s > 0n && s < SECP256K1_N
  const isLowS = s <= SECP256K1_HALF_N
  const rejectionReason = encodingError
    ?? (!isCanonicalR ? 'R must satisfy 0 < r < n' : undefined)
    ?? (!isCanonicalS ? 'S must satisfy 0 < s < n' : undefined)
    ?? (!isLowS ? 'High-S signature is malleable; low-S policy requires s <= n/2' : undefined)
  return {
    isDer, isCompact64, r, s, isLowS, isCanonicalR, isCanonicalS,
    isStrictlyValid: !rejectionReason && (isDer || isCompact64),
    ...(rejectionReason ? { rejectionReason } : {}),
  }
}

/** Public-data curve and signature verification; BigInt arithmetic is not constant-time. */
export class Secp256k1Engine {
  public static pointAdd(left: Point, right: Point): Point { return pointAdd(left, right) }
  public static pointDouble(point: Point): Point { return pointDouble(point) }
  public static scalarMul(scalar: bigint, point: Point): Point { return scalarMul(scalar, point) }
  public static liftX(bytes: Uint8Array): Point { return liftX(bytes) }

  public static verifySchnorr(pubkey32: Uint8Array, msg32: Uint8Array, sig64: Uint8Array): { valid: boolean; reason?: string } {
    if (pubkey32.length !== 32) return { valid: false, reason: 'Public key must contain exactly 32 bytes' }
    if (msg32.length !== 32) return { valid: false, reason: 'Message must contain exactly 32 bytes' }
    if (sig64.length !== 64) return { valid: false, reason: 'Schnorr signature must contain exactly 64 bytes' }
    const point = liftX(pubkey32)
    if (point === null) return { valid: false, reason: 'Invalid public key X coordinate' }
    const r = unsignedBigEndian(sig64.subarray(0, 32))
    const s = unsignedBigEndian(sig64.subarray(32))
    if (r >= SECP256K1_P) return { valid: false, reason: 'r >= p' }
    if (s >= SECP256K1_N) return { valid: false, reason: 's >= n' }
    const e = unsignedBigEndian(taggedHash('BIP0340/challenge', sig64.subarray(0, 32), pubkey32, msg32)) % SECP256K1_N
    const R = pointAdd(scalarMul(s, GENERATOR), scalarMul(SECP256K1_N - e, point))
    if (R === null) return { valid: false, reason: 'R is infinity' }
    if ((R.y & 1n) !== 0n) return { valid: false, reason: 'R has odd Y coordinate' }
    if (R.x !== r) return { valid: false, reason: 'Signature verification equation failed (Rx != r)' }
    return { valid: true }
  }

  public static verifyDLEQ(G1: Point, P1: Point, G2: Point, P2: Point, proof64: Uint8Array, message?: Uint8Array): { valid: boolean; reason?: string } {
    if (proof64.length !== 64) return { valid: false, reason: 'DLEQ proof must contain exactly 64 bytes' }
    if (message !== undefined && message.length !== 32) return { valid: false, reason: 'DLEQ message must contain exactly 32 bytes' }
    for (const [name, point] of [['G1', G1], ['P1', P1], ['G2', G2], ['P2', P2]] as const) {
      if (!isCurvePoint(point)) return { valid: false, reason: `${name} must be a finite point on secp256k1` }
    }
    const e = unsignedBigEndian(proof64.subarray(0, 32))
    const s = unsignedBigEndian(proof64.subarray(32))
    if (e >= SECP256K1_N) return { valid: false, reason: 'e >= n' }
    if (s >= SECP256K1_N) return { valid: false, reason: 's >= n' }
    const R1 = pointAdd(scalarMul(s, G1), scalarMul(SECP256K1_N - e, P1))
    if (R1 === null) return { valid: false, reason: 'R1 is infinity' }
    const R2 = pointAdd(scalarMul(s, G2), scalarMul(SECP256K1_N - e, P2))
    if (R2 === null) return { valid: false, reason: 'R2 is infinity' }
    // BIP-374 transcript order: A, B, C, G, R1, R2 (compressed SEC points).
    const challenge = unsignedBigEndian(taggedHash('BIP0374/challenge',
      compressedPoint(P1!), compressedPoint(G2!), compressedPoint(P2!), compressedPoint(G1!),
      compressedPoint(R1), compressedPoint(R2), message ?? new Uint8Array(0))) % SECP256K1_N
    return challenge === e ? { valid: true } : { valid: false, reason: 'DLEQ challenge verification failed' }
  }

  public static verifyTaprootTweak(internalKey32: Uint8Array, outputKey32: Uint8Array, merkleRoot?: Uint8Array): { valid: boolean; parity: number; reason?: string } {
    const fail = (reason: string) => ({ valid: false, parity: -1, reason })
    if (internalKey32.length !== 32 || outputKey32.length !== 32) return fail('Internal and output keys must contain exactly 32 bytes')
    if (merkleRoot !== undefined && merkleRoot.length !== 32) return fail('Merkle root must contain exactly 32 bytes when supplied')
    const point = liftX(internalKey32)
    if (point === null) return fail('Invalid internal key X coordinate')
    if (unsignedBigEndian(outputKey32) >= SECP256K1_P) return fail('Output key X coordinate >= p')
    const tweak = unsignedBigEndian(taggedHash('TapTweak', internalKey32, merkleRoot ?? new Uint8Array(0)))
    // BIP-341 rejects overflowing tweaks before scalar multiplication.
    if (tweak >= SECP256K1_N) return fail('Taproot tweak >= n')
    const output = pointAdd(point, scalarMul(tweak, GENERATOR))
    if (output === null) return fail('Tweaked point is infinity')
    const parity = Number(output.y & 1n)
    return output.x === unsignedBigEndian(outputKey32)
      ? { valid: true, parity }
      : { valid: false, parity, reason: 'Taproot output key mismatch' }
  }

  public static validateScalar(scalar: bigint): { valid: boolean; reason?: string } {
    if (scalar <= 0n) return { valid: false, reason: 'Scalar must be positive' }
    if (scalar >= SECP256K1_N) return { valid: false, reason: 'Scalar overflow (k >= n)' }
    return { valid: true }
  }

  public static validateFieldElement(elem: bigint): { valid: boolean; reason?: string } {
    if (elem < 0n) return { valid: false, reason: 'Field element must be non-negative' }
    if (elem >= SECP256K1_P) return { valid: false, reason: 'Field element overflow (element >= p)' }
    return { valid: true }
  }

  /** Fixed 256-round exponentiation. JavaScript BigInt arithmetic has no constant-time guarantee. */
  public static sqrtModP(a: bigint): bigint | null {
    const base = ((a % SECP256K1_P) + SECP256K1_P) % SECP256K1_P
    const exponent = (SECP256K1_P + 1n) / 4n
    let root = 1n
    for (let bit = 255n; bit >= 0n; bit--) {
      root = root * root % SECP256K1_P
      // The branch depends only on the fixed, public exponent.
      if (((exponent >> bit) & 1n) !== 0n) root = root * base % SECP256K1_P
    }
    return root * root % SECP256K1_P === base ? root : null
  }

  public static inspectPubKey(bytes: Uint8Array): Secp256k1PubKeyInspection {
    const rawHex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
    let format: Secp256k1PubKeyFormat = 'invalid'
    if (bytes.length === 32) format = 'x-only-bip340'
    else if (bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3)) format = 'compressed'
    else if (bytes.length === 65 && bytes[0] === 4) format = 'uncompressed'
    if (format === 'invalid') {
      return { format, isValid: false, x: 0n, rawHex, rejectionReason: 'Invalid public key length or prefix' }
    }

    const x = unsignedBigEndian(bytes.subarray(format === 'x-only-bip340' ? 0 : 1, format === 'x-only-bip340' ? 32 : 33))
    const result: Secp256k1PubKeyInspection = { format, isValid: false, x, rawHex }
    if (format === 'uncompressed') result.y = unsignedBigEndian(bytes.subarray(33))
    if (x >= SECP256K1_P) return { ...result, rejectionReason: 'Field element overflow (x >= p)' }
    if (result.y !== undefined && result.y >= SECP256K1_P) {
      return { ...result, rejectionReason: 'Field element overflow (y >= p)' }
    }
    const rhs = (x * x % SECP256K1_P * x + 7n) % SECP256K1_P
    if (format === 'uncompressed') {
      if (result.y! * result.y! % SECP256K1_P !== rhs) {
        return { ...result, rejectionReason: 'Point not on secp256k1 curve' }
      }
    } else {
      const root = this.sqrtModP(rhs)
      if (root === null) return { ...result, rejectionReason: 'Point not on secp256k1 curve' }
      const parity = format === 'compressed' ? BigInt(bytes[0]! & 1) : 0n
      result.y = (root & 1n) === parity ? root : (SECP256K1_P - root) % SECP256K1_P
      if ((result.y & 1n) !== parity) return { ...result, rejectionReason: 'Invalid compressed Y parity' }
    }
    return { ...result, isValid: true }
  }

  /** Strict DER without Bitcoin's trailing sighash byte: 8..72 bytes. */
  public static inspectSignatureDER(bytes: Uint8Array): Secp256k1SignatureInspection {
    const fail = (reason: string) => signatureResult(0n, 0n, false, false, reason)
    if (bytes.length < 8 || bytes.length > 72) return fail('DER signature must contain 8..72 bytes')
    if (bytes[0] !== 0x30) return fail('Invalid DER sequence tag')
    if (bytes[1] !== bytes.length - 2) return fail('Invalid DER sequence length')
    if (bytes[2] !== 0x02) return fail('Invalid DER R integer tag')
    const rLength = bytes[3]!
    const sTag = 4 + rLength
    if (rLength === 0 || sTag + 2 >= bytes.length) return fail('Invalid or truncated DER R length')
    if (bytes[sTag] !== 0x02) return fail('Invalid DER S integer tag')
    const sLength = bytes[sTag + 1]!
    if (sLength === 0 || sTag + 2 + sLength !== bytes.length) return fail('Invalid or truncated DER S length')
    for (const [name, start, length] of [['R', 4, rLength], ['S', sTag + 2, sLength]] as const) {
      if ((bytes[start]! & 0x80) !== 0) return fail(`Negative DER ${name} integer`)
      if (length > 1 && bytes[start] === 0 && (bytes[start + 1]! & 0x80) === 0) {
        return fail(`Excessive DER ${name} leading padding`)
      }
    }
    return signatureResult(
      unsignedBigEndian(bytes.subarray(4, sTag)),
      unsignedBigEndian(bytes.subarray(sTag + 2)),
      true, false,
    )
  }

  /** Compact ECDSA r || s, not BIP-340 Schnorr or recoverable signatures. */
  public static inspectCompactSignature(bytes: Uint8Array): Secp256k1SignatureInspection {
    if (bytes.length !== 64) return signatureResult(0n, 0n, false, false, 'Compact ECDSA signature must contain exactly 64 bytes')
    return signatureResult(unsignedBigEndian(bytes.subarray(0, 32)), unsignedBigEndian(bytes.subarray(32)), false, true)
  }
}
