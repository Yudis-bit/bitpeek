import { unsignedBigEndian } from '../bytes'
import { taggedHash } from '../crypto'
import { TaprootEngine } from './taproot'
import { resolveBitcoinVerificationProfile, type BitcoinVerificationProfile } from './verification-profile'
import type {
  TapLeaf, TapTreeStructure, TapTreeResult, TaprootControlBlockInspection,
  TaprootScriptPathVerificationResult, TapscriptKeyAuditResult,
} from './taproot'

export const SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
export const SECP256K1_HALF_N = SECP256K1_N / 2n
export const SECP256K1_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
export const SECP256K1_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n

export type Point = { x: bigint; y: bigint } | null

export interface Secp256k1PublicKeyAggregationResult {
  valid: boolean
  point: Point
  compressed?: Uint8Array
  reason?: string
}

export interface SilentPaymentTweakResult {
  valid: boolean
  tweak: bigint
  tweakBytes?: Uint8Array
  reason?: string
}

export interface SilentPaymentOutputKeyResult {
  valid: boolean
  outputKey32?: Uint8Array
  parity?: number
  reason?: string
}

export interface SilentPaymentTweakVerificationResult {
  valid: boolean
  parity: number
  reason?: string
}

export interface Bip340NonceResult {
  valid: boolean
  k?: bigint
  rx?: bigint
  reason?: string
}

export interface Bip340SignResult {
  valid: boolean
  signature64?: Uint8Array
  rx?: bigint
  s?: bigint
  publicKey32?: Uint8Array
  reason?: string
}

export interface Bip340AuxAuditResult {
  valid: boolean
  matchesAux: boolean
  isDeterministicDefault: boolean
  expectedSignature?: Uint8Array
  candidateSignature?: Uint8Array
  reason?: string
}

export interface SilentPaymentLabelDefinition {
  labelIndex: number
  labelTweak32: Uint8Array
  labelPubKey33?: Uint8Array
}

export interface SilentPaymentScanMatch {
  outputIndex: number
  outputKey32: Uint8Array
  isLabeled: boolean
  labelIndex?: number
  labelTweak32?: Uint8Array
  /** 0 selects the even-Y output lift; 1 selects its negation. */
  candidateSlotParity: number
  batchIndex: number
  batchOffset: number
}

export interface SilentPaymentScanParams {
  txOutputs: Uint8Array[]
  spendPubKey: Uint8Array
  scanPrivKey32: Uint8Array
  sharedSecretTweak: bigint | Uint8Array
  labels?: SilentPaymentLabelDefinition[]
  batchSize?: number
}

export interface SilentPaymentScanResult {
  valid: boolean
  matches: SilentPaymentScanMatch[]
  totalOutputsScanned: number
  batchCount: number
  unlabeledPoint?: Point
  reason?: string
}

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

export function isCurvePoint(point: Point): point is NonNullable<Point> {
  return point !== null && typeof point.x === 'bigint' && typeof point.y === 'bigint'
    && point.x >= 0n && point.x < SECP256K1_P && point.y >= 0n && point.y < SECP256K1_P
    && mod(point.y * point.y) === mod(point.x * point.x * point.x + 7n)
}

export function compressedPoint(point: NonNullable<Point>): Uint8Array {
  if (!isCurvePoint(point)) throw new RangeError('Expected a finite point on secp256k1')
  const bytes = new Uint8Array(33)
  bytes[0] = 2 + Number(point.y & 1n)
  let x = point.x
  for (let index = 32; index > 0; index--) {
    bytes[index] = Number(x & 255n)
    x >>= 8n
  }
  return bytes
}

function bigEndian32(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32)
  for (let index = 31; index >= 0; index--) {
    bytes[index] = Number(value & 255n)
    value >>= 8n
  }
  return bytes
}

function compressedPointHex(point: NonNullable<Point>): string {
  return Array.from(compressedPoint(point), byte => byte.toString(16).padStart(2, '0')).join('')
}

function silentPaymentPubKey(bytes: Uint8Array): Point {
  if (bytes.length === 32) return liftX(bytes)
  if (bytes.length !== 33) return null
  const inspection = Secp256k1Engine.inspectPubKey(bytes)
  return inspection.isValid && inspection.y !== undefined ? { x: inspection.x, y: inspection.y } : null
}

function silentPaymentIndexBytes(index: number): Uint8Array | undefined {
  if (!Number.isSafeInteger(index) || index < 0 || index > 0xffffffff) return undefined
  const bytes = new Uint8Array(4)
  new DataView(bytes.buffer).setUint32(0, index, false)
  return bytes
}

function silentPaymentHashTweak(hash: Uint8Array): SilentPaymentTweakResult {
  const tweak = unsignedBigEndian(hash)
  if (tweak >= SECP256K1_N) return { valid: false, tweak: 0n, reason: 'Tweak scalar >= n' }
  if (tweak === 0n) return { valid: false, tweak: 0n, reason: 'Tweak scalar is zero' }
  return { valid: true, tweak, tweakBytes: hash }
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

/** Reference curve, signing and verification arithmetic; BigInt operations are not constant-time. */
export class Secp256k1Engine {
  public static pointAdd(left: Point, right: Point): Point { return pointAdd(left, right) }
  public static pointDouble(point: Point): Point { return pointDouble(point) }
  public static scalarMul(scalar: bigint, point: Point): Point { return scalarMul(scalar, point) }
  public static liftX(bytes: Uint8Array): Point { return liftX(bytes) }

  public static tapLeafHash(script: Uint8Array, leafVersion?: number): Uint8Array { return TaprootEngine.tapLeafHash(script, leafVersion) }
  public static tapBranchHash(a32: Uint8Array, b32: Uint8Array): Uint8Array { return TaprootEngine.tapBranchHash(a32, b32) }
  public static tapTweakHash(internalKey32: Uint8Array, merkleRoot32?: Uint8Array): Uint8Array { return TaprootEngine.tapTweakHash(internalKey32, merkleRoot32) }
  public static inspectControlBlock(bytes: Uint8Array): TaprootControlBlockInspection { return TaprootEngine.inspectControlBlock(bytes) }
  public static verifyScriptPath(controlBlock: Uint8Array, outputKey32: Uint8Array, leafScript: Uint8Array): TaprootScriptPathVerificationResult {
    return TaprootEngine.verifyScriptPath(controlBlock, outputKey32, leafScript)
  }
  public static buildTapTree(leaves: TapLeaf[], internalKey32: Uint8Array, structure?: TapTreeStructure): TapTreeResult {
    return TaprootEngine.buildTapTree(leaves, internalKey32, structure)
  }
  public static auditTapscriptKeys(pubkeys: Uint8Array[]): TapscriptKeyAuditResult { return TaprootEngine.auditTapscriptKeys(pubkeys) }

  /** BIP-340 synthetic nonce for a 32-byte message. Omitted aux means 32 zero bytes.
   * Returns the scalar normalized to the even-Y commitment, not the raw hash scalar.
   * This reference implementation is not a constant-time signing backend.
   */
  public static bip340DeriveNonce(
    seckey32: Uint8Array, msg32: Uint8Array, auxRand32?: Uint8Array,
  ): Bip340NonceResult {
    if (seckey32.length !== 32) return { valid: false, reason: 'Secret key must be 32 bytes' }
    if (msg32.length !== 32) return { valid: false, reason: 'Message must be 32 bytes' }
    if (auxRand32 !== undefined && auxRand32.length !== 32) {
      return { valid: false, reason: 'auxRand must be 32 bytes when supplied' }
    }
    const dPrime = unsignedBigEndian(seckey32)
    if (dPrime === 0n || dPrime >= SECP256K1_N) {
      return { valid: false, reason: 'Secret key outside range 0 < d < n' }
    }
    const P = scalarMul(dPrime, GENERATOR)
    if (P === null) return { valid: false, reason: 'Public key is point at infinity' }
    const d = (P.y & 1n) === 0n ? dPrime : SECP256K1_N - dPrime
    const auxHash = taggedHash('BIP0340/aux', auxRand32 ?? new Uint8Array(32))
    const t = bigEndian32(d)
    for (let index = 0; index < 32; index++) t[index] = t[index]! ^ auxHash[index]!
    const rand = taggedHash('BIP0340/nonce', t, bigEndian32(P.x), msg32)
    const kPrime = unsignedBigEndian(rand) % SECP256K1_N
    if (kPrime === 0n) return { valid: false, reason: 'Derived nonce is zero' }
    const R = scalarMul(kPrime, GENERATOR)
    if (R === null) return { valid: false, reason: 'R commitment is point at infinity' }
    const k = (R.y & 1n) === 0n ? kPrime : SECP256K1_N - kPrime
    return { valid: true, k, rx: R.x }
  }

  /** Generate and self-verify a 64-byte BIP-340 signature for a 32-byte message. */
  public static bip340Sign(
    seckey32: Uint8Array, msg32: Uint8Array, auxRand32?: Uint8Array,
  ): Bip340SignResult {
    const nonce = this.bip340DeriveNonce(seckey32, msg32, auxRand32)
    if (!nonce.valid || nonce.k === undefined || nonce.rx === undefined) return { valid: false, reason: nonce.reason }
    const dPrime = unsignedBigEndian(seckey32)
    const P = scalarMul(dPrime, GENERATOR)
    if (P === null) return { valid: false, reason: 'Public key is point at infinity' }
    const d = (P.y & 1n) === 0n ? dPrime : SECP256K1_N - dPrime
    const publicKey32 = bigEndian32(P.x)
    const rxBytes = bigEndian32(nonce.rx)
    const e = unsignedBigEndian(taggedHash('BIP0340/challenge', rxBytes, publicKey32, msg32)) % SECP256K1_N
    const s = (nonce.k + e * d) % SECP256K1_N
    const signature64 = new Uint8Array(64)
    signature64.set(rxBytes)
    signature64.set(bigEndian32(s), 32)
    const verification = this.verifySchnorr(publicKey32, msg32, signature64)
    if (!verification.valid) return { valid: false, reason: `Signature self-verification failed: ${verification.reason}` }
    return { valid: true, signature64, rx: nonce.rx, s, publicKey32 }
  }

  /** Compare a signature to zero-aux and candidate-aux signing transcripts.
   * valid reports successful input validation/comparison; matching is reported separately.
   * A mismatch cannot establish whether the original signer used fresh randomness.
   */
  public static bip340AuditSignatureAux(
    seckey32: Uint8Array, msg32: Uint8Array, sig64: Uint8Array, candidateAux32?: Uint8Array,
  ): Bip340AuxAuditResult {
    const fail = (reason?: string): Bip340AuxAuditResult => ({ valid: false, matchesAux: false, isDeterministicDefault: false, reason })
    if (sig64.length !== 64) return fail('Signature must be 64 bytes')
    if (candidateAux32 !== undefined && candidateAux32.length !== 32) return fail('auxRand must be 32 bytes when supplied')
    const deterministic = this.bip340Sign(seckey32, msg32)
    if (!deterministic.valid || !deterministic.signature64) return fail(deterministic.reason)
    const isDeterministicDefault = deterministic.signature64.every((byte, index) => byte === sig64[index])
    let matchesAux = isDeterministicDefault
    let candidateSignature: Uint8Array | undefined
    if (candidateAux32 !== undefined) {
      const candidate = this.bip340Sign(seckey32, msg32, candidateAux32)
      if (!candidate.valid || !candidate.signature64) return fail(candidate.reason)
      candidateSignature = candidate.signature64
      matchesAux = candidateSignature.every((byte, index) => byte === sig64[index])
    }
    return { valid: true, matchesAux, isDeterministicDefault, expectedSignature: deterministic.signature64, candidateSignature }
  }

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

  /** Reference DLEQ prover. BigInt arithmetic is not constant-time.
   * specification uses the repository's nonce transcript and bounded zero-nonce retry.
   * published-bip uses BIP-374's aux XOR and nonce(t, A, C, m), aborting for k=0.
   * Both profiles produce proofs accepted by the existing BIP-374 verifier.
   */
  public static proveDLEQ(
    sk: bigint | Uint8Array, G1: Point, P1: Point, G2: Point, P2: Point,
    auxRand?: Uint8Array, message?: Uint8Array, profile?: BitcoinVerificationProfile,
  ): Uint8Array {
    const rules = resolveBitcoinVerificationProfile(profile)
    if (sk instanceof Uint8Array && sk.length !== 32) throw new RangeError('Secret key must be 32 bytes')
    const scalar = sk instanceof Uint8Array ? unsignedBigEndian(sk) : sk
    if (typeof scalar !== 'bigint' || scalar <= 0n || scalar >= SECP256K1_N) {
      throw new RangeError('Secret key outside range 0 < sk < n')
    }
    if (auxRand !== undefined && auxRand.length !== 32) throw new RangeError('auxRand must be 32 bytes')
    if (message !== undefined && message.length !== 32) throw new RangeError('DLEQ message must contain exactly 32 bytes')
    for (const [name, point] of [['G1', G1], ['P1', P1], ['G2', G2], ['P2', P2]] as const) {
      if (!isCurvePoint(point)) throw new RangeError(`${name} must be a finite point on secp256k1`)
    }
    const expectedP1 = scalarMul(scalar, G1)!
    const expectedP2 = scalarMul(scalar, G2)!
    if (P1!.x !== expectedP1.x || P1!.y !== expectedP1.y) throw new RangeError('P1 does not equal sk * G1')
    if (P2!.x !== expectedP2.x || P2!.y !== expectedP2.y) throw new RangeError('P2 does not equal sk * G2')
    const aux = auxRand ?? new Uint8Array(32)
    const secretBytes = bigEndian32(scalar)
    const m = message ?? new Uint8Array(0)
    let nonceHash: Uint8Array
    if (rules === 'published-bip') {
      const auxHash = taggedHash('BIP0374/aux', aux)
      const t = secretBytes.map((byte, index) => byte ^ auxHash[index]!)
      nonceHash = taggedHash('BIP0374/nonce', t, compressedPoint(P1!), compressedPoint(P2!), m)
    } else {
      nonceHash = taggedHash('BIP0374/nonce', secretBytes, aux, compressedPoint(P1!),
        compressedPoint(G2!), compressedPoint(P2!), compressedPoint(G1!), m)
    }
    let k = unsignedBigEndian(nonceHash) % SECP256K1_N
    if (rules === 'specification') {
      for (let attempt = 0; k === 0n && attempt < 32; attempt++) {
        nonceHash = taggedHash('BIP0374/nonce', nonceHash)
        k = unsignedBigEndian(nonceHash) % SECP256K1_N
      }
    }
    if (k === 0n) throw new RangeError('Derived DLEQ nonce is zero')
    const R1 = scalarMul(k, G1)!
    const R2 = scalarMul(k, G2)!
    const e = unsignedBigEndian(taggedHash('BIP0374/challenge', compressedPoint(P1!), compressedPoint(G2!),
      compressedPoint(P2!), compressedPoint(G1!), compressedPoint(R1), compressedPoint(R2), m)) % SECP256K1_N
    const s = (k + e * scalar) % SECP256K1_N
    const proof = new Uint8Array(64)
    proof.set(bigEndian32(e))
    proof.set(bigEndian32(s), 32)
    const check = this.verifyDLEQ(G1, P1, G2, P2, proof, message)
    if (!check.valid) throw new RangeError(`DLEQ proof self-verification failed: ${check.reason}`)
    return proof
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

  /** Add compressed SEC points, lifting x-only keys to their even-Y points. */
  public static aggregatePublicKeys(pubkeys: Uint8Array[]): Secp256k1PublicKeyAggregationResult {
    if (pubkeys.length === 0) return { valid: false, point: null, reason: 'Empty public key list' }
    let sum: Point = null
    for (const pubkey of pubkeys) {
      const point = silentPaymentPubKey(pubkey)
      if (point === null) return { valid: false, point: null, reason: 'Invalid public key in aggregation' }
      sum = pointAdd(sum, point)
    }
    if (sum === null) return { valid: false, point: null, reason: 'Aggregated public key is point at infinity' }
    return { valid: true, point: sum, compressed: compressedPoint(sum) }
  }

  /** Directive transcript: compressed(Q) || outpointsHash32 || ser32(k).
   * The published BIP-352 transcript hashes compressed(sharedSecret) || ser32(k),
   * with the input hash already multiplied into sharedSecret. This method follows
   * BITPEEK_BIP352_ENGINE_DIRECTIVE.txt's explicit transcript instead.
   */
  public static createSilentPaymentTweak(
    ecdhPoint: Point,
    outpointsHash32: Uint8Array,
    k = 0,
  ): SilentPaymentTweakResult {
    if (!isCurvePoint(ecdhPoint)) return { valid: false, tweak: 0n, reason: 'ECDH point is null or invalid' }
    if (outpointsHash32.length !== 32) return { valid: false, tweak: 0n, reason: 'Outpoints hash must be 32 bytes' }
    const indexBytes = silentPaymentIndexBytes(k)
    if (!indexBytes) return { valid: false, tweak: 0n, reason: 'Output index must be a uint32' }
    return silentPaymentHashTweak(taggedHash('BIP0352/SharedSecret', compressedPoint(ecdhPoint), outpointsHash32, indexBytes))
  }

  /** Reference public-key addition P = B_spend + t*G; never reduce invalid tweaks. */
  public static deriveSilentPaymentOutputKey(
    spendPubKey: Uint8Array,
    tweakScalarOrBytes: bigint | Uint8Array,
  ): SilentPaymentOutputKeyResult {
    const spendPoint = silentPaymentPubKey(spendPubKey)
    if (spendPoint === null) return { valid: false, reason: 'Invalid spend public key' }
    let tweak: bigint
    if (tweakScalarOrBytes instanceof Uint8Array) {
      if (tweakScalarOrBytes.length !== 32) return { valid: false, reason: 'Tweak scalar must be 32 bytes' }
      tweak = unsignedBigEndian(tweakScalarOrBytes)
    } else {
      tweak = tweakScalarOrBytes
    }
    if (typeof tweak !== 'bigint' || tweak <= 0n || tweak >= SECP256K1_N) {
      return { valid: false, reason: 'Tweak scalar outside valid range (0 < t < n)' }
    }
    const output = pointAdd(spendPoint, scalarMul(tweak, GENERATOR))
    if (output === null) return { valid: false, reason: 'Tweaked point is point at infinity' }
    return { valid: true, outputKey32: compressedPoint(output).slice(1), parity: Number(output.y & 1n) }
  }

  /** BIP-352 label hash uses the scan private scalar, including change label zero.
   * This reference BigInt implementation does not provide constant-time handling
   * of private input material.
   */
  public static deriveSilentPaymentLabelTweak(scanPrivKey32: Uint8Array, labelIndex: number): SilentPaymentTweakResult {
    if (scanPrivKey32.length !== 32) return { valid: false, tweak: 0n, reason: 'Scan private key must be 32 bytes' }
    const scanScalar = unsignedBigEndian(scanPrivKey32)
    if (scanScalar === 0n || scanScalar >= SECP256K1_N) {
      return { valid: false, tweak: 0n, reason: 'Scan private key outside valid range (0 < b_scan < n)' }
    }
    const indexBytes = silentPaymentIndexBytes(labelIndex)
    if (!indexBytes) return { valid: false, tweak: 0n, reason: 'Label index must be a uint32' }
    return silentPaymentHashTweak(taggedHash('BIP0352/Label', scanPrivKey32, indexBytes))
  }

  public static verifySilentPaymentTweak(
    spendPubKey: Uint8Array,
    tweakScalarOrBytes: bigint | Uint8Array,
    expectedOutputKey32: Uint8Array,
  ): SilentPaymentTweakVerificationResult {
    if (expectedOutputKey32.length !== 32) return { valid: false, parity: -1, reason: 'Expected output key must be 32 bytes' }
    const derived = this.deriveSilentPaymentOutputKey(spendPubKey, tweakScalarOrBytes)
    if (!derived.valid) return { valid: false, parity: -1, reason: derived.reason }
    let difference = 0
    for (let index = 0; index < 32; index++) difference |= derived.outputKey32![index]! ^ expectedOutputKey32[index]!
    return difference === 0 ? { valid: true, parity: derived.parity! }
      : { valid: false, parity: derived.parity!, reason: 'Output key mismatch' }
  }

  /** Audit candidate-slot inversion against the known incorrect offset placement. */
  public static verifySilentPaymentBatchMapping(
    jStart: number, slotIndex: number,
  ): { correctIndex: number; mutantIndex: number; isEquiv: boolean } {
    if (!Number.isSafeInteger(jStart) || jStart < 0 || !Number.isSafeInteger(slotIndex) || slotIndex < 0
      || !Number.isSafeInteger(jStart + slotIndex)) {
      throw new RangeError('Batch offset and slot index must be nonnegative safe integers with a safe sum')
    }
    const correctIndex = jStart + Math.floor(slotIndex / 2)
    const mutantIndex = Math.floor((jStart + slotIndex) / 2)
    return { correctIndex, mutantIndex, isEquiv: correctIndex === mutantIndex }
  }

  /** Scan all output batches for one precomputed BIP-352 t_k and label cache.
   * Batching partitions transaction positions; it does not advance the protocol's k.
   * Labels and the shared-secret tweak are supplied by the caller; the scan key is validated.
   */
  public static scanSilentPaymentOutputs(params: SilentPaymentScanParams): SilentPaymentScanResult {
    const fail = (reason: string): SilentPaymentScanResult => ({ valid: false, matches: [], totalOutputsScanned: 0, batchCount: 0, reason })
    const batchSize = params.batchSize ?? 50
    if (!Number.isSafeInteger(batchSize) || batchSize <= 0) return fail('batchSize must be a positive safe integer')
    if (params.scanPrivKey32.length !== 32) return fail('Scan private key must be 32 bytes')
    const scanScalar = unsignedBigEndian(params.scanPrivKey32)
    if (scanScalar === 0n || scanScalar >= SECP256K1_N) return fail('Scan private key outside valid range (0 < b_scan < n)')
    const spendPoint = silentPaymentPubKey(params.spendPubKey)
    if (spendPoint === null) return fail('Invalid spend public key')
    let tweak: bigint
    if (params.sharedSecretTweak instanceof Uint8Array) {
      if (params.sharedSecretTweak.length !== 32) return fail('Tweak bytes must be 32 bytes')
      tweak = unsignedBigEndian(params.sharedSecretTweak)
    } else {
      tweak = params.sharedSecretTweak
    }
    if (typeof tweak !== 'bigint' || tweak <= 0n || tweak >= SECP256K1_N) return fail('Tweak scalar outside 0 < t < n')
    const unlabeledPoint = pointAdd(spendPoint, scalarMul(tweak, GENERATOR))
    if (unlabeledPoint === null) return fail('Unlabeled point is infinity')
    const negUnlabeled = { x: unlabeledPoint.x, y: SECP256K1_P - unlabeledPoint.y }

    const labelMap = new Map<string, SilentPaymentLabelDefinition>()
    for (const label of params.labels ?? []) {
      if (!silentPaymentIndexBytes(label.labelIndex)) return fail('Label index must be a uint32')
      if (label.labelTweak32.length !== 32) return fail('Label tweak must be 32 bytes')
      const labelScalar = unsignedBigEndian(label.labelTweak32)
      if (labelScalar === 0n || labelScalar >= SECP256K1_N) return fail('Label tweak scalar outside 0 < m < n')
      const labelPoint = label.labelPubKey33 === undefined ? scalarMul(labelScalar, GENERATOR)
        : label.labelPubKey33.length === 33 ? silentPaymentPubKey(label.labelPubKey33) : null
      if (labelPoint === null) return fail('Invalid label public key')
      labelMap.set(compressedPointHex(labelPoint), label)
    }

    const matches: SilentPaymentScanMatch[] = []
    const totalOutputs = params.txOutputs.length
    const batchCount = Math.ceil(totalOutputs / batchSize) || 1
    for (let batchIndex = 0; batchIndex < batchCount; batchIndex++) {
      const jStart = batchIndex * batchSize
      const jEnd = Math.min(jStart + batchSize, totalOutputs)
      for (let j = jStart; j < jEnd; j++) {
        const outBytes = params.txOutputs[j]
        if (!outBytes || outBytes.length !== 32) continue
        if (unsignedBigEndian(outBytes) === unlabeledPoint.x) {
          matches.push({ outputIndex: j, outputKey32: outBytes, isLabeled: false,
            candidateSlotParity: Number(unlabeledPoint.y & 1n), batchIndex, batchOffset: jStart })
          continue
        }
        if (labelMap.size === 0) continue
        const pEven = liftX(outBytes)
        if (pEven === null) continue
        const pOdd = { x: pEven.x, y: SECP256K1_P - pEven.y }
        // C_even = P_even - P_unlabeled; C_odd = -P_even - P_unlabeled.
        const candidates = [pointAdd(pEven, negUnlabeled), pointAdd(pOdd, negUnlabeled)]
        for (const [parity, candidate] of candidates.entries()) {
          if (candidate === null) continue
          const label = labelMap.get(compressedPointHex(candidate))
          if (!label) continue
          const slotIndex = 2 * (j - jStart) + parity
          const mappedIndex = this.verifySilentPaymentBatchMapping(jStart, slotIndex).correctIndex
          matches.push({ outputIndex: mappedIndex, outputKey32: outBytes, isLabeled: true,
            labelIndex: label.labelIndex, labelTweak32: label.labelTweak32,
            candidateSlotParity: parity, batchIndex, batchOffset: jStart })
          break
        }
      }
    }
    return { valid: true, matches, totalOutputsScanned: totalOutputs, batchCount, unlabeledPoint }
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
