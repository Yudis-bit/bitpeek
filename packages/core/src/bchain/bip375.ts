import { unsignedBigEndian } from '../bytes'
import { taggedHash } from '../crypto'
import {
  Secp256k1Engine, SECP256K1_GX, SECP256K1_GY, SECP256K1_N,
  compressedPoint, liftX, pointAdd, scalarMul, type Point,
} from './secp256k1'
import { resolveBitcoinVerificationProfile, type BitcoinVerificationProfile } from './verification-profile'

export const BIP375_MAX_SIGNERS = 4096
export const BIP375_MAX_OUTPUTS = 2323

export interface Bip375SignerInput {
  inputPubkeyHex: string
  ecdhShareHex: string
  dleqProofHex: string
}

export interface Bip375SignerShare {
  inputPubkey: Uint8Array
  ecdhShare: Uint8Array
  dleqProof: Uint8Array
}

export interface Bip375AuditParams {
  signers: Bip375SignerShare[]
  scanPubkey: Uint8Array
  outpointSmallest: Uint8Array
  /** Eligible transaction input keys, including repeated keys for distinct inputs. */
  allInputPubkeys: Uint8Array[]
  spendPubkey: Uint8Array
  expectedOutputs?: Uint8Array[]
  expectedScalarFold?: Uint8Array
  outputCount?: number
  profile?: BitcoinVerificationProfile
}

export interface Bip375AuditResult {
  valid: boolean
  signerCount: number
  verifiedSigners: boolean[]
  rejectionReason?: string
  aggregatedShareHex?: string
  /** Compressed point S = input_hash * C_sum, not a secret scalar. */
  scalarFoldTweakHex?: string
  inputHashHex?: string
  expectedOutputKeysHex?: string[]
  verifiedOutputs?: boolean[]
  profile: BitcoinVerificationProfile
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

function publicPoint(bytes: Uint8Array): Point {
  if (bytes.length === 32) return liftX(bytes)
  if (bytes.length !== 33 || (bytes[0] !== 2 && bytes[0] !== 3)) return null
  const key = Secp256k1Engine.inspectPubKey(bytes)
  return key.isValid && key.y !== undefined ? { x: key.x, y: key.y } : null
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!
  }
  return a.length - b.length
}

/** Audit already-extracted BIP-375 per-input shares for one recipient.
 * Coverage is a multiset comparison against the caller's eligible input keys.
 * Transaction parsing, eligibility and smallest-outpoint selection belong to the caller.
 */
export function auditBip375Shares(params: Bip375AuditParams): Bip375AuditResult {
  const profile = resolveBitcoinVerificationProfile(params.profile)
  const signerCount = params.signers.length
  const result: Bip375AuditResult = { valid: false, signerCount,
    verifiedSigners: Array.from({ length: Math.min(signerCount, BIP375_MAX_SIGNERS) }, () => false), profile }
  const fail = (rejectionReason: string): Bip375AuditResult => ({ ...result, rejectionReason })
  if (signerCount === 0 || signerCount > BIP375_MAX_SIGNERS) return fail(`signers must contain 1 to ${BIP375_MAX_SIGNERS} entries`)
  if (params.outpointSmallest.length !== 36) return fail('outpointSmallest must contain exactly 36 bytes')
  const scan = publicPoint(params.scanPubkey)
  if (scan === null) return fail('Invalid recipient scan public key')
  const spend = publicPoint(params.spendPubkey)
  if (spend === null) return fail('Invalid recipient spend public key')
  if (params.allInputPubkeys.length === 0 || params.allInputPubkeys.length > BIP375_MAX_SIGNERS) {
    return fail(`allInputPubkeys must contain 1 to ${BIP375_MAX_SIGNERS} eligible input keys`)
  }
  const outputCount = params.outputCount ?? params.expectedOutputs?.length ?? 1
  if (!Number.isSafeInteger(outputCount) || outputCount < 0 || outputCount > BIP375_MAX_OUTPUTS) {
    return fail(`outputCount must be an integer in [0, ${BIP375_MAX_OUTPUTS}]`)
  }
  if (params.expectedOutputs !== undefined && params.expectedOutputs.length !== outputCount) {
    return fail('expectedOutputs length must equal outputCount')
  }
  const remaining = new Map<string, number>()
  let inputSum: Point = null
  for (const [index, key] of params.allInputPubkeys.entries()) {
    const point = publicPoint(key)
    if (point === null) return fail(`Invalid eligible input public key at index ${index}`)
    const id = hex(compressedPoint(point))
    remaining.set(id, (remaining.get(id) ?? 0) + 1)
    inputSum = pointAdd(inputSum, point)
  }
  if (inputSum === null) return fail('Aggregated input public key is point at infinity')
  let shareSum: Point = null
  let firstFailure: string | undefined
  const generator = { x: SECP256K1_GX, y: SECP256K1_GY }
  for (const [index, signer] of params.signers.entries()) {
    const input = publicPoint(signer.inputPubkey)
    const share = signer.ecdhShare.length === 33 ? publicPoint(signer.ecdhShare) : null
    let reason: string | undefined
    if (input === null) reason = 'invalid input public key'
    else {
      const id = hex(compressedPoint(input))
      const count = remaining.get(id) ?? 0
      if (count === 0) reason = 'rogue or duplicate signer key outside the eligible input multiset'
      else remaining.set(id, count - 1)
    }
    if (!reason && share === null) reason = 'invalid compressed ECDH share'
    if (!reason) {
      const check = Secp256k1Engine.verifyDLEQ(generator, input, scan, share, signer.dleqProof)
      if (!check.valid) reason = check.reason
    }
    if (reason) firstFailure ??= `Signer ${index}: ${reason}`
    else {
      result.verifiedSigners[index] = true
      shareSum = pointAdd(shareSum, share)
    }
  }
  if (firstFailure) return fail(firstFailure)
  if (signerCount !== params.allInputPubkeys.length || Array.from(remaining.values()).some(count => count !== 0)) {
    return fail('Missing signer shares: coverage must include every eligible input exactly once')
  }
  if (shareSum === null) return fail('Aggregated ECDH share is point at infinity')
  result.aggregatedShareHex = hex(compressedPoint(shareSum))
  // The requested reference model hashes sorted keys; BIP-352 hashes their aggregate point.
  const inputHash = profile === 'specification'
    ? taggedHash('BIP0352/Inputs', params.outpointSmallest, ...params.allInputPubkeys.slice().sort(compareBytes))
    : taggedHash('BIP0352/Inputs', params.outpointSmallest, compressedPoint(inputSum))
  const inputScalar = unsignedBigEndian(inputHash)
  if (inputScalar === 0n || inputScalar >= SECP256K1_N) return fail('input_hash must satisfy 0 < input_hash < n')
  result.inputHashHex = hex(inputHash)
  const sharedSecret = scalarMul(inputScalar, shareSum)
  if (sharedSecret === null) return fail('Scalar fold is point at infinity')
  result.scalarFoldTweakHex = hex(compressedPoint(sharedSecret))
  if (params.expectedScalarFold !== undefined) {
    const expected = params.expectedScalarFold.length === 33 ? publicPoint(params.expectedScalarFold) : null
    if (expected === null || expected.x !== sharedSecret.x || expected.y !== sharedSecret.y) {
      return fail('Scalar fold mismatch: expected S must equal input_hash * C_sum')
    }
  }
  result.expectedOutputKeysHex = []
  if (params.expectedOutputs !== undefined) result.verifiedOutputs = []
  let firstOutputFailure: string | undefined
  for (let k = 0; k < outputCount; k++) {
    const indexBytes = new Uint8Array(4)
    new DataView(indexBytes.buffer).setUint32(0, k, false)
    const tweak = unsignedBigEndian(taggedHash('BIP0352/SharedSecret', compressedPoint(sharedSecret), indexBytes))
    if (tweak === 0n || tweak >= SECP256K1_N) return fail(`Output ${k}: tweak must satisfy 0 < t_k < n`)
    const output = pointAdd(spend, scalarMul(tweak, generator))
    if (output === null) return fail(`Output ${k}: derived key is point at infinity`)
    const outputHex = output.x.toString(16).padStart(64, '0')
    result.expectedOutputKeysHex.push(outputHex)
    if (params.expectedOutputs !== undefined) {
      const expected = params.expectedOutputs[k]!
      const valid = expected.length === 32 && liftX(expected) !== null && hex(expected) === outputHex
      result.verifiedOutputs!.push(valid)
      if (!valid) firstOutputFailure ??= `Output ${k}: recipient output key mismatch or invalid x-only key`
    }
  }
  return firstOutputFailure ? fail(firstOutputFailure) : { ...result, valid: true }
}
