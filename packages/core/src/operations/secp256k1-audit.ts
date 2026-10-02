import { BitcoinParser } from '../bchain/bitcoin'
import type { BitcoinTransaction } from '../bchain/bitcoin'
import { Secp256k1Engine, SECP256K1_N, SECP256K1_P } from '../bchain/secp256k1'
import type { Secp256k1PubKeyInspection, Secp256k1SignatureInspection } from '../bchain/secp256k1'
import { parseHex } from '../bytes'
import type { OperationDescriptor } from './types'
import type { RecipeFile } from '../recipe'

export const SECP256K1_AUDIT_MAX_BYTES = 1024 * 1024
export const SECP256K1_AUDIT_RECIPE: RecipeFile & { name: string; category: 'crypto' } = {
  schemaVersion: 1, recipeId: 'secp256k1.audit', name: 'secp256k1.audit', category: 'crypto',
  title: 'secp256k1 Audit', engineCompatibility: '1.0.0',
  inputs: [{ id: 'input' }], steps: [{ id: 'audit', operation: 'secp256k1.audit', input: 'input' }],
}
export type Secp256k1AuditFormat = 'auto' | 'pubkey' | 'der' | 'compact' | 'bitcoin-tx'
export type Secp256k1AuditInput = Uint8Array | {
  bytes?: Uint8Array
  rawHex?: string
  format?: Secp256k1AuditFormat
}

export interface Secp256k1AuditFinding {
  severity: 'warning' | 'critical'
  code: 'high-s' | 'field-overflow' | 'scalar-overflow' | 'invalid-point' | 'invalid-encoding' | 'transaction-invariant'
  message: string
  location: string
}

type JsonPubKeyInspection = Omit<Secp256k1PubKeyInspection, 'x' | 'y'> & { x: string; y?: string }
type JsonSignatureInspection = Omit<Secp256k1SignatureInspection, 'r' | 's'> & { r: string; s: string }

export interface Secp256k1AuditResult {
  format: Exclude<Secp256k1AuditFormat, 'auto'> | 'unknown'
  verificationScope: 'encoding-curve-and-context-free-transaction-invariants'
  cryptographicSignaturesVerified: false
  findings: Secp256k1AuditFinding[]
  inspections: Array<{ location: string; kind: 'pubkey' | 'der' | 'compact'; inspection: JsonPubKeyInspection | JsonSignatureInspection }>
  uninspectedLocations: string[]
  transaction?: {
    txidDisplay: string
    txidWire: string
    isSegWit: boolean
    inputCount: number
    outputCount: number
    totalOutputSatoshis: string
    weightUnits: number
    vsizeBytes: number
  }
}

function inspectKey(bytes: Uint8Array, location: string, result: Secp256k1AuditResult): void {
  const key = Secp256k1Engine.inspectPubKey(bytes)
  const { x, y, ...details } = key
  result.inspections.push({ location, kind: 'pubkey', inspection: {
    ...details, x: x.toString(), ...(y !== undefined ? { y: y.toString() } : {}),
  } })
  if (key.isValid) return
  if (key.x >= SECP256K1_P || (key.y !== undefined && key.y >= SECP256K1_P)) {
    const coordinate = key.x >= SECP256K1_P ? 'x' : 'y'
    result.findings.push({ severity: 'critical', code: 'field-overflow', message: `Field element overflow (${coordinate} ≥ p)`, location })
  } else {
    const invalidPoint = key.format !== 'invalid'
    result.findings.push({ severity: 'critical', code: invalidPoint ? 'invalid-point' : 'invalid-encoding', message: key.rejectionReason!, location })
  }
}

function inspectSignature(bytes: Uint8Array, kind: 'der' | 'compact', location: string, result: Secp256k1AuditResult): void {
  const sig = kind === 'der' ? Secp256k1Engine.inspectSignatureDER(bytes) : Secp256k1Engine.inspectCompactSignature(bytes)
  result.inspections.push({ location, kind, inspection: { ...sig, r: sig.r.toString(), s: sig.s.toString() } })
  if (!sig.isDer && !sig.isCompact64) {
    result.findings.push({ severity: 'critical', code: 'invalid-encoding', message: sig.rejectionReason!, location })
    return
  }
  for (const [name, scalar] of [['r', sig.r], ['s', sig.s]] as const) {
    if (scalar >= SECP256K1_N) {
      result.findings.push({ severity: 'critical', code: 'scalar-overflow', message: 'Scalar overflow (k ≥ n)', location: `${location}.${name}` })
    } else if (scalar <= 0n) {
      result.findings.push({ severity: 'critical', code: 'invalid-encoding', message: `${name.toUpperCase()} must satisfy 0 < ${name} < n`, location: `${location}.${name}` })
    }
  }
  if (sig.isCanonicalS && !sig.isLowS) {
    result.findings.push({ severity: 'warning', code: 'high-s', message: 'Malleable signature detected (BIP-62/146 violation)', location })
  }
}

/** Extract script pushes without interpreting payload bytes as opcodes. */
function scriptPushes(script: Uint8Array): Array<{ bytes: Uint8Array; offset: number }> {
  const pushes: Array<{ bytes: Uint8Array; offset: number }> = []
  let cursor = 0
  while (cursor < script.length) {
    const opcode = script[cursor++]!
    let length: number
    if (opcode <= 75) length = opcode
    else if (opcode >= 0x4c && opcode <= 0x4e) {
      const width = 2 ** (opcode - 0x4c)
      if (cursor + width > script.length) throw new Error('Truncated script push length')
      const view = new DataView(script.buffer, script.byteOffset + cursor, width)
      length = width === 1 ? view.getUint8(0) : width === 2 ? view.getUint16(0, true) : view.getUint32(0, true)
      cursor += width
    } else continue
    if (cursor + length > script.length) throw new Error('Truncated script push payload')
    pushes.push({ bytes: script.subarray(cursor, cursor + length), offset: cursor })
    cursor += length
  }
  return pushes
}

function inspectEcdsaCandidate(bytes: Uint8Array, location: string, result: Secp256k1AuditResult): void {
  // Script signatures include one sighash byte outside the DER sequence.
  if (bytes.length >= 9 && bytes.length <= 73 && bytes[0] === 0x30) {
    inspectSignature(bytes.subarray(0, -1), 'der', location, result)
  } else if ((bytes.length === 33 || bytes.length === 65) && bytes[0]! >= 2 && bytes[0]! <= 7) {
    inspectKey(bytes, location, result)
  } else if (bytes.length > 0) result.uninspectedLocations.push(location)
}

function auditTransaction(tx: BitcoinTransaction, result: Secp256k1AuditResult): void {
  const invariant = (message: string, location: string) => result.findings.push({ severity: 'critical', code: 'transaction-invariant', message, location })
  const total = tx.outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n)
  const maxMoney = 21_000_000n * 100_000_000n
  result.transaction = {
    txidDisplay: tx.txidDisplay, txidWire: tx.txidWire, isSegWit: tx.isSegWit,
    inputCount: tx.inputs.length, outputCount: tx.outputs.length, totalOutputSatoshis: total.toString(),
    weightUnits: tx.weightUnits, vsizeBytes: tx.vsizeBytes,
  }
  if (tx.inputs.length === 0) invariant('Transaction has no inputs', 'transaction.inputs')
  if (tx.outputs.length === 0) invariant('Transaction has no outputs', 'transaction.outputs')
  if (total > maxMoney) invariant('Total output value exceeds MAX_MONEY', 'transaction.outputs')
  if (tx.weightUnits > 4_000_000) invariant('Transaction weight exceeds the block weight limit', 'transaction')
  const nullHash = '0'.repeat(64)
  const isCoinbase = tx.inputs.length === 1 && tx.inputs[0]!.txidWireHex === nullHash && tx.inputs[0]!.vout === 0xffffffff
  const outpoints = new Set<string>()
  tx.inputs.forEach((input, index) => {
    const location = `transaction.inputs[${index}]`
    const outpoint = `${input.txidWireHex}:${input.vout}`
    if (outpoints.has(outpoint)) invariant('Duplicate transaction input outpoint', location)
    outpoints.add(outpoint)
    if (isCoinbase) {
      if (input.scriptSig.length < 2 || input.scriptSig.length > 100) invariant('Coinbase scriptSig must contain 2..100 bytes', `${location}.scriptSig`)
      result.uninspectedLocations.push(`${location}.scriptSig`)
    } else {
      if (input.txidWireHex === nullHash && input.vout === 0xffffffff) invariant('Null prevout in a non-coinbase transaction', location)
      try {
        for (const push of scriptPushes(input.scriptSig)) {
          inspectEcdsaCandidate(push.bytes, `${location}.scriptSig@${push.offset}`, result)
        }
      } catch (error: unknown) {
        result.findings.push({ severity: 'critical', code: 'invalid-encoding', message: error instanceof Error ? error.message : String(error), location: `${location}.scriptSig` })
      }
    }
    const witness = input.witness ?? []
    // Recognize a P2WPKH-shaped stack. Other stacks require prevout/script context,
    // especially Taproot Schnorr signatures and control blocks.
    if (!isCoinbase && witness.length === 2 && witness[1]!.length === 33 && (witness[0]!.length === 0 || witness[0]![0] === 0x30)) {
      if (witness[0]!.length > 0) inspectSignature(witness[0]!.subarray(0, -1), 'der', `${location}.witness[0]`, result)
      inspectKey(witness[1]!, `${location}.witness[1]`, result)
    } else witness.forEach((_, item) => result.uninspectedLocations.push(`${location}.witness[${item}]`))
  })
  tx.outputs.forEach((output, index) => {
    const location = `transaction.outputs[${index}]`
    if (output.valueSatoshis > maxMoney) invariant('Output value exceeds MAX_MONEY', `${location}.valueSatoshis`)
    const script = output.scriptPubKey
    if ((script.length === 35 && script[0] === 33 || script.length === 67 && script[0] === 65) && script[script.length - 1] === 0xac) {
      inspectKey(script.subarray(1, -1), `${location}.scriptPubKey`, result)
    } else if (script.length === 34 && script[0] === 0x51 && script[1] === 32) {
      inspectKey(script.subarray(2), `${location}.scriptPubKey`, result)
    } else if (script.length > 0) result.uninspectedLocations.push(`${location}.scriptPubKey`)
  })
}

/** Auto detection is heuristic; use format for ambiguous raw encodings. */
export function auditSecp256k1(bytes: Uint8Array, format: Secp256k1AuditFormat = 'auto'): Secp256k1AuditResult {
  if (bytes.length > SECP256K1_AUDIT_MAX_BYTES) throw new RangeError('secp256k1 audit input exceeds 1 MiB')
  if (!['auto', 'pubkey', 'der', 'compact', 'bitcoin-tx'].includes(format)) throw new Error('Unsupported secp256k1 audit format')
  const result: Secp256k1AuditResult = {
    format: 'unknown', verificationScope: 'encoding-curve-and-context-free-transaction-invariants',
    cryptographicSignaturesVerified: false, findings: [], inspections: [], uninspectedLocations: [],
  }
  if (format === 'auto' || format === 'bitcoin-tx') {
    let tx: BitcoinTransaction | undefined
    try { tx = BitcoinParser.parseTransaction(bytes) } catch (error: unknown) {
      if (format === 'bitcoin-tx') {
        result.format = 'bitcoin-tx'
        result.findings.push({ severity: 'critical', code: 'invalid-encoding', message: error instanceof Error ? error.message : String(error), location: 'transaction' })
        return result
      }
    }
    if (tx) {
      result.format = 'bitcoin-tx'
      auditTransaction(tx, result)
      return result
    }
  }
  let detected = format
  if (detected === 'auto') {
    const isKeyLength = [32, 33, 65].includes(bytes.length)
    const looksDer = bytes[0] === 0x30 && bytes.length >= 8 && bytes.length <= 72
    const isDer = looksDer && Secp256k1Engine.inspectSignatureDER(bytes).isDer
    if (isDer) detected = 'der'
    else if (isKeyLength && Secp256k1Engine.inspectPubKey(bytes).isValid) detected = 'pubkey'
    else if (looksDer && bytes.length !== 64) detected = 'der'
    else if (isKeyLength) detected = 'pubkey'
    else if (bytes.length === 64) detected = 'compact'
  }
  if (detected === 'pubkey') { result.format = detected; inspectKey(bytes, 'input', result) }
  else if (detected === 'der' || detected === 'compact') { result.format = detected; inspectSignature(bytes, detected, 'input', result) }
  else result.findings.push({ severity: 'critical', code: 'invalid-encoding', message: 'Unrecognized secp256k1 audit input', location: 'input' })
  return result
}

export const secp256k1AuditOperation: OperationDescriptor<Secp256k1AuditInput, Secp256k1AuditResult> & { category: 'crypto' } = {
  id: 'secp256k1.audit', category: 'crypto', version: '1.0.0', title: 'secp256k1 Encoding and Curve Audit',
  description: 'Inspect public keys, ECDSA encoding/low-S policy, and context-free Bitcoin transaction invariants.',
  environment: 'any', deterministic: true, readOnly: true,
  resourceProfile: { maxMemoryBytes: 16 * 1024 * 1024, maxExecutionMs: 5000 },
  async execute(input, context) {
    if (context?.signal?.aborted) throw new Error('secp256k1 audit was aborted')
    if (input instanceof Uint8Array) return auditSecp256k1(input)
    if (input.bytes !== undefined && input.rawHex !== undefined) throw new Error('Supply either bytes or rawHex, not both')
    let bytes = input.bytes
    if (input.rawHex !== undefined) {
      if (input.rawHex.length > SECP256K1_AUDIT_MAX_BYTES * 3) throw new RangeError('secp256k1 audit hex input exceeds its size limit')
      const parsed = parseHex(input.rawHex)
      if (!parsed.ok) throw new Error(parsed.error)
      bytes = parsed.bytes
    }
    if (!bytes && context?.source) {
      if (context.source.size > SECP256K1_AUDIT_MAX_BYTES) throw new RangeError('secp256k1 audit input exceeds 1 MiB')
      bytes = await context.source.read(0, context.source.size, context.signal)
      if (bytes.length !== context.source.size) throw new Error('Incomplete ByteSource read for secp256k1 audit')
    }
    if (!bytes) throw new Error('bytes, rawHex, or ByteSource context required for secp256k1 audit')
    return auditSecp256k1(bytes, input.format)
  },
}
