import { sha256 } from '../crypto'
import { Secp256k1Engine, liftX } from './secp256k1'
import { sha1, ripemd160 } from './script-hashes'
import { resolveBitcoinVerificationProfile, type BitcoinVerificationProfile } from './verification-profile'

export const TAPSCRIPT_MAX_STACK_SIZE = 1000
export const TAPSCRIPT_MAX_ELEMENT_SIZE = 520
export const TAPSCRIPT_SIGOPS_BASE = 50
export const TAPSCRIPT_SIGOPS_COST = 50

export type TapscriptSafetySeverity = 'fatal' | 'warning' | 'info'
export interface TapscriptSafetyFinding {
  severity: TapscriptSafetySeverity
  code: 'sigops-budget-exhaustion' | 'conditional-sigops-exhaustion' | 'anyone-can-spend'
    | 'op-success-override' | 'timelock-unit-collision' | 'disabled-opcode'
    | 'stack-overflow-risk' | 'dead-code' | 'malformed-script' | 'analysis-incomplete'
  message: string
  details?: Record<string, unknown>
}
export interface TapscriptBranchAnalysis {
  branchIndex: number
  conditionPath: string[]
  sigopsRequired: number
  budgetExceeded: boolean
  requiresSignatures: boolean
  hasOpSuccess: boolean
  terminatesSafely: boolean
}
export interface TapscriptAuditResult {
  scriptHex: string
  scriptLength: number
  sigopsBudget: number
  minSigopsRequired: number
  maxSigopsRequired: number
  isPermanentlyUnspendable: boolean
  hasAnyoneCanSpendPath: boolean
  hasOpSuccess: boolean
  branches: TapscriptBranchAnalysis[]
  findings: TapscriptSafetyFinding[]
  disassembly: string[]
  profile: BitcoinVerificationProfile
  budgetScope: 'script-bytes' | 'serialized-witness'
  /** Static satisfiability remains conservative for unknown witness data. */
  analysisComplete: boolean
}
export interface TapscriptEvalStep {
  pc: number
  opcodeName: string
  opcodeHex: string
  budgetRemaining: number
  stackSize: number
  topStackHex?: string
  executed?: boolean
}
export interface TapscriptEvalResult {
  success: boolean
  budgetRemaining: number
  finalStack: string[]
  finalAltStack: string[]
  stepsExecuted: number
  failureReason?: string
  trace?: TapscriptEvalStep[]
  traceTruncated?: boolean
  profile: BitcoinVerificationProfile
  budgetScope: 'script-bytes' | 'serialized-witness'
  simulationMode: boolean
  cryptographicSignaturesVerified: boolean
}
export interface TapscriptBudgetOptions {
  profile?: BitcoinVerificationProfile
  /** Complete serialized transaction-input witness size, including CompactSize prefixes,
   * script, control block and optional annex. Required for the published-bip profile.
   */
  serializedWitnessSize?: number
}
export interface TapscriptAuditOptions extends TapscriptBudgetOptions {
  maxBranches?: number
  maxAnalysisSteps?: number
}
export interface TapscriptSignatureContext {
  pc: number
  opcodePosition: number
  codeSeparatorPosition: number
  hashType: number
}
export interface TapscriptEvalOptions extends TapscriptBudgetOptions {
  traceExecution?: boolean
  traceLimit?: number
  /** Explicit structural simulation; never reports cryptographic verification. */
  simulationMode?: boolean
  /** Already-computed 32-byte TapSighash for a fixed context. */
  message?: Uint8Array
  /** Resolve transaction sighashes for each hash type and executed CODESEPARATOR. */
  signatureMessage?: (context: TapscriptSignatureContext) => Uint8Array
  lockTime?: number
  inputSequence?: number
  transactionVersion?: number
}
export type TapscriptOpcodeKind = 'push' | 'small-integer' | 'op-success' | 'disabled' | 'control' | 'signature' | 'standard' | 'invalid'
export interface TapscriptOpcodeClassification {
  opcode: number
  name: string
  kind: TapscriptOpcodeKind
}
export interface TapscriptInstruction extends TapscriptOpcodeClassification {
  pc: number
  nextPc: number
  opcodePosition: number
  data?: Uint8Array
}

const NAMES: Record<number, string> = {
  0x00: 'OP_0', 0x4c: 'OP_PUSHDATA1', 0x4d: 'OP_PUSHDATA2', 0x4e: 'OP_PUSHDATA4', 0x4f: 'OP_1NEGATE',
  0x50: 'OP_RESERVED', 0x61: 'OP_NOP', 0x62: 'OP_VER', 0x63: 'OP_IF', 0x64: 'OP_NOTIF',
  0x65: 'OP_VERIF', 0x66: 'OP_VERNOTIF', 0x67: 'OP_ELSE', 0x68: 'OP_ENDIF', 0x69: 'OP_VERIFY', 0x6a: 'OP_RETURN',
  0x6b: 'OP_TOALTSTACK', 0x6c: 'OP_FROMALTSTACK', 0x6d: 'OP_2DROP', 0x6e: 'OP_2DUP', 0x6f: 'OP_3DUP',
  0x70: 'OP_2OVER', 0x71: 'OP_2ROT', 0x72: 'OP_2SWAP', 0x73: 'OP_IFDUP', 0x74: 'OP_DEPTH',
  0x75: 'OP_DROP', 0x76: 'OP_DUP', 0x77: 'OP_NIP', 0x78: 'OP_OVER', 0x79: 'OP_PICK',
  0x7a: 'OP_ROLL', 0x7b: 'OP_ROT', 0x7c: 'OP_SWAP', 0x7d: 'OP_TUCK', 0x7e: 'OP_CAT',
  0x7f: 'OP_SUBSTR', 0x80: 'OP_LEFT', 0x81: 'OP_RIGHT', 0x82: 'OP_SIZE', 0x83: 'OP_INVERT',
  0x84: 'OP_AND', 0x85: 'OP_OR', 0x86: 'OP_XOR', 0x87: 'OP_EQUAL', 0x88: 'OP_EQUALVERIFY',
  0x89: 'OP_RESERVED1', 0x8a: 'OP_RESERVED2', 0x8b: 'OP_1ADD', 0x8c: 'OP_1SUB',
  0x8d: 'OP_2MUL', 0x8e: 'OP_2DIV', 0x8f: 'OP_NEGATE', 0x90: 'OP_ABS', 0x91: 'OP_NOT',
  0x92: 'OP_0NOTEQUAL', 0x93: 'OP_ADD', 0x94: 'OP_SUB', 0x95: 'OP_MUL', 0x96: 'OP_DIV',
  0x97: 'OP_MOD', 0x98: 'OP_LSHIFT', 0x99: 'OP_RSHIFT', 0x9a: 'OP_BOOLAND', 0x9b: 'OP_BOOLOR',
  0x9c: 'OP_NUMEQUAL', 0x9d: 'OP_NUMEQUALVERIFY', 0x9e: 'OP_NUMNOTEQUAL', 0x9f: 'OP_LESSTHAN',
  0xa0: 'OP_GREATERTHAN', 0xa1: 'OP_LESSTHANOREQUAL', 0xa2: 'OP_GREATERTHANOREQUAL',
  0xa3: 'OP_MIN', 0xa4: 'OP_MAX', 0xa5: 'OP_WITHIN', 0xa6: 'OP_RIPEMD160', 0xa7: 'OP_SHA1',
  0xa8: 'OP_SHA256', 0xa9: 'OP_HASH160', 0xaa: 'OP_HASH256', 0xab: 'OP_CODESEPARATOR',
  0xac: 'OP_CHECKSIG', 0xad: 'OP_CHECKSIGVERIFY', 0xae: 'OP_CHECKMULTISIG', 0xaf: 'OP_CHECKMULTISIGVERIFY',
  0xb0: 'OP_NOP1', 0xb1: 'OP_CHECKLOCKTIMEVERIFY', 0xb2: 'OP_CHECKSEQUENCEVERIFY',
  0xb3: 'OP_NOP4', 0xb4: 'OP_NOP5', 0xb5: 'OP_NOP6', 0xb6: 'OP_NOP7', 0xb7: 'OP_NOP8',
  0xb8: 'OP_NOP9', 0xb9: 'OP_NOP10', 0xba: 'OP_CHECKSIGADD', 0xff: 'OP_INVALIDOPCODE',
}

export function isTapscriptOpSuccess(opcode: number, profile?: BitcoinVerificationProfile): boolean {
  const rules = resolveBitcoinVerificationProfile(profile)
  if (!Number.isInteger(opcode) || opcode < 0 || opcode > 255) return false
  if (rules === 'published-bip') {
    return opcode === 80 || opcode === 98 || (opcode >= 126 && opcode <= 129)
      || (opcode >= 131 && opcode <= 134) || (opcode >= 137 && opcode <= 138)
      || (opcode >= 141 && opcode <= 142) || (opcode >= 149 && opcode <= 153)
      || (opcode >= 187 && opcode <= 254)
  }
  // Preserve the supplied specification's assignments, with CHECKSIGADD (0xba)
  // and its explicitly disabled OP_2MUL/OP_2DIV taking precedence over its range shorthand.
  return opcode === 0x50 || opcode === 0x62 || (opcode >= 0x7c && opcode <= 0x81)
    || (opcode >= 0x83 && opcode <= 0x86) || opcode === 0x8b || opcode === 0x8c
    || (opcode >= 0x8f && opcode <= 0x99) || opcode === 0xb9 || (opcode >= 0xbb && opcode <= 0xfe)
}

export function classifyTapscriptOpcode(opcode: number, profile?: BitcoinVerificationProfile): TapscriptOpcodeClassification {
  const rules = resolveBitcoinVerificationProfile(profile)
  if (!Number.isInteger(opcode) || opcode < 0 || opcode > 255) throw new RangeError('Opcode must be a byte')
  if (isTapscriptOpSuccess(opcode, rules)) return { opcode, name: `OP_SUCCESS${opcode}`, kind: 'op-success' }
  const name = opcode >= 0x51 && opcode <= 0x60 ? `OP_${opcode - 0x50}`
    : opcode > 0 && opcode < 0x4c ? `OP_PUSHBYTES_${opcode}` : NAMES[opcode] ?? `OP_UNKNOWN${opcode}`
  const kind: TapscriptOpcodeKind = opcode <= 0x4e ? 'push'
    : opcode === 0x4f || (opcode >= 0x51 && opcode <= 0x60) ? 'small-integer'
    : opcode === 0xae || opcode === 0xaf || (rules === 'specification' && (opcode === 0x8d || opcode === 0x8e)) ? 'disabled'
    : opcode === 0xac || opcode === 0xad || opcode === 0xba ? 'signature'
    : [0x63, 0x64, 0x67, 0x68].includes(opcode) ? 'control'
    : NAMES[opcode] !== undefined && ![0x50, 0x62, 0x65, 0x66, 0x89, 0x8a, 0xff].includes(opcode) ? 'standard' : 'invalid'
  return { opcode, name, kind }
}

function bytesHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

function decodeScript(script: Uint8Array, profile: BitcoinVerificationProfile): {
  instructions: TapscriptInstruction[]; success?: TapscriptInstruction; error?: string
} {
  const instructions: TapscriptInstruction[] = []
  for (let pc = 0; pc < script.length;) {
    const start = pc
    const opcode = script[pc++]
    const classification = classifyTapscriptOpcode(opcode, profile)
    let data: Uint8Array | undefined
    if (opcode <= 0x4e) {
      let length = opcode
      const width = opcode === 0x4c ? 1 : opcode === 0x4d ? 2 : opcode === 0x4e ? 4 : 0
      if (width > 0) {
        if (pc + width > script.length) return { instructions, error: `Truncated ${classification.name} length at byte ${start}` }
        length = 0
        for (let i = 0; i < width; i++) length += script[pc++] * 2 ** (8 * i)
      }
      if (length > script.length - pc) return { instructions, error: `Truncated data push at byte ${start}` }
      data = script.subarray(pc, pc + length)
      pc += length
    }
    const instruction = { ...classification, pc: start, nextPc: pc, opcodePosition: instructions.length, ...(data === undefined ? {} : { data }) }
    instructions.push(instruction)
    // OP_SUCCESS preflight precedes stack checks, branch execution and decoding of later bytes.
    if (classification.kind === 'op-success') return { instructions, success: instruction }
  }
  return { instructions }
}

function instructionText(instruction: TapscriptInstruction): string {
  return `${instruction.pc.toString(16).padStart(4, '0')}: ${instruction.name}${instruction.data?.length ? ` ${bytesHex(instruction.data)}` : ''}`
}

export function disassembleTapscript(script: Uint8Array, profile?: BitcoinVerificationProfile): string[] {
  const decoded = decodeScript(script, resolveBitcoinVerificationProfile(profile))
  return [...decoded.instructions.map(instructionText), ...(decoded.error ? [decoded.error] : [])]
}

function compactSizeWidth(value: number): number {
  return value < 0xfd ? 1 : value <= 0xffff ? 3 : value <= 0xffffffff ? 5 : 9
}

export function calculateSerializedWitnessSize(witness: readonly Uint8Array[]): number {
  return compactSizeWidth(witness.length) + witness.reduce((size, item) => size + compactSizeWidth(item.length) + item.length, 0)
}

export function calculateTapscriptSigopsBudget(script: Uint8Array, options: TapscriptBudgetOptions = {}): number {
  const profile = resolveBitcoinVerificationProfile(options.profile)
  if (profile === 'specification') {
    if (options.serializedWitnessSize !== undefined) throw new RangeError('serializedWitnessSize applies only to published-bip')
    return TAPSCRIPT_SIGOPS_BASE + script.length
  }
  const size = options.serializedWitnessSize
  if (size === undefined || !Number.isSafeInteger(size) || size < script.length + compactSizeWidth(script.length) + 35
    || size > Number.MAX_SAFE_INTEGER - TAPSCRIPT_SIGOPS_BASE) {
    throw new RangeError('published-bip requires the complete serializedWitnessSize, including script and control block')
  }
  return TAPSCRIPT_SIGOPS_BASE + size
}

export function encodeTapscriptNumber(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array(0)
  const negative = value < 0n
  let magnitude = negative ? -value : value
  const bytes: number[] = []
  while (magnitude !== 0n) { bytes.push(Number(magnitude & 255n)); magnitude >>= 8n }
  if ((bytes[bytes.length - 1] & 0x80) !== 0) bytes.push(negative ? 0x80 : 0)
  else if (negative) bytes[bytes.length - 1] |= 0x80
  return new Uint8Array(bytes)
}

export function decodeTapscriptNumber(bytes: Uint8Array, maxBytes = 4): bigint {
  if (bytes.length > maxBytes) throw new RangeError(`Script number exceeds ${maxBytes}-byte arithmetic limit`)
  if (bytes.length === 0) return 0n
  let result = 0n
  for (let i = 0; i < bytes.length; i++) result |= BigInt(bytes[i]) << BigInt(8 * i)
  const signBit = 0x80n << BigInt(8 * (bytes.length - 1))
  return (result & signBit) !== 0n ? -(result & ~signBit) : result
}

export function castTapscriptBool(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return !(i === bytes.length - 1 && bytes[i] === 0x80)
  }
  return false
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}

function scriptHash(opcode: number, data: Uint8Array): Uint8Array {
  switch (opcode) {
    case 0xa6: return ripemd160(data)
    case 0xa7: return sha1(data)
    case 0xa8: return sha256(data)
    case 0xa9: return ripemd160(sha256(data))
    default: return sha256(sha256(data))
  }
}

function numericOperation(opcode: number, values: bigint[]): bigint {
  const [a, b, c] = values
  switch (opcode) {
    case 0x8b: return a + 1n
    case 0x8c: return a - 1n
    case 0x8f: return -a
    case 0x90: return a < 0n ? -a : a
    case 0x91: return a === 0n ? 1n : 0n
    case 0x92: return a !== 0n ? 1n : 0n
    case 0x93: return a + b
    case 0x94: return a - b
    case 0x9a: return a !== 0n && b !== 0n ? 1n : 0n
    case 0x9b: return a !== 0n || b !== 0n ? 1n : 0n
    case 0x9c: case 0x9d: return a === b ? 1n : 0n
    case 0x9e: return a !== b ? 1n : 0n
    case 0x9f: return a < b ? 1n : 0n
    case 0xa0: return a > b ? 1n : 0n
    case 0xa1: return a <= b ? 1n : 0n
    case 0xa2: return a >= b ? 1n : 0n
    case 0xa3: return a < b ? a : b
    case 0xa4: return a > b ? a : b
    case 0xa5: return a >= b && a < c ? 1n : 0n
    default: throw new RangeError('Unsupported numeric opcode')
  }
}

function numericArity(opcode: number): number {
  return opcode === 0xa5 ? 3 : opcode >= 0x8b && opcode <= 0x92 ? 1 : 2
}

function isNumericOpcode(opcode: number): boolean {
  return [0x8b, 0x8c, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94].includes(opcode) || (opcode >= 0x9a && opcode <= 0xa5)
}

/** Execute the supplied initial stack and precomputed signature context.
 * Transaction/witness commitment verification is a separate caller responsibility.
 */
export function evaluateTapscript(script: Uint8Array, witness: readonly Uint8Array[] = [], options: TapscriptEvalOptions = {}): TapscriptEvalResult {
  const profile = resolveBitcoinVerificationProfile(options.profile)
  let budgetRemaining = calculateTapscriptSigopsBudget(script, options)
  const stack: Uint8Array[] = witness.map(item => item.slice()), alt: Uint8Array[] = [], conditions: boolean[] = []
  const trace: TapscriptEvalStep[] = []
  const traceLimit = options.traceLimit ?? 10000
  if (!Number.isSafeInteger(traceLimit) || traceLimit < 0 || traceLimit > 100000) throw new RangeError('traceLimit must be in [0, 100000]')
  let stepsExecuted = 0, signaturesVerified = 0, codeSeparatorPosition = 0xffffffff
  const result = (success: boolean, failureReason?: string): TapscriptEvalResult => ({ success, failureReason,
    budgetRemaining, finalStack: stack.map(bytesHex), finalAltStack: alt.map(bytesHex), stepsExecuted,
    ...(options.traceExecution ? { trace, traceTruncated: stepsExecuted > trace.length } : {}),
    profile, budgetScope: profile === 'specification' ? 'script-bytes' : 'serialized-witness',
    simulationMode: options.simulationMode ?? false,
    cryptographicSignaturesVerified: success && signaturesVerified > 0 && !options.simulationMode })
  const decoded = decodeScript(script, profile)
  if (decoded.success) {
    stepsExecuted = 1
    if (options.traceExecution && traceLimit > 0) trace.push({ pc: decoded.success.pc, opcodeName: decoded.success.name,
      opcodeHex: decoded.success.opcode.toString(16).padStart(2, '0'), budgetRemaining, stackSize: stack.length, executed: true })
    return result(true)
  }
  if (decoded.error) return result(false, decoded.error)
  if (stack.length > TAPSCRIPT_MAX_STACK_SIZE) return result(false, 'Initial stack exceeds 1000 elements')
  if (stack.some(item => item.length > TAPSCRIPT_MAX_ELEMENT_SIZE)) return result(false, 'Initial stack element exceeds 520 bytes')
  const need = (count: number) => { if (stack.length < count) throw new RangeError('Stack underflow') }
  const pop = () => { need(1); return stack.pop()! }
  const number = (maxBytes = 4) => decodeTapscriptNumber(pop(), maxBytes)
  const pushNumber = (value: bigint) => stack.push(encodeTapscriptNumber(value))
  const signature = (sig: Uint8Array, pubkey: Uint8Array, instruction: TapscriptInstruction): boolean => {
    if (pubkey.length === 0) throw new RangeError('Signature public key is empty')
    if (sig.length === 0) return false
    budgetRemaining -= TAPSCRIPT_SIGOPS_COST
    if (budgetRemaining < 0) throw new RangeError('Sigops budget exhausted')
    // Unknown public key lengths are consensus upgrade hooks and accept nonempty signatures.
    if (pubkey.length !== 32) return true
    if (sig.length !== 64 && sig.length !== 65) throw new RangeError('Schnorr signature must contain 64 or 65 bytes')
    const hashType = sig.length === 65 ? sig[64] : 0
    if (sig.length === 65 && ![1, 2, 3, 0x81, 0x82, 0x83].includes(hashType)) throw new RangeError('Invalid or explicit default Schnorr hash type')
    if (options.simulationMode) {
      if (liftX(pubkey) === null) throw new RangeError('Invalid x-only signature public key')
      return true
    }
    const context = { pc: instruction.pc, opcodePosition: instruction.opcodePosition, codeSeparatorPosition, hashType }
    const message = options.signatureMessage ? options.signatureMessage(context) : options.message
    if (message === undefined || message.length !== 32) throw new RangeError('A 32-byte signature message/context is required for cryptographic evaluation')
    const verification = Secp256k1Engine.verifySchnorr(pubkey, message, sig.subarray(0, 64))
    if (!verification.valid) throw new RangeError(`Schnorr verification failed: ${verification.reason}`)
    signaturesVerified++
    return true
  }
  for (const instruction of decoded.instructions) {
    const opcode = instruction.opcode
    const active = conditions.every(Boolean)
    let failure: string | undefined
    stepsExecuted++
    try {
      // Push-size and VERIF/VERNOTIF checks also apply in inactive branches.
      if (instruction.data && instruction.data.length > TAPSCRIPT_MAX_ELEMENT_SIZE) throw new RangeError('Script push exceeds 520 bytes')
      if (opcode === 0x65 || opcode === 0x66) throw new RangeError(`Invalid ${instruction.name}`)
      if (opcode === 0x63 || opcode === 0x64) {
        let condition = false
        if (active) {
          const value = pop()
          if (value.length !== 0 && !(value.length === 1 && value[0] === 1)) throw new RangeError('MINIMALIF requires empty or 01')
          condition = castTapscriptBool(value)
          if (opcode === 0x64) condition = !condition
        }
        conditions.push(condition)
      } else if (opcode === 0x67) {
        if (conditions.length === 0) throw new RangeError('Unmatched OP_ELSE')
        conditions[conditions.length - 1] = !conditions[conditions.length - 1]
      } else if (opcode === 0x68) {
        if (conditions.length === 0) throw new RangeError('Unmatched OP_ENDIF')
        conditions.pop()
      } else if (active) {
        if (instruction.kind === 'disabled' || instruction.kind === 'invalid') throw new RangeError(`Disabled or invalid ${instruction.name}`)
        if (instruction.data !== undefined) stack.push(instruction.data.slice())
        else if (opcode === 0x4f) pushNumber(-1n)
        else if (opcode >= 0x51 && opcode <= 0x60) pushNumber(BigInt(opcode - 0x50))
        else if (isNumericOpcode(opcode)) {
          const arity = numericArity(opcode)
          need(arity)
          const values = stack.splice(stack.length - arity).map(value => decodeTapscriptNumber(value))
          const value = numericOperation(opcode, values)
          if (opcode === 0x9d) { if (value === 0n) throw new RangeError('OP_NUMEQUALVERIFY failed') }
          else pushNumber(value)
        } else if (opcode >= 0xa6 && opcode <= 0xaa) stack.push(scriptHash(opcode, pop()))
        else switch (opcode) {
          case 0x61: case 0xb0: case 0xb3: case 0xb4: case 0xb5: case 0xb6: case 0xb7: case 0xb8: case 0xb9: break
          case 0x69: if (!castTapscriptBool(pop())) throw new RangeError('OP_VERIFY failed'); break
          case 0x6a: throw new RangeError('OP_RETURN makes this execution unspendable')
          case 0x6b: alt.push(pop()); break
          case 0x6c: if (alt.length === 0) throw new RangeError('Alt stack underflow'); stack.push(alt.pop()!); break
          case 0x6d: need(2); stack.splice(-2); break
          case 0x6e: need(2); stack.push(...stack.slice(-2).map(item => item.slice())); break
          case 0x6f: need(3); stack.push(...stack.slice(-3).map(item => item.slice())); break
          case 0x70: need(4); stack.push(...stack.slice(-4, -2).map(item => item.slice())); break
          case 0x71: need(6); stack.push(...stack.splice(stack.length - 6, 2)); break
          case 0x72: need(4); stack.push(...stack.splice(stack.length - 4, 2)); break
          case 0x73: need(1); if (castTapscriptBool(stack[stack.length - 1])) stack.push(stack[stack.length - 1].slice()); break
          case 0x74: pushNumber(BigInt(stack.length)); break
          case 0x75: pop(); break
          case 0x76: need(1); stack.push(stack[stack.length - 1].slice()); break
          case 0x77: need(2); stack.splice(-2, 1); break
          case 0x78: need(2); stack.push(stack[stack.length - 2].slice()); break
          case 0x79: case 0x7a: {
            const position = number()
            if (position < 0n || position >= BigInt(stack.length)) throw new RangeError('OP_PICK/ROLL index outside stack')
            const index = stack.length - 1 - Number(position)
            stack.push(opcode === 0x79 ? stack[index].slice() : stack.splice(index, 1)[0])
            break
          }
          case 0x7b: need(3); stack.push(stack.splice(stack.length - 3, 1)[0]); break
          case 0x7c: need(2); stack.push(stack.splice(stack.length - 2, 1)[0]); break
          case 0x7d: need(2); stack.splice(stack.length - 2, 0, stack[stack.length - 1].slice()); break
          case 0x82: need(1); pushNumber(BigInt(stack[stack.length - 1].length)); break
          case 0x87: case 0x88: {
            const right = pop(), left = pop(), equal = equalBytes(left, right)
            if (opcode === 0x88) { if (!equal) throw new RangeError('OP_EQUALVERIFY failed') }
            else pushNumber(equal ? 1n : 0n)
            break
          }
          case 0xab: codeSeparatorPosition = instruction.opcodePosition; break
          case 0xac: case 0xad: {
            const pubkey = pop(), sig = pop(), valid = signature(sig, pubkey, instruction)
            if (opcode === 0xad) { if (!valid) throw new RangeError('OP_CHECKSIGVERIFY failed') }
            else pushNumber(valid ? 1n : 0n)
            break
          }
          case 0xba: {
            const pubkey = pop(), accumulator = number(), sig = pop()
            pushNumber(accumulator + (signature(sig, pubkey, instruction) ? 1n : 0n))
            break
          }
          case 0xb1: {
            need(1)
            const lock = decodeTapscriptNumber(stack[stack.length - 1], 5)
            if (lock < 0n || lock > 0xffffffffn) throw new RangeError('CLTV requires a nonnegative uint32 lock time')
            if (options.lockTime === undefined || options.inputSequence === undefined) throw new RangeError('CLTV transaction context is required')
            if ((lock < 500000000n) !== (options.lockTime < 500000000)) throw new RangeError('CLTV timelock unit collision')
            if (lock > BigInt(options.lockTime) || options.inputSequence === 0xffffffff) throw new RangeError('CLTV lock time or final sequence check failed')
            break
          }
          case 0xb2: {
            need(1)
            const sequence = decodeTapscriptNumber(stack[stack.length - 1], 5)
            if (sequence < 0n) throw new RangeError('CSV sequence must be nonnegative')
            if ((sequence & 0x80000000n) !== 0n) break
            if (options.inputSequence === undefined || options.transactionVersion === undefined) throw new RangeError('CSV transaction context is required')
            const input = BigInt(options.inputSequence)
            if (options.transactionVersion < 2 || (input & 0x80000000n) !== 0n) throw new RangeError('CSV transaction version or disabled sequence check failed')
            if ((sequence & 0x400000n) !== (input & 0x400000n)) throw new RangeError('CSV timelock unit collision')
            if ((sequence & 0x40ffffn) > (input & 0x40ffffn)) throw new RangeError('CSV relative lock time check failed')
            break
          }
          default: throw new RangeError(`Unsupported ${instruction.name}`)
        }
      }
      if (stack.length + alt.length > TAPSCRIPT_MAX_STACK_SIZE) throw new RangeError('Combined stack exceeds 1000 elements')
    } catch (error) { failure = error instanceof Error ? error.message : String(error) }
    if (options.traceExecution && trace.length < traceLimit) trace.push({ pc: instruction.pc, opcodeName: instruction.name,
      opcodeHex: opcode.toString(16).padStart(2, '0'), budgetRemaining, stackSize: stack.length,
      topStackHex: stack.length ? bytesHex(stack[stack.length - 1]) : undefined, executed: active || instruction.kind === 'control' })
    if (failure) return result(false, failure)
  }
  if (conditions.length) return result(false, 'Unbalanced conditional')
  if (stack.length !== 1) return result(false, 'Clean stack requires exactly one final element')
  return castTapscriptBool(stack[0]) ? result(true) : result(false, 'Final stack element is false')
}

interface StaticTapscriptPath {
  frames: { parent: boolean; take: boolean }[]
  selected: TapscriptInstruction[]
  conditionPath: string[]
  failure?: string
}

/** Bounded conservative path analysis. Potential sigops costs assume nonempty signatures;
 * unknown witness satisfiability is reported as incomplete, never as proven failure.
 */
export function auditTapscript(script: Uint8Array, options: TapscriptAuditOptions = {}): TapscriptAuditResult {
  const profile = resolveBitcoinVerificationProfile(options.profile)
  const budget = calculateTapscriptSigopsBudget(script, options)
  const decoded = decodeScript(script, profile)
  const findings: TapscriptSafetyFinding[] = []
  const maxBranches = options.maxBranches ?? 256, maxSteps = options.maxAnalysisSteps ?? 100000
  if (!Number.isSafeInteger(maxBranches) || maxBranches < 1 || maxBranches > 4096) throw new RangeError('maxBranches must be in [1, 4096]')
  if (!Number.isSafeInteger(maxSteps) || maxSteps < 1 || maxSteps > 1000000) throw new RangeError('maxAnalysisSteps must be in [1, 1000000]')
  let paths: StaticTapscriptPath[] = [{ frames: [], selected: [], conditionPath: [] }]
  let analysisComplete = true, steps = 0
  if (decoded.error) {
    paths[0].failure = decoded.error
    findings.push({ severity: 'fatal', code: 'malformed-script', message: decoded.error })
  } else if (!decoded.success) {
    for (const instruction of decoded.instructions) {
      const next: StaticTapscriptPath[] = []
      for (const path of paths) {
        if (++steps > maxSteps) { analysisComplete = false; break }
        const active = path.frames.every(frame => frame.parent && frame.take)
        const op = instruction.opcode
        if (op === 0x63 || op === 0x64) {
          const previous = path.selected[path.selected.length - 1]
          let known: boolean | undefined
          if (previous?.nextPc === instruction.pc) {
            if (previous.opcode === 0x00) known = false
            else if (previous.opcode === 0x51) known = true
            else if (previous.data?.length === 1 && previous.data[0] === 1) known = true
          }
          if (known !== undefined && op === 0x64) known = !known
          const choices = active ? known === undefined ? [false, true] : [known] : [false]
          for (const take of choices) next.push({ ...path, frames: [...path.frames, { parent: active, take }],
            selected: active ? [...path.selected, instruction] : path.selected.slice(), conditionPath: active ? [...path.conditionPath, `${instruction.pc}:${take ? 'then' : 'else'}`] : path.conditionPath.slice() })
        } else {
          const copy = { ...path, frames: path.frames.map(frame => ({ ...frame })), selected: path.selected.slice() }
          if (op === 0x67 || op === 0x68) {
            copy.selected.push(instruction)
            if (copy.frames.length === 0) copy.failure ??= `Unmatched ${instruction.name}`
            else if (op === 0x67) copy.frames[copy.frames.length - 1].take = !copy.frames[copy.frames.length - 1].take
            else copy.frames.pop()
          } else {
            if (active) copy.selected.push(instruction)
            if (op === 0x65 || op === 0x66 || (instruction.data && instruction.data.length > 520)
              || (active && (op === 0x6a || instruction.kind === 'disabled' || instruction.kind === 'invalid'))) {
              copy.failure ??= `${instruction.name} prevents satisfaction`
            }
          }
          next.push(copy)
        }
      }
      if (steps > maxSteps) break
      if (next.length > maxBranches) { analysisComplete = false; paths = next.slice(0, maxBranches); break }
      paths = next
    }
    for (const path of paths) {
      if (path.frames.length && analysisComplete) path.failure ??= 'Unbalanced conditional'
      const last = path.selected[path.selected.length - 1]
      if (last && (last.opcode === 0x00 || (last.data !== undefined && !castTapscriptBool(last.data)))) {
        path.failure ??= 'Unconditionally false final stack value'
      }
    }
  }
  const branches = paths.map((path, index): TapscriptBranchAnalysis => {
    const sigopsRequired = path.selected.filter(item => item.kind === 'signature').length * TAPSCRIPT_SIGOPS_COST
    return { branchIndex: index, conditionPath: path.conditionPath, sigopsRequired,
      budgetExceeded: sigopsRequired > budget, requiresSignatures: sigopsRequired > 0,
      hasOpSuccess: decoded.success !== undefined, terminatesSafely: !path.failure }
  })
  const permanentlyUnspendable = !decoded.success && analysisComplete && paths.every(path => path.failure !== undefined)
  let anyoneCanSpend = decoded.success !== undefined
  if (!anyoneCanSpend && !decoded.error) {
    // Concrete public witnesses establish existence without assuming unknown signatures valid.
    const candidates: Uint8Array[][] = [[], [new Uint8Array(0)], [new Uint8Array([1])],
      [new Uint8Array([1]), new Uint8Array([1])], [new Uint8Array(0), new Uint8Array([1])]]
    anyoneCanSpend = candidates.some(witness => evaluateTapscript(script, witness, options).success)
  }
  if (decoded.success) findings.push({ severity: 'warning', code: 'op-success-override', message: `${decoded.success.name} overrides script execution and stack checks` })
  if (anyoneCanSpend) findings.push({ severity: 'warning', code: 'anyone-can-spend', message: 'A signature-free public witness satisfies this leaf; transaction commitments are outside this audit' })
  if (branches.some(branch => branch.budgetExceeded)) findings.push({ severity: 'warning',
    code: branches.length > 1 ? 'conditional-sigops-exhaustion' : 'sigops-budget-exhaustion',
    message: 'Nonempty signatures on an analyzed path can exhaust the sigops budget' })
  if (paths.some(path => path.failure?.includes('CHECKMULTISIG'))) findings.push({ severity: 'fatal', code: 'disabled-opcode', message: 'An analyzed execution encounters a disabled signature opcode' })
  if (!permanentlyUnspendable && !anyoneCanSpend) analysisComplete = false
  if (!analysisComplete) findings.push({ severity: 'info', code: 'analysis-incomplete', message: 'Witness-dependent satisfiability or resource limits prevent a complete static verdict' })
  return { scriptHex: bytesHex(script), scriptLength: script.length, sigopsBudget: budget,
    minSigopsRequired: Math.min(...branches.map(branch => branch.sigopsRequired)), maxSigopsRequired: Math.max(...branches.map(branch => branch.sigopsRequired)),
    isPermanentlyUnspendable: permanentlyUnspendable, hasAnyoneCanSpendPath: anyoneCanSpend,
    hasOpSuccess: decoded.success !== undefined, branches, findings, disassembly: decoded.instructions.map(instructionText),
    profile, budgetScope: profile === 'specification' ? 'script-bytes' : 'serialized-witness', analysisComplete }
}
