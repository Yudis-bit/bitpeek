import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js'
import {
  auditSecp256k1, ConstantTimeAuditor, FileByteSource, BitpeekError, parseHex,
  SECP256K1_AUDIT_MAX_BYTES, sha256Hex, Secp256k1Engine, ReferenceDisassembler,
} from '../../core/src/index.js'
import type { Secp256k1AuditFormat, TaintSource } from '../../core/src/index.js'
import type { McpSecurityManager } from './security.js'

export const MCP_TIMING_MAX_BYTES = 65536
export const MCP_TIMING_MAX_INSTRUCTIONS = 10000
const sourceProperties = {
  handle: { type: 'string', minLength: 1, description: 'Session returned by bitpeek_open; audit a range in this file.' },
  rawHex: { type: 'string', minLength: 2, description: 'Inline complete hex bytes. Supply this or handle.' },
  offset: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER, description: 'File byte offset (default 0); only with handle.' },
  length: { type: 'integer', minimum: 1, description: 'Exact file range length; only with handle.' },
}
const sourceChoices = [
  { required: ['rawHex'], not: { anyOf: [{ required: ['handle'] }, { required: ['offset'] }, { required: ['length'] }] } },
  { required: ['handle'], not: { required: ['rawHex'] } },
]
const auditAnnotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
const hex32 = { type: 'string', minLength: 64, maxLength: 96, description: '32-byte hexadecimal value.' }
const pointHex = { type: 'string', minLength: 66, maxLength: 195, description: 'Compressed (33-byte) or uncompressed (65-byte) SEC public key; preserves Y parity.' }
const verificationProperties = {
  pubkeyHex: { ...hex32, description: 'BIP-340 x-only public key. rawHex/file range supplies the 64-byte signature.' },
  messageHex: { ...hex32, description: '32-byte Schnorr message; optional 32-byte BIP-374 proof message.' },
  g1Hex: { ...pointHex, description: 'DLEQ first generator G (G1).' },
  p1Hex: { ...pointHex, description: 'DLEQ first public point A (P1).' },
  g2Hex: { ...pointHex, description: 'DLEQ second generator B (G2).' },
  p2Hex: { ...pointHex, description: 'DLEQ second public point C (P2). rawHex/file range supplies the 64-byte proof.' },
  internalKeyHex: { ...hex32, description: 'Taproot x-only internal key. rawHex/file range supplies the 32-byte output key.' },
  merkleRootHex: { ...hex32, description: 'Optional Taproot Merkle root; omit for a key-only tweak.' },
  expectedParity: { type: 'integer', enum: [0, 1], description: 'Optional expected Taproot output Y parity.' },
  spendKeyHex: { type: 'string', minLength: 64, maxLength: 66, description: 'BIP-352 spend public key B_spend (32-byte x-only or 33-byte compressed hex).' },
  tweakHex: { type: 'string', minLength: 64, maxLength: 64, description: '32-byte BIP-352 scalar tweak t_k.' },
}

export const MCP_AUDIT_TOOLS: Tool[] = [
  {
    name: 'bitpeek_secp256k1_audit',
    description: 'Audit secp256k1 encodings and Bitcoin transactions, or verify BIP-340 Schnorr signatures, BIP-374 DLEQ proofs (including BIP-375 shares), BIP-341 Taproot tweaks, and BIP-352 Silent Payments output-key tweaks. Verification formats return PASS/FAIL with exact reasons. Supply signature/proof/output key as rawHex or an open file range and matching key/message parameters. Maximum 1 MiB.',
    annotations: auditAnnotations,
    inputSchema: {
      type: 'object', additionalProperties: false, oneOf: sourceChoices,
      properties: {
        ...sourceProperties,
        rawHex: { ...sourceProperties.rawHex, maxLength: SECP256K1_AUDIT_MAX_BYTES * 3 },
        length: { ...sourceProperties.length, maximum: SECP256K1_AUDIT_MAX_BYTES, description: 'Exact range length; defaults to all remaining file bytes. Maximum 1 MiB.' },
        format: { type: 'string', enum: ['auto', 'pubkey', 'der', 'compact', 'bitcoin-tx', 'bip340-schnorr', 'dleq', 'taproot-tweak', 'bip352-tweak'], default: 'auto' },
        ...verificationProperties,
      },
    },
  },
  {
    name: 'bitpeek_constant_time_audit',
    description: 'Statically inspect a secret-handling code region for conditional branches, indexed memory/cache hazards, variable-latency arithmetic, and undecoded instructions. Uses the reference x86_64/AArch64 disassembler. Optional secretRegisters adds forward symbolic taint verification of the selected sequence. A clean result is not a timing proof. Maximum 65536 bytes; reports classified hazards, assembly context, and exact relative/file offsets and bigint addresses.',
    annotations: auditAnnotations,
    inputSchema: {
      type: 'object', additionalProperties: false, oneOf: sourceChoices,
      properties: {
        ...sourceProperties,
        rawHex: { ...sourceProperties.rawHex, maxLength: MCP_TIMING_MAX_BYTES * 3 },
        length: { ...sourceProperties.length, maximum: MCP_TIMING_MAX_BYTES, description: 'Exact range length; defaults to the first 256 remaining bytes. Maximum 65536.' },
        arch: { type: 'string', enum: ['x86_64', 'aarch64'], default: 'x86_64' },
        baseAddress: { type: 'string', pattern: '^(0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})$', description: 'Unsigned 64-bit address of the selected region; defaults to file offset or zero for inline hex.' },
        maxInstructions: { type: 'integer', minimum: 1, maximum: MCP_TIMING_MAX_INSTRUCTIONS, default: MCP_TIMING_MAX_INSTRUCTIONS },
        checkMemoryLookups: { type: 'boolean', default: true, description: 'Inspect indexed memory operands for potential cache-timing leaks.' },
        secretRegisters: {
          type: 'array', items: { type: 'string' },
          description: 'Optional list of register names to mark as secret taint sources (e.g. ["rdi", "rsi"] for x86_64 System V ABI, or ["x0", "x1"] for AAPCS64). Triggers forward symbolic taint verification.',
        },
      },
    },
  },
]

function safeInteger(value: unknown, name: string, minimum: number, maximum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new BitpeekError('INVALID_INPUT', `${name} must be a safe integer in [${minimum}, ${maximum}]`)
  }
  return value
}

function checkSignal(signal?: AbortSignal): void {
  if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Audit request was cancelled')
}

function hexArgument(args: Record<string, unknown>, name: string, maxBytes = 32): Uint8Array {
  const value = args[name]
  if (typeof value !== 'string' || value.length === 0 || value.length > maxBytes * 3) {
    throw new BitpeekError('INVALID_INPUT', `${name} must be a nonempty hex string of at most ${maxBytes} bytes`)
  }
  const parsed = parseHex(value)
  if (!parsed.ok) throw new BitpeekError('INVALID_INPUT', `${name}: ${parsed.error}`)
  if (parsed.bytes.length === 0 || parsed.bytes.length > maxBytes) throw new BitpeekError('INVALID_INPUT', `${name} exceeds its byte limit or is empty`)
  return parsed.bytes
}

function pointArgument(args: Record<string, unknown>, name: string): { x: bigint; y: bigint } {
  const bytes = hexArgument(args, name, 65)
  const inspection = Secp256k1Engine.inspectPubKey(bytes)
  if (!inspection.isValid || (bytes.length !== 33 && bytes.length !== 65) || inspection.y === undefined) {
    throw new BitpeekError('INVALID_INPUT', `${name}: ${inspection.rejectionReason ?? 'DLEQ requires a compressed or uncompressed SEC point'}`)
  }
  return { x: inspection.x, y: inspection.y }
}

async function readAuditInput(
  args: Record<string, unknown>, security: McpSecurityManager,
  maxBytes: number, defaultLength?: number, signal?: AbortSignal,
): Promise<{ bytes: Uint8Array; source: { kind: 'hex' | 'session'; length: number; sha256: string; handle?: string; offset?: number } }> {
  checkSignal(signal)
  const hasHex = args.rawHex !== undefined
  const hasHandle = args.handle !== undefined
  if (hasHex === hasHandle) throw new BitpeekError('INVALID_INPUT', 'Supply exactly one of rawHex or handle')
  if (hasHex) {
    if (args.offset !== undefined || args.length !== undefined) throw new BitpeekError('INVALID_INPUT', 'offset and length require a session handle')
    if (typeof args.rawHex !== 'string') throw new BitpeekError('INVALID_INPUT', 'rawHex must be a string')
    if (args.rawHex.length > maxBytes * 3) throw new BitpeekError('RESOURCE_LIMIT', 'Hex input exceeds the audit size limit')
    const parsed = parseHex(args.rawHex)
    if (!parsed.ok) throw new BitpeekError('INVALID_INPUT', parsed.error)
    if (parsed.bytes.length === 0) throw new BitpeekError('INVALID_INPUT', 'Audit input must contain bytes')
    if (parsed.bytes.length > maxBytes) throw new BitpeekError('RESOURCE_LIMIT', `Audit input exceeds ${maxBytes} bytes`)
    return { bytes: parsed.bytes, source: { kind: 'hex', length: parsed.bytes.length, sha256: sha256Hex(parsed.bytes) } }
  }
  if (typeof args.handle !== 'string' || args.handle.length === 0) throw new BitpeekError('INVALID_INPUT', 'handle must be a nonempty string')
  const session = security.getSession(args.handle)
  const offset = safeInteger(args.offset ?? 0, 'offset', 0, Number.MAX_SAFE_INTEGER)
  const requestedLength = args.length === undefined ? undefined : safeInteger(args.length, 'length', 1, maxBytes)
  const path = await security.validateInputPath(session.canonicalPath)
  const file = await FileByteSource.open(path)
  try {
    if (file.size !== session.size) throw new BitpeekError('SOURCE_CHANGED', 'File size changed; reopen the file before auditing')
    if (offset > file.size) throw new BitpeekError('INVALID_RANGE', 'offset exceeds file size')
    const remaining = file.size - offset
    const length = requestedLength ?? (defaultLength === undefined ? remaining : Math.min(defaultLength, remaining))
    if (length === 0) throw new BitpeekError('INVALID_RANGE', 'Audit range must contain bytes')
    if (length > maxBytes) throw new BitpeekError('RESOURCE_LIMIT', `Audit range exceeds ${maxBytes} bytes; select offset and length explicitly`)
    if (length > remaining) throw new BitpeekError('INVALID_RANGE', 'Audit range exceeds file size')
    const bytes = await file.read(offset, length, signal)
    checkSignal(signal)
    return { bytes, source: { kind: 'session', handle: args.handle, offset, length: bytes.length, sha256: sha256Hex(bytes) } }
  } finally {
    await file.close()
  }
}

export async function callAuditTool(
  name: 'bitpeek_secp256k1_audit' | 'bitpeek_constant_time_audit',
  args: Record<string, unknown>, security: McpSecurityManager, signal?: AbortSignal,
): Promise<CallToolResult> {
  const allowed = new Set(['rawHex', 'handle', 'offset', 'length', ...(name === 'bitpeek_secp256k1_audit' ? ['format', ...Object.keys(verificationProperties)] : ['arch', 'baseAddress', 'maxInstructions', 'checkMemoryLookups', 'secretRegisters'])])
  for (const key of Object.keys(args)) if (!allowed.has(key)) throw new BitpeekError('INVALID_INPUT', `Unsupported audit argument: ${key}`)
  let payload: Record<string, unknown>
  if (name === 'bitpeek_secp256k1_audit') {
    const format = args.format ?? 'auto'
    if (typeof format !== 'string' || !['auto', 'pubkey', 'der', 'compact', 'bitcoin-tx', 'bip340-schnorr', 'dleq', 'taproot-tweak', 'bip352-tweak'].includes(format)) throw new BitpeekError('INVALID_INPUT', 'Unsupported secp256k1 audit format')
    const parameters = format === 'bip340-schnorr' ? ['pubkeyHex', 'messageHex']
      : format === 'dleq' ? ['g1Hex', 'p1Hex', 'g2Hex', 'p2Hex', 'messageHex']
      : format === 'taproot-tweak' ? ['internalKeyHex', 'merkleRootHex', 'expectedParity']
      : format === 'bip352-tweak' ? ['spendKeyHex', 'tweakHex'] : []
    for (const key of Object.keys(verificationProperties)) {
      if (args[key] !== undefined && !parameters.includes(key)) throw new BitpeekError('INVALID_INPUT', `${key} is not supported for format ${format}`)
    }
    const { bytes, source } = await readAuditInput(args, security, SECP256K1_AUDIT_MAX_BYTES, undefined, signal)
    if (parameters.length === 0) payload = { ...auditSecp256k1(bytes, format as Secp256k1AuditFormat), source }
    else {
      let verification: { valid: boolean; reason?: string; parity?: number }
      if (format === 'bip340-schnorr') {
        verification = Secp256k1Engine.verifySchnorr(hexArgument(args, 'pubkeyHex'), hexArgument(args, 'messageHex'), bytes)
      } else if (format === 'dleq') {
        verification = Secp256k1Engine.verifyDLEQ(pointArgument(args, 'g1Hex'), pointArgument(args, 'p1Hex'),
          pointArgument(args, 'g2Hex'), pointArgument(args, 'p2Hex'), bytes,
          args.messageHex === undefined ? undefined : hexArgument(args, 'messageHex'))
      } else if (format === 'bip352-tweak') {
        if (typeof args.spendKeyHex !== 'string' || args.spendKeyHex.length < 64 || args.spendKeyHex.length > 66) {
          throw new BitpeekError('INVALID_INPUT', 'spendKeyHex must contain 64 to 66 hexadecimal characters')
        }
        if (typeof args.tweakHex !== 'string' || args.tweakHex.length !== 64) {
          throw new BitpeekError('INVALID_INPUT', 'tweakHex must contain 64 hexadecimal characters')
        }
        const spendPubKey = hexArgument(args, 'spendKeyHex', 33)
        const tweak = hexArgument(args, 'tweakHex')
        if (spendPubKey.length !== 32 && spendPubKey.length !== 33) throw new BitpeekError('INVALID_INPUT', 'spendKeyHex must contain 32 or 33 bytes')
        if (tweak.length !== 32) throw new BitpeekError('INVALID_INPUT', 'tweakHex must contain 32 bytes')
        verification = Secp256k1Engine.verifySilentPaymentTweak(spendPubKey, tweak, bytes)
      } else {
        if (args.expectedParity !== undefined && args.expectedParity !== 0 && args.expectedParity !== 1) throw new BitpeekError('INVALID_INPUT', 'expectedParity must be 0 or 1')
        verification = Secp256k1Engine.verifyTaprootTweak(hexArgument(args, 'internalKeyHex'), bytes,
          args.merkleRootHex === undefined ? undefined : hexArgument(args, 'merkleRootHex'))
        if (verification.valid && args.expectedParity !== undefined && verification.parity !== args.expectedParity) {
          verification = { ...verification, valid: false, reason: 'Taproot output Y parity mismatch' }
        }
      }
      const status = verification.valid ? 'PASS' : 'FAIL'
      payload = { format, ...verification, status, source, verificationScope: 'cryptographic-verification',
        cryptographicSignaturesVerified: format === 'bip340-schnorr' && verification.valid,
        summary: `${status}: ${format} ${verification.valid ? 'verification succeeded' : verification.reason}` }
      if (format === 'bip352-tweak' && !verification.valid) payload.rejectionReason = verification.reason
    }
  } else {
    const arch = args.arch ?? 'x86_64'
    if (arch !== 'x86_64' && arch !== 'aarch64') throw new BitpeekError('INVALID_INPUT', 'arch must be x86_64 or aarch64')
    const maxInstructions = safeInteger(args.maxInstructions ?? MCP_TIMING_MAX_INSTRUCTIONS, 'maxInstructions', 1, MCP_TIMING_MAX_INSTRUCTIONS)
    const checkMemoryLookups = args.checkMemoryLookups === undefined ? true : args.checkMemoryLookups
    if (typeof checkMemoryLookups !== 'boolean') throw new BitpeekError('INVALID_INPUT', 'checkMemoryLookups must be a boolean')
    let secrets: TaintSource[] = []
    if (args.secretRegisters !== undefined) {
      if (!Array.isArray(args.secretRegisters) || Array.from(args.secretRegisters).some(register => typeof register !== 'string' || register.trim().length === 0)) {
        throw new BitpeekError('INVALID_INPUT', 'secretRegisters must be an array of nonempty register names')
      }
      secrets = args.secretRegisters.map((register: string) => ({ type: 'REGISTER', identifier: register.toLowerCase().trim() }))
    }
    let suppliedAddress: bigint | undefined
    if (args.baseAddress !== undefined) {
      if (typeof args.baseAddress !== 'string' || !/^(0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})$/.test(args.baseAddress)) throw new BitpeekError('INVALID_INPUT', 'baseAddress must be an unsigned 64-bit hexadecimal or decimal string')
      suppliedAddress = BigInt(args.baseAddress)
      if (suppliedAddress > 0xffffffffffffffffn) throw new BitpeekError('INVALID_INPUT', 'baseAddress exceeds the unsigned 64-bit address range')
    }
    const { bytes, source } = await readAuditInput(args, security, MCP_TIMING_MAX_BYTES, 256, signal)
    const baseAddress = suppliedAddress ?? BigInt(source.offset ?? 0)
    if (baseAddress + BigInt(bytes.length - 1) > 0xffffffffffffffffn) throw new BitpeekError('INVALID_RANGE', 'Code range exceeds the unsigned 64-bit address range')
    const audit = ConstantTimeAuditor.auditBytes(bytes, { arch, baseAddress, maxInstructions, checkMemoryLookups })
    payload = {
      ...audit, arch, baseAddress: `0x${baseAddress.toString(16)}`, source,
      verificationScope: 'static-instruction-patterns', constantTimeProven: false,
      checkMemoryLookups,
      summary: audit.isCleanConstantTime ? 'No listed static instruction hazards found'
        : `${audit.hazards.length} hazard(s); ${audit.branchCount} conditional branch(es)${audit.hazards.length === 0 ? '; no instructions examined' : ''}`,
      hazards: audit.hazards.map(hazard => ({
        ...hazard, address: `0x${(baseAddress + BigInt(hazard.offset)).toString(16)}`,
        ...(source.offset !== undefined ? { fileOffset: source.offset + hazard.offset } : {}),
      })),
      suspiciousInstructions: audit.suspiciousInstructions.map(finding => ({
        ...finding, address: `0x${(baseAddress + BigInt(finding.offset)).toString(16)}`,
        ...(source.offset !== undefined ? { fileOffset: source.offset + finding.offset } : {}),
      })),
    }
    if (secrets.length > 0) {
      const instructions = ReferenceDisassembler.disassemble(bytes, { arch, baseAddress, maxInstructions })
      let taintAnalysis
      try {
        taintAnalysis = ConstantTimeAuditor.verifyNonInterference(instructions, secrets, arch, { baseAddress })
      } catch (error) {
        if (error instanceof RangeError) throw new BitpeekError('INVALID_INPUT', error.message)
        throw error
      }
      const decodedBytes = instructions.reduce((sum, instruction) => sum + instruction.length, 0)
      if (decodedBytes < bytes.length) {
        taintAnalysis.violations.push({ offset: decodedBytes, mnemonic: '<unexamined>', category: 'UNDECODED', severity: 'WARN', reason: 'Instruction budget left bytes unexamined' })
        taintAnalysis.hasViolations = true
        taintAnalysis.isProvablyConstantTime = false
      }
      payload.taintAnalysis = {
        ...taintAnalysis,
        violations: taintAnalysis.violations.map(hazard => ({
          ...hazard, address: `0x${(baseAddress + BigInt(hazard.offset)).toString(16)}`,
          ...(source.offset !== undefined ? { fileOffset: source.offset + hazard.offset } : {}),
        })),
      }
      if (taintAnalysis.hasViolations) {
        payload.isCleanConstantTime = false
        payload.hasCacheTimingHazards = audit.hasCacheTimingHazards || taintAnalysis.violations.some(hazard => hazard.category === 'CACHE_TIMING')
        payload.hasVariableLatencyHazards = audit.hasVariableLatencyHazards || taintAnalysis.violations.some(hazard => hazard.category === 'VARIABLE_LATENCY')
        payload.summary = `${payload.summary}; ${taintAnalysis.violations.length} taint verification finding(s)`
      }
    }
  }
  return { structuredContent: payload, content: [{ type: 'text', text: JSON.stringify(payload) }] }
}
