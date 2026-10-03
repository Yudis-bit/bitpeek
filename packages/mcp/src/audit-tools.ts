import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js'
import {
  auditSecp256k1, ConstantTimeAuditor, FileByteSource, BitpeekError, parseHex,
  SECP256K1_AUDIT_MAX_BYTES, sha256Hex, Secp256k1Engine, ReferenceDisassembler,
  TaprootEngine, TAPROOT_CONTROL_MAX_SIZE, SECP256K1_GX, SECP256K1_GY, unsignedBigEndian,
} from '../../core/src/index.js'
import type { Secp256k1AuditFormat, SilentPaymentLabelDefinition, TapTreeStructure, TaintSource } from '../../core/src/index.js'
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
const maxScanOutputs = SECP256K1_AUDIT_MAX_BYTES / 32
const secp256k1Formats = ['auto', 'pubkey', 'der', 'compact', 'bitcoin-tx', 'bip340-schnorr', 'dleq', 'taproot-tweak', 'bip352-tweak', 'bip340-sign', 'bip340-aux-audit', 'bip352-scan', 'taproot-control-block', 'tapscript-keys', 'taptree-builder']
const noSource = { anyOf: ['rawHex', 'handle', 'offset', 'length'].map(name => ({ required: [name] })) }
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
  seckeyHex: { ...hex32, description: '32-byte private key for reference BIP-340 signing or aux audit.' },
  auxRandHex: { ...hex32, description: 'Optional 32-byte BIP-340 auxiliary randomness; omitted means zero aux.' },
  scanPrivKeyHex: { ...hex32, description: '32-byte recipient scan private key for BIP-352.' },
  outputsHex: {
    type: 'array', maxItems: maxScanOutputs,
    items: { type: 'string', minLength: 64, maxLength: 64, pattern: '^[0-9a-fA-F]{64}$' },
    description: '32-byte x-only transaction output keys for BIP-352; alternative to packed rawHex/file bytes.',
  },
  batchSize: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER, default: 50, description: 'BIP-352 transaction-output batch size.' },
  labels: {
    type: 'array', maxItems: maxScanOutputs,
    items: {
      type: 'object', additionalProperties: false, required: ['labelIndex', 'labelTweakHex'],
      properties: {
        labelIndex: { type: 'integer', minimum: 0, maximum: 0xffffffff },
        labelTweakHex: { type: 'string', minLength: 64, maxLength: 64, pattern: '^[0-9a-fA-F]{64}$' },
        labelPubKeyHex: { type: 'string', minLength: 66, maxLength: 66, pattern: '^(02|03)[0-9a-fA-F]{64}$' },
      },
    },
    description: 'Precomputed label tweaks and optional corresponding compressed tweak points (m*G).',
  },
  controlBlockHex: { type: 'string', minLength: 66, maxLength: TAPROOT_CONTROL_MAX_SIZE * 3,
    description: 'BIP-341 control block (33 + 32*m bytes, m <= 128). rawHex/file bytes supply the expected output key.' },
  leafScriptHex: { type: 'string', maxLength: SECP256K1_AUDIT_MAX_BYTES * 3,
    description: 'Script committed by the control block. Empty scripts are accepted for commitment verification.' },
  scriptHexes: { type: 'array', minItems: 1, maxItems: maxScanOutputs,
    items: { type: 'string', maxLength: SECP256K1_AUDIT_MAX_BYTES * 3 },
    description: 'Leaf scripts for TapTree construction, in pairing order. Empty leaf scripts are allowed. Combined script bytes <= 1 MiB.' },
  leafVersions: { type: 'array', maxItems: maxScanOutputs,
    items: { type: 'integer', minimum: 0, maximum: 254, multipleOf: 2 },
    description: 'Optional even leaf version per script; length must match scriptHexes. Defaults to 0xc0.' },
  treeStructure: { $ref: '#/$defs/tapTreeStructure',
    description: 'Optional custom binary shape of leaf indices, e.g. [0,[1,2]]. Every script index must occur exactly once; depth <= 128.' },
  keysHex: { type: 'array', maxItems: maxScanOutputs, items: { type: 'string', maxLength: 195 },
    description: 'Descriptor keys to audit after x-only canonicalization. Supports mixed x-only and compressed keys; invalid encodings are findings.' },
  keySize: { type: 'integer', enum: [32, 33], default: 32,
    description: 'Key width for packed tapscript-keys rawHex/file input; use keysHex for mixed widths.' },
}

export const MCP_AUDIT_TOOLS: Tool[] = [
  {
    name: 'bitpeek_secp256k1_audit',
    description: 'Audit secp256k1 encodings and Bitcoin transactions; verify BIP-340 signatures, BIP-374 DLEQ proofs (including BIP-375 shares), BIP-341 and BIP-352 tweaks; reference-sign or compare BIP-340 aux, scan BIP-352 batches, verify Taproot script commitments, audit descriptor key canonicalization, or build TapTrees/control blocks. BigInt reference signing is not constant-time. Use rawHex/file bytes for signatures, proofs, messages, output keys, packed keys, or builder internal keys. Direct signing/scanning/key-audit/builder inputs use messageHex/outputsHex/keysHex/internalKeyHex respectively. Maximum 1 MiB of source bytes or combined array bytes. Script commitment checks do not execute Tapscript.',
    annotations: auditAnnotations,
    inputSchema: {
      type: 'object', additionalProperties: false, oneOf: [
        ...sourceChoices,
        { properties: { format: { const: 'bip340-sign' } }, required: ['format', 'seckeyHex', 'messageHex'], not: noSource },
        { properties: { format: { const: 'bip352-scan' } }, required: ['format', 'spendKeyHex', 'scanPrivKeyHex', 'tweakHex', 'outputsHex'], not: noSource },
        { properties: { format: { const: 'tapscript-keys' } }, required: ['format', 'keysHex'], not: noSource },
        { properties: { format: { const: 'taptree-builder' } }, required: ['format', 'internalKeyHex', 'scriptHexes'], not: noSource },
      ],
      $defs: { tapTreeStructure: { anyOf: [
        { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER },
        { type: 'array', minItems: 2, maxItems: 2, items: { $ref: '#/$defs/tapTreeStructure' } },
      ] } },
      properties: {
        ...sourceProperties,
        rawHex: { ...sourceProperties.rawHex, maxLength: SECP256K1_AUDIT_MAX_BYTES * 3 },
        length: { ...sourceProperties.length, maximum: SECP256K1_AUDIT_MAX_BYTES, description: 'Exact range length; defaults to all remaining file bytes. Maximum 1 MiB.' },
        format: { type: 'string', enum: secp256k1Formats, default: 'auto' },
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

function hexArgument(args: Record<string, unknown>, name: string, maxBytes = 32, allowEmpty = false): Uint8Array {
  const value = args[name]
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || value.length > maxBytes * 3) {
    throw new BitpeekError('INVALID_INPUT', `${name} must be a nonempty hex string of at most ${maxBytes} bytes`)
  }
  const parsed = parseHex(value)
  if (!parsed.ok) throw new BitpeekError('INVALID_INPUT', `${name}: ${parsed.error}`)
  if ((!allowEmpty && parsed.bytes.length === 0) || parsed.bytes.length > maxBytes) throw new BitpeekError('INVALID_INPUT', `${name} exceeds its byte limit or is empty`)
  return parsed.bytes
}

function hexArrayArgument(args: Record<string, unknown>, name: string, maxBytesEach: number): Uint8Array[] {
  const values = args[name]
  if (!Array.isArray(values)) throw new BitpeekError('INVALID_INPUT', `${name} must be an array of hex strings`)
  if (values.length > maxScanOutputs) throw new BitpeekError('RESOURCE_LIMIT', `${name} exceeds the audit array size limit`)
  let totalBytes = 0
  return Array.from(values, (value: unknown, index) => {
    const entry = `${name}[${index}]`
    const bytes = hexArgument({ [entry]: value }, entry, maxBytesEach, true)
    totalBytes += bytes.length
    if (totalBytes > SECP256K1_AUDIT_MAX_BYTES) throw new BitpeekError('RESOURCE_LIMIT', `${name} combined bytes exceed the audit size limit`)
    return bytes
  })
}

function pointArgument(args: Record<string, unknown>, name: string): { x: bigint; y: bigint } {
  const bytes = hexArgument(args, name, 65)
  const inspection = Secp256k1Engine.inspectPubKey(bytes)
  if (!inspection.isValid || (bytes.length !== 33 && bytes.length !== 65) || inspection.y === undefined) {
    throw new BitpeekError('INVALID_INPUT', `${name}: ${inspection.rejectionReason ?? 'DLEQ requires a compressed or uncompressed SEC point'}`)
  }
  return { x: inspection.x, y: inspection.y }
}

function silentPaymentArguments(args: Record<string, unknown>): { spendPubKey: Uint8Array; tweak: Uint8Array } {
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
  return { spendPubKey, tweak }
}

function silentPaymentLabels(args: Record<string, unknown>): SilentPaymentLabelDefinition[] | undefined {
  if (args.labels === undefined) return undefined
  if (!Array.isArray(args.labels)) throw new BitpeekError('INVALID_INPUT', 'labels must be an array')
  if (args.labels.length > maxScanOutputs) throw new BitpeekError('RESOURCE_LIMIT', 'Label cache exceeds the audit size limit')
  return Array.from(args.labels, (value: unknown, index) => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new BitpeekError('INVALID_INPUT', `labels[${index}] must be an object`)
    const label = value as Record<string, unknown>
    for (const key of Object.keys(label)) {
      if (!['labelIndex', 'labelTweakHex', 'labelPubKeyHex'].includes(key)) throw new BitpeekError('INVALID_INPUT', `Unsupported label argument: ${key}`)
    }
    const labelIndex = safeInteger(label.labelIndex, 'labelIndex', 0, 0xffffffff)
    const labelTweak32 = hexArgument(label, 'labelTweakHex')
    if (labelTweak32.length !== 32) throw new BitpeekError('INVALID_INPUT', 'labelTweakHex must contain 32 bytes')
    const labelPubKey33 = label.labelPubKeyHex === undefined ? undefined : hexArgument(label, 'labelPubKeyHex', 33)
    if (labelPubKey33 !== undefined && labelPubKey33.length !== 33) throw new BitpeekError('INVALID_INPUT', 'labelPubKeyHex must contain 33 bytes')
    return { labelIndex, labelTweak32, labelPubKey33 }
  })
}

function hexBytes(bytes?: Uint8Array): string | undefined {
  return bytes === undefined ? undefined : Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
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
    if (typeof format !== 'string' || !secp256k1Formats.includes(format)) throw new BitpeekError('INVALID_INPUT', 'Unsupported secp256k1 audit format')
    const parameters = format === 'bip340-schnorr' ? ['pubkeyHex', 'messageHex']
      : format === 'dleq' ? ['g1Hex', 'p1Hex', 'g2Hex', 'p2Hex', 'messageHex']
      : format === 'taproot-tweak' ? ['internalKeyHex', 'merkleRootHex', 'expectedParity']
      : format === 'bip352-tweak' ? ['spendKeyHex', 'tweakHex']
      : format === 'bip340-sign' || format === 'bip340-aux-audit' ? ['seckeyHex', 'messageHex', 'auxRandHex']
      : format === 'bip352-scan' ? ['spendKeyHex', 'scanPrivKeyHex', 'tweakHex', 'outputsHex', 'batchSize', 'labels']
      : format === 'taproot-control-block' ? ['controlBlockHex', 'leafScriptHex']
      : format === 'tapscript-keys' ? ['keysHex', 'keySize']
      : format === 'taptree-builder' ? ['internalKeyHex', 'scriptHexes', 'leafVersions', 'treeStructure'] : []
    for (const key of Object.keys(verificationProperties)) {
      if (args[key] !== undefined && !parameters.includes(key)) throw new BitpeekError('INVALID_INPUT', `${key} is not supported for format ${format}`)
    }
    const hasSource = args.rawHex !== undefined || args.handle !== undefined
    if (format === 'bip340-sign' && hasSource && args.messageHex !== undefined) {
      throw new BitpeekError('INVALID_INPUT', 'Supply messageHex or rawHex/handle for signing, not both')
    }
    if (format === 'bip352-scan' && hasSource && args.outputsHex !== undefined) {
      throw new BitpeekError('INVALID_INPUT', 'Supply outputsHex or rawHex/handle for scanning, not both')
    }
    if (format === 'tapscript-keys' && hasSource && args.keysHex !== undefined) {
      throw new BitpeekError('INVALID_INPUT', 'Supply keysHex or rawHex/handle for key auditing, not both')
    }
    if (format === 'tapscript-keys' && args.keysHex !== undefined && args.keySize !== undefined) {
      throw new BitpeekError('INVALID_INPUT', 'keySize applies only to packed rawHex/file key input')
    }
    if (format === 'taptree-builder' && hasSource && args.internalKeyHex !== undefined) {
      throw new BitpeekError('INVALID_INPUT', 'Supply internalKeyHex or rawHex/handle for tree building, not both')
    }
    let inlineKeys: Uint8Array[] | undefined
    let input: Awaited<ReturnType<typeof readAuditInput>>
    if (!hasSource && ['bip340-sign', 'bip352-scan', 'tapscript-keys', 'taptree-builder'].includes(format)) {
      checkSignal(signal)
      if (args.offset !== undefined || args.length !== undefined) throw new BitpeekError('INVALID_INPUT', 'offset and length require a session handle')
      let bytes: Uint8Array
      if (format === 'bip340-sign') bytes = hexArgument(args, 'messageHex')
      else if (format === 'taptree-builder') bytes = hexArgument(args, 'internalKeyHex')
      else if (format === 'tapscript-keys') {
        inlineKeys = hexArrayArgument(args, 'keysHex', 65)
        bytes = new Uint8Array(inlineKeys.reduce((length, key) => length + key.length, 0))
        let offset = 0
        for (const key of inlineKeys) { bytes.set(key, offset); offset += key.length }
      }
      else {
        if (!Array.isArray(args.outputsHex)) throw new BitpeekError('INVALID_INPUT', 'outputsHex must be an array of 32-byte hex strings')
        if (args.outputsHex.length > maxScanOutputs) throw new BitpeekError('RESOURCE_LIMIT', 'Output keys exceed the audit size limit')
        bytes = new Uint8Array(args.outputsHex.length * 32)
        for (const [index, value] of args.outputsHex.entries()) {
          if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) throw new BitpeekError('INVALID_INPUT', `outputsHex[${index}] must contain 64 hexadecimal characters`)
          bytes.set(hexArgument({ output: value }, 'output'), index * 32)
        }
      }
      input = { bytes, source: { kind: 'hex', length: bytes.length, sha256: sha256Hex(bytes) } }
    } else input = await readAuditInput(args, security, SECP256K1_AUDIT_MAX_BYTES, undefined, signal)
    const { bytes, source } = input
    if (format === 'bip340-sign') {
      const signing = Secp256k1Engine.bip340Sign(hexArgument(args, 'seckeyHex'), bytes,
        args.auxRandHex === undefined ? undefined : hexArgument(args, 'auxRandHex'))
      const status = signing.valid ? 'PASS' : 'FAIL'
      payload = { format, valid: signing.valid, reason: signing.reason, status, source,
        signatureHex: hexBytes(signing.signature64), publicKeyHex: hexBytes(signing.publicKey32),
        rx: signing.rx === undefined ? undefined : `0x${signing.rx.toString(16)}`,
        s: signing.s === undefined ? undefined : `0x${signing.s.toString(16)}`,
        verificationScope: 'reference-signing', cryptographicSignaturesVerified: signing.valid,
        summary: `${status}: ${format} ${signing.valid ? 'signature generated and verified' : signing.reason}` }
    } else if (format === 'bip340-aux-audit') {
      const audit = Secp256k1Engine.bip340AuditSignatureAux(hexArgument(args, 'seckeyHex'), hexArgument(args, 'messageHex'), bytes,
        args.auxRandHex === undefined ? undefined : hexArgument(args, 'auxRandHex'))
      const status = audit.valid && audit.matchesAux ? 'PASS' : 'FAIL'
      const reason = audit.reason ?? (audit.matchesAux ? undefined : args.auxRandHex === undefined
        ? 'Observed signature does not match zero aux' : 'Observed signature does not match candidate aux')
      payload = { format, valid: audit.valid, matchesAux: audit.matchesAux, isDeterministicDefault: audit.isDeterministicDefault,
        expectedSignatureHex: hexBytes(audit.expectedSignature), candidateSignatureHex: hexBytes(audit.candidateSignature),
        status, reason, source, verificationScope: 'auxiliary-randomness-comparison',
        cryptographicSignaturesVerified: audit.valid && (audit.matchesAux || audit.isDeterministicDefault),
        summary: `${status}: ${format} ${status === 'PASS' ? 'signature matches supplied aux or zero default' : reason}` }
    } else if (format === 'bip352-scan') {
      if (bytes.length % 32 !== 0) throw new BitpeekError('INVALID_INPUT', 'Packed BIP-352 output bytes must be a multiple of 32')
      const { spendPubKey, tweak } = silentPaymentArguments(args)
      const txOutputs = Array.from({ length: bytes.length / 32 }, (_, index) => bytes.slice(index * 32, (index + 1) * 32))
      const scan = Secp256k1Engine.scanSilentPaymentOutputs({ txOutputs, spendPubKey, sharedSecretTweak: tweak,
        scanPrivKey32: hexArgument(args, 'scanPrivKeyHex'), labels: silentPaymentLabels(args),
        batchSize: args.batchSize === undefined ? undefined : safeInteger(args.batchSize, 'batchSize', 1, Number.MAX_SAFE_INTEGER) })
      const status = scan.valid ? 'PASS' : 'FAIL'
      payload = { format, valid: scan.valid, reason: scan.reason, status, source,
        totalOutputsScanned: scan.totalOutputsScanned, batchCount: scan.batchCount,
        matches: scan.matches.map(({ outputKey32, labelTweak32, ...match }) => ({ ...match,
          outputKeyHex: hexBytes(outputKey32), ...(labelTweak32 ? { labelTweakHex: hexBytes(labelTweak32) } : {}) })),
        unlabeledPoint: scan.unlabeledPoint ? { x: `0x${scan.unlabeledPoint.x.toString(16)}`, y: `0x${scan.unlabeledPoint.y.toString(16)}` } : undefined,
        verificationScope: 'silent-payment-output-scan', cryptographicSignaturesVerified: false,
        summary: `${status}: ${format} ${scan.valid ? `${scan.matches.length} matching output(s) across ${scan.batchCount} batch(es)` : scan.reason}` }
    } else if (format === 'taproot-control-block') {
      const verification = TaprootEngine.verifyScriptPath(hexArgument(args, 'controlBlockHex', TAPROOT_CONTROL_MAX_SIZE), bytes,
        hexArgument(args, 'leafScriptHex', SECP256K1_AUDIT_MAX_BYTES, true))
      const status = verification.valid ? 'PASS' : 'FAIL'
      payload = { format, valid: verification.valid, reason: verification.reason, status, source,
        leafVersion: verification.leafVersion, outputParity: verification.outputParity, pathLength: verification.pathLength,
        internalKeyHex: hexBytes(verification.internalKey32), merkleRootHex: hexBytes(verification.merkleRoot),
        computedOutputKeyHex: hexBytes(verification.computedOutputKey32),
        verificationScope: 'taproot-script-commitment', cryptographicSignaturesVerified: false,
        summary: `${status}: ${format} ${verification.valid ? 'script commitment verified' : verification.reason}` }
    } else if (format === 'tapscript-keys') {
      let keys = inlineKeys
      if (keys === undefined) {
        const keySize = args.keySize === undefined ? 32 : args.keySize
        if (keySize !== 32 && keySize !== 33) throw new BitpeekError('INVALID_INPUT', 'keySize must be 32 or 33')
        if (bytes.length % keySize !== 0) throw new BitpeekError('INVALID_INPUT', `Packed key bytes must be a multiple of keySize (${keySize})`)
        keys = Array.from({ length: bytes.length / keySize }, (_, index) => bytes.slice(index * keySize, (index + 1) * keySize))
      }
      const audit = TaprootEngine.auditTapscriptKeys(keys)
      const status = !audit.valid ? 'FAIL' : audit.findings.length > 0 ? 'WARN' : 'PASS'
      payload = { format, ...audit, status, source, verificationScope: 'tapscript-key-canonicalization', cryptographicSignaturesVerified: false,
        summary: `${status}: ${format} ${audit.findings.length} finding(s) across ${audit.totalKeysExamined} key(s)` }
    } else if (format === 'taptree-builder') {
      const scripts = hexArrayArgument(args, 'scriptHexes', SECP256K1_AUDIT_MAX_BYTES)
      const versions = args.leafVersions
      if (versions !== undefined && (!Array.isArray(versions) || versions.length !== scripts.length
        || Array.from(versions).some(version => typeof version !== 'number' || !Number.isInteger(version) || version < 0 || version > 254 || (version & 1) !== 0))) {
        throw new BitpeekError('INVALID_INPUT', 'leafVersions must contain one even byte per script')
      }
      let tree
      try {
        tree = TaprootEngine.buildTapTree(scripts.map((script, index) => ({ script, leafVersion: (versions as number[] | undefined)?.[index] })),
          bytes, args.treeStructure as TapTreeStructure | undefined)
      } catch (error) {
        if (error instanceof RangeError) throw new BitpeekError('INVALID_INPUT', error.message)
        throw error
      }
      const tweak = unsignedBigEndian(TaprootEngine.tapTweakHash(bytes, tree.merkleRoot))
      const output = Secp256k1Engine.pointAdd(Secp256k1Engine.liftX(bytes), Secp256k1Engine.scalarMul(tweak, { x: SECP256K1_GX, y: SECP256K1_GY }))!
      payload = { format, valid: true, status: 'PASS', source, merkleRootHex: hexBytes(tree.merkleRoot),
        outputKeyHex: output.x.toString(16).padStart(64, '0'), outputParity: Number(output.y & 1n),
        leaves: tree.leaves.map(leaf => ({ scriptHex: hexBytes(leaf.script), leafVersion: leaf.leafVersion,
          leafHashHex: hexBytes(leaf.leafHash), merklePathHexes: leaf.merklePath.map(node => hexBytes(node)), controlBlockHex: hexBytes(leaf.controlBlock) })),
        verificationScope: 'taproot-tree-construction', cryptographicSignaturesVerified: false,
        summary: `PASS: ${format} built ${tree.leaves.length} leaf/leaves` }
    } else if (parameters.length === 0) payload = { ...auditSecp256k1(bytes, format as Secp256k1AuditFormat), source }
    else {
      let verification: { valid: boolean; reason?: string; parity?: number }
      if (format === 'bip340-schnorr') {
        verification = Secp256k1Engine.verifySchnorr(hexArgument(args, 'pubkeyHex'), hexArgument(args, 'messageHex'), bytes)
      } else if (format === 'dleq') {
        verification = Secp256k1Engine.verifyDLEQ(pointArgument(args, 'g1Hex'), pointArgument(args, 'p1Hex'),
          pointArgument(args, 'g2Hex'), pointArgument(args, 'p2Hex'), bytes,
          args.messageHex === undefined ? undefined : hexArgument(args, 'messageHex'))
      } else if (format === 'bip352-tweak') {
        const { spendPubKey, tweak } = silentPaymentArguments(args)
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
