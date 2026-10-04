import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js'
import {
  auditSecp256k1, ConstantTimeAuditor, FileByteSource, BitpeekError, parseHex,
  SECP256K1_AUDIT_MAX_BYTES, sha256Hex, Secp256k1Engine, ReferenceDisassembler,
  TaprootEngine, TAPROOT_CONTROL_MAX_SIZE, SECP256K1_GX, SECP256K1_GY, unsignedBigEndian,
  auditTapscript, evaluateTapscript, auditBip375Shares, BIP375_MAX_SIGNERS, BIP375_MAX_OUTPUTS,
  decodeSwiftECBytes, encodeSwiftEC, auditBip324Frame, deriveBip324SessionKeys,
  BIP324_MAX_AUDIT_PACKET_INDEX, auditDifferentialExecution, generateSecp256k1Boundaries, auditSecp256k1BoundaryExecutions,
} from '../../core/src/index.js'
import type { Secp256k1AuditFormat, SilentPaymentLabelDefinition, TapTreeStructure, TaintSource,
  Bip375SignerShare, BitcoinVerificationProfile, Secp256k1DifferentialOperation, Point } from '../../core/src/index.js'
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
const masterFormats = ['tapscript-audit', 'tapscript-eval', 'bip375-audit', 'bip324-swift-ec', 'bip324-frame-audit', 'secp256k1-diff-oracle']
const secp256k1Formats = ['auto', 'pubkey', 'der', 'compact', 'bitcoin-tx', 'bip340-schnorr', 'dleq', 'taproot-tweak', 'bip352-tweak', 'bip340-sign', 'bip340-aux-audit', 'bip352-scan', 'taproot-control-block', 'tapscript-keys', 'taptree-builder', ...masterFormats]
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
  profile: { type: 'string', enum: ['specification', 'published-bip'], default: 'specification',
    description: 'Phase 3 reference rules or published BIP-342/BIP-352 rules. Published Tapscript requires serializedWitnessSize.' },
  witnessHexes: { type: 'array', maxItems: maxScanOutputs, items: { type: 'string', maxLength: SECP256K1_AUDIT_MAX_BYTES * 3 },
    description: 'Initial Tapscript stack, in bottom-to-top order; excludes script, control block and annex. Combined bytes <= 1 MiB.' },
  serializedWitnessSize: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER - 50,
    description: 'Complete serialized input witness size, including CompactSize prefixes, script, control block and annex; required for published-bip.' },
  simulationMode: { type: 'boolean', default: false, description: 'Explicit structural signature simulation; never claims cryptographic verification.' },
  traceExecution: { type: 'boolean', default: false },
  traceLimit: { type: 'integer', minimum: 0, maximum: 100000, default: 10000 },
  lockTime: { type: 'integer', minimum: 0, maximum: 0xffffffff },
  inputSequence: { type: 'integer', minimum: 0, maximum: 0xffffffff },
  transactionVersion: { type: 'integer', minimum: -0x80000000, maximum: 0x7fffffff },
  signers: { type: 'array', minItems: 1, maxItems: BIP375_MAX_SIGNERS,
    items: { type: 'object', additionalProperties: false, required: ['inputPubkeyHex', 'ecdhShareHex', 'dleqProofHex'], properties: {
      inputPubkeyHex: { type: 'string', minLength: 64, maxLength: 66, pattern: '^[0-9a-fA-F]+$' },
      ecdhShareHex: { type: 'string', minLength: 66, maxLength: 66, pattern: '^(02|03)[0-9a-fA-F]{64}$' },
      dleqProofHex: { type: 'string', minLength: 128, maxLength: 128, pattern: '^[0-9a-fA-F]{128}$' },
    } }, description: 'Extracted per-input BIP-375 ECDH shares and BIP-374 proofs, for one recipient.' },
  scanKeyHex: { type: 'string', minLength: 64, maxLength: 66, description: 'Recipient scan public key.' },
  outpointSmallestHex: { type: 'string', minLength: 72, maxLength: 72, pattern: '^[0-9a-fA-F]{72}$' },
  allInputPubkeysHex: { type: 'array', minItems: 1, maxItems: BIP375_MAX_SIGNERS,
    items: { type: 'string', minLength: 64, maxLength: 66 }, description: 'All eligible input keys; repeated keys represent distinct inputs.' },
  expectedScalarFoldHex: { type: 'string', minLength: 66, maxLength: 66 },
  outputCount: { type: 'integer', minimum: 0, maximum: BIP375_MAX_OUTPUTS },
  swiftEcHex: { type: 'string', minLength: 128, maxLength: 128, pattern: '^[0-9a-fA-F]{128}$', description: '64-byte ElligatorSwift wire encoding; all bit strings decode.' },
  swiftAction: { type: 'string', enum: ['decode', 'encode'], default: 'decode' },
  bip324PacketHex: { type: 'string', maxLength: SECP256K1_AUDIT_MAX_BYTES * 3, description: 'Exactly one encrypted BIP-324 v2 packet.' },
  lengthKeyHex: hex32,
  payloadKeyHex: hex32,
  sharedSecretHex: { ...hex32, description: 'Encoding-bound BIP-324 ECDH transcript hash, for HKDF session derivation.' },
  networkMagicHex: { type: 'string', minLength: 8, maxLength: 8, description: 'Required four network magic bytes with sharedSecretHex.' },
  direction: { type: 'string', enum: ['initiator', 'responder'], description: 'Sending direction; required with sharedSecretHex.' },
  packetIndex: { type: 'integer', minimum: 0, maximum: BIP324_MAX_AUDIT_PACKET_INDEX, default: 0,
    description: 'Packet index starting at zero, using initial keys with ratchets advanced to this index.' },
  aadHex: { type: 'string', maxLength: 4095 * 3, description: 'First-packet garbage AAD; later packets normally use empty AAD.' },
  inspectApplicationPayload: { type: 'boolean', default: false, description: 'Inspect application message command framing; omit for version-negotiation packets.' },
  diffOp: { type: 'string', enum: ['mul', 'add', 'doubling', 'inversion', 'schnorr', 'identities'], default: 'identities' },
  runBoundaries: { type: 'boolean', default: false, description: 'Also execute the deterministic scalar/field/infinity/parity boundary campaign against repository arithmetic.' },
  scalarHex: hex32,
  scalar2Hex: hex32,
  fieldElementHex: hex32,
  diffPointHex: { type: 'string', maxLength: 195, description: 'SEC point, or 00 for group infinity.' },
  diffOtherPointHex: { type: 'string', maxLength: 195 },
  diffThirdPointHex: { type: 'string', maxLength: 195 },
  observedResultHex: { type: 'string', maxLength: 195, description: 'Observed native/Wasm/C affine SEC point (00 = infinity) or 32-byte inverse, for comparison.' },
  observedValid: { type: 'boolean', description: 'Observed Schnorr verifier result.' },
  criticalCodeHex: { type: 'string', maxLength: MCP_TIMING_MAX_BYTES * 3, description: 'Optional critical machine-code region for static timing hazard inspection.' },
  diffArch: { type: 'string', enum: ['x86_64', 'aarch64'], default: 'x86_64' },
}

export const MCP_AUDIT_TOOLS: Tool[] = [
  {
    name: 'bitpeek_secp256k1_audit',
    description: 'Audit secp256k1 and Bitcoin encodings; verify Schnorr, DLEQ, Taproot and silent-payment invariants; evaluate/audit Tapscript, audit extracted BIP-375 shares, encode/decode BIP-324 SwiftEC, inspect authenticated v2 frames, and compare independent Jacobian arithmetic with repository or supplied observed results. BigInt reference operations are not constant-time. Maximum 1 MiB of source/combined array bytes. New formats include JSON and reportMarkdown. Script commitments, transaction sighashes and extracted input eligibility remain caller responsibilities.',
    annotations: auditAnnotations,
    inputSchema: {
      type: 'object', additionalProperties: false, oneOf: [
        ...sourceChoices,
        { properties: { format: { const: 'bip340-sign' } }, required: ['format', 'seckeyHex', 'messageHex'], not: noSource },
        { properties: { format: { const: 'bip352-scan' } }, required: ['format', 'spendKeyHex', 'scanPrivKeyHex', 'tweakHex', 'outputsHex'], not: noSource },
        { properties: { format: { const: 'tapscript-keys' } }, required: ['format', 'keysHex'], not: noSource },
        { properties: { format: { const: 'taptree-builder' } }, required: ['format', 'internalKeyHex', 'scriptHexes'], not: noSource },
        { properties: { format: { enum: ['tapscript-audit', 'tapscript-eval'] } }, required: ['format', 'leafScriptHex'], not: noSource },
        { properties: { format: { const: 'bip375-audit' } }, required: ['format', 'signers', 'scanKeyHex', 'spendKeyHex', 'outpointSmallestHex', 'allInputPubkeysHex'], not: noSource },
        { properties: { format: { const: 'bip324-swift-ec' } }, required: ['format', 'swiftEcHex'], not: noSource },
        { properties: { format: { const: 'bip324-swift-ec' }, swiftAction: { const: 'encode' } }, required: ['format', 'swiftAction', 'pubkeyHex', 'auxRandHex'], not: { anyOf: [noSource, { required: ['swiftEcHex'] }] } },
        { properties: { format: { const: 'bip324-frame-audit' } }, required: ['format', 'bip324PacketHex'], not: noSource },
        { properties: { format: { const: 'secp256k1-diff-oracle' } }, required: ['format'], not: noSource },
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

function exactHexArgument(args: Record<string, unknown>, name: string, size: number): Uint8Array {
  const bytes = hexArgument(args, name, size)
  if (bytes.length !== size) throw new BitpeekError('INVALID_INPUT', `${name} must contain exactly ${size} bytes`)
  return bytes
}
function booleanArgument(args: Record<string, unknown>, name: string, fallback = false): boolean {
  const value = args[name] === undefined ? fallback : args[name]
  if (typeof value !== 'boolean') throw new BitpeekError('INVALID_INPUT', `${name} must be a boolean`)
  return value
}
function verificationProfile(args: Record<string, unknown>): BitcoinVerificationProfile {
  const value = args.profile === undefined ? 'specification' : args.profile
  if (value !== 'specification' && value !== 'published-bip') throw new BitpeekError('INVALID_INPUT', 'profile must be specification or published-bip')
  return value
}
function joinAuditBytes(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((size, part) => size + part.length, 0)
  if (length > SECP256K1_AUDIT_MAX_BYTES) throw new BitpeekError('RESOURCE_LIMIT', 'Combined audit bytes exceed 1 MiB')
  const bytes = new Uint8Array(length)
  let offset = 0
  for (const part of parts) { bytes.set(part, offset); offset += part.length }
  return bytes
}
function bip375Signers(args: Record<string, unknown>): Bip375SignerShare[] {
  if (!Array.isArray(args.signers) || args.signers.length === 0 || args.signers.length > BIP375_MAX_SIGNERS) {
    throw new BitpeekError('INVALID_INPUT', `signers must contain 1 to ${BIP375_MAX_SIGNERS} entries`)
  }
  return Array.from(args.signers, (entry: unknown, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) throw new BitpeekError('INVALID_INPUT', `signers[${index}] must be an object`)
    const signer = entry as Record<string, unknown>
    for (const key of Object.keys(signer)) if (!['inputPubkeyHex', 'ecdhShareHex', 'dleqProofHex'].includes(key)) {
      throw new BitpeekError('INVALID_INPUT', `Unsupported signer property: ${key}`)
    }
    return { inputPubkey: hexArgument(signer, 'inputPubkeyHex', 33), ecdhShare: exactHexArgument(signer, 'ecdhShareHex', 33),
      dleqProof: exactHexArgument(signer, 'dleqProofHex', 64) }
  })
}
function differentialPoint(args: Record<string, unknown>, name: string): Point {
  const bytes = hexArgument(args, name, 65)
  if (bytes.length === 1 && bytes[0] === 0) return null
  if (bytes.length === 32) {
    const point = Secp256k1Engine.liftX(bytes)
    if (point !== null) return point
    throw new BitpeekError('INVALID_INPUT', `${name} is not a valid x-only point`)
  }
  return pointArgument(args, name)
}
function jsonSafeRecord(value: unknown): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value, (_key, item: unknown) => typeof item === 'bigint' ? `0x${item.toString(16)}` : item)) as Record<string, unknown>
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
      : format === 'taptree-builder' ? ['internalKeyHex', 'scriptHexes', 'leafVersions', 'treeStructure']
      : format === 'tapscript-audit' ? ['leafScriptHex', 'profile', 'serializedWitnessSize']
      : format === 'tapscript-eval' ? ['leafScriptHex', 'profile', 'serializedWitnessSize', 'witnessHexes', 'messageHex', 'simulationMode', 'traceExecution', 'traceLimit', 'lockTime', 'inputSequence', 'transactionVersion']
      : format === 'bip375-audit' ? ['signers', 'scanKeyHex', 'spendKeyHex', 'outpointSmallestHex', 'allInputPubkeysHex', 'outputsHex', 'expectedScalarFoldHex', 'outputCount', 'profile']
      : format === 'bip324-swift-ec' ? ['swiftEcHex', 'swiftAction', 'pubkeyHex', 'auxRandHex']
      : format === 'bip324-frame-audit' ? ['bip324PacketHex', 'lengthKeyHex', 'payloadKeyHex', 'sharedSecretHex', 'networkMagicHex', 'direction', 'packetIndex', 'aadHex', 'inspectApplicationPayload']
      : format === 'secp256k1-diff-oracle' ? ['diffOp', 'runBoundaries', 'scalarHex', 'scalar2Hex', 'fieldElementHex', 'diffPointHex', 'diffOtherPointHex', 'diffThirdPointHex', 'observedResultHex', 'observedValid', 'pubkeyHex', 'messageHex', 'criticalCodeHex', 'diffArch'] : []
    for (const key of Object.keys(verificationProperties)) {
      if (args[key] !== undefined && !parameters.includes(key)) throw new BitpeekError('INVALID_INPUT', `${key} is not supported for format ${format}`)
    }
    const hasSource = args.rawHex !== undefined || args.handle !== undefined
    const directSourceProperty = format.startsWith('tapscript-') && masterFormats.includes(format) ? 'leafScriptHex'
      : format === 'bip324-frame-audit' ? 'bip324PacketHex'
      : format === 'bip324-swift-ec' ? args.swiftAction === 'encode' ? 'pubkeyHex' : 'swiftEcHex' : undefined
    if (hasSource && directSourceProperty && args[directSourceProperty] !== undefined) throw new BitpeekError('INVALID_INPUT', `Supply ${directSourceProperty} or rawHex/handle, not both`)
    if (format === 'bip375-audit' && hasSource) throw new BitpeekError('INVALID_INPUT', 'bip375-audit requires extracted signers and eligible input keys, without rawHex/handle')
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
    let signers: Bip375SignerShare[] | undefined
    let allInputPubkeys: Uint8Array[] | undefined
    let input: Awaited<ReturnType<typeof readAuditInput>>
    if (!hasSource && ['bip340-sign', 'bip352-scan', 'tapscript-keys', 'taptree-builder', ...masterFormats].includes(format)) {
      checkSignal(signal)
      if (args.offset !== undefined || args.length !== undefined) throw new BitpeekError('INVALID_INPUT', 'offset and length require a session handle')
      let bytes: Uint8Array
      if (directSourceProperty) bytes = hexArgument(args, directSourceProperty, SECP256K1_AUDIT_MAX_BYTES, true)
      else if (format === 'bip375-audit') {
        signers = bip375Signers(args)
        allInputPubkeys = hexArrayArgument(args, 'allInputPubkeysHex', 33)
        bytes = joinAuditBytes([...signers.flatMap(signer => [new Uint8Array([signer.inputPubkey.length]), signer.inputPubkey, signer.ecdhShare, signer.dleqProof]),
          ...allInputPubkeys.flatMap(key => [new Uint8Array([key.length]), key])])
      }
      else if (format === 'secp256k1-diff-oracle') bytes = new Uint8Array(0)
      else if (format === 'bip340-sign') bytes = hexArgument(args, 'messageHex')
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
    if (format === 'tapscript-audit' || format === 'tapscript-eval') {
      const profile = verificationProfile(args)
      const options = { profile, serializedWitnessSize: args.serializedWitnessSize === undefined ? undefined
        : safeInteger(args.serializedWitnessSize, 'serializedWitnessSize', 0, Number.MAX_SAFE_INTEGER - 50) }
      try {
        if (format === 'tapscript-audit') {
          const audit = auditTapscript(bytes, options)
          const status = audit.isPermanentlyUnspendable ? 'FAIL' : audit.findings.some(finding => finding.severity !== 'info') ? 'WARN' : audit.analysisComplete ? 'PASS' : 'INCOMPLETE'
          payload = { format, ...audit, valid: !audit.isPermanentlyUnspendable, status, source,
            verificationScope: 'tapscript-static-safety', cryptographicSignaturesVerified: false,
            summary: `${status}: ${format} ${audit.findings.length} finding(s)` }
        } else {
          const witness = args.witnessHexes === undefined ? [] : hexArrayArgument(args, 'witnessHexes', SECP256K1_AUDIT_MAX_BYTES)
          joinAuditBytes([bytes, ...witness])
          const evaluation = evaluateTapscript(bytes, witness, { ...options,
            simulationMode: booleanArgument(args, 'simulationMode'), traceExecution: booleanArgument(args, 'traceExecution'),
            traceLimit: args.traceLimit === undefined ? undefined : safeInteger(args.traceLimit, 'traceLimit', 0, 100000),
            message: args.messageHex === undefined ? undefined : exactHexArgument(args, 'messageHex', 32),
            lockTime: args.lockTime === undefined ? undefined : safeInteger(args.lockTime, 'lockTime', 0, 0xffffffff),
            inputSequence: args.inputSequence === undefined ? undefined : safeInteger(args.inputSequence, 'inputSequence', 0, 0xffffffff),
            transactionVersion: args.transactionVersion === undefined ? undefined : safeInteger(args.transactionVersion, 'transactionVersion', -0x80000000, 0x7fffffff) })
          payload = { format, ...evaluation, valid: evaluation.success, status: evaluation.success ? 'PASS' : 'FAIL', source,
            verificationScope: evaluation.simulationMode ? 'tapscript-structural-simulation' : 'tapscript-precomputed-sighash-evaluation',
            summary: `${evaluation.success ? 'PASS' : 'FAIL'}: ${format} ${evaluation.failureReason ?? 'script evaluation succeeded'}` }
        }
      } catch (error) {
        if (error instanceof RangeError) throw new BitpeekError('INVALID_INPUT', error.message)
        throw error
      }
    } else if (format === 'bip375-audit') {
      const expectedOutputs = args.outputsHex === undefined ? undefined : hexArrayArgument(args, 'outputsHex', 32)
      joinAuditBytes([bytes, ...(expectedOutputs ?? [])])
      const audit = auditBip375Shares({ signers: signers!, allInputPubkeys: allInputPubkeys!,
        scanPubkey: hexArgument(args, 'scanKeyHex', 33), spendPubkey: hexArgument(args, 'spendKeyHex', 33),
        outpointSmallest: exactHexArgument(args, 'outpointSmallestHex', 36), expectedOutputs,
        expectedScalarFold: args.expectedScalarFoldHex === undefined ? undefined : exactHexArgument(args, 'expectedScalarFoldHex', 33),
        outputCount: args.outputCount === undefined ? undefined : safeInteger(args.outputCount, 'outputCount', 0, BIP375_MAX_OUTPUTS), profile: verificationProfile(args) })
      payload = { format, ...audit, status: audit.valid ? 'PASS' : 'FAIL', source, verificationScope: 'extracted-bip375-share-proofs-and-scalar-fold',
        cryptographicSignaturesVerified: false, dleqProofsVerified: audit.valid,
        summary: `${audit.valid ? 'PASS' : 'FAIL'}: ${format} ${audit.rejectionReason ?? `${audit.signerCount} signer share(s) verified`}` }
    } else if (format === 'bip324-swift-ec') {
      const action = args.swiftAction === undefined ? 'decode' : args.swiftAction
      if (action !== 'decode' && action !== 'encode') throw new BitpeekError('INVALID_INPUT', 'swiftAction must be decode or encode')
      if (action === 'decode' && (args.pubkeyHex !== undefined || args.auxRandHex !== undefined)) throw new BitpeekError('INVALID_INPUT', 'pubkeyHex and auxRandHex apply only to SwiftEC encoding')
      if (action === 'encode' && args.swiftEcHex !== undefined) throw new BitpeekError('INVALID_INPUT', 'swiftEcHex applies only to SwiftEC decoding')
      try {
        const point = action === 'decode' ? decodeSwiftECBytes(bytes) : differentialPoint({ pubkeyHex: hexBytes(bytes) }, 'pubkeyHex')
        if (point === null) throw new BitpeekError('INVALID_INPUT', 'SwiftEC cannot encode infinity')
        const encoding = action === 'decode' ? bytes : encodeSwiftEC(point, exactHexArgument(args, 'auxRandHex', 32))
        payload = { format, action, valid: true, status: 'PASS', source, swiftEcHex: hexBytes(encoding),
          point: { x: `0x${point.x.toString(16)}`, y: `0x${point.y.toString(16)}` },
          verificationScope: 'bip324-elligator-swift-reference', constantTimeProven: false,
          summary: `PASS: ${format} ${action} produced a valid secp256k1 point/encoding` }
      } catch (error) {
        if (error instanceof RangeError) throw new BitpeekError('INVALID_INPUT', error.message)
        throw error
      }
    } else if (format === 'bip324-frame-audit') {
      const hasKeys = args.lengthKeyHex !== undefined || args.payloadKeyHex !== undefined
      if (hasKeys && args.sharedSecretHex !== undefined) throw new BitpeekError('INVALID_INPUT', 'Supply directional keys or sharedSecretHex, not both')
      if (args.sharedSecretHex === undefined && (args.networkMagicHex !== undefined || args.direction !== undefined)) throw new BitpeekError('INVALID_INPUT', 'networkMagicHex and direction require sharedSecretHex')
      let keys
      if (hasKeys) keys = { lengthKey: exactHexArgument(args, 'lengthKeyHex', 32), payloadKey: exactHexArgument(args, 'payloadKeyHex', 32) }
      else if (args.sharedSecretHex !== undefined) {
        if (args.direction !== 'initiator' && args.direction !== 'responder') throw new BitpeekError('INVALID_INPUT', 'direction must be initiator or responder with sharedSecretHex')
        const session = deriveBip324SessionKeys(exactHexArgument(args, 'sharedSecretHex', 32), exactHexArgument(args, 'networkMagicHex', 4))
        keys = args.direction === 'initiator' ? { lengthKey: session.initiatorLengthKey, payloadKey: session.initiatorPayloadKey }
          : { lengthKey: session.responderLengthKey, payloadKey: session.responderPayloadKey }
      }
      const audit = auditBip324Frame(bytes, { keys, packetIndex: args.packetIndex === undefined ? undefined : safeInteger(args.packetIndex, 'packetIndex', 0, BIP324_MAX_AUDIT_PACKET_INDEX),
        aad: args.aadHex === undefined ? undefined : hexArgument(args, 'aadHex', 4095, true), inspectApplicationPayload: booleanArgument(args, 'inspectApplicationPayload') })
      const status = audit.valid === null ? 'INCOMPLETE' : audit.valid ? 'PASS' : 'FAIL'
      payload = { format, ...audit, status, source, cryptographicSignaturesVerified: false, constantTimeProven: false,
        summary: `${status}: ${format} ${audit.authenticationVerified ? 'Poly1305 tag verified' : audit.findings[0]?.message ?? 'frame inspection'}` }
    } else if (format === 'secp256k1-diff-oracle') {
      const operation = args.diffOp === undefined ? 'identities' : args.diffOp
      if (typeof operation !== 'string' || !['mul', 'add', 'doubling', 'inversion', 'schnorr', 'identities'].includes(operation)) throw new BitpeekError('INVALID_INPUT', 'Unsupported diffOp')
      const operationProperties = operation === 'mul' ? ['scalarHex', 'diffPointHex', 'observedResultHex']
        : operation === 'add' ? ['diffPointHex', 'diffOtherPointHex', 'observedResultHex']
        : operation === 'doubling' ? ['diffPointHex', 'observedResultHex']
        : operation === 'inversion' ? ['fieldElementHex', 'observedResultHex']
        : operation === 'schnorr' ? ['pubkeyHex', 'messageHex', 'observedValid']
        : ['scalarHex', 'scalar2Hex', 'diffPointHex', 'diffOtherPointHex', 'diffThirdPointHex']
      for (const key of parameters) {
        if (args[key] !== undefined && !['diffOp', 'runBoundaries', 'criticalCodeHex', 'diffArch', ...operationProperties].includes(key)) {
          throw new BitpeekError('INVALID_INPUT', `${key} is not supported for diffOp ${operation}`)
        }
      }
      if (args.diffArch !== undefined && args.diffArch !== 'x86_64' && args.diffArch !== 'aarch64') throw new BitpeekError('INVALID_INPUT', 'diffArch must be x86_64 or aarch64')
      if (args.observedResultHex !== undefined && args.observedValid !== undefined) throw new BitpeekError('INVALID_INPUT', 'Supply only the observed result for the selected operation')
      if (args.observedValid !== undefined && operation !== 'schnorr') throw new BitpeekError('INVALID_INPUT', 'observedValid applies only to Schnorr verification')
      if (args.observedResultHex !== undefined && ['schnorr', 'identities'].includes(operation)) throw new BitpeekError('INVALID_INPUT', 'observedResultHex requires a single arithmetic operation')
      if (hasSource && !['mul', 'inversion', 'doubling', 'add', 'schnorr'].includes(operation)) throw new BitpeekError('INVALID_INPUT', 'rawHex/handle requires a single differential operation')
      if (hasSource && ((operation === 'mul' && args.scalarHex !== undefined) || (operation === 'inversion' && args.fieldElementHex !== undefined)
        || ((operation === 'doubling' || operation === 'add') && (args.diffPointHex !== undefined || args.diffOtherPointHex !== undefined)))) {
        throw new BitpeekError('INVALID_INPUT', 'Packed differential input conflicts with direct input')
      }
      const packed = (size: number) => { if (bytes.length !== size) throw new BitpeekError('INVALID_INPUT', `Packed ${operation} input must contain ${size} bytes`); return unsignedBigEndian(bytes) }
      const point = args.diffPointHex === undefined ? undefined : differentialPoint(args, 'diffPointHex')
      const observedResult = args.observedValid !== undefined ? booleanArgument(args, 'observedValid')
        : args.observedResultHex === undefined ? undefined : operation === 'inversion' ? unsignedBigEndian(exactHexArgument(args, 'observedResultHex', 32)) : differentialPoint(args, 'observedResultHex')
      try {
        const audit = auditDifferentialExecution(operation as Secp256k1DifferentialOperation, {
          scalar: hasSource && operation === 'mul' ? packed(32) : args.scalarHex === undefined ? undefined : unsignedBigEndian(exactHexArgument(args, 'scalarHex', 32)),
          scalar2: args.scalar2Hex === undefined ? undefined : unsignedBigEndian(exactHexArgument(args, 'scalar2Hex', 32)),
          fieldElement: hasSource && operation === 'inversion' ? packed(32) : args.fieldElementHex === undefined ? undefined : unsignedBigEndian(exactHexArgument(args, 'fieldElementHex', 32)),
          point: hasSource && operation === 'doubling' ? differentialPoint({ point: hexBytes(bytes) }, 'point')
            : hasSource && operation === 'add' ? (packed(66), differentialPoint({ point: hexBytes(bytes.subarray(0, 33)) }, 'point')) : point,
          otherPoint: hasSource && operation === 'add' ? differentialPoint({ point: hexBytes(bytes.subarray(33)) }, 'point')
            : args.diffOtherPointHex === undefined ? undefined : differentialPoint(args, 'diffOtherPointHex'),
          thirdPoint: args.diffThirdPointHex === undefined ? undefined : differentialPoint(args, 'diffThirdPointHex'), observedResult,
          pubkey32: args.pubkeyHex === undefined ? undefined : exactHexArgument(args, 'pubkeyHex', 32),
          message32: args.messageHex === undefined ? undefined : exactHexArgument(args, 'messageHex', 32),
          signature64: hasSource && operation === 'schnorr' ? bytes : undefined,
          criticalCode: args.criticalCodeHex === undefined ? undefined : hexArgument(args, 'criticalCodeHex', MCP_TIMING_MAX_BYTES),
          arch: args.diffArch as 'x86_64' | 'aarch64' | undefined })
        const campaign = booleanArgument(args, 'runBoundaries') ? auditSecp256k1BoundaryExecutions() : undefined
        const valid = audit.valid && (campaign?.valid ?? true)
        payload = { format, ...jsonSafeRecord(audit), valid, boundaries: jsonSafeRecord({ vectors: generateSecp256k1Boundaries() }).vectors,
          boundaryCampaign: campaign === undefined ? undefined : jsonSafeRecord(campaign),
          status: valid ? 'PASS' : 'FAIL', source, verificationScope: 'independent-Jacobian-differential-arithmetic',
          comparisonTarget: observedResult === undefined ? 'repository-affine-BigInt' : 'supplied-observed-result',
          summary: `${valid ? 'PASS' : 'FAIL'}: ${format} ${audit.divergenceCount + (campaign?.divergenceCount ?? 0)}/${audit.comparisons + (campaign?.comparisons ?? 0)} comparison(s) diverged` }
      } catch (error) {
        if (error instanceof RangeError) throw new BitpeekError('INVALID_INPUT', error.message)
        throw error
      }
    } else if (format === 'bip340-sign') {
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
  if (typeof args.format === 'string' && masterFormats.includes(args.format)) {
    payload.reportMarkdown = `**${payload.status}: ${args.format}**\n\n${payload.summary}\n\nVerification scope: ${payload.verificationScope}.`
  }
  return { structuredContent: payload, content: [{ type: 'text', text: JSON.stringify(payload) }] }
}
