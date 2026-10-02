import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js'
import {
  auditSecp256k1, ConstantTimeAuditor, FileByteSource, BitpeekError, parseHex,
  SECP256K1_AUDIT_MAX_BYTES, sha256Hex,
} from '../../core/src/index.js'
import type { Secp256k1AuditFormat } from '../../core/src/index.js'
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

export const MCP_AUDIT_TOOLS: Tool[] = [
  {
    name: 'bitpeek_secp256k1_audit',
    description: 'Audit secp256k1 public keys, strict DER or compact ECDSA signatures, and raw Bitcoin transactions. Returns curve/scalar/encoding findings and low-S policy warnings. Does not verify signed messages or full consensus. Accepts inline hex or an open file range up to 1 MiB; use format when encodings are ambiguous.',
    annotations: auditAnnotations,
    inputSchema: {
      type: 'object', additionalProperties: false, oneOf: sourceChoices,
      properties: {
        ...sourceProperties,
        rawHex: { ...sourceProperties.rawHex, maxLength: SECP256K1_AUDIT_MAX_BYTES * 3 },
        length: { ...sourceProperties.length, maximum: SECP256K1_AUDIT_MAX_BYTES, description: 'Exact range length; defaults to all remaining file bytes. Maximum 1 MiB.' },
        format: { type: 'string', enum: ['auto', 'pubkey', 'der', 'compact', 'bitcoin-tx'], default: 'auto' },
      },
    },
  },
  {
    name: 'bitpeek_constant_time_audit',
    description: 'Statically inspect a caller-selected secret-handling code region for conditional branches, integer division, and undecoded instructions. Uses the reference x86_64/AArch64 disassembler. A clean result is not a timing proof. Accepts inline hex or an open file range up to 65536 bytes; reports exact relative/file offsets and bigint addresses.',
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
  const allowed = new Set(['rawHex', 'handle', 'offset', 'length', ...(name === 'bitpeek_secp256k1_audit' ? ['format'] : ['arch', 'baseAddress', 'maxInstructions'])])
  for (const key of Object.keys(args)) if (!allowed.has(key)) throw new BitpeekError('INVALID_INPUT', `Unsupported audit argument: ${key}`)
  let payload: Record<string, unknown>
  if (name === 'bitpeek_secp256k1_audit') {
    const format = args.format ?? 'auto'
    if (typeof format !== 'string' || !['auto', 'pubkey', 'der', 'compact', 'bitcoin-tx'].includes(format)) throw new BitpeekError('INVALID_INPUT', 'Unsupported secp256k1 audit format')
    const { bytes, source } = await readAuditInput(args, security, SECP256K1_AUDIT_MAX_BYTES, undefined, signal)
    payload = { ...auditSecp256k1(bytes, format as Secp256k1AuditFormat), source }
  } else {
    const arch = args.arch ?? 'x86_64'
    if (arch !== 'x86_64' && arch !== 'aarch64') throw new BitpeekError('INVALID_INPUT', 'arch must be x86_64 or aarch64')
    const maxInstructions = safeInteger(args.maxInstructions ?? MCP_TIMING_MAX_INSTRUCTIONS, 'maxInstructions', 1, MCP_TIMING_MAX_INSTRUCTIONS)
    let suppliedAddress: bigint | undefined
    if (args.baseAddress !== undefined) {
      if (typeof args.baseAddress !== 'string' || !/^(0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})$/.test(args.baseAddress)) throw new BitpeekError('INVALID_INPUT', 'baseAddress must be an unsigned 64-bit hexadecimal or decimal string')
      suppliedAddress = BigInt(args.baseAddress)
      if (suppliedAddress > 0xffffffffffffffffn) throw new BitpeekError('INVALID_INPUT', 'baseAddress exceeds the unsigned 64-bit address range')
    }
    const { bytes, source } = await readAuditInput(args, security, MCP_TIMING_MAX_BYTES, 256, signal)
    const baseAddress = suppliedAddress ?? BigInt(source.offset ?? 0)
    if (baseAddress + BigInt(bytes.length - 1) > 0xffffffffffffffffn) throw new BitpeekError('INVALID_RANGE', 'Code range exceeds the unsigned 64-bit address range')
    const audit = ConstantTimeAuditor.auditBytes(bytes, { arch, baseAddress, maxInstructions })
    payload = {
      ...audit, arch, baseAddress: `0x${baseAddress.toString(16)}`, source,
      verificationScope: 'static-instruction-patterns', constantTimeProven: false,
      suspiciousInstructions: audit.suspiciousInstructions.map(finding => ({
        ...finding, address: `0x${(baseAddress + BigInt(finding.offset)).toString(16)}`,
        ...(source.offset !== undefined ? { fileOffset: source.offset + finding.offset } : {}),
      })),
    }
  }
  return { structuredContent: payload, content: [{ type: 'text', text: JSON.stringify(payload) }] }
}
