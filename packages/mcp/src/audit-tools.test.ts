import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { createBitpeekMcpServer } from './server'
import { McpSecurityManager } from './security'
import { callAuditTool } from './audit-tools'
import {
  auditSecp256k1, FileByteSource, SECP256K1_AUDIT_RECIPE, SECP256K1_P, SECP256K1_N,
} from '../../core/src/index'

const KEY_HEX = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const HIGH_S_HEX = `3026020101022100${(SECP256K1_N - 1n).toString(16)}`

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('Expected a JSON object')
  return value as Record<string, unknown>
}

async function call(client: Client, name: string, args: Record<string, unknown>) {
  const response = CallToolResultSchema.parse(await client.callTool({ name, arguments: args }))
  const content = response.content.find(item => item.type === 'text')
  if (!content || content.type !== 'text') throw new Error('Missing MCP text response')
  return { response, text: content.text, payload: response.isError ? undefined : record(JSON.parse(content.text)) }
}

describe('MCP audit tools over the SDK protocol transport', () => {
  let directory: string
  let client: Client
  let server: ReturnType<typeof createBitpeekMcpServer>
  let security: McpSecurityManager

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'bitpeek-audit-mcp-'))
    security = new McpSecurityManager({ allowedInputRoots: [directory], allowedOutputRoots: [directory] })
    server = createBitpeekMcpServer(security)
    client = new Client({ name: 'audit-protocol-tests', version: '1.0.0' })
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    await server.connect(serverTransport)
    await client.connect(clientTransport)
  })

  afterEach(async () => {
    vi.restoreAllMocks()
    await client.close()
    await server.close()
    security.closeAll()
    await rm(directory, { recursive: true, force: true })
  })

  async function open(bytes: Uint8Array): Promise<{ handle: string; path: string }> {
    const path = join(directory, 'input.bin')
    await writeFile(path, bytes)
    const { payload } = await call(client, 'bitpeek_open', { filePath: path })
    if (typeof payload?.handle !== 'string') throw new Error('Missing session handle')
    return { handle: payload.handle, path }
  }

  it('advertises both read-only audit tools, schemas, and capabilities to an MCP client', async () => {
    const listed = await client.listTools()
    expect(listed.tools).toHaveLength(17)
    for (const name of ['bitpeek_secp256k1_audit', 'bitpeek_constant_time_audit']) {
      const tool = listed.tools.find(item => item.name === name)
      expect(tool?.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false })
      expect(tool?.inputSchema.oneOf).toHaveLength(2)
      expect(tool?.inputSchema.additionalProperties).toBe(false)
    }
    const { payload } = await call(client, 'bitpeek_capabilities', {})
    expect(payload?.auditTools).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'bitpeek_secp256k1_audit' }),
      expect.objectContaining({ name: 'bitpeek_constant_time_audit' }),
    ]))
    expect(payload?.limits).toMatchObject({ maxSecp256k1AuditBytes: 1048576, maxConstantTimeAuditBytes: 65536, maxConstantTimeAuditInstructions: 10000 })
  })

  it('returns exact JSON-safe core public key results as text and structuredContent', async () => {
    const { response, payload } = await call(client, 'bitpeek_secp256k1_audit', { rawHex: KEY_HEX })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject(auditSecp256k1(Uint8Array.from(Buffer.from(KEY_HEX, 'hex'))))
    expect(response.structuredContent).toEqual(payload)
    expect(payload?.source).toMatchObject({ kind: 'hex', length: 33, sha256: expect.stringMatching(/^[a-f0-9]{64}$/) })
  })

  it.each([
    [HIGH_S_HEX, 'high-s', 'warning'],
    [`02${SECP256K1_P.toString(16)}`, 'field-overflow', 'critical'],
    [`${SECP256K1_N.toString(16)}${'0'.repeat(63)}1`, 'scalar-overflow', 'critical'],
    ['00'.repeat(32), 'invalid-point', 'critical'],
  ])('returns audit findings without treating them as MCP call failures', async (rawHex, code, severity) => {
    const { response, payload } = await call(client, 'bitpeek_secp256k1_audit', { rawHex })
    expect(response.isError).toBeUndefined()
    expect(payload?.findings).toEqual(expect.arrayContaining([expect.objectContaining({ code, severity })]))
  })

  it('honors explicit format for ambiguous compact and DER bytes', async () => {
    const { payload } = await call(client, 'bitpeek_secp256k1_audit', { rawHex: '30' + '00'.repeat(63), format: 'compact' })
    expect(payload?.format).toBe('compact')
    const derResult = await call(client, 'bitpeek_secp256k1_audit', { rawHex: '30' + '00'.repeat(63), format: 'der' })
    expect(derResult.payload?.format).toBe('der')
  })

  it('reads an exact file range and matches the inline audit result', async () => {
    const { handle } = await open(Uint8Array.from([255, ...Buffer.from(KEY_HEX, 'hex'), 255]))
    const { payload } = await call(client, 'bitpeek_secp256k1_audit', { handle, offset: 1, length: 33, format: 'pubkey' })
    expect(payload).toMatchObject(auditSecp256k1(Uint8Array.from(Buffer.from(KEY_HEX, 'hex')), 'pubkey'))
    expect(payload?.source).toMatchObject({ kind: 'session', handle, offset: 1, length: 33 })
  })

  it('audits a raw Bitcoin transaction over MCP', async () => {
    const raw = new Uint8Array(60)
    raw[0] = 2
    raw[4] = 1
    raw.fill(1, 5, 37)
    raw.fill(255, 42, 46)
    raw[46] = 1
    raw[47] = 1
    const { payload } = await call(client, 'bitpeek_secp256k1_audit', { rawHex: Buffer.from(raw).toString('hex'), format: 'bitcoin-tx' })
    expect(payload).toMatchObject({ format: 'bitcoin-tx', findings: [], cryptographicSignaturesVerified: false })
    expect(payload?.transaction).toMatchObject({ inputCount: 1, outputCount: 1, totalOutputSatoshis: '1', weightUnits: 240 })
  })

  it('runs the same built-in audit through the existing MCP recipe tool', async () => {
    const bytes = Uint8Array.from(Buffer.from(HIGH_S_HEX, 'hex'))
    const { handle } = await open(bytes)
    const { payload } = await call(client, 'bitpeek_run_recipe', { recipeJson: JSON.stringify(SECP256K1_AUDIT_RECIPE), inputs: { input: handle }, dryRun: true })
    expect(payload?.ok).toBe(true)
    expect(payload?.stepResults).toEqual([expect.objectContaining({
      operation: 'secp256k1.audit', status: 'success', outputValue: auditSecp256k1(bytes),
    })])
  })

  it('audits x86 branches and divisions with addresses beyond Number.MAX_SAFE_INTEGER', async () => {
    const { payload } = await call(client, 'bitpeek_constant_time_audit', { rawHex: '90740048f7f1c3', baseAddress: '0x8000000000000000' })
    expect(payload).toMatchObject({ arch: 'x86_64', hasConditionalBranches: true, branchCount: 1, isCleanConstantTime: false, constantTimeProven: false })
    expect(payload?.suspiciousInstructions).toEqual([
      expect.objectContaining({ offset: 1, mnemonic: 'je', address: '0x8000000000000001' }),
      expect.objectContaining({ offset: 3, mnemonic: 'div', address: '0x8000000000000003' }),
    ])
  })

  it('audits AArch64 machine code', async () => {
    const { payload } = await call(client, 'bitpeek_constant_time_audit', { rawHex: '000000542008c29a', arch: 'aarch64' })
    expect(payload?.branchCount).toBe(1)
    expect(payload?.suspiciousInstructions).toEqual([
      expect.objectContaining({ offset: 0, mnemonic: 'b.eq' }), expect.objectContaining({ offset: 4, mnemonic: 'udiv' }),
    ])
  })

  it('reports relative offsets, file offsets, and default/explicit base addresses', async () => {
    const { handle } = await open(Uint8Array.from([0, 0, 0x90, 0x74, 0, 0xc3]))
    const { payload } = await call(client, 'bitpeek_constant_time_audit', { handle, offset: 2, length: 4 })
    expect(payload?.baseAddress).toBe('0x2')
    expect(payload?.suspiciousInstructions).toEqual([expect.objectContaining({ offset: 1, fileOffset: 3, address: '0x3' })])
    const explicit = await call(client, 'bitpeek_constant_time_audit', { handle, offset: 2, length: 4, baseAddress: '4198400' })
    expect(explicit.payload?.suspiciousInstructions).toEqual([expect.objectContaining({ fileOffset: 3, address: '0x401001' })])
  })

  it('keeps unknown code and instruction-budget omissions out of clean results', async () => {
    for (const args of [{ rawHex: '00' }, { rawHex: '74' }, { rawHex: '90c3', maxInstructions: 1 }]) {
      const { payload } = await call(client, 'bitpeek_constant_time_audit', args)
      expect(payload?.isCleanConstantTime).toBe(false)
    }
    const clean = await call(client, 'bitpeek_constant_time_audit', { rawHex: '90c3' })
    expect(clean.payload).toMatchObject({ isCleanConstantTime: true, constantTimeProven: false })
  })

  it.each([
    {}, { rawHex: '' }, { rawHex: 'gg' }, { rawHex: '0' }, { rawHex: 1 },
    { handle: 123 }, { handle: '' }, { handle: 'sess_missing' },
    { rawHex: KEY_HEX, handle: 'sess_missing' }, { rawHex: KEY_HEX, offset: 0 },
    { rawHex: KEY_HEX, length: 33 }, { rawHex: KEY_HEX, format: 'schnorr' },
    { rawHex: KEY_HEX, filePath: 'input.bin' },
  ])('rejects invalid secp256k1 MCP arguments %j', async args => {
    const { response } = await call(client, 'bitpeek_secp256k1_audit', args)
    expect(response.isError).toBe(true)
  })

  it.each([
    { arch: 'arm64' }, { arch: 64 }, { baseAddress: '-1' }, { baseAddress: 1 },
    { baseAddress: '1.5' }, { baseAddress: '18446744073709551616' },
    { baseAddress: '0xffffffffffffffff' }, { maxInstructions: 0 }, { maxInstructions: 1.5 },
    { maxInstructions: 10001 }, { maxInstructions: '10' },
  ])('rejects invalid timing audit arguments %j', async args => {
    expect((await call(client, 'bitpeek_constant_time_audit', { rawHex: '90c3', ...args })).response.isError).toBe(true)
  })

  it('rejects invalid ranges without coercion or silent clipping', async () => {
    const { handle } = await open(new Uint8Array(34))
    for (const range of [{ offset: -1 }, { offset: 0.5 }, { offset: '0' }, { offset: 35 }, { offset: Number.MAX_SAFE_INTEGER + 1 }, { length: 0 }, { length: -1 }, { length: 1.5 }, { length: '1' }, { offset: 33, length: 2 }]) {
      expect((await call(client, 'bitpeek_secp256k1_audit', { handle, ...range })).response.isError).toBe(true)
    }
  })

  it('enforces byte limits for inline data and sessions while allowing bounded ranges in large files', async () => {
    expect((await call(client, 'bitpeek_constant_time_audit', { rawHex: '90'.repeat(65537) })).response.isError).toBe(true)
    const { handle } = await open(new Uint8Array(1048577))
    expect((await call(client, 'bitpeek_secp256k1_audit', { handle })).response.isError).toBe(true)
    expect((await call(client, 'bitpeek_secp256k1_audit', { handle, length: 32 })).response.isError).toBeUndefined()
    expect((await call(client, 'bitpeek_constant_time_audit', { handle, length: 65537 })).response.isError).toBe(true)
  })

  it('rejects closed sessions and files whose size changed after opening', async () => {
    const { handle, path } = await open(Uint8Array.from(Buffer.from(KEY_HEX, 'hex')))
    await writeFile(path, new Uint8Array(34))
    expect((await call(client, 'bitpeek_secp256k1_audit', { handle })).text).toContain('File size changed')
    await call(client, 'bitpeek_close', { handle })
    expect((await call(client, 'bitpeek_secp256k1_audit', { handle })).response.isError).toBe(true)
  })

  it('revalidates session paths against allowed roots on audit calls', async () => {
    const outside = await mkdtemp(join(tmpdir(), 'bitpeek-audit-outside-'))
    try {
      const path = join(outside, 'outside.bin')
      await writeFile(path, Uint8Array.from(Buffer.from(KEY_HEX, 'hex')))
      const handle = security.createSession(path, 33)
      expect((await call(client, 'bitpeek_secp256k1_audit', { handle })).text).toContain('Access denied')
    } finally { await rm(outside, { recursive: true, force: true }) }
  })

  it('closes the file when range validation fails and respects cancellation', async () => {
    const { handle, path } = await open(Uint8Array.from(Buffer.from(KEY_HEX, 'hex')))
    const file = await FileByteSource.open(path)
    const close = vi.spyOn(file, 'close')
    vi.spyOn(FileByteSource, 'open').mockResolvedValueOnce(file)
    expect((await call(client, 'bitpeek_secp256k1_audit', { handle, offset: 34 })).response.isError).toBe(true)
    expect(close).toHaveBeenCalledOnce()
    await expect(callAuditTool('bitpeek_secp256k1_audit', { rawHex: KEY_HEX }, security, AbortSignal.abort())).rejects.toThrow('cancelled')
  })
})

it('starts the installed MCP launcher with node and completes real stdio calls from an unrelated cwd', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'bitpeek-stdio-audit-'))
  const client = new Client({ name: 'stdio-audit-tests', version: '1.0.0' })
  const launcher = fileURLToPath(new URL('../bin/bitpeek-mcp.js', import.meta.url))
  const transport = new StdioClientTransport({ command: process.execPath, args: [launcher, '--allowed-roots', directory], cwd: directory, stderr: 'pipe' })
  let stderr = ''
  transport.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString() })
  try {
    await client.connect(transport)
    const tools = await client.listTools()
    expect(tools.tools).toHaveLength(17)
    const { payload } = await call(client, 'bitpeek_secp256k1_audit', { rawHex: HIGH_S_HEX })
    expect(payload?.findings).toEqual([expect.objectContaining({ code: 'high-s' })])
    const path = join(directory, 'code.bin')
    await writeFile(path, Uint8Array.from([0x90, 0x74, 0, 0xc3]))
    const opened = await call(client, 'bitpeek_open', { filePath: path })
    const timing = await call(client, 'bitpeek_constant_time_audit', { handle: opened.payload?.handle, length: 4 })
    expect(timing.payload?.branchCount).toBe(1)
    expect(stderr).toContain('Bitpeek MCP server running on stdio.')
  } finally {
    await client.close()
    await transport.close()
    await rm(directory, { recursive: true, force: true })
  }
}, 20000)
