import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { createBitpeekMcpServer } from './server'
import { McpSecurityManager } from './security'

describe('constant-time secret taint verification over MCP', () => {
  let directory: string
  let client: Client
  let server: ReturnType<typeof createBitpeekMcpServer>
  let security: McpSecurityManager

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'bitpeek-taint-audit-'))
    security = new McpSecurityManager({ allowedInputRoots: [directory], allowedOutputRoots: [directory] })
    server = createBitpeekMcpServer(security)
    client = new Client({ name: 'taint-audit-tests', version: '1.0.0' })
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    await server.connect(serverTransport)
    await client.connect(clientTransport)
  })

  afterEach(async () => {
    await client.close()
    await server.close()
    security.closeAll()
    await rm(directory, { recursive: true, force: true })
  })

  async function call(args: Record<string, unknown>, name = 'bitpeek_constant_time_audit') {
    const response = CallToolResultSchema.parse(await client.callTool({ name, arguments: args }))
    const content = response.content.find(item => item.type === 'text')
    if (!content || content.type !== 'text') throw new Error('Missing MCP text response')
    const payload = response.isError ? undefined : response.structuredContent ?? JSON.parse(content.text) as Record<string, unknown>
    return { response, text: content.text, payload }
  }

  it('advertises the optional array of secret register names', async () => {
    const { tools } = await client.listTools()
    const audit = tools.find(tool => tool.name === 'bitpeek_constant_time_audit')!
    expect(audit.inputSchema.properties?.secretRegisters).toMatchObject({ type: 'array', items: { type: 'string' }, description: expect.stringContaining('symbolic taint') })
    expect(audit.inputSchema.required ?? []).not.toContain('secretRegisters')
    expect(audit.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false })
  })

  it('verifies a clean secret-handling sequence and returns JSON-safe trace data', async () => {
    const { response, payload, text } = await call({ rawHex: '4889f8c3', secretRegisters: ['rdi'] })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ isCleanConstantTime: true, constantTimeProven: false, verificationScope: 'static-instruction-patterns',
      taintAnalysis: { isProvablyConstantTime: true, hasViolations: false, activeTaints: ['rdi', 'rax'], violations: [], trace: [
        { offset: 0, mnemonic: 'mov', operands: 'rax, rdi', taintedInputs: ['rdi'], taintedOutputs: ['rax'] },
        { offset: 3, mnemonic: 'ret', operands: '', taintedInputs: [], taintedOutputs: [] },
      ] } })
    expect(JSON.parse(text)).toEqual(payload)
  })

  it('reports a secret compare/branch chain with precise relative and bigint addresses', async () => {
    const { response, payload, text } = await call({ rawHex: '4889f84883f8007400c3', secretRegisters: ['rdi'], baseAddress: '0x8000000000000000' })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ isCleanConstantTime: false, branchCount: 1, taintAnalysis: {
      isProvablyConstantTime: false, hasViolations: true, activeTaints: ['rdi', 'rax', 'rflags'],
      violations: [{ offset: 7, mnemonic: 'je', category: 'BRANCH', severity: 'CRITICAL', address: '0x8000000000000007',
        reason: 'Conditional branch depends on secret-tainted flags; violates constant-time non-interference.' }],
    } })
    expect(JSON.parse(text)).toEqual(payload)
  })

  it('makes the overall clean flag false for a leak missed by the existing heuristic', async () => {
    const rawHex = '4889f8488b10'
    expect((await call({ rawHex })).payload?.isCleanConstantTime).toBe(true)
    const { payload } = await call({ rawHex, secretRegisters: ['rdi'], checkMemoryLookups: false })
    expect(payload).toMatchObject({ isCleanConstantTime: false, hasCacheTimingHazards: true, taintAnalysis: { isProvablyConstantTime: false, hasViolations: true,
      violations: [{ offset: 3, mnemonic: 'mov', operands: 'rdx, [rax]', category: 'CACHE_TIMING', severity: 'CRITICAL' }] } })
  })

  it('normalizes whitespace, case, aliases and duplicate secret sources', async () => {
    const { payload } = await call({ rawHex: '4889f84883f8007400', secretRegisters: [' EDI ', 'RDI'] })
    expect(payload).toMatchObject({ taintAnalysis: { activeTaints: ['rdi', 'rax', 'rflags'], hasViolations: true } })
  })

  it('retains the exact legacy response when secrets are omitted or empty', async () => {
    const args = { rawHex: '4889f87400' }
    const legacy = await call(args)
    const empty = await call({ ...args, secretRegisters: [] })
    expect(empty.payload).toEqual(legacy.payload)
    expect(empty.payload).not.toHaveProperty('taintAnalysis')
    expect(legacy.payload).not.toHaveProperty('taintAnalysis')
  })

  it('keeps public branches in the legacy audit while reporting no secret dependency', async () => {
    const { payload } = await call({ rawHex: '7400', secretRegisters: ['rdi'] })
    expect(payload).toMatchObject({ isCleanConstantTime: false, branchCount: 1,
      taintAnalysis: { isProvablyConstantTime: true, hasViolations: false, violations: [] } })
  })

  it('reports secret shift counts and implicit division inputs', async () => {
    for (const args of [{ rawHex: '48d3e0', secretRegisters: ['ecx'] }, { rawHex: '48f7f1', secretRegisters: ['rax'] }]) {
      expect((await call(args)).payload).toMatchObject({ isCleanConstantTime: false,
        taintAnalysis: { hasViolations: true, violations: [{ category: 'VARIABLE_LATENCY', severity: 'HIGH' }] } })
    }
  })

  it('tracks real decoded stack spill and reload dependencies', async () => {
    const { payload } = await call({ rawHex: '48897c2408488b4424084883f8007400', secretRegisters: ['rdi'] })
    expect(payload).toMatchObject({ taintAnalysis: { hasViolations: true,
      activeTaints: expect.arrayContaining(['rsp+8', 'rax', 'rflags']),
      violations: [{ offset: 14, mnemonic: 'je', category: 'BRANCH' }] } })
  })

  it('verifies AArch64 public code with declared input secrets', async () => {
    const { payload } = await call({ rawHex: '1f2003d5c0035fd6', arch: 'aarch64', secretRegisters: ['x0'] })
    expect(payload).toMatchObject({ arch: 'aarch64', isCleanConstantTime: true,
      taintAnalysis: { isProvablyConstantTime: true, hasViolations: false, activeTaints: ['x0'], violations: [] } })
  })

  it('detects AArch64 direct register test branches using W/X aliases', async () => {
    const { payload } = await call({ rawHex: '000000b4', arch: 'aarch64', secretRegisters: [' W0 '] })
    expect(payload).toMatchObject({ isCleanConstantTime: false, taintAnalysis: { hasViolations: true,
      violations: [{ offset: 0, mnemonic: 'cbz', severity: 'CRITICAL', category: 'BRANCH', address: '0x0',
        reason: 'Direct register test branch depends on secret-tainted register.' }],
      trace: [{ taintedInputs: ['x0'], violation: { type: 'BRANCH_DEPENDENCY' } }] } })
  })

  it('detects secret AArch64 memory indices', async () => {
    const { payload } = await call({ rawHex: '206862f8', arch: 'aarch64', secretRegisters: ['x2'] })
    expect(payload).toMatchObject({ taintAnalysis: { hasViolations: true,
      violations: [{ category: 'CACHE_TIMING', severity: 'CRITICAL', operands: 'x0, [x1, x2]' }] } })
  })

  it('reports file offsets and high addresses for a selected session range', async () => {
    const path = join(directory, 'code.bin')
    await writeFile(path, Buffer.from('00004889f84883f8007400c3', 'hex'))
    const opened = await call({ filePath: path }, 'bitpeek_open')
    const { payload } = await call({ handle: opened.payload?.handle, offset: 2, length: 10, baseAddress: '0x8000000000000000', secretRegisters: ['rdi'] })
    expect(payload).toMatchObject({ source: { kind: 'session', offset: 2, length: 10 }, taintAnalysis: {
      hasViolations: true, violations: [{ offset: 7, fileOffset: 9, address: '0x8000000000000007' }] } })
  })

  it('keeps instruction-budget omissions out of provably clean results', async () => {
    const { payload } = await call({ rawHex: '904889f8', secretRegisters: ['rdi'], maxInstructions: 1 })
    expect(payload).toMatchObject({ isCleanConstantTime: false, taintAnalysis: { isProvablyConstantTime: false, hasViolations: true,
      trace: [{ offset: 0, mnemonic: 'nop' }], violations: [{ offset: 1, mnemonic: '<unexamined>', category: 'UNDECODED' }] } })
  })

  it.each(['00', '48', '4889'])('fails closed for unknown or truncated code %s', async rawHex => {
    expect((await call({ rawHex, secretRegisters: ['rdi'] })).payload).toMatchObject({ isCleanConstantTime: false,
      taintAnalysis: { isProvablyConstantTime: false, hasViolations: true, violations: expect.arrayContaining([expect.objectContaining({ category: 'UNDECODED' })]) } })
  })

  it.each([null, 'rdi', 1, [1], [''], ['  '], [null], [{}], [['rdi']], ['unknown'], ['x0']])('rejects malformed or unknown secretRegisters %j', async secretRegisters => {
    const { response, text } = await call({ rawHex: '90', secretRegisters })
    expect(response.isError).toBe(true)
    expect(text).toMatch(/secretRegisters|secret register/)
  })

  it('rejects the timing-only parameter for the secp256k1 audit', async () => {
    const { response } = await call({ rawHex: '00'.repeat(32), secretRegisters: ['rdi'] }, 'bitpeek_secp256k1_audit')
    expect(response.isError).toBe(true)
  })
})
