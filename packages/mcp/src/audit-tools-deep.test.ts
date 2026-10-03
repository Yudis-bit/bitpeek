import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { createBitpeekMcpServer } from './server'
import { McpSecurityManager } from './security'

const schnorr = {
  format: 'bip340-schnorr',
  pubkeyHex: 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
  messageHex: '00'.repeat(32),
  rawHex: 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0',
}
const taproot = {
  format: 'taproot-tweak',
  internalKeyHex: '187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27',
  merkleRootHex: '5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21',
  rawHex: '147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3',
}
const dleq = {
  format: 'dleq',
  g1Hex: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  p1Hex: '02637b2c3ea8ca80b9caecc50f4134c86ae9cf7a269133e7afc71f30e3a3cda60c',
  g2Hex: '034bccb1c570ac1f3bc42d61fe35de605b99626501ccb20297e1acbbf2d7152aa1',
  p2Hex: '0285b826c8dd175805901906b6c9b4140a30cbcc94c6e7dcf36476038bf90d4718',
  rawHex: '503562d36910cd2d61a4d07c8ff680265c713e63dde0dcb88e6ea3c58597bdc05b86db9af95eccc475ce2177f941c118fefed20227d4ce8ce9557cb008758de6',
}

describe('deep audits through MCP protocol calls', () => {
  let client: Client
  let server: ReturnType<typeof createBitpeekMcpServer>
  let security: McpSecurityManager
  let directory: string

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'bitpeek-deep-audit-'))
    security = new McpSecurityManager({ allowedInputRoots: [directory], allowedOutputRoots: [directory] })
    server = createBitpeekMcpServer(security)
    client = new Client({ name: 'deep-audit-tests', version: '1.0.0' })
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

  async function call(name: string, args: Record<string, unknown>) {
    const response = CallToolResultSchema.parse(await client.callTool({ name, arguments: args }))
    const content = response.content.find(item => item.type === 'text')
    if (!content || content.type !== 'text') throw new Error('Missing text response')
    const payload = response.isError ? undefined : response.structuredContent ?? JSON.parse(content.text) as Record<string, unknown>
    return { response, payload, text: content.text }
  }

  it('advertises new formats and default memory inspection', async () => {
    const { tools } = await client.listTools()
    const timing = tools.find(tool => tool.name === 'bitpeek_constant_time_audit')!
    expect(timing.inputSchema.properties?.checkMemoryLookups).toMatchObject({ type: 'boolean', default: true })
    const crypto = tools.find(tool => tool.name === 'bitpeek_secp256k1_audit')!
    expect(crypto.inputSchema.properties?.format).toMatchObject({ enum: expect.arrayContaining(['bip340-schnorr', 'dleq', 'taproot-tweak']) })
  })
  it.each([undefined, true])('returns structured indexed memory hazards when enabled (%s)', async checkMemoryLookups => {
    const { response, payload, text } = await call('bitpeek_constant_time_audit', {
      rawHex: '90488b04cb', baseAddress: '0x8000000000000000', ...(checkMemoryLookups === undefined ? {} : { checkMemoryLookups }),
    })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ checkMemoryLookups: true, hasCacheTimingHazards: true, hasVariableLatencyHazards: false, branchCount: 0, isCleanConstantTime: false, summary: expect.stringContaining('1 hazard') })
    expect(payload?.hazards).toEqual([expect.objectContaining({ offset: 1, address: '0x8000000000000001', mnemonic: 'mov', operands: 'rax, [rbx + rcx*8]', severity: 'HIGH', category: 'CACHE_TIMING' })])
    expect(JSON.parse(text)).toEqual(payload)
  })
  it('disables memory inspection while retaining branches and variable latency checks', async () => {
    const { payload } = await call('bitpeek_constant_time_audit', { rawHex: '488b04cb48d3e07400', checkMemoryLookups: false })
    expect(payload).toMatchObject({ hasCacheTimingHazards: false, hasVariableLatencyHazards: true, branchCount: 1, isCleanConstantTime: false })
    expect(payload?.hazards).toEqual([
      expect.objectContaining({ offset: 4, category: 'VARIABLE_LATENCY', operands: 'rax, cl', severity: 'WARN' }),
      expect.objectContaining({ offset: 7, category: 'BRANCH', severity: 'CRITICAL' }),
    ])
  })
  it('reports exact file offsets for a selected indexed memory range', async () => {
    const path = join(directory, 'code.bin')
    await writeFile(path, Buffer.from('000090488b04cb', 'hex'))
    const { payload: opened } = await call('bitpeek_open', { filePath: path })
    const { payload } = await call('bitpeek_constant_time_audit', { handle: opened?.handle, offset: 2, length: 5 })
    expect(payload?.hazards).toEqual([expect.objectContaining({ offset: 1, fileOffset: 3, address: '0x3' })])
  })
  it('reports ARM register-offset loads and undecoded byte spans', async () => {
    const { payload } = await call('bitpeek_constant_time_audit', { rawHex: '206862f800', arch: 'aarch64' })
    expect(payload?.hazards).toEqual([
      expect.objectContaining({ offset: 0, mnemonic: 'ldr', operands: 'x0, [x1, x2]', category: 'CACHE_TIMING' }),
      expect.objectContaining({ offset: 4, category: 'UNDECODED' }),
    ])
  })
  it('verifies a published BIP-340 signature with PASS and matching JSON content', async () => {
    const { response, payload, text } = await call('bitpeek_secp256k1_audit', schnorr)
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: true, status: 'PASS', cryptographicSignaturesVerified: true, verificationScope: 'cryptographic-verification', source: { length: 64 } })
    expect(JSON.parse(text)).toEqual(payload)
  })
  it('returns FAIL and the exact scalar overflow reason as an audit result', async () => {
    const { response, payload } = await call('bitpeek_secp256k1_audit', {
      ...schnorr, rawHex: schnorr.rawHex.slice(0, 64) + 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
    })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', reason: 's >= n', cryptographicSignaturesVerified: false, summary: 'FAIL: bip340-schnorr s >= n' })
  })
  it('verifies a signature read from an authorized file range', async () => {
    const path = join(directory, 'signature.bin')
    await writeFile(path, Buffer.from(`00${schnorr.rawHex}00`, 'hex'))
    const { payload: opened } = await call('bitpeek_open', { filePath: path })
    const { rawHex: _rawHex, ...parameters } = schnorr
    const { payload } = await call('bitpeek_secp256k1_audit', { ...parameters, handle: opened?.handle, offset: 1, length: 64 })
    expect(payload).toMatchObject({ valid: true, status: 'PASS', source: { kind: 'session', offset: 1, length: 64 } })
  })
  it('verifies BIP-374 proof and detects a changed share', async () => {
    expect((await call('bitpeek_secp256k1_audit', dleq)).payload).toMatchObject({ valid: true, status: 'PASS', cryptographicSignaturesVerified: false })
    expect((await call('bitpeek_secp256k1_audit', { ...dleq, p2Hex: dleq.p1Hex })).payload).toMatchObject({ valid: false, status: 'FAIL', reason: 'DLEQ challenge verification failed' })
  })
  it('verifies Taproot output, Merkle root and optional parity', async () => {
    expect((await call('bitpeek_secp256k1_audit', { ...taproot, expectedParity: 1 })).payload).toMatchObject({ valid: true, status: 'PASS', parity: 1 })
    expect((await call('bitpeek_secp256k1_audit', { ...taproot, expectedParity: 0 })).payload).toMatchObject({ valid: false, status: 'FAIL', parity: 1, reason: 'Taproot output Y parity mismatch' })
    expect((await call('bitpeek_secp256k1_audit', { ...taproot, rawHex: schnorr.pubkeyHex })).payload?.status).toBe('FAIL')
  })
  it.each([
    { ...schnorr, pubkeyHex: undefined }, { ...schnorr, messageHex: undefined },
    { ...schnorr, messageHex: 'gg'.repeat(32) }, { ...schnorr, pubkeyHex: 12 },
    { ...schnorr, g1Hex: dleq.g1Hex }, { ...dleq, g1Hex: schnorr.pubkeyHex },
    { ...dleq, p2Hex: '00'.repeat(33) }, { ...dleq, p2Hex: undefined },
    { ...taproot, expectedParity: 2 }, { ...taproot, expectedParity: '1' },
    { rawHex: dleq.g1Hex, format: 'pubkey', messageHex: schnorr.messageHex },
  ])('rejects missing, malformed or inapplicable crypto arguments %j', async args => {
    expect((await call('bitpeek_secp256k1_audit', args)).response.isError).toBe(true)
  })
  it.each([0, 'true', null])('rejects non-boolean checkMemoryLookups %s', async checkMemoryLookups => {
    expect((await call('bitpeek_constant_time_audit', { rawHex: '90', checkMemoryLookups })).response.isError).toBe(true)
  })
})
