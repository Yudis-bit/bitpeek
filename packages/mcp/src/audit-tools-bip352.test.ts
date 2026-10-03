import { readFileSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { SECP256K1_N as N, SECP256K1_P as P, SECP256K1_GX as GX } from '../../core/src/index'
import { createBitpeekMcpServer } from './server'
import { McpSecurityManager } from './security'

interface ReferenceOutput {
  comment: string
  spendPubKey: string
  tweak: string
  outputKey: string
  parity: number
}

const vectors = JSON.parse(readFileSync(new URL('../../core/src/bchain/fixtures/bip352-reference.json', import.meta.url), 'utf8')) as { outputs: ReferenceOutput[] }
const reference = vectors.outputs[0]
const argumentsFor = (vector: ReferenceOutput = reference): Record<string, unknown> => ({
  format: 'bip352-tweak', spendKeyHex: vector.spendPubKey, tweakHex: vector.tweak, rawHex: vector.outputKey,
})
const scalarHex = (value: bigint) => value.toString(16).padStart(64, '0')

describe('BIP-352 tweak verification over the MCP protocol', () => {
  let directory: string
  let client: Client
  let server: ReturnType<typeof createBitpeekMcpServer>
  let security: McpSecurityManager

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'bitpeek-bip352-mcp-'))
    security = new McpSecurityManager({ allowedInputRoots: [directory], allowedOutputRoots: [directory] })
    server = createBitpeekMcpServer(security)
    client = new Client({ name: 'bip352-protocol-tests', version: '1.0.0' })
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

  async function call(args: Record<string, unknown>, name = 'bitpeek_secp256k1_audit') {
    const response = CallToolResultSchema.parse(await client.callTool({ name, arguments: args }))
    const content = response.content.find(item => item.type === 'text')
    if (!content || content.type !== 'text') throw new Error('Missing MCP text response')
    const payload = response.isError ? undefined : response.structuredContent ?? JSON.parse(content.text) as Record<string, unknown>
    return { response, payload, text: content.text }
  }

  it('advertises the new format and key/scalar schemas alongside the existing formats', async () => {
    const { tools } = await client.listTools()
    const tool = tools.find(item => item.name === 'bitpeek_secp256k1_audit')!
    expect(tool.inputSchema.properties?.format).toMatchObject({ default: 'auto', enum: [
      'auto', 'pubkey', 'der', 'compact', 'bitcoin-tx', 'bip340-schnorr', 'dleq', 'taproot-tweak', 'bip352-tweak',
    ] })
    expect(tool.inputSchema.properties?.spendKeyHex).toMatchObject({ type: 'string', minLength: 64, maxLength: 66 })
    expect(tool.inputSchema.properties?.tweakHex).toMatchObject({ type: 'string', minLength: 64, maxLength: 64 })
    expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false })
    expect(tools).toHaveLength(17)
  })

  it.each([vectors.outputs.find(vector => vector.parity === 0)!, vectors.outputs.find(vector => vector.parity === 1)!])('returns PASS for a published output with parity $parity', async vector => {
    const { response, payload, text } = await call(argumentsFor(vector))
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ format: 'bip352-tweak', valid: true, status: 'PASS', parity: vector.parity,
      verificationScope: 'cryptographic-verification', cryptographicSignaturesVerified: false,
      source: { kind: 'hex', length: 32, sha256: expect.stringMatching(/^[a-f0-9]{64}$/) },
      summary: 'PASS: bip352-tweak verification succeeded' })
    expect(payload).not.toHaveProperty('rejectionReason')
    expect(JSON.parse(text)).toEqual(payload)
    expect(response.structuredContent).toEqual(payload)
  })

  it('accepts an x-only even-Y spend key and uppercase hex', async () => {
    const { payload } = await call({ ...argumentsFor(), spendKeyHex: reference.spendPubKey.slice(2).toUpperCase(), tweakHex: reference.tweak.toUpperCase() })
    expect(payload).toMatchObject({ valid: true, status: 'PASS', parity: reference.parity })
  })

  it('preserves compressed odd-Y spend-key semantics', async () => {
    const odd = vectors.outputs.find(vector => vector.spendPubKey.startsWith('03'))!
    expect((await call(argumentsFor(odd))).payload).toMatchObject({ valid: true, parity: odd.parity })
    expect((await call({ ...argumentsFor(odd), spendKeyHex: odd.spendPubKey.slice(2) })).payload).toMatchObject({ valid: false, status: 'FAIL', rejectionReason: 'Output key mismatch' })
  })

  it('returns FAIL with derived parity and a rejection reason for output mismatch', async () => {
    const damaged = Buffer.from(reference.outputKey, 'hex')
    damaged[31] ^= 1
    const { response, payload, text } = await call({ ...argumentsFor(), rawHex: damaged.toString('hex') })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', parity: reference.parity, reason: 'Output key mismatch', rejectionReason: 'Output key mismatch',
      summary: 'FAIL: bip352-tweak Output key mismatch', cryptographicSignaturesVerified: false })
    expect(JSON.parse(text)).toEqual(payload)
  })

  it.each([0n, N, N + 1n])('returns mathematical FAIL for noncanonical scalar %s', async tweak => {
    const { response, payload } = await call({ ...argumentsFor(), tweakHex: scalarHex(tweak) })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', parity: -1, rejectionReason: 'Tweak scalar outside valid range (0 < t < n)' })
  })

  it.each(['00'.repeat(32), `02${scalarHex(P)}`, `04${scalarHex(GX)}`])('returns mathematical FAIL for invalid spend point %s', async spendKeyHex => {
    const { response, payload } = await call({ ...argumentsFor(), spendKeyHex })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', parity: -1, rejectionReason: 'Invalid spend public key' })
  })

  it('returns FAIL when the tweak cancels the spend point', async () => {
    const { response, payload } = await call({ format: 'bip352-tweak', spendKeyHex: `02${scalarHex(GX)}`, tweakHex: scalarHex(N - 1n), rawHex: scalarHex(GX) })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', parity: -1, rejectionReason: 'Tweaked point is point at infinity' })
  })

  it.each([31, 33, 64])('returns FAIL when the expected output has %s bytes', async length => {
    const { response, payload } = await call({ ...argumentsFor(), rawHex: '01'.repeat(length) })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', parity: -1, rejectionReason: 'Expected output key must be 32 bytes' })
  })

  it('verifies an authorized exact file range and retains source metadata', async () => {
    const path = join(directory, 'expected-output.bin')
    await writeFile(path, Buffer.from(`0000${reference.outputKey}0000`, 'hex'))
    const opened = await call({ filePath: path }, 'bitpeek_open')
    const { rawHex: _rawHex, ...parameters } = argumentsFor()
    const { response, payload, text } = await call({ ...parameters, handle: opened.payload?.handle, offset: 2, length: 32 })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: true, status: 'PASS', parity: reference.parity, source: { kind: 'session', offset: 2, length: 32 } })
    expect(JSON.parse(text)).toEqual(payload)
  })

  it.each([
    { spendKeyHex: undefined }, { tweakHex: undefined }, { spendKeyHex: null }, { tweakHex: 1 },
    { spendKeyHex: '' }, { tweakHex: '' }, { spendKeyHex: 'gg'.repeat(32) }, { tweakHex: 'gg'.repeat(32) },
    { spendKeyHex: '01'.repeat(31) }, { spendKeyHex: '01'.repeat(34) },
    { tweakHex: '01'.repeat(31) }, { tweakHex: '01'.repeat(33) },
    { spendKeyHex: `0x${reference.spendPubKey}` }, { spendKeyHex: `${reference.spendPubKey} ` },
    { spendKeyHex: '01'.repeat(32) + '0' }, { spendKeyHex: Array(33).fill('01').join(' ') },
    { tweakHex: `0x${reference.tweak}` }, { tweakHex: Array(32).fill('01').join(' ') },
  ])('rejects missing or malformed key/scalar parameters %j', async args => {
    const { response, text } = await call({ ...argumentsFor(), ...args })
    expect(response.isError).toBe(true)
    expect(text).toMatch(/spendKeyHex|tweakHex/)
  })

  it.each(['pubkeyHex', 'internalKeyHex', 'merkleRootHex', 'messageHex', 'expectedParity'])('rejects unrelated verification parameter %s', async name => {
    const { response, text } = await call({ ...argumentsFor(), [name]: name === 'expectedParity' ? 0 : '00'.repeat(32) })
    expect(response.isError).toBe(true)
    expect(text).toContain(`${name} is not supported for format bip352-tweak`)
  })

  it.each(['auto', 'pubkey', 'der', 'compact', 'bitcoin-tx', 'bip340-schnorr', 'dleq', 'taproot-tweak'])('rejects Silent Payments parameters for existing format %s', async format => {
    const { response, text } = await call({ ...argumentsFor(), format })
    expect(response.isError).toBe(true)
    expect(text).toContain(`spendKeyHex is not supported for format ${format}`)
  })

  it('rejects Silent Payments parameters on the timing tool', async () => {
    expect((await call({ rawHex: '90', spendKeyHex: reference.spendPubKey, tweakHex: reference.tweak }, 'bitpeek_constant_time_audit')).response.isError).toBe(true)
  })
})
