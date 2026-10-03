import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { SECP256K1_GX, TAPROOT_CONTROL_MAX_SIZE, SECP256K1_AUDIT_MAX_BYTES } from '../../core/src/index'
import { callAuditTool } from './audit-tools'
import { createBitpeekMcpServer } from './server'
import { McpSecurityManager } from './security'

interface PublishedLeaf { id: number; script: string; leafVersion: number }
type PublishedTree = PublishedLeaf | [PublishedTree, PublishedTree]
interface WalletVector {
  given: { internalPubkey: string; scriptTree: PublishedTree | null }
  intermediary: { leafHashes?: string[]; merkleRoot: string | null; tweakedPubkey: string }
  expected: { scriptPathControlBlocks?: string[] }
}
const { scriptPubKey: vectors } = JSON.parse(readFileSync(new URL('../../core/src/bchain/fixtures/bip341-wallet-reference.json', import.meta.url), 'utf8')) as { scriptPubKey: WalletVector[] }
const gx = SECP256K1_GX.toString(16)
const x2 = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
function leaves(tree: PublishedTree): PublishedLeaf[] {
  return Array.isArray(tree) ? [...leaves(tree[0]), ...leaves(tree[1])] : [tree]
}
function shape(tree: PublishedTree): unknown {
  return Array.isArray(tree) ? [shape(tree[0]), shape(tree[1])] : tree.id
}
const published = vectors.flatMap((vector, vectorIndex) => vector.given.scriptTree === null ? []
  : leaves(vector.given.scriptTree).map(leaf => ({ vector, vectorIndex, leaf, leafIndex: leaf.id })))
const verifyArguments = (vector = vectors[5]!, leafIndex = 1): Record<string, unknown> => ({ format: 'taproot-control-block',
  rawHex: vector.intermediary.tweakedPubkey, controlBlockHex: vector.expected.scriptPathControlBlocks![leafIndex],
  leafScriptHex: leaves(vector.given.scriptTree!).find(leaf => leaf.id === leafIndex)!.script })
const buildArguments = (): Record<string, unknown> => ({ format: 'taptree-builder', internalKeyHex: gx, scriptHexes: ['51', '52'] })

describe('Taproot tree, script-commitment and key audits over MCP', () => {
  let directory: string
  let security: McpSecurityManager
  let client: Client
  let server: ReturnType<typeof createBitpeekMcpServer>

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'bitpeek-taproot-mcp-'))
    security = new McpSecurityManager({ allowedInputRoots: [directory], allowedOutputRoots: [directory] })
    server = createBitpeekMcpServer(security)
    client = new Client({ name: 'taproot-protocol-tests', version: '1.0.0' })
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
    if (payload) expect(JSON.parse(content.text)).toEqual(payload)
    return { response, payload, text: content.text }
  }

  it('advertises the additive formats and script, proof, key and custom-tree inputs', async () => {
    const { tools } = await client.listTools()
    expect(tools).toHaveLength(17)
    const tool = tools.find(item => item.name === 'bitpeek_secp256k1_audit')!
    expect(tool.inputSchema.properties?.format).toMatchObject({ enum: expect.arrayContaining([
      'bip340-sign', 'bip352-scan', 'taproot-control-block', 'tapscript-keys', 'taptree-builder',
    ]) })
    expect(tool.inputSchema.properties?.controlBlockHex).toMatchObject({ type: 'string', minLength: 66, maxLength: TAPROOT_CONTROL_MAX_SIZE * 3 })
    expect(tool.inputSchema.properties?.scriptHexes).toMatchObject({ type: 'array', minItems: 1 })
    expect(tool.inputSchema.properties?.keysHex).toMatchObject({ type: 'array' })
    expect(tool.inputSchema.properties?.keySize).toMatchObject({ enum: [32, 33], default: 32 })
    expect(tool.inputSchema.properties?.treeStructure).toMatchObject({ $ref: '#/$defs/tapTreeStructure' })
    expect(tool.inputSchema.oneOf).toEqual(expect.arrayContaining([
      expect.objectContaining({ required: ['format', 'keysHex'] }),
      expect.objectContaining({ required: ['format', 'internalKeyHex', 'scriptHexes'] }),
    ]))
  })

  it.each(published)('verifies published control block vector $vectorIndex leaf $leafIndex with JSON-safe fields', async ({ vector, leaf }) => {
    const { response, payload } = await call(verifyArguments(vector, leaf.id))
    const control = Buffer.from(vector.expected.scriptPathControlBlocks![leaf.id]!, 'hex')
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ format: 'taproot-control-block', valid: true, status: 'PASS',
      leafVersion: leaf.leafVersion, outputParity: control[0]! & 1, pathLength: (control.length - 33) / 32,
      internalKeyHex: vector.given.internalPubkey, merkleRootHex: vector.intermediary.merkleRoot,
      computedOutputKeyHex: vector.intermediary.tweakedPubkey,
      verificationScope: 'taproot-script-commitment', cryptographicSignaturesVerified: false,
      source: { kind: 'hex', length: 32, sha256: createHash('sha256').update(Buffer.from(vector.intermediary.tweakedPubkey, 'hex')).digest('hex') } })
  })

  it.each([
    { field: 'leafScriptHex', byte: 0, reason: 'Computed Taproot output key X does not match expected outputKey32' },
    { field: 'controlBlockHex', byte: 33, reason: 'Computed Taproot output key X does not match expected outputKey32' },
    { field: 'controlBlockHex', byte: 0, reason: 'Computed Taproot output key Y parity does not match control block header parity' },
    { field: 'rawHex', byte: 31, reason: 'Computed Taproot output key X does not match expected outputKey32' },
  ])('rejects a single-byte $field mutation at byte $byte', async ({ field, byte, reason }) => {
    const args = verifyArguments()
    const changed = Buffer.from(args[field] as string, 'hex')
    changed[byte] = changed[byte]! ^ 1
    const { response, payload } = await call({ ...args, [field]: changed.toString('hex') })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', reason, cryptographicSignaturesVerified: false })
  })

  it.each(vectors.filter(vector => vector.given.scriptTree !== null))('builds the published tree for $given.internalPubkey', async vector => {
    const originalTree = vector.given.scriptTree!
    const originalLeaves = leaves(originalTree).sort((a, b) => a.id - b.id)
    const { response, payload } = await call({ format: 'taptree-builder', internalKeyHex: vector.given.internalPubkey,
      scriptHexes: originalLeaves.map(leaf => leaf.script), leafVersions: originalLeaves.map(leaf => leaf.leafVersion), treeStructure: shape(originalTree) })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: true, status: 'PASS', merkleRootHex: vector.intermediary.merkleRoot,
      outputKeyHex: vector.intermediary.tweakedPubkey, cryptographicSignaturesVerified: false, verificationScope: 'taproot-tree-construction' })
    const builtLeaves = payload?.leaves as Array<Record<string, unknown>>
    expect(builtLeaves.map(leaf => leaf.controlBlockHex)).toEqual(vector.expected.scriptPathControlBlocks)
    expect(builtLeaves.map(leaf => leaf.leafHashHex)).toEqual(vector.intermediary.leafHashes)
  })

  it('round-trips generated control blocks, including an empty script, into commitment verification', async () => {
    const { payload } = await call({ ...buildArguments(), scriptHexes: ['', '51', '52'] })
    expect(payload).toMatchObject({ valid: true, outputKeyHex: expect.stringMatching(/^[0-9a-f]{64}$/) })
    for (const leaf of payload?.leaves as Array<Record<string, unknown>>) {
      const verified = await call({ format: 'taproot-control-block', rawHex: payload?.outputKeyHex,
        controlBlockHex: leaf.controlBlockHex, leafScriptHex: leaf.scriptHex })
      expect(verified.payload).toMatchObject({ valid: true, status: 'PASS', merkleRootHex: payload?.merkleRootHex })
    }
  })

  it('reports parity collisions and duplicate canonical groups as WARN, independently of input validity', async () => {
    const { payload } = await call({ format: 'tapscript-keys', keysHex: [`02${gx}`, `03${gx}`, x2, x2] })
    expect(payload).toMatchObject({ valid: true, status: 'WARN', totalKeysExamined: 4, uniqueXOnlyKeys: 2,
      hasParityCollisions: true, hasDuplicateXOnly: true, verificationScope: 'tapscript-key-canonicalization', cryptographicSignaturesVerified: false })
    expect((payload?.findings as Array<Record<string, unknown>>).map(finding => finding.code)).toEqual(['parity-collision', 'duplicate-xonly'])
  })

  it('returns clean key audits for distinct keys and an empty list', async () => {
    expect((await call({ format: 'tapscript-keys', keysHex: [gx, x2] })).payload)
      .toMatchObject({ valid: true, status: 'PASS', uniqueXOnlyKeys: 2, findings: [] })
    expect((await call({ format: 'tapscript-keys', keysHex: [] })).payload)
      .toMatchObject({ valid: true, status: 'PASS', totalKeysExamined: 0, source: { length: 0 } })
  })

  it.each(['', '00'.repeat(32), '04' + gx, '00'.repeat(65)])('reports invalid key encoding %s as an audit finding', async key => {
    const { response, payload } = await call({ format: 'tapscript-keys', keysHex: [key] })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', uniqueXOnlyKeys: 0,
      findings: [{ severity: 'warning', code: 'invalid-key' }] })
  })

  it('audits packed x-only keys with default width and compressed keys with explicit width', async () => {
    expect((await call({ format: 'tapscript-keys', rawHex: gx + gx })).payload)
      .toMatchObject({ valid: true, status: 'WARN', totalKeysExamined: 2, hasDuplicateXOnly: true })
    expect((await call({ format: 'tapscript-keys', keySize: 33, rawHex: `02${gx}03${gx}` })).payload)
      .toMatchObject({ valid: true, status: 'WARN', totalKeysExamined: 2, hasParityCollisions: true })
  })

  it('accepts authorized exact file ranges for all three formats', async () => {
    const vector = vectors[3]!
    const path = join(directory, 'taproot-inputs.bin')
    await writeFile(path, Buffer.from(`0000${vector.given.internalPubkey}${vector.intermediary.tweakedPubkey}02${gx}03${gx}`, 'hex'))
    const opened = await call({ filePath: path }, 'bitpeek_open')
    const originalLeaves = leaves(vector.given.scriptTree!)
    const built = await call({ format: 'taptree-builder', handle: opened.payload?.handle, offset: 2, length: 32,
      scriptHexes: originalLeaves.map(leaf => leaf.script), leafVersions: originalLeaves.map(leaf => leaf.leafVersion) })
    expect(built.payload).toMatchObject({ valid: true, merkleRootHex: vector.intermediary.merkleRoot, source: { kind: 'session', offset: 2, length: 32 } })
    const { rawHex: _raw, ...verificationArgs } = verifyArguments(vector, 0)
    expect((await call({ ...verificationArgs, handle: opened.payload?.handle, offset: 34, length: 32 })).payload)
      .toMatchObject({ valid: true, source: { kind: 'session', offset: 34, length: 32 } })
    expect((await call({ format: 'tapscript-keys', handle: opened.payload?.handle, offset: 66, length: 66, keySize: 33 })).payload)
      .toMatchObject({ valid: true, status: 'WARN', hasParityCollisions: true, source: { kind: 'session', offset: 66, length: 66 } })
  })

  it('returns mathematical FAIL results for malformed control blocks and short output keys', async () => {
    expect((await call({ ...verifyArguments(), controlBlockHex: '00'.repeat(34) })).payload)
      .toMatchObject({ valid: false, status: 'FAIL', reason: 'Control block size must be 33 + 32*m bytes' })
    expect((await call({ ...verifyArguments(), controlBlockHex: 'c0' + '00'.repeat(32) })).payload)
      .toMatchObject({ valid: false, status: 'FAIL', reason: 'Invalid internal key X coordinate (not on curve or >= p)' })
    expect((await call({ ...verifyArguments(), rawHex: '00'.repeat(31) })).payload)
      .toMatchObject({ valid: false, status: 'FAIL', reason: 'Output key must be 32 bytes' })
  })

  it.each([
    { controlBlockHex: undefined }, { leafScriptHex: undefined }, { controlBlockHex: 'gg' },
    { leafScriptHex: '0' }, { controlBlockHex: '00'.repeat(TAPROOT_CONTROL_MAX_SIZE + 32) },
    { internalKeyHex: gx },
  ])('rejects malformed or unrelated commitment arguments %j', async override => {
    expect((await call({ ...verifyArguments(), ...override })).response.isError).toBe(true)
  })

  it.each([
    { internalKeyHex: undefined }, { internalKeyHex: null }, { internalKeyHex: '00'.repeat(32) },
    { scriptHexes: undefined }, { scriptHexes: null }, { scriptHexes: [] }, { scriptHexes: [null] }, { scriptHexes: ['0'] },
    { leafVersions: null }, { leafVersions: [192] }, { leafVersions: [192, 193] }, { leafVersions: [-2, 192] },
    { leafVersions: [256, 192] }, { leafVersions: ['192', 192] },
    { treeStructure: null }, { treeStructure: [0, 0] }, { treeStructure: [0, 2] }, { treeStructure: [0] },
    { rawHex: gx }, { offset: 0 }, { pubkeyHex: gx },
  ])('rejects malformed, conflicting or incomplete builder arguments %j', async override => {
    expect((await call({ ...buildArguments(), ...override })).response.isError).toBe(true)
  })

  it.each([
    { keysHex: undefined }, { keysHex: null }, { keysHex: [null] }, { keysHex: ['gg'] },
    { rawHex: gx }, { keySize: 33 }, { offset: 0 }, { messageHex: gx },
  ])('rejects malformed or conflicting key-array arguments %j', async override => {
    expect((await call({ format: 'tapscript-keys', keysHex: [gx], ...override })).response.isError).toBe(true)
  })

  it.each([31, 34, '33', null])('rejects invalid packed key width %s', async keySize => {
    expect((await call({ format: 'tapscript-keys', rawHex: gx, keySize })).response.isError).toBe(true)
  })

  it('rejects packed key inputs with an incomplete final key', async () => {
    expect((await call({ format: 'tapscript-keys', rawHex: gx + '00' })).text).toContain('multiple of keySize (32)')
  })

  it('enforces array count and combined script byte limits', async () => {
    const tooMany = Array(SECP256K1_AUDIT_MAX_BYTES / 32 + 1).fill('')
    expect((await call({ ...buildArguments(), scriptHexes: tooMany })).text).toContain('audit array size limit')
    expect((await call({ format: 'tapscript-keys', keysHex: tooMany })).text).toContain('audit array size limit')
    const script = '51'.repeat(SECP256K1_AUDIT_MAX_BYTES / 2 + 1)
    expect((await call({ ...buildArguments(), scriptHexes: [script, script] })).text).toContain('combined bytes exceed the audit size limit')
  })

  it('keeps new parameters isolated from existing audit formats and the timing tool', async () => {
    expect((await call({ format: 'pubkey', rawHex: `02${gx}`, keysHex: [gx] })).text).toContain('keysHex is not supported for format pubkey')
    expect((await call({ rawHex: '90', scriptHexes: ['51'] }, 'bitpeek_constant_time_audit')).text).toContain('Unsupported audit argument: scriptHexes')
  })

  it('honors cancellation for direct builders and key audits', async () => {
    const controller = new AbortController()
    controller.abort()
    for (const args of [buildArguments(), { format: 'tapscript-keys', keysHex: [gx] }]) {
      await expect(callAuditTool('bitpeek_secp256k1_audit', args, security, controller.signal)).rejects.toMatchObject({ code: 'CANCELLED' })
    }
  })
})
