import { readFileSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js'
import {
  SECP256K1_GX, SECP256K1_GY, SECP256K1_N as N, SECP256K1_P as P, SECP256K1_AUDIT_MAX_BYTES,
  Secp256k1Engine, scalarMul, compressedPoint, encodeSwiftEC, Bip324PacketCipher, deriveBip324SessionKeys,
} from '../../core/src/index'
import { callAuditTool } from './audit-tools'
import { createBitpeekMcpServer } from './server'
import { McpSecurityManager } from './security'

const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'))
const hex = (data: Uint8Array) => Buffer.from(data).toString('hex')
const be = (value: bigint) => value.toString(16).padStart(64, '0')
const G = { x: SECP256K1_GX, y: SECP256K1_GY }
const formats = ['tapscript-audit', 'tapscript-eval', 'bip375-audit', 'bip324-swift-ec', 'bip324-frame-audit', 'secp256k1-diff-oracle']
const swift = hex(encodeSwiftEC(G, bytes(be(1n))))
const keys = { lengthKey: bytes(be(1n)), payloadKey: bytes(be(2n)) }
const packet = hex(new Bip324PacketCipher(keys).encode(bytes('100102')))
const scan = scalarMul(5n, G)!, input = scalarMul(3n, G)!, share = scalarMul(3n, scan)!
const signer = { inputPubkeyHex: hex(compressedPoint(input)), ecdhShareHex: hex(compressedPoint(share)),
  dleqProofHex: hex(Secp256k1Engine.proveDLEQ(3n, G, input, scan, share)) }
const bip375 = { format: 'bip375-audit', signers: [signer], scanKeyHex: hex(compressedPoint(scan)), spendKeyHex: hex(compressedPoint(G)),
  outpointSmallestHex: '00'.repeat(36), allInputPubkeysHex: [signer.inputPubkeyHex] }
const { vectors } = JSON.parse(readFileSync(new URL('../../core/src/bchain/fixtures/bip340-signing-vectors.json', import.meta.url), 'utf8')) as {
  vectors: { publicKey: string; message: string; signature: string }[]
}
const vector = vectors[0]

describe('Phase 3/4/5 master formats through a live MCP client/server', () => {
  let directory: string, client: Client, server: ReturnType<typeof createBitpeekMcpServer>, security: McpSecurityManager
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'bitpeek-master-'))
    security = new McpSecurityManager({ allowedInputRoots: [directory], allowedOutputRoots: [directory] })
    server = createBitpeekMcpServer(security); client = new Client({ name: 'master-conformance-tests', version: '1.0.0' })
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    await server.connect(serverTransport); await client.connect(clientTransport)
  })
  afterAll(async () => {
    await client.close(); await server.close(); security.closeAll()
    await rm(directory, { recursive: true, force: true })
  })
  async function call(args: Record<string, unknown>) {
    const response = CallToolResultSchema.parse(await client.callTool({ name: 'bitpeek_secp256k1_audit', arguments: args }))
    const content = response.content.find(item => item.type === 'text')
    if (!content || content.type !== 'text') throw new Error('Missing response text')
    const payload = response.isError ? undefined : response.structuredContent ?? JSON.parse(content.text) as Record<string, unknown>
    if (payload) {
      expect(JSON.parse(content.text)).toEqual(payload)
      expect(payload.reportMarkdown).toEqual(expect.stringContaining(`**${payload.status}: ${args.format}**`))
    }
    return { response, payload, text: content.text }
  }
  async function fileSource(name: string, data: Uint8Array, offset = 0, length = data.length) {
    const path = join(directory, name)
    await writeFile(path, data)
    return { handle: security.createSession(await security.validateInputPath(path), data.length), offset, length }
  }
  it('advertises all new formats and strict share/witness/frame/oracle properties', async () => {
    const { tools } = await client.listTools(), tool = tools.find(tool => tool.name === 'bitpeek_secp256k1_audit')!
    expect(tool.inputSchema.properties?.format).toMatchObject({ enum: expect.arrayContaining(formats) })
    expect(tool.inputSchema.properties?.witnessHexes).toMatchObject({ type: 'array' })
    expect(tool.inputSchema.properties?.signers).toMatchObject({ type: 'array', items: { additionalProperties: false, required: ['inputPubkeyHex', 'ecdhShareHex', 'dleqProofHex'] } })
    expect(tool.inputSchema.properties?.swiftEcHex).toMatchObject({ minLength: 128, maxLength: 128 })
    expect(tool.inputSchema.properties?.diffOp).toMatchObject({ enum: expect.arrayContaining(['mul', 'add', 'doubling', 'inversion']) })
    expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false })
  })
  it.each([
    { format: 'tapscript-audit', leafScriptHex: '51' }, { format: 'tapscript-eval', leafScriptHex: '51' }, bip375,
    { format: 'bip324-swift-ec', swiftEcHex: swift }, { format: 'bip324-frame-audit', bip324PacketHex: packet, lengthKeyHex: be(1n), payloadKeyHex: be(2n) },
    { format: 'secp256k1-diff-oracle', diffOp: 'identities' },
  ])('returns JSON-safe structured output and Markdown for $format', async args => {
    const { response, payload } = await call(args)
    expect(response.isError).toBeUndefined(); expect(payload?.valid).toBe(true)
    expect(payload?.verificationScope).toEqual(expect.any(String))
  })
  it('reports an anyone-can-spend leaf as a warning and OP_RETURN as failure', async () => {
    expect((await call({ format: 'tapscript-audit', rawHex: '51' })).payload).toMatchObject({ status: 'WARN', hasAnyoneCanSpendPath: true })
    expect((await call({ format: 'tapscript-audit', rawHex: '6a' })).payload).toMatchObject({ status: 'FAIL', isPermanentlyUnspendable: true })
  })
  it('allows direct empty scripts and initial stacks', async () => {
    expect((await call({ format: 'tapscript-eval', leafScriptHex: '', witnessHexes: ['01'] })).payload).toMatchObject({ valid: true, finalStack: ['01'] })
  })
  it('verifies actual Schnorr signatures and charges the complete published witness budget', async () => {
    const { payload } = await call({ format: 'tapscript-eval', leafScriptHex: '20' + vector.publicKey + 'ac', witnessHexes: [vector.signature],
      messageHex: vector.message, profile: 'published-bip', serializedWitnessSize: 135, traceExecution: true })
    expect(payload).toMatchObject({ valid: true, profile: 'published-bip', budgetScope: 'serialized-witness', cryptographicSignaturesVerified: true,
      simulationMode: false, budgetRemaining: 135 })
    expect(payload?.trace).toEqual(expect.arrayContaining([expect.objectContaining({ opcodeName: 'OP_CHECKSIG' })]))
  })
  it('labels structural simulation and never claims cryptographic verification', async () => {
    const { payload } = await call({ format: 'tapscript-eval', rawHex: '20' + vector.publicKey + 'ac', witnessHexes: ['00'.repeat(64)], simulationMode: true })
    expect(payload).toMatchObject({ valid: true, simulationMode: true, cryptographicSignaturesVerified: false, verificationScope: 'tapscript-structural-simulation' })
  })
  it('fails a signature lacking its precomputed sighash context', async () => {
    expect((await call({ format: 'tapscript-eval', rawHex: '20' + vector.publicKey + 'ac', witnessHexes: [vector.signature] })).payload).toMatchObject({ valid: false, cryptographicSignaturesVerified: false })
  })
  it('bounds execution trace output', async () => {
    expect((await call({ format: 'tapscript-eval', rawHex: '61616151', traceExecution: true, traceLimit: 1 })).payload).toMatchObject({ valid: true, traceTruncated: true, trace: [expect.any(Object)] })
  })
  it('exposes real signer proof and output-fold verdicts for both Phase 3 profiles', async () => {
    for (const profile of ['specification', 'published-bip']) {
      const first = (await call({ ...bip375, profile, outputCount: 2 })).payload!
      expect(first).toMatchObject({ valid: true, verifiedSigners: [true], dleqProofsVerified: true, profile })
      const second = (await call({ ...bip375, profile, outputsHex: first.expectedOutputKeysHex, expectedScalarFoldHex: first.scalarFoldTweakHex })).payload
      expect(second).toMatchObject({ valid: true, verifiedOutputs: [true, true] })
    }
  })
  it('rejects malleated shares and rogue signer coverage with audit failure results', async () => {
    const proof = bytes(signer.dleqProofHex); proof[1] ^= 1
    expect((await call({ ...bip375, signers: [{ ...signer, dleqProofHex: hex(proof) }] })).payload?.valid).toBe(false)
    expect((await call({ ...bip375, allInputPubkeysHex: [hex(compressedPoint(G))] })).payload?.valid).toBe(false)
  })
  it('encodes SwiftEC points with explicit entropy and round-trips the wire bytes', async () => {
    const encoded = (await call({ format: 'bip324-swift-ec', swiftAction: 'encode', pubkeyHex: be(G.x), auxRandHex: be(1n) })).payload!
    expect(encoded.swiftEcHex).toBe(swift)
    const decoded = (await call({ format: 'bip324-swift-ec', rawHex: encoded.swiftEcHex })).payload!
    expect(decoded.point).toEqual(encoded.point)
    expect(decoded.constantTimeProven).toBe(false)
  })
  it('decodes arbitrary 64-byte SwiftEC strings including noncanonical field values', async () => {
    expect((await call({ format: 'bip324-swift-ec', swiftEcHex: 'ff'.repeat(64) })).payload?.valid).toBe(true)
  })
  it('reports frame authenticity as incomplete when directional keys are absent', async () => {
    expect((await call({ format: 'bip324-frame-audit', bip324PacketHex: packet })).payload).toMatchObject({ valid: null, status: 'INCOMPLETE', authenticationVerified: false })
  })
  it('detects plaintext v1 leakage and malformed application command framing', async () => {
    expect((await call({ format: 'bip324-frame-audit', rawHex: 'f9beb4d976657273696f6e0000000000' + '00'.repeat(8) })).payload).toMatchObject({ valid: false, findings: [expect.objectContaining({ code: 'plaintext-p2p-leak' })] })
    const malformed = hex(new Bip324PacketCipher(keys).encode(bytes('00')))
    expect((await call({ format: 'bip324-frame-audit', bip324PacketHex: malformed, lengthKeyHex: be(1n), payloadKeyHex: be(2n), inspectApplicationPayload: true })).payload).toMatchObject({ valid: false, authenticationVerified: true })
  })
  it.each([0, 2, 3, 10, 22])('detects encrypted frame corruption at byte %s', async index => {
    const altered = bytes(packet); altered[index] ^= 1
    const { payload } = await call({ format: 'bip324-frame-audit', bip324PacketHex: hex(altered), lengthKeyHex: be(1n), payloadKeyHex: be(2n) })
    expect(payload).toMatchObject({ valid: false, authenticationVerified: false }); expect(payload).not.toHaveProperty('contentsHex')
  })
  it('derives directional keys through HKDF and advances ratchets to a supplied index', async () => {
    const session = deriveBip324SessionKeys(bytes(be(42n)), bytes('f9beb4d9'))
    const frame = hex(new Bip324PacketCipher({ lengthKey: session.initiatorLengthKey, payloadKey: session.initiatorPayloadKey }, 225).encode(bytes('10'), bytes('aabb')))
    expect((await call({ format: 'bip324-frame-audit', bip324PacketHex: frame, sharedSecretHex: be(42n), networkMagicHex: 'f9beb4d9', direction: 'initiator', packetIndex: 225, aadHex: 'aabb' })).payload).toMatchObject({ valid: true, authenticationVerified: true, packetIndex: 225 })
  })
  it.each(['mul', 'add', 'doubling', 'inversion', 'identities'])('compares independent reference arithmetic for $0', async diffOp => {
    expect((await call({ format: 'secp256k1-diff-oracle', diffOp })).payload).toMatchObject({ valid: true, divergenceCount: 0, constantTimeProven: false, referenceIsConstantTime: false })
  })
  it('reports supplied mutant output as a divergence, with JSON-safe coordinates and boundaries', async () => {
    const { payload } = await call({ format: 'secp256k1-diff-oracle', diffOp: 'mul', scalarHex: be(N + 1n), observedResultHex: '00' })
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', divergenceCount: 1, comparisonTarget: 'supplied-observed-result' })
    expect(payload?.checks).toEqual([expect.objectContaining({ reference: { x: `0x${G.x.toString(16)}`, y: `0x${G.y.toString(16)}` }, candidate: null })])
    expect(payload?.boundaries).toEqual(expect.arrayContaining([expect.objectContaining({ name: 'scalar-order', value: `0x${N.toString(16)}` })]))
  })
  it('runs the automated scalar, field and point boundary campaign over MCP', async () => {
    expect((await call({ format: 'secp256k1-diff-oracle', runBoundaries: true })).payload).toMatchObject({ valid: true,
      boundaryCampaign: { valid: true, comparisons: 41, divergenceCount: 0, skippedOperations: [] } })
  })
  it('performs differential Schnorr verification against a supplied native acceptance result', async () => {
    expect((await call({ format: 'secp256k1-diff-oracle', diffOp: 'schnorr', rawHex: vector.signature, pubkeyHex: vector.publicKey, messageHex: vector.message, observedValid: false })).payload).toMatchObject({ valid: false, divergenceCount: 1 })
  })
  it('connects timing hazard inspection without a timing-proof claim', async () => {
    expect((await call({ format: 'secp256k1-diff-oracle', diffOp: 'mul', criticalCodeHex: '75029090' })).payload).toMatchObject({ valid: true, constantTimeProven: false, timingAudit: { hasConditionalBranches: true } })
  })
  it.each([
    ['tapscript-audit', '51'], ['tapscript-eval', '51'], ['bip324-swift-ec', swift],
    ['bip324-frame-audit', packet], ['secp256k1-diff-oracle', be(2n)],
  ])('audits an actual file-session range for %s', async (format, data) => {
    const range = await fileSource(`${format}.bin`, new Uint8Array([0xaa, ...bytes(data), 0xbb]), 1, data.length / 2)
    const extra = format === 'bip324-frame-audit' ? { lengthKeyHex: be(1n), payloadKeyHex: be(2n) }
      : format === 'secp256k1-diff-oracle' ? { diffOp: 'mul' } : {}
    expect((await call({ format, ...range, ...extra })).payload).toMatchObject({ valid: true, source: { kind: 'session', offset: 1, length: data.length / 2 } })
  })
  it.each([
    { format: 'tapscript-eval', leafScriptHex: '51', rawHex: '51' },
    { format: 'bip324-swift-ec', swiftEcHex: swift, rawHex: swift },
    { format: 'bip324-frame-audit', bip324PacketHex: packet, rawHex: packet },
    { ...bip375, rawHex: '51' },
    { format: 'secp256k1-diff-oracle', diffOp: 'mul', rawHex: be(2n), scalarHex: be(2n) },
  ])('rejects conflicting sources for $format', async args => { expect((await call(args)).response.isError).toBe(true) })
  it.each([
    { format: 'tapscript-eval', leafScriptHex: '51', simulationMode: 'true' },
    { format: 'tapscript-eval', leafScriptHex: '51', traceLimit: -1 },
    { format: 'tapscript-audit', leafScriptHex: '51', profile: 'published-bip' },
    { format: 'tapscript-audit', leafScriptHex: '51', profile: 'unknown' },
    { format: 'bip324-swift-ec', swiftEcHex: '00'.repeat(63) },
    { format: 'bip324-frame-audit', bip324PacketHex: packet, lengthKeyHex: be(1n) },
    { format: 'bip324-frame-audit', bip324PacketHex: packet, sharedSecretHex: be(42n) },
    { format: 'bip324-frame-audit', bip324PacketHex: packet, direction: 'initiator' },
    { format: 'secp256k1-diff-oracle', diffOp: 'inversion', fieldElementHex: be(P) },
    { format: 'secp256k1-diff-oracle', diffOp: 'unsupported' },
    { format: 'secp256k1-diff-oracle', diffOp: 'mul', observedValid: false },
    { ...bip375, signers: [{ ...signer, extra: true }] },
    { format: 'tapscript-audit', leafScriptHex: '51', diffOp: 'mul' },
  ])('validates format-specific arguments for $format', async args => { expect((await call(args)).response.isError).toBe(true) })
  it('enforces combined witness/input byte bounds before evaluation', async () => {
    expect((await call({ format: 'tapscript-eval', leafScriptHex: '51', witnessHexes: ['00'.repeat(SECP256K1_AUDIT_MAX_BYTES)] })).response.isError).toBe(true)
  })
  it('honors cancellation and rejects unknown top-level arguments in direct handler calls', async () => {
    const controller = new AbortController(); controller.abort()
    await expect(callAuditTool('bitpeek_secp256k1_audit', { format: 'secp256k1-diff-oracle' }, security, controller.signal)).rejects.toMatchObject({ code: 'CANCELLED' })
    await expect(callAuditTool('bitpeek_secp256k1_audit', { format: 'tapscript-eval', leafScriptHex: '51', extra: true }, security)).rejects.toMatchObject({ code: 'INVALID_INPUT' })
  })
})
