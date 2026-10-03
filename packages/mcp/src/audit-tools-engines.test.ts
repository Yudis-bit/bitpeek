import { createECDH, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { SECP256K1_N as N, SECP256K1_AUDIT_MAX_BYTES } from '../../core/src/index'
import { callAuditTool } from './audit-tools'
import { createBitpeekMcpServer } from './server'
import { McpSecurityManager } from './security'

interface SigningVector { index: number; secretKey: string; publicKey: string; auxRand: string; message: string; signature: string }
const { vectors } = JSON.parse(readFileSync(new URL('../../core/src/bchain/fixtures/bip340-signing-vectors.json', import.meta.url), 'utf8')) as { vectors: SigningVector[] }
const zero = '00'.repeat(32)
const be = (value: bigint) => value.toString(16).padStart(64, '0')
function nativeKey(scalar: bigint): string {
  const key = createECDH('secp256k1')
  key.setPrivateKey(Buffer.from(be(scalar), 'hex'))
  return key.getPublicKey(undefined, 'compressed').toString('hex')
}
const signingArguments = (vector = vectors[0]!) => ({ format: 'bip340-sign', seckeyHex: vector.secretKey, messageHex: vector.message, auxRandHex: vector.auxRand })
const scanArguments = () => ({ format: 'bip352-scan', spendKeyHex: nativeKey(3n), scanPrivKeyHex: be(42n), tweakHex: be(1n),
  outputsHex: [] as string[], labels: [
    { labelIndex: 0, labelTweakHex: be(11n), labelPubKeyHex: nativeKey(11n) },
    { labelIndex: 7, labelTweakHex: be(2n) },
  ] })

describe('BIP-340 signing/aux audit and BIP-352 scanning over MCP', () => {
  let directory: string
  let client: Client
  let server: ReturnType<typeof createBitpeekMcpServer>
  let security: McpSecurityManager

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'bitpeek-crypto-engines-'))
    security = new McpSecurityManager({ allowedInputRoots: [directory], allowedOutputRoots: [directory] })
    server = createBitpeekMcpServer(security)
    client = new Client({ name: 'crypto-engine-tests', version: '1.0.0' })
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
    if (!content || content.type !== 'text') throw new Error('Missing text response')
    const payload = response.isError ? undefined : response.structuredContent ?? JSON.parse(content.text) as Record<string, unknown>
    if (payload) expect(JSON.parse(content.text)).toEqual(payload)
    return { response, payload, text: content.text }
  }

  it('advertises the additive formats, direct message/output inputs, and label cache', async () => {
    const { tools } = await client.listTools()
    const tool = tools.find(item => item.name === 'bitpeek_secp256k1_audit')!
    expect(tools).toHaveLength(17)
    expect(tool.inputSchema.properties?.format).toMatchObject({ enum: expect.arrayContaining(['bip340-sign', 'bip340-aux-audit', 'bip352-scan']) })
    expect(tool.inputSchema.properties?.seckeyHex).toMatchObject({ type: 'string', minLength: 64 })
    expect(tool.inputSchema.properties?.outputsHex).toMatchObject({ type: 'array', maxItems: SECP256K1_AUDIT_MAX_BYTES / 32,
      items: { type: 'string', minLength: 64, maxLength: 64 } })
    expect(tool.inputSchema.properties?.labels).toMatchObject({ type: 'array', items: { type: 'object', required: ['labelIndex', 'labelTweakHex'] } })
    expect(tool.inputSchema.oneOf).toEqual(expect.arrayContaining([
      expect.objectContaining({ required: ['format', 'seckeyHex', 'messageHex'] }),
      expect.objectContaining({ required: ['format', 'spendKeyHex', 'scanPrivKeyHex', 'tweakHex', 'outputsHex'] }),
    ]))
  })

  it.each(vectors)('returns the published signature for vector $index as JSON-safe hex', async vector => {
    const { response, payload } = await call(signingArguments(vector))
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ format: 'bip340-sign', valid: true, status: 'PASS',
      signatureHex: vector.signature.toLowerCase(), publicKeyHex: vector.publicKey.toLowerCase(),
      rx: `0x${BigInt(`0x${vector.signature.slice(0, 64)}`).toString(16)}`,
      s: `0x${BigInt(`0x${vector.signature.slice(64)}`).toString(16)}`,
      verificationScope: 'reference-signing', cryptographicSignaturesVerified: true,
      source: { kind: 'hex', length: 32, sha256: createHash('sha256').update(Buffer.from(vector.message, 'hex')).digest('hex') } })
    expect(payload).not.toHaveProperty('seckeyHex')
  })

  it('uses deterministic zero aux when omitted', async () => {
    const { auxRandHex: _aux, ...args } = signingArguments()
    expect((await call(args)).payload).toMatchObject({ valid: true, signatureHex: vectors[0]!.signature.toLowerCase() })
  })

  it('accepts a signing message through the existing rawHex source', async () => {
    const { messageHex, ...args } = signingArguments()
    expect((await call({ ...args, rawHex: messageHex })).payload).toMatchObject({ valid: true, signatureHex: vectors[0]!.signature.toLowerCase() })
  })

  it('audits the deterministic default without candidate aux', async () => {
    const vector = vectors[0]!
    const { payload } = await call({ format: 'bip340-aux-audit', seckeyHex: vector.secretKey, messageHex: vector.message, rawHex: vector.signature })
    expect(payload).toMatchObject({ valid: true, status: 'PASS', matchesAux: true, isDeterministicDefault: true,
      expectedSignatureHex: vector.signature.toLowerCase(), cryptographicSignaturesVerified: true,
      verificationScope: 'auxiliary-randomness-comparison' })
    expect(payload?.candidateSignatureHex).toBeUndefined()
  })

  it('audits the candidate aux in a published nondefault signature', async () => {
    const vector = vectors[1]!
    const { payload } = await call({ ...signingArguments(vector), format: 'bip340-aux-audit', rawHex: vector.signature })
    expect(payload).toMatchObject({ valid: true, status: 'PASS', matchesAux: true, isDeterministicDefault: false,
      candidateSignatureHex: vector.signature.toLowerCase(), cryptographicSignaturesVerified: true })
  })

  it('returns a comparison FAIL for wrong candidate aux', async () => {
    const vector = vectors[1]!
    const { response, payload } = await call({ ...signingArguments(vector), format: 'bip340-aux-audit', rawHex: vector.signature, auxRandHex: zero })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: true, status: 'FAIL', matchesAux: false, isDeterministicDefault: false,
      cryptographicSignaturesVerified: false, reason: 'Observed signature does not match candidate aux' })
  })

  it('reports deterministic-default identification separately from candidate mismatch', async () => {
    const vector = vectors[0]!
    const { payload } = await call({ ...signingArguments(vector), format: 'bip340-aux-audit', rawHex: vector.signature, auxRandHex: be(1n) })
    expect(payload).toMatchObject({ valid: true, status: 'FAIL', matchesAux: false, isDeterministicDefault: true, cryptographicSignaturesVerified: true })
  })

  it.each([0n, N])('reports a mathematical signing FAIL for secret key %s', async scalar => {
    const { response, payload } = await call({ ...signingArguments(), seckeyHex: be(scalar) })
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', reason: 'Secret key outside range 0 < d < n', cryptographicSignaturesVerified: false })
    expect(payload?.signatureHex).toBeUndefined()
  })

  it('rejects malformed candidate aux instead of passing an aux=0 match', async () => {
    const vector = vectors[0]!
    const { payload } = await call({ ...signingArguments(), format: 'bip340-aux-audit', rawHex: vector.signature, auxRandHex: '00'.repeat(31) })
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', matchesAux: false, isDeterministicDefault: false, reason: 'auxRand must be 32 bytes when supplied' })
  })

  it('does not accept a short observed signature', async () => {
    const { payload } = await call({ ...signingArguments(), format: 'bip340-aux-audit', rawHex: '00'.repeat(63) })
    expect(payload).toMatchObject({ valid: false, status: 'FAIL', reason: 'Signature must be 64 bytes' })
  })

  it('scans direct output arrays across boundaries with both candidate parities and labels', async () => {
    const args = scanArguments()
    args.outputsHex = Array(125).fill(nativeKey(1n).slice(2)) as string[]
    args.outputsHex[49] = nativeKey(15n).slice(2)
    args.outputsHex[50] = nativeKey(6n).slice(2)
    args.outputsHex[100] = nativeKey(4n).slice(2)
    const { response, payload } = await call(args)
    expect(response.isError).toBeUndefined()
    expect(payload).toMatchObject({ format: 'bip352-scan', valid: true, status: 'PASS', totalOutputsScanned: 125, batchCount: 3,
      cryptographicSignaturesVerified: false, verificationScope: 'silent-payment-output-scan', source: { kind: 'hex', length: 4000 },
      unlabeledPoint: { x: expect.stringMatching(/^0x[0-9a-f]+$/), y: expect.stringMatching(/^0x[0-9a-f]+$/) } })
    expect(payload?.matches).toEqual([
      { outputIndex: 49, outputKeyHex: args.outputsHex[49], isLabeled: true, labelIndex: 0, labelTweakHex: be(11n), candidateSlotParity: 0, batchIndex: 0, batchOffset: 0 },
      { outputIndex: 50, outputKeyHex: args.outputsHex[50], isLabeled: true, labelIndex: 7, labelTweakHex: be(2n), candidateSlotParity: 1, batchIndex: 1, batchOffset: 50 },
      { outputIndex: 100, outputKeyHex: args.outputsHex[100], isLabeled: false, candidateSlotParity: 0, batchIndex: 2, batchOffset: 100 },
    ])
  })

  it('accepts an empty output array', async () => {
    expect((await call(scanArguments())).payload).toMatchObject({ valid: true, matches: [], totalOutputsScanned: 0, batchCount: 1, source: { length: 0 } })
  })

  it('scans packed output keys through rawHex', async () => {
    const { outputsHex: _outputs, ...args } = scanArguments()
    const { payload } = await call({ ...args, rawHex: nativeKey(15n).slice(2) + nativeKey(6n).slice(2), batchSize: 1 })
    expect(payload).toMatchObject({ valid: true, batchCount: 2, matches: [
      { outputIndex: 0, candidateSlotParity: 0, batchIndex: 0 }, { outputIndex: 1, candidateSlotParity: 1, batchIndex: 1 },
    ] })
  })

  it('reads exact authorized file ranges for signing and scanning', async () => {
    const path = join(directory, 'inputs.bin')
    await writeFile(path, Buffer.from(`0000${zero}${nativeKey(6n).slice(2)}0000`, 'hex'))
    const opened = await call({ filePath: path }, 'bitpeek_open')
    const { messageHex: _message, ...signArgs } = signingArguments()
    const signed = await call({ ...signArgs, handle: opened.payload?.handle, offset: 2, length: 32 })
    expect(signed.payload).toMatchObject({ valid: true, signatureHex: vectors[0]!.signature.toLowerCase(), source: { kind: 'session', offset: 2, length: 32 } })
    const { outputsHex: _outputs, ...scanArgs } = scanArguments()
    const scanned = await call({ ...scanArgs, handle: opened.payload?.handle, offset: 34, length: 32 })
    expect(scanned.payload).toMatchObject({ valid: true, source: { kind: 'session', offset: 34, length: 32 }, matches: [{ outputIndex: 0, labelIndex: 7, candidateSlotParity: 1 }] })
  })

  it.each([
    { seckeyHex: undefined }, { seckeyHex: null }, { seckeyHex: 'gg'.repeat(32) },
    { messageHex: undefined }, { messageHex: 'gg'.repeat(32) }, { auxRandHex: 7 },
    { rawHex: zero }, { offset: 0 }, { length: 32 }, { pubkeyHex: vectors[0]!.publicKey },
  ])('rejects missing, conflicting or unrelated signing parameters %j', async override => {
    expect((await call({ ...signingArguments(), ...override })).response.isError).toBe(true)
  })

  it.each([
    { outputsHex: undefined }, { outputsHex: null }, { outputsHex: ['00'] }, { outputsHex: ['gg'.repeat(32)] },
    { scanPrivKeyHex: undefined }, { tweakHex: undefined }, { labels: {} }, { labels: [null] },
    { labels: [{ labelIndex: -1, labelTweakHex: be(2n) }] },
    { labels: [{ labelIndex: 1, labelTweakHex: be(2n), unexpected: true }] },
    { labels: [{ labelIndex: 1, labelTweakHex: '01', labelPubKeyHex: nativeKey(2n) }] },
    { labels: [{ labelIndex: 1, labelTweakHex: be(2n), labelPubKeyHex: zero }] },
    { batchSize: 0 }, { batchSize: 0.5 }, { batchSize: '50' }, { offset: 0 }, { rawHex: zero },
    { seckeyHex: be(1n) },
  ])('rejects malformed or conflicting scan parameters %j', async override => {
    expect((await call({ ...scanArguments(), ...override })).response.isError).toBe(true)
  })

  it('rejects truncated packed outputs and arrays exceeding the source byte budget', async () => {
    const { outputsHex: _outputs, ...args } = scanArguments()
    expect((await call({ ...args, rawHex: '00'.repeat(33) })).text).toContain('multiple of 32')
    const oversized = Array(SECP256K1_AUDIT_MAX_BYTES / 32 + 1).fill(zero)
    expect((await call({ ...args, outputsHex: oversized })).text).toContain('audit size limit')
  })

  it('reports invalid scan keys as a mathematical FAIL', async () => {
    expect((await call({ ...scanArguments(), scanPrivKeyHex: zero })).payload)
      .toMatchObject({ valid: false, status: 'FAIL', matches: [], reason: 'Scan private key outside valid range (0 < b_scan < n)' })
  })

  it('continues to reject the new parameters on unrelated existing formats and timing audits', async () => {
    expect((await call({ format: 'pubkey', rawHex: nativeKey(1n), seckeyHex: be(1n) })).text).toContain('seckeyHex is not supported for format pubkey')
    expect((await call({ rawHex: '90', outputsHex: [] }, 'bitpeek_constant_time_audit')).text).toContain('Unsupported audit argument: outputsHex')
  })

  it('honors cancellation for the source-less signing and scanning inputs', async () => {
    const controller = new AbortController()
    controller.abort()
    for (const args of [signingArguments(), scanArguments()]) {
      await expect(callAuditTool('bitpeek_secp256k1_audit', args, security, controller.signal))
        .rejects.toMatchObject({ code: 'CANCELLED' })
    }
  })
})
