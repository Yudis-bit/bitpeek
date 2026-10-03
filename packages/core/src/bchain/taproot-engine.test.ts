import { createECDH, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { unsignedBigEndian } from '../bytes'
import { Secp256k1Engine as Curve, SECP256K1_GX as GX, SECP256K1_N as N, SECP256K1_P as P } from './secp256k1'
import { TaprootEngine as Engine, TAPROOT_LEAF_TAPSCRIPT, TAPROOT_CONTROL_MAX_SIZE } from './taproot'
import { TaprootEngine as BarrelEngine } from '../index'
import type { TapLeaf, TapTreeStructure, TapTreeResult, TaprootControlBlockInspection,
  TaprootScriptPathVerificationResult, TapscriptKeyAuditResult } from '../index'

interface PublishedLeaf { id: number; script: string; leafVersion: number }
type PublishedTree = PublishedLeaf | [PublishedTree, PublishedTree]
interface WalletVector {
  given: { internalPubkey: string; scriptTree: PublishedTree | null }
  intermediary: { leafHashes?: string[]; merkleRoot: string | null; tweak: string; tweakedPubkey: string }
  expected: { scriptPathControlBlocks?: string[] }
}
const { scriptPubKey: walletVectors } = JSON.parse(readFileSync(new URL('./fixtures/bip341-wallet-reference.json', import.meta.url), 'utf8')) as { scriptPubKey: WalletVector[] }
const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'))
const toHex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex')
const be = (value: bigint) => hex(value.toString(16).padStart(64, '0'))
const internalKey = be(GX)
const scripts = [hex('51'), hex('52'), hex('53')]
const xMismatch = 'Computed Taproot output key X does not match expected outputKey32'
const parityMismatch = 'Computed Taproot output key Y parity does not match control block header parity'
const invalidInternal = 'Invalid internal key X coordinate (not on curve or >= p)'

function flattenTree(tree: PublishedTree): PublishedLeaf[] {
  return Array.isArray(tree) ? [...flattenTree(tree[0]), ...flattenTree(tree[1])] : [tree]
}
function treeShape(tree: PublishedTree): TapTreeStructure {
  return Array.isArray(tree) ? [treeShape(tree[0]), treeShape(tree[1])] : tree.id
}
const publishedLeaves = walletVectors.flatMap((vector, vectorIndex) => vector.given.scriptTree === null ? []
  : flattenTree(vector.given.scriptTree).map(leaf => ({ vector, vectorIndex, leaf, leafIndex: leaf.id })))

function nativeHash(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const tagHash = createHash('sha256').update(tag).digest()
  const hash = createHash('sha256').update(tagHash).update(tagHash)
  for (const part of parts) hash.update(part)
  return Uint8Array.from(hash.digest())
}
function nativeBranch(a: Uint8Array, b: Uint8Array): Uint8Array {
  return Buffer.compare(a, b) <= 0 ? nativeHash('TapBranch', a, b) : nativeHash('TapBranch', b, a)
}
function nativeOutput(root: Uint8Array): Uint8Array {
  // G is the even-Y internal key, so Q=(1+TapTweak(G.x,root))*G.
  const scalar = (1n + unsignedBigEndian(nativeHash('TapTweak', internalKey, root))) % N
  const key = createECDH('secp256k1')
  key.setPrivateKey(be(scalar))
  return Uint8Array.from(key.getPublicKey(undefined, 'compressed'))
}
function controlBlock(header: number, key = internalKey, path: Uint8Array[] = []): Uint8Array {
  const bytes = new Uint8Array(33 + 32 * path.length)
  bytes[0] = header
  bytes.set(key, 1)
  path.forEach((node, index) => bytes.set(node, 33 + 32 * index))
  return bytes
}
function spine(depth: number): TapTreeStructure {
  let structure: TapTreeStructure = depth
  for (let index = depth - 1; index >= 0; index--) structure = [index, structure]
  return structure
}

afterEach(() => vi.restoreAllMocks())

describe('BIP-341 TapLeaf, TapBranch and TapTweak hashes', () => {
  it.each(publishedLeaves)('matches published TapLeaf vector $vectorIndex leaf $leafIndex', ({ vector, leaf }) => {
    expect(toHex(Engine.tapLeafHash(hex(leaf.script), leaf.leafVersion))).toBe(vector.intermediary.leafHashes![leaf.id])
  })

  it.each([
    [0, '00'], [1, '01'], [252, 'fc'], [253, 'fdfd00'], [254, 'fdfe00'],
    [65535, 'fdffff'], [65536, 'fe00000100'], [65537, 'fe01000100'],
  ] as const)('uses canonical little-endian CompactSize for a %s-byte script', (length, prefix) => {
    const script = Uint8Array.from({ length }, (_, index) => index & 255)
    expect(Engine.tapLeafHash(script)).toEqual(nativeHash('TapLeaf', hex('c0'), hex(prefix), script))
  })

  it.each([0x00, 0xc0, 0xfa, 0xfe])('commits to the even leaf version %s', version => {
    expect(Engine.tapLeafHash(scripts[0]!, version)).toEqual(nativeHash('TapLeaf', Uint8Array.of(version), hex('01'), scripts[0]!))
  })

  it.each([-2, -1, 1, 0xc1, 0xff, 256, 0.5, NaN, Infinity])('rejects a non-byte or odd leaf version %s', version => {
    expect(() => Engine.tapLeafHash(scripts[0]!, version)).toThrow('Leaf version must be an even byte')
  })

  it('sorts branch hashes lexicographically, including differences in the last byte', () => {
    const pairs = [[hex('01' + 'ff'.repeat(31)), hex('02' + '00'.repeat(31))], [be(1n), be(2n)], [be(257n), be(256n)]]
    for (const [a, b] of pairs) {
      const expected = nativeBranch(a!, b!)
      expect(Engine.tapBranchHash(a!, b!)).toEqual(expected)
      expect(Engine.tapBranchHash(b!, a!)).toEqual(expected)
    }
  })

  it('hashes equal branch children without dropping either commitment', () => {
    const child = be(42n)
    expect(Engine.tapBranchHash(child, child)).toEqual(nativeHash('TapBranch', child, child))
  })

  it.each([0, 31, 33])('rejects %s-byte branch children', length => {
    expect(() => Engine.tapBranchHash(new Uint8Array(length), be(1n))).toThrow(RangeError)
    expect(() => Engine.tapBranchHash(be(1n), new Uint8Array(length))).toThrow(RangeError)
  })

  it.each(walletVectors)('matches the published TapTweak for internal key $given.internalPubkey', vector => {
    const root = vector.intermediary.merkleRoot === null ? undefined : hex(vector.intermediary.merkleRoot)
    expect(toHex(Engine.tapTweakHash(hex(vector.given.internalPubkey), root))).toBe(vector.intermediary.tweak)
  })

  it('distinguishes an omitted Merkle root from a zero root', () => {
    expect(Engine.tapTweakHash(internalKey)).toEqual(nativeHash('TapTweak', internalKey))
    expect(Engine.tapTweakHash(internalKey, be(0n))).toEqual(nativeHash('TapTweak', internalKey, be(0n)))
    expect(Engine.tapTweakHash(internalKey)).not.toEqual(Engine.tapTweakHash(internalKey, be(0n)))
  })

  it.each([0, 31, 33])('rejects %s-byte internal keys or supplied roots', length => {
    expect(() => Engine.tapTweakHash(new Uint8Array(length))).toThrow('Internal key must be 32 bytes')
    expect(() => Engine.tapTweakHash(internalKey, new Uint8Array(length))).toThrow('Merkle root must be 32 bytes when supplied')
  })
})

describe('BIP-341 control block wire inspection', () => {
  it.each([0xc0, 0xc1, 0xfa, 0xfb, 0, 1, 0xfe, 0xff])('decodes masked leaf version and parity from header %s', header => {
    const path = [be(1n), be(P)] // Siblings are opaque hashes, not curve points.
    const bytes = controlBlock(header, internalKey, path)
    const inspection: TaprootControlBlockInspection = Engine.inspectControlBlock(bytes)
    expect(inspection).toEqual({ isValid: true, leafVersion: header & 0xfe, outputParity: header & 1,
      internalKey32: internalKey, pathLength: 2, merklePath: path, rawBytes: bytes })
  })

  it.each([0, 1, 32])('rejects a short %s-byte block', length => {
    expect(Engine.inspectControlBlock(new Uint8Array(length))).toMatchObject({ isValid: false,
      rejectionReason: `Control block too short (${length} < 33 bytes)` })
  })

  it.each([34, 64, 66, TAPROOT_CONTROL_MAX_SIZE + 1])('rejects malformed framing of length %s', length => {
    expect(Engine.inspectControlBlock(new Uint8Array(length))).toMatchObject({ isValid: false, rejectionReason: 'Control block size must be 33 + 32*m bytes' })
  })

  it.each([0, 1, 128])('accepts a valid depth of %s nodes', depth => {
    expect(Engine.inspectControlBlock(controlBlock(0xc1, internalKey, Array.from({ length: depth }, () => be(0n)))))
      .toMatchObject({ isValid: true, pathLength: depth, outputParity: 1 })
  })

  it('rejects more than 128 nodes', () => {
    const bytes = controlBlock(0xc0, internalKey, Array.from({ length: 129 }, () => be(0n)))
    expect(Engine.inspectControlBlock(bytes)).toMatchObject({ isValid: false, rejectionReason: 'Control block exceeds maximum depth (128 nodes)' })
  })

  it.each([0n, P, P + 1n])('rejects invalid internal X %s while preserving decoded header fields', x => {
    expect(Engine.inspectControlBlock(controlBlock(0xc1, be(x)))).toMatchObject({ isValid: false,
      leafVersion: 0xc0, outputParity: 1, internalKey32: be(x), rejectionReason: invalidInternal })
  })

  it('copies input bytes and independently owns parsed fields, including Node Buffer inputs', () => {
    const original = controlBlock(0xc0, internalKey, [be(42n)])
    const bytes = Buffer.from(original)
    const inspected = Engine.inspectControlBlock(bytes)
    bytes.fill(0)
    expect(inspected.rawBytes).toEqual(original)
    expect(inspected.internalKey32).toEqual(internalKey)
    expect(inspected.merklePath).toEqual([be(42n)])
    inspected.rawBytes.fill(0)
    expect(inspected.internalKey32).toEqual(internalKey)
    expect(inspected.merklePath).toEqual([be(42n)])
  })
})

describe('BIP-341 script-path commitment verification', () => {
  it.each(publishedLeaves)('verifies published vector $vectorIndex leaf $leafIndex', ({ vector, leaf }) => {
    const control = hex(vector.expected.scriptPathControlBlocks![leaf.id]!)
    const result: TaprootScriptPathVerificationResult = Engine.verifyScriptPath(control, hex(vector.intermediary.tweakedPubkey), hex(leaf.script))
    expect(result).toEqual({ valid: true, leafVersion: leaf.leafVersion, outputParity: control[0]! & 1,
      internalKey32: hex(vector.given.internalPubkey), merkleRoot: hex(vector.intermediary.merkleRoot!),
      pathLength: (control.length - 33) / 32, computedOutputKey32: hex(vector.intermediary.tweakedPubkey) })
  })

  it.each(publishedLeaves)('rejects a one-byte script mutation in vector $vectorIndex leaf $leafIndex', ({ vector, leaf }) => {
    const script = hex(leaf.script)
    script[0] = script[0]! ^ 1
    expect(Engine.verifyScriptPath(hex(vector.expected.scriptPathControlBlocks![leaf.id]!), hex(vector.intermediary.tweakedPubkey), script))
      .toEqual({ valid: false, reason: xMismatch })
  })

  it.each(publishedLeaves)('rejects a parity-bit mutation in vector $vectorIndex leaf $leafIndex', ({ vector, leaf }) => {
    const control = hex(vector.expected.scriptPathControlBlocks![leaf.id]!)
    control[0] = control[0]! ^ 1
    expect(Engine.verifyScriptPath(control, hex(vector.intermediary.tweakedPubkey), hex(leaf.script))).toEqual({ valid: false, reason: parityMismatch })
  })

  it('rejects single-byte mutations in every Merkle sibling and a reordered path', () => {
    const vector = walletVectors[5]!
    const leaf = flattenTree(vector.given.scriptTree!)[1]!
    const control = hex(vector.expected.scriptPathControlBlocks![leaf.id]!)
    const output = hex(vector.intermediary.tweakedPubkey)
    for (let index = 33; index < control.length; index += 32) {
      const mutated = control.slice()
      mutated[index] = mutated[index]! ^ 1
      expect(Engine.verifyScriptPath(mutated, output, hex(leaf.script))).toEqual({ valid: false, reason: xMismatch })
    }
    const reordered = control.slice()
    reordered.set(control.subarray(65, 97), 33)
    reordered.set(control.subarray(33, 65), 65)
    expect(Engine.verifyScriptPath(reordered, output, hex(leaf.script))).toEqual({ valid: false, reason: xMismatch })
  })

  it('rejects leaf-version and output-key mutations with exact reasons', () => {
    const vector = walletVectors[1]!
    const leaf = flattenTree(vector.given.scriptTree!)[0]!
    const control = hex(vector.expected.scriptPathControlBlocks![0]!)
    const output = hex(vector.intermediary.tweakedPubkey)
    const alteredVersion = control.slice()
    alteredVersion[0] = alteredVersion[0]! ^ 2
    expect(Engine.verifyScriptPath(alteredVersion, output, hex(leaf.script))).toEqual({ valid: false, reason: xMismatch })
    output[31] = output[31]! ^ 1
    expect(Engine.verifyScriptPath(control, output, hex(leaf.script))).toEqual({ valid: false, reason: xMismatch })
  })

  it('rejects a single-byte internal-key mutation', () => {
    const vector = walletVectors[1]!
    const leaf = flattenTree(vector.given.scriptTree!)[0]!
    const control = hex(vector.expected.scriptPathControlBlocks![0]!)
    control[1] = control[1]! ^ 1
    const reason = Curve.liftX(control.subarray(1, 33)) === null ? invalidInternal : xMismatch
    expect(Engine.verifyScriptPath(control, hex(vector.intermediary.tweakedPubkey), hex(leaf.script))).toEqual({ valid: false, reason })
  })

  it.each([0, 31, 33])('rejects %s-byte output keys', length => {
    expect(Engine.verifyScriptPath(controlBlock(0xc0), new Uint8Array(length), scripts[0]!)).toEqual({ valid: false, reason: 'Output key must be 32 bytes' })
  })

  it('rejects out-of-field outputs and malformed control blocks', () => {
    expect(Engine.verifyScriptPath(controlBlock(0xc0), be(P), scripts[0]!)).toEqual({ valid: false, reason: 'Output key X coordinate >= p' })
    expect(Engine.verifyScriptPath(new Uint8Array(32), internalKey, scripts[0]!)).toEqual({ valid: false, reason: 'Control block too short (32 < 33 bytes)' })
  })

  it.each([N, N + 1n])('rejects tweak %s before scalar reduction in verification and building', tweak => {
    vi.spyOn(Engine, 'tapTweakHash').mockReturnValue(be(tweak))
    expect(Engine.verifyScriptPath(controlBlock(0xc0), internalKey, scripts[0]!)).toEqual({ valid: false, reason: 'Taproot tweak scalar >= n' })
    expect(() => Engine.buildTapTree([{ script: scripts[0]! }], internalKey)).toThrow('Taproot tweak scalar >= n')
  })

  it('permits a zero tweak, which is valid for BIP-341', () => {
    vi.spyOn(Engine, 'tapTweakHash').mockReturnValue(be(0n))
    const tree = Engine.buildTapTree([{ script: scripts[0]! }], internalKey)
    expect(Engine.verifyScriptPath(tree.leaves[0]!.controlBlock, internalKey, scripts[0]!)).toMatchObject({ valid: true, outputParity: 0 })
  })

  it('rejects a tweak that cancels the internal point', () => {
    vi.spyOn(Engine, 'tapTweakHash').mockReturnValue(be(N - 1n))
    expect(Engine.verifyScriptPath(controlBlock(0xc0), internalKey, scripts[0]!)).toEqual({ valid: false, reason: 'Tweaked output point is infinity' })
    expect(() => Engine.buildTapTree([{ script: scripts[0]! }], internalKey)).toThrow('Taproot output point is infinity')
  })
})

describe('TapTree construction and control block synthesis', () => {
  it.each(walletVectors.filter(vector => vector.given.scriptTree !== null))('reproduces the published tree and control blocks for $given.internalPubkey', vector => {
    const publishedTree = vector.given.scriptTree!
    const leaves = flattenTree(publishedTree).sort((a, b) => a.id - b.id).map(leaf => ({ script: hex(leaf.script), leafVersion: leaf.leafVersion }))
    const tree: TapTreeResult = Engine.buildTapTree(leaves, hex(vector.given.internalPubkey), treeShape(publishedTree))
    expect(toHex(tree.merkleRoot)).toBe(vector.intermediary.merkleRoot)
    expect(tree.leaves.map(leaf => toHex(leaf.leafHash))).toEqual(vector.intermediary.leafHashes)
    expect(tree.leaves.map(leaf => toHex(leaf.controlBlock))).toEqual(vector.expected.scriptPathControlBlocks)
  })

  it.each([2, 3])('builds the expected %s-leaf default tree and verifies every path against OpenSSL', count => {
    const leaves = scripts.slice(0, count).map(script => ({ script }))
    const hashes = leaves.map(leaf => nativeHash('TapLeaf', hex('c0'), hex('01'), leaf.script))
    const branch = nativeBranch(hashes[0]!, hashes[1]!)
    const root = count === 2 ? branch : nativeBranch(branch, hashes[2]!)
    const tree = Engine.buildTapTree(leaves, internalKey)
    expect(tree.merkleRoot).toEqual(root)
    expect(tree.leaves.map(leaf => leaf.merklePath)).toEqual(count === 2 ? [[hashes[1]], [hashes[0]]]
      : [[hashes[1], hashes[2]], [hashes[0], hashes[2]], [branch]])
    const native = nativeOutput(root)
    for (const leaf of tree.leaves) {
      expect(leaf.controlBlock[0]).toBe(0xc0 | (native[0]! & 1))
      expect(Engine.verifyScriptPath(leaf.controlBlock, native.slice(1), leaf.script)).toMatchObject({ valid: true, merkleRoot: root })
    }
  })

  it.each([1, 5, 7, 8])('round-trips every leaf in a %s-leaf tree', count => {
    const leaves = Array.from({ length: count }, (_, index) => ({ script: Uint8Array.of(0x51, index) }))
    const tree = Engine.buildTapTree(leaves, internalKey)
    const output = nativeOutput(tree.merkleRoot).slice(1)
    for (const leaf of tree.leaves) expect(Engine.verifyScriptPath(leaf.controlBlock, output, leaf.script).valid).toBe(true)
  })

  it('supports an empty script and duplicate leaves with both commitments present', () => {
    const empty: TapLeaf = { script: new Uint8Array(0) }
    const tree = Engine.buildTapTree([empty, empty], internalKey)
    const leafHash = nativeHash('TapLeaf', hex('c000'))
    expect(tree.merkleRoot).toEqual(nativeBranch(leafHash, leafHash))
    for (const leaf of tree.leaves) {
      expect(leaf.merklePath).toEqual([leafHash])
      expect(Engine.verifyScriptPath(leaf.controlBlock, nativeOutput(tree.merkleRoot).slice(1), leaf.script).valid).toBe(true)
    }
  })

  it('supports custom shape, orientation-invariant branches and correct leaf positions', () => {
    const leaves = scripts.map(script => ({ script }))
    const a = Engine.buildTapTree(leaves, internalKey, [0, [1, 2]])
    const b = Engine.buildTapTree(leaves, internalKey, [[2, 1], 0])
    expect(a).toEqual(b)
    expect(a.leaves.map(leaf => leaf.merklePath.length)).toEqual([1, 2, 2])
    expect(a.merkleRoot).not.toEqual(Engine.buildTapTree(leaves, internalKey).merkleRoot)
  })

  it('synthesizes and verifies a maximum-depth 128-node control block', () => {
    const leaves = Array.from({ length: 129 }, (_, index) => ({ script: Uint8Array.of(0x51, index) }))
    const tree = Engine.buildTapTree(leaves, internalKey, spine(128))
    const leaf = tree.leaves[128]!
    expect(leaf.controlBlock.length).toBe(TAPROOT_CONTROL_MAX_SIZE)
    expect(Engine.verifyScriptPath(leaf.controlBlock, nativeOutput(tree.merkleRoot).slice(1), leaf.script)).toMatchObject({ valid: true, pathLength: 128 })
  })

  it('rejects custom paths deeper than 128 nodes', () => {
    const leaves = Array.from({ length: 130 }, () => ({ script: scripts[0]! }))
    expect(() => Engine.buildTapTree(leaves, internalKey, spine(129))).toThrow('TapTree exceeds maximum depth (128 nodes)')
  })

  it.each([[-1, 1], [0.5, 1], [0, 2], [0, 0], 0, [0], [0, 1, 2], null].map(structure => ({ structure })))('rejects an invalid custom shape $structure', ({ structure }) => {
    expect(() => Engine.buildTapTree([{ script: scripts[0]! }, { script: scripts[1]! }], internalKey, structure as TapTreeStructure)).toThrow(RangeError)
  })

  it('rejects empty leaf sets, malformed internal keys, and invalid leaf versions', () => {
    expect(() => Engine.buildTapTree([], internalKey)).toThrow('TapTree requires at least one leaf')
    expect(() => Engine.buildTapTree([{ script: scripts[0]! }], new Uint8Array(31))).toThrow('Internal key must be 32 bytes')
    expect(() => Engine.buildTapTree([{ script: scripts[0]! }], be(0n))).toThrow('Invalid internal key X coordinate')
    expect(() => Engine.buildTapTree([{ script: scripts[0]!, leafVersion: 0xc1 }], internalKey)).toThrow('Leaf version must be an even byte')
  })

  it('owns input scripts and proof buffers independently, including Buffer scripts', () => {
    const script = Buffer.from('51', 'hex')
    const tree = Engine.buildTapTree([{ script }, { script: scripts[1]! }], internalKey)
    const originalRoot = tree.merkleRoot.slice()
    const originalControl = tree.leaves[1]!.controlBlock.slice()
    const originalPath = tree.leaves[1]!.merklePath[0]!.slice()
    script.fill(0)
    expect(tree.leaves[0]!.script).toEqual(hex('51'))
    tree.leaves[0]!.leafHash.fill(0)
    expect(tree.merkleRoot).toEqual(originalRoot)
    expect(tree.leaves[1]!.controlBlock).toEqual(originalControl)
    expect(tree.leaves[1]!.merklePath[0]).toEqual(originalPath)
  })
})

describe('BIP-342 descriptor key canonicalization audit', () => {
  const x1 = internalKey
  const x2 = hex('c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
  const even = hex(`02${toHex(x1)}`)
  const odd = hex(`03${toHex(x1)}`)

  it('flags opposite compressed parities collapsing to one canonical key', () => {
    const audit: TapscriptKeyAuditResult = Engine.auditTapscriptKeys([even, odd])
    expect(audit).toMatchObject({ valid: true, totalKeysExamined: 2, uniqueXOnlyKeys: 1, hasParityCollisions: true, hasDuplicateXOnly: false })
    expect(audit.findings).toEqual([{ severity: 'warning', code: 'parity-collision', xHex: toHex(x1),
      message: expect.stringContaining('when converted for Tapscript'),
      compressedForms: [`compressed-02:${toHex(even)}`, `compressed-03:${toHex(odd)}`] }])
  })

  it.each([[x1, x1], [even, even], [x1, even], [x1, odd]].map(keys => ({ keys })))('flags repeated canonical x-only keys for $keys', ({ keys }) => {
    const audit = Engine.auditTapscriptKeys(keys)
    expect(audit).toMatchObject({ valid: true, uniqueXOnlyKeys: 1, hasParityCollisions: false, hasDuplicateXOnly: true })
    expect(audit.findings).toEqual([expect.objectContaining({ severity: 'info', code: 'duplicate-xonly', xHex: toHex(x1) })])
  })

  it('reports both collision classes across distinct groups with stable ordering', () => {
    const audit = Engine.auditTapscriptKeys([even, odd, x1, x2, x2])
    expect(audit).toMatchObject({ valid: true, totalKeysExamined: 5, uniqueXOnlyKeys: 2, hasParityCollisions: true, hasDuplicateXOnly: true })
    expect(audit.findings.map(finding => finding.code)).toEqual(['parity-collision', 'duplicate-xonly'])
  })

  it('returns clean findings for distinct curve keys and empty input', () => {
    expect(Engine.auditTapscriptKeys([even, x2])).toEqual({ valid: true, totalKeysExamined: 2, uniqueXOnlyKeys: 2,
      hasParityCollisions: false, hasDuplicateXOnly: false, findings: [] })
    expect(Engine.auditTapscriptKeys([])).toMatchObject({ valid: true, totalKeysExamined: 0, uniqueXOnlyKeys: 0, findings: [] })
  })

  it.each([new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), new Uint8Array(65), hex(`04${toHex(x1)}`), be(0n), be(P), hex(`02${toHex(be(P))}`)])('reports invalid or off-curve key %s', key => {
    const audit = Engine.auditTapscriptKeys([key, x1])
    expect(audit).toMatchObject({ valid: false, totalKeysExamined: 2, uniqueXOnlyKeys: 1, hasParityCollisions: false, hasDuplicateXOnly: false })
    expect(audit.findings).toEqual([expect.objectContaining({ severity: 'warning', code: 'invalid-key', message: expect.stringContaining('index 0') })])
  })

  it('does not turn repeated invalid keys into valid collision groups', () => {
    const invalid = be(0n)
    expect(Engine.auditTapscriptKeys([invalid, invalid])).toMatchObject({ valid: false, uniqueXOnlyKeys: 0, hasParityCollisions: false, hasDuplicateXOnly: false })
  })

  it('does not mutate any key input', () => {
    const keys = [even.slice(), odd.slice(), x1.slice()]
    const copies = keys.map(key => key.slice())
    Engine.auditTapscriptKeys(keys)
    expect(keys).toEqual(copies)
  })
})

describe('Taproot public exports and Secp256k1Engine helpers', () => {
  it('exports the dedicated engine and forwards every helper without changing results', () => {
    expect(BarrelEngine).toBe(Engine)
    expect(TAPROOT_LEAF_TAPSCRIPT).toBe(0xc0)
    const leaves = scripts.slice(0, 2).map(script => ({ script }))
    const tree = Engine.buildTapTree(leaves, internalKey)
    expect(Curve.tapLeafHash(scripts[0]!)).toEqual(Engine.tapLeafHash(scripts[0]!))
    expect(Curve.tapBranchHash(be(1n), be(2n))).toEqual(Engine.tapBranchHash(be(1n), be(2n)))
    expect(Curve.tapTweakHash(internalKey, tree.merkleRoot)).toEqual(Engine.tapTweakHash(internalKey, tree.merkleRoot))
    expect(Curve.inspectControlBlock(tree.leaves[0]!.controlBlock)).toEqual(Engine.inspectControlBlock(tree.leaves[0]!.controlBlock))
    expect(Curve.buildTapTree(leaves, internalKey)).toEqual(tree)
    const output = nativeOutput(tree.merkleRoot).slice(1)
    expect(Curve.verifyScriptPath(tree.leaves[0]!.controlBlock, output, scripts[0]!)).toEqual(Engine.verifyScriptPath(tree.leaves[0]!.controlBlock, output, scripts[0]!))
    expect(Curve.auditTapscriptKeys([internalKey, internalKey])).toEqual(Engine.auditTapscriptKeys([internalKey, internalKey]))
  })
})
