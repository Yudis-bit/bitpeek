import { taggedHash } from '../crypto'
import { unsignedBigEndian } from '../bytes'
import { SECP256K1_N, SECP256K1_P, SECP256K1_GX, SECP256K1_GY, liftX, pointAdd, scalarMul, type Point } from './secp256k1'
import { auditBip375Shares, type Bip375AuditParams, type Bip375AuditResult } from './bip375'

export const TAPROOT_LEAF_TAPSCRIPT = 0xc0
export const TAPROOT_CONTROL_BASE_SIZE = 33
export const TAPROOT_CONTROL_NODE_SIZE = 32
export const TAPROOT_CONTROL_MAX_NODES = 128
export const TAPROOT_CONTROL_MAX_SIZE = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODES

export interface TapLeaf {
  script: Uint8Array
  leafVersion?: number
}

/** A leaf index or a binary pair; every input leaf must occur exactly once. */
export type TapTreeStructure = number | readonly [TapTreeStructure, TapTreeStructure]

export interface TapTreeLeafInfo extends TapLeaf {
  leafVersion: number
  leafHash: Uint8Array
  merklePath: Uint8Array[]
  controlBlock: Uint8Array
}

export interface TapTreeResult {
  merkleRoot: Uint8Array
  leaves: TapTreeLeafInfo[]
}

export interface TaprootControlBlockInspection {
  isValid: boolean
  leafVersion: number
  outputParity: number
  internalKey32: Uint8Array
  pathLength: number
  merklePath: Uint8Array[]
  rawBytes: Uint8Array
  rejectionReason?: string
}

export interface TaprootScriptPathVerificationResult {
  valid: boolean
  leafVersion?: number
  outputParity?: number
  internalKey32?: Uint8Array
  merkleRoot?: Uint8Array
  pathLength?: number
  computedOutputKey32?: Uint8Array
  reason?: string
}

export interface TapscriptKeyAuditFinding {
  severity: 'warning' | 'info'
  code: 'parity-collision' | 'duplicate-xonly' | 'invalid-key'
  message: string
  xHex: string
  compressedForms?: string[]
}

export interface TapscriptKeyAuditResult {
  valid: boolean
  totalKeysExamined: number
  uniqueXOnlyKeys: number
  hasParityCollisions: boolean
  hasDuplicateXOnly: boolean
  findings: TapscriptKeyAuditFinding[]
}

function encodeCompactSize(length: number): Uint8Array {
  if (length < 0xfd) return new Uint8Array([length])
  if (length <= 0xffff) {
    const bytes = new Uint8Array(3)
    bytes[0] = 0xfd
    new DataView(bytes.buffer).setUint16(1, length, true)
    return bytes
  }
  if (length <= 0xffffffff) {
    const bytes = new Uint8Array(5)
    bytes[0] = 0xfe
    new DataView(bytes.buffer).setUint32(1, length, true)
    return bytes
  }
  const bytes = new Uint8Array(9)
  bytes[0] = 0xff
  new DataView(bytes.buffer).setBigUint64(1, BigInt(length), true)
  return bytes
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let index = 0; index < a.length; index++) {
    if (a[index] !== b[index]) return a[index]! < b[index]! ? -1 : 1
  }
  return 0
}

function bigEndian32(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32)
  for (let index = 31; index >= 0; index--) {
    bytes[index] = Number(value & 255n)
    value >>= 8n
  }
  return bytes
}

function bytesHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

function tweakedPoint(internalPoint: NonNullable<Point>, tweak: bigint): Point {
  // Resolve curve constants at call time: Secp256k1Engine also forwards to this module.
  return pointAdd(internalPoint, scalarMul(tweak, { x: SECP256K1_GX, y: SECP256K1_GY }))
}

/** Public-data BIP-341 commitment checks and descriptor key audits, without script execution. */
export class TaprootEngine {
  public static auditBip375Shares(params: Bip375AuditParams): Bip375AuditResult { return auditBip375Shares(params) }

  public static tapLeafHash(script: Uint8Array, leafVersion = TAPROOT_LEAF_TAPSCRIPT): Uint8Array {
    if (!Number.isInteger(leafVersion) || leafVersion < 0 || leafVersion > 0xff || (leafVersion & 1) !== 0) {
      throw new RangeError('Leaf version must be an even byte')
    }
    return taggedHash('TapLeaf', new Uint8Array([leafVersion]), encodeCompactSize(script.length), script)
  }

  /** Lexicographical sorting applies to each pair of 32-byte child hashes. */
  public static tapBranchHash(a32: Uint8Array, b32: Uint8Array): Uint8Array {
    if (a32.length !== 32 || b32.length !== 32) throw new RangeError('TapBranch elements must be exactly 32 bytes')
    return compareBytes(a32, b32) <= 0 ? taggedHash('TapBranch', a32, b32) : taggedHash('TapBranch', b32, a32)
  }

  public static tapTweakHash(internalKey32: Uint8Array, merkleRoot32?: Uint8Array): Uint8Array {
    if (internalKey32.length !== 32) throw new RangeError('Internal key must be 32 bytes')
    if (merkleRoot32 !== undefined && merkleRoot32.length !== 32) throw new RangeError('Merkle root must be 32 bytes when supplied')
    return taggedHash('TapTweak', internalKey32, merkleRoot32 ?? new Uint8Array(0))
  }

  public static inspectControlBlock(bytes: Uint8Array): TaprootControlBlockInspection {
    const rawBytes = new Uint8Array(bytes)
    const fail = (rejectionReason: string): TaprootControlBlockInspection => ({ isValid: false,
      leafVersion: 0, outputParity: 0, internalKey32: new Uint8Array(32), pathLength: 0, merklePath: [], rawBytes, rejectionReason })
    if (bytes.length < TAPROOT_CONTROL_BASE_SIZE) return fail(`Control block too short (${bytes.length} < 33 bytes)`)
    if ((bytes.length - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE !== 0) return fail('Control block size must be 33 + 32*m bytes')
    if (bytes.length > TAPROOT_CONTROL_MAX_SIZE) return fail(`Control block exceeds maximum depth (${TAPROOT_CONTROL_MAX_NODES} nodes)`)
    const leafVersion = bytes[0]! & 0xfe
    const outputParity = bytes[0]! & 1
    const internalKey32 = rawBytes.slice(1, TAPROOT_CONTROL_BASE_SIZE)
    if (liftX(internalKey32) === null) {
      return { ...fail('Invalid internal key X coordinate (not on curve or >= p)'), leafVersion, outputParity, internalKey32 }
    }
    const pathLength = (bytes.length - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE
    const merklePath = Array.from({ length: pathLength }, (_, index) => {
      const offset = TAPROOT_CONTROL_BASE_SIZE + index * TAPROOT_CONTROL_NODE_SIZE
      return rawBytes.slice(offset, offset + TAPROOT_CONTROL_NODE_SIZE)
    })
    return { isValid: true, leafVersion, outputParity, internalKey32, pathLength, merklePath, rawBytes }
  }

  /** Verify the script's Merkle commitment and output key, not witness/script execution. */
  public static verifyScriptPath(
    controlBlock: Uint8Array, outputKey32: Uint8Array, leafScript: Uint8Array,
  ): TaprootScriptPathVerificationResult {
    const fail = (reason: string): TaprootScriptPathVerificationResult => ({ valid: false, reason })
    if (outputKey32.length !== 32) return fail('Output key must be 32 bytes')
    if (unsignedBigEndian(outputKey32) >= SECP256K1_P) return fail('Output key X coordinate >= p')
    const inspection = this.inspectControlBlock(controlBlock)
    if (!inspection.isValid) return fail(inspection.rejectionReason!)
    let merkleRoot = this.tapLeafHash(leafScript, inspection.leafVersion)
    for (const sibling of inspection.merklePath) merkleRoot = this.tapBranchHash(merkleRoot, sibling)
    const tweak = unsignedBigEndian(this.tapTweakHash(inspection.internalKey32, merkleRoot))
    if (tweak >= SECP256K1_N) return fail('Taproot tweak scalar >= n')
    const internalPoint = liftX(inspection.internalKey32)!
    const outputPoint = tweakedPoint(internalPoint, tweak)
    if (outputPoint === null) return fail('Tweaked output point is infinity')
    if (outputPoint.x !== unsignedBigEndian(outputKey32)) return fail('Computed Taproot output key X does not match expected outputKey32')
    const outputParity = Number(outputPoint.y & 1n)
    if (outputParity !== inspection.outputParity) return fail('Computed Taproot output key Y parity does not match control block header parity')
    return { valid: true, leafVersion: inspection.leafVersion, outputParity, internalKey32: inspection.internalKey32,
      merkleRoot, pathLength: inspection.pathLength, computedOutputKey32: bigEndian32(outputPoint.x) }
  }

  /** Pair adjacent leaves at each level, carrying unpaired nodes, or use a supplied binary shape. */
  public static buildTapTree(leaves: TapLeaf[], internalKey32: Uint8Array, structure?: TapTreeStructure): TapTreeResult {
    if (leaves.length === 0) throw new RangeError('TapTree requires at least one leaf')
    if (internalKey32.length !== 32) throw new RangeError('Internal key must be 32 bytes')
    const internalPoint = liftX(internalKey32)
    if (internalPoint === null) throw new RangeError('Invalid internal key X coordinate')
    const infos = leaves.map(leaf => {
      const version = leaf.leafVersion ?? TAPROOT_LEAF_TAPSCRIPT
      return { script: new Uint8Array(leaf.script), version, hash: this.tapLeafHash(leaf.script, version), path: [] as Uint8Array[] }
    })
    interface TreeNode { hash: Uint8Array; leaves: number[] }
    const nodes: TreeNode[] = infos.map((info, index) => ({ hash: info.hash, leaves: [index] }))
    const combine = (left: TreeNode, right: TreeNode): TreeNode => {
      for (const index of left.leaves) infos[index]!.path.push(right.hash)
      for (const index of right.leaves) infos[index]!.path.push(left.hash)
      return { hash: this.tapBranchHash(left.hash, right.hash), leaves: [...left.leaves, ...right.leaves] }
    }
    let merkleRoot: Uint8Array
    if (structure === undefined) {
      let currentLevel = nodes
      while (currentLevel.length > 1) {
        const nextLevel: TreeNode[] = []
        for (let index = 0; index < currentLevel.length; index += 2) {
          nextLevel.push(index + 1 < currentLevel.length ? combine(currentLevel[index]!, currentLevel[index + 1]!) : currentLevel[index]!)
        }
        currentLevel = nextLevel
      }
      merkleRoot = currentLevel[0]!.hash
    } else {
      const used = new Set<number>()
      const walk = (node: TapTreeStructure, depth: number): TreeNode => {
        if (depth > TAPROOT_CONTROL_MAX_NODES) throw new RangeError('TapTree exceeds maximum depth (128 nodes)')
        if (typeof node === 'number') {
          if (!Number.isSafeInteger(node) || node < 0 || node >= nodes.length) throw new RangeError('TapTree leaf index is out of range')
          if (used.has(node)) throw new RangeError('TapTree structure repeats a leaf index')
          used.add(node)
          return nodes[node]!
        }
        if (!Array.isArray(node) || node.length !== 2) throw new RangeError('TapTree branches must contain exactly two children')
        return combine(walk(node[0], depth + 1), walk(node[1], depth + 1))
      }
      merkleRoot = walk(structure, 0).hash
      if (used.size !== leaves.length) throw new RangeError('TapTree structure must include every leaf')
    }
    const tweak = unsignedBigEndian(this.tapTweakHash(internalKey32, merkleRoot))
    if (tweak >= SECP256K1_N) throw new RangeError('Taproot tweak scalar >= n')
    const outputPoint = tweakedPoint(internalPoint, tweak)
    if (outputPoint === null) throw new RangeError('Taproot output point is infinity')
    const outputParity = Number(outputPoint.y & 1n)
    const finalLeaves: TapTreeLeafInfo[] = infos.map(info => {
      const controlBlock = new Uint8Array(TAPROOT_CONTROL_BASE_SIZE + info.path.length * TAPROOT_CONTROL_NODE_SIZE)
      controlBlock[0] = info.version | outputParity
      controlBlock.set(internalKey32, 1)
      info.path.forEach((node, index) => controlBlock.set(node, TAPROOT_CONTROL_BASE_SIZE + index * TAPROOT_CONTROL_NODE_SIZE))
      return { script: info.script, leafVersion: info.version, leafHash: info.hash.slice(),
        merklePath: info.path.map(node => node.slice()), controlBlock }
    })
    return { merkleRoot: merkleRoot.slice(), leaves: finalLeaves }
  }

  /** Audit descriptor keys after x-only canonicalization. Raw 33-byte keys embedded
   * in Tapscript are unknown key types under BIP-342, not automatically converted.
   * A parity-collision finding takes precedence over a duplicate finding for its X.
   */
  public static auditTapscriptKeys(pubkeys: Uint8Array[]): TapscriptKeyAuditResult {
    const groups = new Map<string, { forms: Set<string>; count: number }>()
    const findings: TapscriptKeyAuditFinding[] = []
    for (const [index, key] of pubkeys.entries()) {
      const compressed = key.length === 33 && (key[0] === 2 || key[0] === 3)
      if (key.length !== 32 && !compressed) {
        findings.push({ severity: 'warning', code: 'invalid-key', xHex: bytesHex(key),
          message: `Public key at index ${index} has unsupported length or prefix (${key.length} bytes)` })
        continue
      }
      const xBytes = compressed ? key.subarray(1) : key
      const xHex = bytesHex(xBytes)
      if (liftX(xBytes) === null) {
        findings.push({ severity: 'warning', code: 'invalid-key', xHex,
          message: `Public key at index ${index} has an invalid X coordinate (not on curve or >= p)` })
        continue
      }
      const group = groups.get(xHex) ?? { forms: new Set<string>(), count: 0 }
      group.forms.add(compressed ? `compressed-0${key[0]}:${bytesHex(key)}` : `x-only:${xHex}`)
      group.count++
      groups.set(xHex, group)
    }
    let hasParityCollisions = false
    let hasDuplicateXOnly = false
    for (const [xHex, group] of groups) {
      const compressedForms = Array.from(group.forms)
      if (compressedForms.some(form => form.startsWith('compressed-02')) && compressedForms.some(form => form.startsWith('compressed-03'))) {
        hasParityCollisions = true
        findings.push({ severity: 'warning', code: 'parity-collision', xHex, compressedForms,
          message: `Parity collision: 02 and 03 compressed forms canonicalize to the same x-only key ${xHex} when converted for Tapscript.` })
      } else if (group.count > 1) {
        hasDuplicateXOnly = true
        findings.push({ severity: 'info', code: 'duplicate-xonly', xHex, compressedForms,
          message: `Duplicate x-only key ${xHex} appears ${group.count} times in spending conditions.` })
      }
    }
    return { valid: !findings.some(finding => finding.code === 'invalid-key'), totalKeysExamined: pubkeys.length,
      uniqueXOnlyKeys: groups.size, hasParityCollisions, hasDuplicateXOnly, findings }
  }
}
