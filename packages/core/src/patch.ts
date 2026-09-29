import { BitpeekError } from './errors'
import { sha256Hex } from './crypto'

export interface OffsetPatchChange {
  offset: number
  remove: string
  insert: string
}

export interface OffsetPatchOperation {
  offset: number
  bytes: string
  precondition?: string
}

export interface OffsetPatchFileV1Changes {
  format: 'bitpeek-offset-patch'
  version: 1
  semantics: 'reference-to-current'
  source: {
    name: string
    length: number
    sha256?: string
  }
  target: {
    name: string
    length: number
    sha256?: string
  }
  changes: OffsetPatchChange[]
}

export interface OffsetPatchFileV1Operations {
  format: 'bitpeek-offset-patch'
  version: 1
  targetLength: number
  referenceName?: string
  currentName?: string
  referenceSha256?: string
  currentSha256?: string
  operations: OffsetPatchOperation[]
}

export type OffsetPatchFileV1 = OffsetPatchFileV1Changes | OffsetPatchFileV1Operations

export interface OffsetPatchFileV2 {
  format: 'bitpeek-offset-patch'
  version: 2
  sourceLength: number
  targetLength: number
  sourceSha256: string
  targetSha256: string
  operations: OffsetPatchOperation[]
}

export type AnyOffsetPatchFile = OffsetPatchFileV1 | OffsetPatchFileV2

// Backward-compatible alias for existing consumers
export type OffsetPatchFile = OffsetPatchFileV1Changes

export type PatchIntegrityLevel = 'verified-hashes' | 'preconditions-only'

export interface PatchValidationSuccess {
  ok: true
  patch: AnyOffsetPatchFile
  dialect: 'v1-changes' | 'v1-operations' | 'v2'
}

export interface PatchValidationFailure {
  ok: false
  error: string
}

export type PatchValidationResult = PatchValidationSuccess | PatchValidationFailure

export interface PatchVerificationSuccess {
  ok: true
  integrity: PatchIntegrityLevel
  sourceSha256Matches?: boolean
  targetSha256Matches?: boolean
}

export interface PatchVerificationFailure {
  ok: false
  error: string
}

export type PatchVerificationResult = PatchVerificationSuccess | PatchVerificationFailure

export interface ApplyPatchSuccess {
  ok: true
  target: Uint8Array
  integrity: PatchIntegrityLevel
}

export interface ApplyPatchFailure {
  ok: false
  error: string
}

export type ApplyPatchResult = ApplyPatchSuccess | ApplyPatchFailure

const MAX_TARGET_BYTES = 512 * 1024 * 1024 // 512 MiB limit
const MAX_PATCH_CHANGES = 50_000

function isValidHex(hex: string): boolean {
  const clean = hex.replace(/\s+/g, '')
  if (clean.length % 2 !== 0) return false
  return /^[0-9a-fA-F]*$/.test(clean)
}

export function parseHexBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '')
  if (clean === '') return new Uint8Array(0)
  if (!isValidHex(clean)) {
    throw new BitpeekError('INVALID_INPUT', 'Malformed hexadecimal string in patch.')
  }
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

export function formatHexBytes(bytes: Uint8Array): string {
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] ?? 0).toString(16).toUpperCase().padStart(2, '0')
  }
  return hex
}

export function validateOffsetPatch(input: unknown): PatchValidationResult {
  if (typeof input !== 'object' || input === null) {
    return { ok: false, error: 'Patch must be a valid JSON object.' }
  }

  const obj = input as Record<string, unknown>

  if (obj['format'] !== 'bitpeek-offset-patch') {
    return { ok: false, error: 'Unsupported patch format; expected "bitpeek-offset-patch".' }
  }

  const version = obj['version']
  if (version !== 1 && version !== 2) {
    return { ok: false, error: `Unsupported patch version; expected version 1 or 2, got ${version}.` }
  }

  // Dialect Detection: v2
  if (version === 2) {
    const sourceLength = obj['sourceLength']
    const targetLength = obj['targetLength']
    const sourceSha = obj['sourceSha256']
    const targetSha = obj['targetSha256']
    const rawOps = obj['operations']

    if (!Number.isSafeInteger(sourceLength) || (sourceLength as number) < 0) {
      return { ok: false, error: 'Patch sourceLength must be a non-negative safe integer.' }
    }
    if (!Number.isSafeInteger(targetLength) || (targetLength as number) < 0) {
      return { ok: false, error: 'Patch targetLength must be a non-negative safe integer.' }
    }
    if ((targetLength as number) > MAX_TARGET_BYTES) {
      return { ok: false, error: `Patch targetLength exceeds budget of ${MAX_TARGET_BYTES} bytes.` }
    }
    if (typeof sourceSha !== 'string' || !/^[0-9a-fA-F]{64}$/.test(sourceSha)) {
      return { ok: false, error: 'Patch v2 requires a valid 64-character sourceSha256 hex string.' }
    }
    if (typeof targetSha !== 'string' || !/^[0-9a-fA-F]{64}$/.test(targetSha)) {
      return { ok: false, error: 'Patch v2 requires a valid 64-character targetSha256 hex string.' }
    }
    if (!Array.isArray(rawOps)) {
      return { ok: false, error: 'Patch v2 operations must be an array.' }
    }
    if (rawOps.length > MAX_PATCH_CHANGES) {
      return { ok: false, error: `Patch contains too many operations (${rawOps.length} > ${MAX_PATCH_CHANGES}).` }
    }

    const operations: OffsetPatchOperation[] = []
    let lastOffset = -1
    let lastLen = 0

    for (let i = 0; i < rawOps.length; i++) {
      const op = rawOps[i] as Record<string, unknown> | null
      if (!op || typeof op !== 'object') {
        return { ok: false, error: `Operation at index ${i} is not an object.` }
      }
      const offset = op['offset']
      if (!Number.isSafeInteger(offset) || (offset as number) < 0) {
        return { ok: false, error: `Operation at index ${i} has invalid offset: ${offset}` }
      }
      const bytes = op['bytes']
      if (typeof bytes !== 'string' || !isValidHex(bytes)) {
        return { ok: false, error: `Operation at index ${i} has invalid bytes hex string.` }
      }
      const precondition = op['precondition']
      if (precondition !== undefined && (typeof precondition !== 'string' || !isValidHex(precondition))) {
        return { ok: false, error: `Operation at index ${i} has invalid precondition hex string.` }
      }

      const byteLen = bytes.replace(/\s+/g, '').length / 2
      if ((offset as number) + byteLen > (targetLength as number)) {
        return { ok: false, error: `Operation at index ${i} exceeds target length.` }
      }

      if (i > 0 && (offset as number) < lastOffset + lastLen) {
        return { ok: false, error: `Operation at index ${i} overlaps with preceding operation at offset ${lastOffset}.` }
      }

      lastOffset = offset as number
      lastLen = byteLen
      operations.push({
        offset: offset as number,
        bytes,
        ...(precondition ? { precondition } : {}),
      })
    }

    return {
      ok: true,
      dialect: 'v2',
      patch: {
        format: 'bitpeek-offset-patch',
        version: 2,
        sourceLength: sourceLength as number,
        targetLength: targetLength as number,
        sourceSha256: sourceSha.toLowerCase(),
        targetSha256: targetSha.toLowerCase(),
        operations,
      },
    }
  }

  // Dialect Detection: v1 (changes dialect vs operations dialect)
  const rawChanges = obj['changes']
  const rawOps = obj['operations']

  if (Array.isArray(rawOps)) {
    // v1-operations dialect
    const targetLength = obj['targetLength']
    if (!Number.isSafeInteger(targetLength) || (targetLength as number) < 0) {
      return { ok: false, error: 'Patch v1 operations dialect requires targetLength.' }
    }
    const operations: OffsetPatchOperation[] = []
    let lastOffset = -1
    let lastLen = 0

    for (let i = 0; i < rawOps.length; i++) {
      const op = rawOps[i] as Record<string, unknown> | null
      if (!op || typeof op !== 'object') {
        return { ok: false, error: `Operation at index ${i} is not an object.` }
      }
      const offset = op['offset']
      if (!Number.isSafeInteger(offset) || (offset as number) < 0) {
        return { ok: false, error: `Operation at index ${i} has invalid offset: ${offset}` }
      }
      const bytes = op['bytes']
      if (typeof bytes !== 'string' || !isValidHex(bytes)) {
        return { ok: false, error: `Operation at index ${i} has invalid bytes hex string.` }
      }
      const precondition = op['precondition']
      if (precondition !== undefined && (typeof precondition !== 'string' || !isValidHex(precondition))) {
        return { ok: false, error: `Operation at index ${i} has invalid precondition hex string.` }
      }
      const byteLen = bytes.replace(/\s+/g, '').length / 2
      if (i > 0 && (offset as number) < lastOffset + lastLen) {
        return { ok: false, error: `Operation at index ${i} overlaps with preceding operation.` }
      }
      lastOffset = offset as number
      lastLen = byteLen
      operations.push({
        offset: offset as number,
        bytes,
        ...(precondition ? { precondition } : {}),
      })
    }

    return {
      ok: true,
      dialect: 'v1-operations',
      patch: {
        format: 'bitpeek-offset-patch',
        version: 1,
        targetLength: targetLength as number,
        referenceName: typeof obj['referenceName'] === 'string' ? obj['referenceName'] : undefined,
        currentName: typeof obj['currentName'] === 'string' ? obj['currentName'] : undefined,
        referenceSha256: typeof obj['referenceSha256'] === 'string' ? obj['referenceSha256'].toLowerCase() : undefined,
        currentSha256: typeof obj['currentSha256'] === 'string' ? obj['currentSha256'].toLowerCase() : undefined,
        operations,
      },
    }
  }

  // v1-changes dialect (legacy internal format)
  const source = obj['source'] as Record<string, unknown> | undefined
  const target = obj['target'] as Record<string, unknown> | undefined

  if (!source || typeof source !== 'object') {
    return { ok: false, error: 'Patch source metadata is missing.' }
  }
  if (!target || typeof target !== 'object') {
    return { ok: false, error: 'Patch target metadata is missing.' }
  }

  const sourceLength = source['length']
  if (!Number.isSafeInteger(sourceLength) || (sourceLength as number) < 0) {
    return { ok: false, error: 'Patch source length must be a non-negative safe integer.' }
  }

  const targetLength = target['length']
  if (!Number.isSafeInteger(targetLength) || (targetLength as number) < 0) {
    return { ok: false, error: 'Patch target length must be a non-negative safe integer.' }
  }
  if ((targetLength as number) > MAX_TARGET_BYTES) {
    return { ok: false, error: `Patch target length exceeds maximum budget of ${MAX_TARGET_BYTES} bytes.` }
  }

  const sourceSha = source['sha256']
  if (sourceSha !== undefined) {
    if (typeof sourceSha !== 'string' || !/^[0-9a-fA-F]{64}$/.test(sourceSha)) {
      return { ok: false, error: 'Invalid source SHA-256 hash in patch.' }
    }
  }

  const targetSha = target['sha256']
  if (targetSha !== undefined) {
    if (typeof targetSha !== 'string' || !/^[0-9a-fA-F]{64}$/.test(targetSha)) {
      return { ok: false, error: 'Invalid target SHA-256 hash in patch.' }
    }
  }

  if (!Array.isArray(rawChanges)) {
    return { ok: false, error: 'Patch changes must be an array.' }
  }
  if (rawChanges.length > MAX_PATCH_CHANGES) {
    return { ok: false, error: `Patch contains too many changes (${rawChanges.length} > ${MAX_PATCH_CHANGES}).` }
  }

  const changes: OffsetPatchChange[] = []
  let lastOffset = -1
  let lastRemoveLen = 0

  for (let i = 0; i < rawChanges.length; i++) {
    const change = rawChanges[i] as Record<string, unknown> | null
    if (!change || typeof change !== 'object') {
      return { ok: false, error: `Change at index ${i} is not an object.` }
    }

    const offset = change['offset']
    if (!Number.isSafeInteger(offset) || (offset as number) < 0) {
      return { ok: false, error: `Change at index ${i} has an invalid offset.` }
    }

    const remove = change['remove']
    if (typeof remove !== 'string' || !isValidHex(remove)) {
      return { ok: false, error: `Change at index ${i} has an invalid remove hex string.` }
    }

    const insert = change['insert']
    if (typeof insert !== 'string' || !isValidHex(insert)) {
      return { ok: false, error: `Change at index ${i} has an invalid insert hex string.` }
    }

    const removeByteLen = remove.length / 2
    const insertByteLen = insert.length / 2

    if ((offset as number) + removeByteLen > (sourceLength as number)) {
      return { ok: false, error: `Change at index ${i} removal exceeds source length.` }
    }
    if ((offset as number) + insertByteLen > (targetLength as number)) {
      return { ok: false, error: `Change at index ${i} insertion exceeds target length.` }
    }

    if (i > 0 && (offset as number) < lastOffset + lastRemoveLen) {
      return { ok: false, error: `Change at index ${i} overlaps with preceding change at offset ${lastOffset}.` }
    }

    lastOffset = offset as number
    lastRemoveLen = removeByteLen
    changes.push({
      offset: offset as number,
      remove,
      insert,
    })
  }

  return {
    ok: true,
    dialect: 'v1-changes',
    patch: {
      format: 'bitpeek-offset-patch',
      version: 1,
      semantics: 'reference-to-current',
      source: {
        name: typeof source['name'] === 'string' ? source['name'] : 'reference.bin',
        length: sourceLength as number,
        ...(sourceSha ? { sha256: (sourceSha as string).toLowerCase() } : {}),
      },
      target: {
        name: typeof target['name'] === 'string' ? target['name'] : 'current.bin',
        length: targetLength as number,
        ...(targetSha ? { sha256: (targetSha as string).toLowerCase() } : {}),
      },
      changes,
    },
  }
}

export function verifyPatch(
  reference: Uint8Array,
  patch: AnyOffsetPatchFile,
): PatchVerificationResult {
  let expectedSourceLength: number | undefined
  let expectedSourceSha: string | undefined
  let expectedTargetSha: string | undefined

  if (patch.version === 2) {
    expectedSourceLength = patch.sourceLength
    expectedSourceSha = patch.sourceSha256
    expectedTargetSha = patch.targetSha256
  } else if ('source' in patch) {
    expectedSourceLength = patch.source.length
    expectedSourceSha = patch.source.sha256
    expectedTargetSha = patch.target.sha256
  } else {
    expectedSourceSha = patch.referenceSha256
    expectedTargetSha = patch.currentSha256
  }

  if (expectedSourceLength !== undefined && reference.length !== expectedSourceLength) {
    return {
      ok: false,
      error: `Reference size mismatch: file has ${reference.length} bytes, patch expects ${expectedSourceLength} bytes.`,
    }
  }

  let sourceSha256Matches: boolean | undefined
  if (expectedSourceSha) {
    const actualSourceSha = sha256Hex(reference).toLowerCase()
    if (actualSourceSha !== expectedSourceSha.toLowerCase()) {
      return {
        ok: false,
        error: `Source SHA-256 mismatch: expected ${expectedSourceSha}, got ${actualSourceSha}.`,
      }
    }
    sourceSha256Matches = true
  }

  // Preconditions verification
  if ('operations' in patch) {
    for (const op of patch.operations) {
      if (op.precondition) {
        const preBytes = parseHexBytes(op.precondition)
        for (let j = 0; j < preBytes.length; j++) {
          if (reference[op.offset + j] !== preBytes[j]) {
            return {
              ok: false,
              error: `Precondition failed at offset ${op.offset + j}: expected 0x${(preBytes[j] ?? 0).toString(16).padStart(2, '0')}, found 0x${(reference[op.offset + j] ?? 0).toString(16).padStart(2, '0')}.`,
            }
          }
        }
      }
    }
  } else if ('changes' in patch) {
    for (let i = 0; i < patch.changes.length; i++) {
      const change = patch.changes[i]!
      const removeBytes = parseHexBytes(change.remove)
      for (let j = 0; j < removeBytes.length; j++) {
        if (reference[change.offset + j] !== removeBytes[j]) {
          return {
            ok: false,
            error: `Precondition failed at offset ${change.offset + j}: expected 0x${(removeBytes[j] ?? 0).toString(16).padStart(2, '0')}, found 0x${(reference[change.offset + j] ?? 0).toString(16).padStart(2, '0')}.`,
          }
        }
      }
    }
  }

  const integrity: PatchIntegrityLevel =
    expectedSourceSha && expectedTargetSha ? 'verified-hashes' : 'preconditions-only'

  return {
    ok: true,
    integrity,
    sourceSha256Matches,
  }
}

export function applyVerifiedPatch(
  reference: Uint8Array,
  patch: AnyOffsetPatchFile,
): ApplyPatchResult {
  const verification = verifyPatch(reference, patch)
  if (!verification.ok) {
    return { ok: false, error: verification.error }
  }

  let targetLength: number
  let expectedTargetSha: string | undefined

  if (patch.version === 2) {
    targetLength = patch.targetLength
    expectedTargetSha = patch.targetSha256
  } else if ('source' in patch) {
    targetLength = patch.target.length
    expectedTargetSha = patch.target.sha256
  } else {
    targetLength = patch.targetLength
    expectedTargetSha = patch.currentSha256
  }

  const target = new Uint8Array(targetLength)
  target.set(reference.subarray(0, Math.min(reference.length, targetLength)))

  if ('operations' in patch) {
    for (const op of patch.operations) {
      const bytes = parseHexBytes(op.bytes)
      target.set(bytes, op.offset)
    }
  } else if ('changes' in patch) {
    for (const change of patch.changes) {
      const insertBytes = parseHexBytes(change.insert)
      target.set(insertBytes, change.offset)
    }
  }

  if (expectedTargetSha) {
    const actualTargetSha = sha256Hex(target).toLowerCase()
    if (actualTargetSha !== expectedTargetSha.toLowerCase()) {
      return {
        ok: false,
        error: `Target SHA-256 mismatch after applying patch: expected ${expectedTargetSha}, computed ${actualTargetSha}.`,
      }
    }
  }

  return {
    ok: true,
    target,
    integrity: verification.integrity,
  }
}
