import { BitpeekError } from './errors'
import { sha256Hex } from './crypto'

export interface OffsetPatchChange {
  offset: number
  remove: string
  insert: string
}

export interface OffsetPatchFile {
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

export type PatchIntegrityLevel = 'verified-hashes' | 'preconditions-only'

export interface PatchValidationSuccess {
  ok: true
  patch: OffsetPatchFile
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
  if (hex.length % 2 !== 0) return false
  return /^[0-9a-fA-F]*$/.test(hex)
}

export function parseHexBytes(hex: string): Uint8Array {
  if (hex === '') return new Uint8Array(0)
  if (!isValidHex(hex)) {
    throw new BitpeekError('INVALID_INPUT', 'Malformed hexadecimal string in patch.')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
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
  if (obj['version'] !== 1) {
    return { ok: false, error: 'Unsupported patch version; expected version 1.' }
  }
  if (obj['semantics'] !== 'reference-to-current') {
    return { ok: false, error: 'Unsupported patch semantics; expected "reference-to-current".' }
  }

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

  const rawChanges = obj['changes']
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

    // Overlap check: changes must be strictly sorted by offset and not overlap
    if (i > 0) {
      if ((offset as number) < lastOffset + lastRemoveLen) {
        return { ok: false, error: `Change at index ${i} overlaps with preceding change at offset ${lastOffset}.` }
      }
    }

    lastOffset = offset as number
    lastRemoveLen = removeByteLen

    changes.push({
      offset: offset as number,
      remove,
      insert,
    })
  }

  const validated: OffsetPatchFile = {
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
  }

  return { ok: true, patch: validated }
}

export function verifyPatch(
  reference: Uint8Array,
  patch: OffsetPatchFile,
): PatchVerificationResult {
  if (reference.length !== patch.source.length) {
    return {
      ok: false,
      error: `Reference size mismatch: file has ${reference.length} bytes, patch expects ${patch.source.length} bytes.`,
    }
  }

  let sourceSha256Matches: boolean | undefined
  if (patch.source.sha256) {
    const actualSourceSha = sha256Hex(reference).toLowerCase()
    if (actualSourceSha !== patch.source.sha256.toLowerCase()) {
      return {
        ok: false,
        error: `Source SHA-256 mismatch: expected ${patch.source.sha256}, got ${actualSourceSha}.`,
      }
    }
    sourceSha256Matches = true
  }

  // Verify byte preconditions
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

  const integrity: PatchIntegrityLevel =
    patch.source.sha256 && patch.target.sha256 ? 'verified-hashes' : 'preconditions-only'

  return {
    ok: true,
    integrity,
    sourceSha256Matches,
  }
}

export function applyVerifiedPatch(
  reference: Uint8Array,
  patch: OffsetPatchFile,
): ApplyPatchResult {
  const verification = verifyPatch(reference, patch)
  if (!verification.ok) {
    return { ok: false, error: verification.error }
  }

  // Allocate atomic target buffer
  const target = new Uint8Array(patch.target.length)
  target.set(reference.subarray(0, Math.min(reference.length, target.length)))

  for (const change of patch.changes) {
    const insertBytes = parseHexBytes(change.insert)
    target.set(insertBytes, change.offset)
  }

  if (patch.target.sha256) {
    const actualTargetSha = sha256Hex(target).toLowerCase()
    if (actualTargetSha !== patch.target.sha256.toLowerCase()) {
      return {
        ok: false,
        error: `Target SHA-256 mismatch after applying patch: expected ${patch.target.sha256}, computed ${actualTargetSha}.`,
      }
    }
  }

  return {
    ok: true,
    target,
    integrity: verification.integrity,
  }
}
