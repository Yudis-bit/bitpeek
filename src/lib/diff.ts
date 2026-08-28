import { formatHex, parseHex } from './bytes'

export type DifferenceKind = 'modified' | 'current-only' | 'reference-only'

export interface DifferenceRange {
  start: number
  end: number
  length: number
  kind: DifferenceKind
}

export interface ByteDiff {
  offsets: number[]
  ranges: DifferenceRange[]
  modified: number
  currentOnly: number
  referenceOnly: number
}

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

interface PatchMetadata {
  referenceName?: string
  currentName?: string
  referenceSha256?: string
  currentSha256?: string
}

function differenceKind(
  current: Uint8Array,
  reference: Uint8Array,
  offset: number,
): DifferenceKind | null {
  if (offset >= current.length) return 'reference-only'
  if (offset >= reference.length) return 'current-only'
  return current[offset] === reference[offset] ? null : 'modified'
}

export function diffBytes(
  current: Uint8Array,
  reference: Uint8Array,
): ByteDiff {
  const offsets: number[] = []
  const ranges: DifferenceRange[] = []
  let modified = 0
  let currentOnly = 0
  let referenceOnly = 0
  let activeRange: DifferenceRange | null = null
  const length = Math.max(current.length, reference.length)

  for (let offset = 0; offset < length; offset += 1) {
    const kind = differenceKind(current, reference, offset)
    if (kind === null) {
      activeRange = null
      continue
    }

    offsets.push(offset)
    if (kind === 'modified') modified += 1
    else if (kind === 'current-only') currentOnly += 1
    else referenceOnly += 1

    if (
      activeRange &&
      activeRange.kind === kind &&
      activeRange.end === offset - 1
    ) {
      activeRange.end = offset
      activeRange.length += 1
    } else {
      activeRange = { start: offset, end: offset, length: 1, kind }
      ranges.push(activeRange)
    }
  }

  return { offsets, ranges, modified, currentOnly, referenceOnly }
}

export function createOffsetPatch(
  reference: Uint8Array,
  current: Uint8Array,
  metadata: PatchMetadata = {},
): OffsetPatchFile {
  const diff = diffBytes(current, reference)
  const changes = diff.ranges.map((range) => ({
    offset: range.start,
    remove: formatHex(reference.slice(range.start, range.end + 1)),
    insert: formatHex(current.slice(range.start, range.end + 1)),
  }))

  return {
    format: 'bitpeek-offset-patch',
    version: 1,
    semantics: 'reference-to-current',
    source: {
      name: metadata.referenceName ?? 'reference.bin',
      length: reference.length,
      ...(metadata.referenceSha256
        ? { sha256: metadata.referenceSha256 }
        : {}),
    },
    target: {
      name: metadata.currentName ?? 'current.bin',
      length: current.length,
      ...(metadata.currentSha256 ? { sha256: metadata.currentSha256 } : {}),
    },
    changes,
  }
}

function parsePatchBytes(value: string): Uint8Array {
  const parsed = parseHex(value)
  if (!parsed.ok) throw new TypeError('Patch contains malformed hexadecimal data.')
  return parsed.bytes
}

export function applyOffsetPatch(
  reference: Uint8Array,
  patch: OffsetPatchFile,
): Uint8Array {
  if (
    patch.format !== 'bitpeek-offset-patch' ||
    patch.version !== 1 ||
    patch.semantics !== 'reference-to-current'
  ) {
    throw new TypeError('Unsupported bitpeek patch format.')
  }
  if (reference.length !== patch.source.length) {
    throw new RangeError('Reference length does not match the patch source.')
  }

  const result = new Uint8Array(patch.target.length)
  result.set(reference.subarray(0, Math.min(reference.length, result.length)))

  for (const change of patch.changes) {
    if (!Number.isInteger(change.offset) || change.offset < 0) {
      throw new RangeError('Patch change has an invalid offset.')
    }
    const remove = change.remove === '' ? new Uint8Array() : parsePatchBytes(change.remove)
    const insert = change.insert === '' ? new Uint8Array() : parsePatchBytes(change.insert)
    if (change.offset + remove.length > reference.length) {
      throw new RangeError('Patch removal is outside the reference bytes.')
    }
    for (let index = 0; index < remove.length; index += 1) {
      if (reference[change.offset + index] !== remove[index]) {
        throw new Error('Reference bytes do not match the patch precondition.')
      }
    }
    if (change.offset + insert.length > result.length) {
      throw new RangeError('Patch insertion is outside the target bytes.')
    }
    result.set(insert, change.offset)
  }

  return result
}

export function serializeOffsetPatch(patch: OffsetPatchFile): string {
  return JSON.stringify(patch, null, 2) + '\n'
}
