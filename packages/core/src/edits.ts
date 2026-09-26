import { BitpeekError } from './errors'

export interface BytePatch {
  start: number
  before: Uint8Array
  after: Uint8Array
  label: string
}

export type RangeOperation = 'reverse' | 'invert' | 'xor-mask' | 'fill' | 'byteswap'

export interface TransformOptions {
  xorMask?: Uint8Array
  fillByte?: number
  groupWidth?: 2 | 4 | 8
}

export function createPatch(
  before: Uint8Array,
  after: Uint8Array,
  start: number,
  endInclusive: number,
  label: string,
): BytePatch {
  if (before.length !== after.length) {
    throw new RangeError('Byte patches require arrays of equal length.')
  }
  if (start < 0 || endInclusive < start || endInclusive >= before.length) {
    throw new RangeError('Patch range is outside the byte array.')
  }
  return {
    start,
    before: before.slice(start, endInclusive + 1),
    after: after.slice(start, endInclusive + 1),
    label,
  }
}

export function applyPatch(
  bytes: Uint8Array,
  patch: BytePatch,
  direction: 'undo' | 'redo',
): Uint8Array {
  const values = direction === 'undo' ? patch.before : patch.after
  if (patch.start < 0 || patch.start + values.length > bytes.length) {
    throw new RangeError('Patch range is outside the byte array.')
  }
  const result = bytes.slice()
  result.set(values, patch.start)
  return result
}

export function transformRange(
  bytes: Uint8Array,
  start: number,
  endInclusive: number,
  operation: RangeOperation,
  options: TransformOptions = {},
): Uint8Array {
  if (start < 0 || endInclusive < start || endInclusive >= bytes.length) {
    throw new RangeError('Transform range is outside the byte array.')
  }
  const length = endInclusive - start + 1
  const result = bytes.slice()

  switch (operation) {
    case 'reverse': {
      for (
        let left = start, right = endInclusive;
        left < right;
        left += 1, right -= 1
      ) {
        const leftValue = result[left] ?? 0
        result[left] = result[right] ?? 0
        result[right] = leftValue
      }
      break
    }

    case 'invert': {
      for (let index = start; index <= endInclusive; index += 1) {
        result[index] = (result[index] ?? 0) ^ 0xff
      }
      break
    }

    case 'xor-mask': {
      const mask = options.xorMask
      if (!mask || mask.length === 0) {
        throw new BitpeekError('INVALID_INPUT', 'XOR mask must be a non-empty byte sequence.')
      }
      for (let i = 0; i < length; i++) {
        const maskByte = mask[i % mask.length] ?? 0
        result[start + i] = (result[start + i] ?? 0) ^ maskByte
      }
      break
    }

    case 'fill': {
      const fillByte = options.fillByte
      if (
        fillByte === undefined ||
        !Number.isInteger(fillByte) ||
        fillByte < 0 ||
        fillByte > 255
      ) {
        throw new BitpeekError(
          'INVALID_INPUT',
          'Fill operation requires an integer byte value from 0 to 255.',
        )
      }
      result.fill(fillByte, start, endInclusive + 1)
      break
    }

    case 'byteswap': {
      const groupWidth = options.groupWidth
      if (groupWidth !== 2 && groupWidth !== 4 && groupWidth !== 8) {
        throw new BitpeekError(
          'INVALID_INPUT',
          'Byteswap group width must be 2, 4, or 8 bytes.',
        )
      }
      if (length % groupWidth !== 0) {
        throw new BitpeekError(
          'INVALID_RANGE',
          `Selection length (${length}) must be a multiple of group width (${groupWidth}) for byteswap.`,
        )
      }
      for (let offset = start; offset <= endInclusive; offset += groupWidth) {
        for (let i = 0, j = groupWidth - 1; i < j; i++, j--) {
          const temp = result[offset + i] ?? 0
          result[offset + i] = result[offset + j] ?? 0
          result[offset + j] = temp
        }
      }
      break
    }
  }

  return result
}

export function patchesSize(patches: BytePatch[]): number {
  return patches.reduce(
    (total, patch) => total + patch.before.length + patch.after.length,
    0,
  )
}

export function appendPatch(
  patches: BytePatch[],
  patch: BytePatch,
  maximumBytes = 32 * 1024 * 1024,
): BytePatch[] {
  const result = [...patches, patch]
  while (result.length > 1 && patchesSize(result) > maximumBytes) {
    result.shift()
  }
  return result
}

// Unified Transaction Model for Document State (F06)
export type DocumentTransaction =
  | {
      type: 'patch'
      patch: BytePatch
      label: string
    }
  | {
      type: 'replace'
      before: Uint8Array
      after: Uint8Array
      label: string
    }

export interface UnifiedHistoryState {
  undo: DocumentTransaction[]
  redo: DocumentTransaction[]
}

export function createEmptyHistory(): UnifiedHistoryState {
  return { undo: [], redo: [] }
}

export function pushTransaction(
  history: UnifiedHistoryState,
  tx: DocumentTransaction,
  maxEntries = 100,
): UnifiedHistoryState {
  const undo = [...history.undo, tx]
  while (undo.length > maxEntries) undo.shift()
  return { undo, redo: [] }
}

export function applyUndo(
  currentBytes: Uint8Array,
  history: UnifiedHistoryState,
): { nextBytes: Uint8Array; history: UnifiedHistoryState; label: string } | null {
  const tx = history.undo.at(-1)
  if (!tx) return null

  let nextBytes: Uint8Array
  if (tx.type === 'patch') {
    nextBytes = applyPatch(currentBytes, tx.patch, 'undo')
  } else {
    nextBytes = tx.before.slice()
  }

  return {
    nextBytes,
    history: {
      undo: history.undo.slice(0, -1),
      redo: [...history.redo, tx],
    },
    label: tx.label,
  }
}

export function applyRedo(
  currentBytes: Uint8Array,
  history: UnifiedHistoryState,
): { nextBytes: Uint8Array; history: UnifiedHistoryState; label: string } | null {
  const tx = history.redo.at(-1)
  if (!tx) return null

  let nextBytes: Uint8Array
  if (tx.type === 'patch') {
    nextBytes = applyPatch(currentBytes, tx.patch, 'redo')
  } else {
    nextBytes = tx.after.slice()
  }

  return {
    nextBytes,
    history: {
      undo: [...history.undo, tx],
      redo: history.redo.slice(0, -1),
    },
    label: tx.label,
  }
}
