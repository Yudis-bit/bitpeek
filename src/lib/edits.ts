export interface BytePatch {
  start: number
  before: Uint8Array
  after: Uint8Array
  label: string
}

export type RangeOperation = 'reverse' | 'invert'

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
): Uint8Array {
  if (start < 0 || endInclusive < start || endInclusive >= bytes.length) {
    throw new RangeError('Transform range is outside the byte array.')
  }
  const result = bytes.slice()
  if (operation === 'reverse') {
    for (
      let left = start, right = endInclusive;
      left < right;
      left += 1, right -= 1
    ) {
      const leftValue = result[left] ?? 0
      result[left] = result[right] ?? 0
      result[right] = leftValue
    }
  } else {
    for (let index = start; index <= endInclusive; index += 1) {
      result[index] = (result[index] ?? 0) ^ 0xff
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
  maximumBytes = 16 * 1024 * 1024,
): BytePatch[] {
  const result = [...patches, patch]
  while (result.length > 1 && patchesSize(result) > maximumBytes) result.shift()
  return result
}
