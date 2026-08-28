export type ExtractedStringEncoding = 'ASCII' | 'UTF-16LE' | 'UTF-16BE'

export interface ExtractedString {
  offset: number
  byteLength: number
  characterLength: number
  encoding: ExtractedStringEncoding
  value: string
}

export interface StringScanResult {
  items: ExtractedString[]
  truncated: boolean
}

function isPrintableAscii(value: number): boolean {
  return value >= 0x20 && value <= 0x7e
}

function codeUnitsToString(values: ArrayLike<number>): string {
  const chunkSize = 0x8000
  let result = ''
  for (let offset = 0; offset < values.length; offset += chunkSize) {
    const chunk: number[] = []
    const end = Math.min(values.length, offset + chunkSize)
    for (let index = offset; index < end; index += 1) {
      chunk.push(values[index] ?? 0)
    }
    result += String.fromCharCode(...chunk)
  }
  return result
}

function scanAscii(
  bytes: Uint8Array,
  minimumLength: number,
): ExtractedString[] {
  const result: ExtractedString[] = []
  let start = -1

  for (let offset = 0; offset <= bytes.length; offset += 1) {
    const printable = offset < bytes.length && isPrintableAscii(bytes[offset] ?? 0)
    if (printable && start === -1) start = offset
    if (!printable && start !== -1) {
      const length = offset - start
      if (length >= minimumLength) {
        result.push({
          offset: start,
          byteLength: length,
          characterLength: length,
          encoding: 'ASCII',
          value: codeUnitsToString(bytes.subarray(start, offset)),
        })
      }
      start = -1
    }
  }

  return result
}

function scanAsciiLikeUtf16(
  bytes: Uint8Array,
  minimumLength: number,
  littleEndian: boolean,
): ExtractedString[] {
  const result: ExtractedString[] = []

  for (let alignment = 0; alignment < 2; alignment += 1) {
    let start = -1
    let characters: number[] = []

    for (let offset = alignment; offset <= bytes.length - 2; offset += 2) {
      const first = bytes[offset] ?? 0
      const second = bytes[offset + 1] ?? 0
      const value = littleEndian ? first : second
      const zero = littleEndian ? second : first
      const printable = zero === 0 && isPrintableAscii(value)

      if (printable) {
        if (start === -1) start = offset
        characters.push(value)
      } else if (start !== -1) {
        if (characters.length >= minimumLength) {
          result.push({
            offset: start,
            byteLength: characters.length * 2,
            characterLength: characters.length,
            encoding: littleEndian ? 'UTF-16LE' : 'UTF-16BE',
            value: codeUnitsToString(characters),
          })
        }
        start = -1
        characters = []
      }
    }

    if (start !== -1 && characters.length >= minimumLength) {
      result.push({
        offset: start,
        byteLength: characters.length * 2,
        characterLength: characters.length,
        encoding: littleEndian ? 'UTF-16LE' : 'UTF-16BE',
        value: codeUnitsToString(characters),
      })
    }
  }

  return result
}

export function extractPrintableStrings(
  bytes: Uint8Array,
  minimumLength = 4,
  limit = 2_000,
): StringScanResult {
  if (!Number.isInteger(minimumLength) || minimumLength < 2 || minimumLength > 64) {
    throw new RangeError('Minimum string length must be an integer from 2 to 64.')
  }
  if (!Number.isInteger(limit) || limit < 1) {
    throw new RangeError('String result limit must be a positive integer.')
  }

  const all = [
    ...scanAscii(bytes, minimumLength),
    ...scanAsciiLikeUtf16(bytes, minimumLength, true),
    ...scanAsciiLikeUtf16(bytes, minimumLength, false),
  ].sort((left, right) => left.offset - right.offset || left.byteLength - right.byteLength)

  return {
    items: all.slice(0, limit),
    truncated: all.length > limit,
  }
}

export function formatStringReport(items: ExtractedString[]): string {
  return items
    .map(
      (item) =>
        '0x' +
        item.offset.toString(16).toUpperCase().padStart(6, '0') +
        '\t' +
        item.encoding +
        '\t' +
        item.byteLength +
        '\t' +
        JSON.stringify(item.value),
    )
    .join('\n')
}
