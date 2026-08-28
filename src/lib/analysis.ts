import { encodeText } from './bytes'

export type Endianness = 'big' | 'little'
export type SearchMode = 'hex' | 'text'

export interface BytePattern {
  values: Uint8Array
  masks: Uint8Array
}

export type PatternParseResult =
  | { ok: true; pattern: BytePattern }
  | { ok: false; error: string }

export interface PatternMatches {
  offsets: number[]
  truncated: boolean
}

export type OffsetParseResult =
  | { ok: true; value: number }
  | { ok: false; error: string }

export interface FileSignature {
  name: string
  mime: string
}

const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, value) => {
  let remainder = value
  for (let bit = 0; bit < 8; bit += 1) {
    remainder =
      (remainder & 1) === 1
        ? 0xedb88320 ^ (remainder >>> 1)
        : remainder >>> 1
  }
  return remainder >>> 0
})

function patternSuccess(
  nibbles: Array<{ value: number; mask: number }>,
): PatternParseResult {
  const values: number[] = []
  const masks: number[] = []
  for (let index = 0; index < nibbles.length; index += 2) {
    const high = nibbles[index]
    const low = nibbles[index + 1]
    if (high && low) {
      values.push((high.value << 4) | low.value)
      masks.push((high.mask << 4) | low.mask)
    }
  }
  return {
    ok: true,
    pattern: {
      values: Uint8Array.from(values),
      masks: Uint8Array.from(masks),
    },
  }
}

export function parseHexPattern(input: string): PatternParseResult {
  if (input.trim() === '') {
    return {
      ok: true,
      pattern: { values: new Uint8Array(), masks: new Uint8Array() },
    }
  }

  const nibbles: Array<{ value: number; mask: number }> = []
  let cursor = 0

  while (cursor < input.length) {
    while (cursor < input.length && /[\s,:-]/.test(input[cursor] ?? '')) {
      cursor += 1
    }
    if (cursor >= input.length) break

    const tokenStart = cursor
    while (cursor < input.length && !/[\s,:-]/.test(input[cursor] ?? '')) {
      cursor += 1
    }
    const token = input.slice(tokenStart, cursor)
    const hasPrefix = token.startsWith('0x') || token.startsWith('0X')
    const digits = hasPrefix ? token.slice(2) : token
    const digitStart = tokenStart + (hasPrefix ? 2 : 0)

    if (digits.length === 0) {
      return {
        ok: false,
        error:
          'Pattern prefix at position ' + (tokenStart + 1) + ' is incomplete.',
      }
    }
    if (digits.length % 2 !== 0) {
      return { ok: false, error: 'Search pattern must contain complete bytes.' }
    }

    for (let index = 0; index < digits.length; index += 1) {
      const character = digits[index] ?? ''
      if (character === '?') nibbles.push({ value: 0, mask: 0 })
      else if (/[0-9a-fA-F]/.test(character)) {
        nibbles.push({ value: Number.parseInt(character, 16), mask: 0xf })
      } else {
        return {
          ok: false,
          error:
            'Invalid pattern character at position ' +
            (digitStart + index + 1) +
            '.',
        }
      }
    }
  }

  return patternSuccess(nibbles)
}

export function parseSearchPattern(
  input: string,
  mode: SearchMode,
): PatternParseResult {
  if (mode === 'hex') return parseHexPattern(input)
  const encoded = encodeText(input)
  return {
    ok: true,
    pattern: {
      values: encoded,
      masks: new Uint8Array(encoded.length).fill(0xff),
    },
  }
}

export function findBytePattern(
  bytes: Uint8Array,
  pattern: BytePattern,
  limit = 10_000,
): PatternMatches {
  if (pattern.values.length === 0 || pattern.values.length > bytes.length) {
    return { offsets: [], truncated: false }
  }

  const offsets: number[] = []
  const finalStart = bytes.length - pattern.values.length
  for (let start = 0; start <= finalStart; start += 1) {
    let matches = true
    for (let index = 0; index < pattern.values.length; index += 1) {
      const mask = pattern.masks[index] ?? 0
      const actual = (bytes[start + index] ?? 0) & mask
      const expected = (pattern.values[index] ?? 0) & mask
      if (actual !== expected) {
        matches = false
        break
      }
    }
    if (matches) {
      if (offsets.length === limit) return { offsets, truncated: true }
      offsets.push(start)
    }
  }
  return { offsets, truncated: false }
}

export function parseOffset(
  input: string,
  byteLength: number,
): OffsetParseResult {
  const trimmed = input.trim()
  if (trimmed === '') return { ok: false, error: 'Enter an offset.' }

  const isHex = /^0x/i.test(trimmed)
  const digits = isHex ? trimmed.slice(2) : trimmed
  const valid = isHex ? /^[0-9a-fA-F]+$/.test(digits) : /^\d+$/.test(digits)
  if (!valid) {
    return {
      ok: false,
      error: 'Offset must be decimal or prefixed hexadecimal.',
    }
  }

  const value = Number.parseInt(digits, isHex ? 16 : 10)
  if (!Number.isSafeInteger(value) || value < 0 || value >= byteLength) {
    return {
      ok: false,
      error:
        byteLength === 0
          ? 'No bytes to navigate.'
          : 'Offset must be between 0 and ' + (byteLength - 1) + '.',
    }
  }
  return { ok: true, value }
}

function dataView(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
}

export function readFloat16(
  bytes: Uint8Array,
  endian: Endianness,
): number {
  if (bytes.length !== 2) {
    throw new RangeError('Float16 requires exactly 2 bytes.')
  }
  const raw = dataView(bytes).getUint16(0, endian === 'little')
  const sign = (raw & 0x8000) === 0 ? 1 : -1
  const exponent = (raw >>> 10) & 0x1f
  const fraction = raw & 0x03ff
  if (exponent === 0x1f) return fraction === 0 ? sign * Infinity : Number.NaN
  if (exponent === 0) {
    if (fraction === 0) return sign === -1 ? -0 : 0
    return sign * fraction * 2 ** -24
  }
  return sign * (1 + fraction / 1024) * 2 ** (exponent - 15)
}

export function readFloat32(
  bytes: Uint8Array,
  endian: Endianness,
): number {
  if (bytes.length !== 4) {
    throw new RangeError('Float32 requires exactly 4 bytes.')
  }
  return dataView(bytes).getFloat32(0, endian === 'little')
}

export function readFloat64(
  bytes: Uint8Array,
  endian: Endianness,
): number {
  if (bytes.length !== 8) {
    throw new RangeError('Float64 requires exactly 8 bytes.')
  }
  return dataView(bytes).getFloat64(0, endian === 'little')
}

export function formatFloat(value: number): string {
  if (Number.isNaN(value)) return 'NaN'
  if (value === Infinity) return '+Infinity'
  if (value === -Infinity) return '-Infinity'
  if (Object.is(value, -0)) return '-0'
  return String(value)
}

export function sum8(bytes: Uint8Array): number {
  let result = 0
  for (const byte of bytes) result = (result + byte) & 0xff
  return result
}

export function xor8(bytes: Uint8Array): number {
  let result = 0
  for (const byte of bytes) result ^= byte
  return result
}

export function crc16CcittFalse(bytes: Uint8Array): number {
  let crc = 0xffff
  for (const byte of bytes) {
    crc ^= byte << 8
    for (let bit = 0; bit < 8; bit += 1) {
      crc =
        (crc & 0x8000) !== 0
          ? ((crc << 1) ^ 0x1021) & 0xffff
          : (crc << 1) & 0xffff
    }
  }
  return crc
}

export function crc32Ieee(bytes: Uint8Array): number {
  let crc = 0xffffffff
  for (const byte of bytes) {
    crc = (crc >>> 8) ^ (CRC32_TABLE[(crc ^ byte) & 0xff] ?? 0)
  }
  return (crc ^ 0xffffffff) >>> 0
}

export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0
  const counts = new Uint32Array(256)
  for (const byte of bytes) counts[byte] = (counts[byte] ?? 0) + 1
  let entropy = 0
  for (const count of counts) {
    if (count === 0) continue
    const probability = count / bytes.length
    entropy -= probability * Math.log2(probability)
  }
  return entropy
}

function startsWith(bytes: Uint8Array, signature: number[]): boolean {
  return signature.every((value, index) => bytes[index] === value)
}

function asciiAt(bytes: Uint8Array, offset: number, text: string): boolean {
  return Array.from(text).every(
    (character, index) => bytes[offset + index] === character.charCodeAt(0),
  )
}

export function detectFileSignature(
  bytes: Uint8Array,
): FileSignature | null {
  if (
    startsWith(bytes, [
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ])
  ) {
    return { name: 'PNG image', mime: 'image/png' }
  }
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) {
    return { name: 'JPEG image', mime: 'image/jpeg' }
  }
  if (asciiAt(bytes, 0, 'GIF87a') || asciiAt(bytes, 0, 'GIF89a')) {
    return { name: 'GIF image', mime: 'image/gif' }
  }
  if (asciiAt(bytes, 0, '%PDF-')) {
    return { name: 'PDF document', mime: 'application/pdf' }
  }
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) {
    return { name: 'ZIP archive', mime: 'application/zip' }
  }
  if (startsWith(bytes, [0x1f, 0x8b])) {
    return { name: 'Gzip stream', mime: 'application/gzip' }
  }
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) {
    return { name: 'ELF executable', mime: 'application/x-elf' }
  }
  if (startsWith(bytes, [0x00, 0x61, 0x73, 0x6d])) {
    return { name: 'WebAssembly module', mime: 'application/wasm' }
  }
  if (asciiAt(bytes, 0, 'SQLite format 3\0')) {
    return { name: 'SQLite database', mime: 'application/vnd.sqlite3' }
  }
  if (startsWith(bytes, [0x42, 0x4d])) {
    return { name: 'BMP image', mime: 'image/bmp' }
  }
  if (asciiAt(bytes, 0, 'RIFF') && asciiAt(bytes, 8, 'WAVE')) {
    return { name: 'WAVE audio', mime: 'audio/wav' }
  }
  if (asciiAt(bytes, 0, 'RIFF') && asciiAt(bytes, 8, 'WEBP')) {
    return { name: 'WebP image', mime: 'image/webp' }
  }
  return null
}
