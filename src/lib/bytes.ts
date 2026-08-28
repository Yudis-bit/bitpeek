export const INPUT_MODES = ['hex', 'binary', 'decimal', 'text', 'base64'] as const

export type InputMode = (typeof INPUT_MODES)[number]

export type ParseResult =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; error: string }

export interface ByteSelection {
  anchor: number
  focus: number
}

export interface SelectionRange {
  start: number
  end: number
  length: number
}

const utf8Encoder = new TextEncoder()
const utf8Decoder = new TextDecoder('utf-8', {
  fatal: false,
  ignoreBOM: true,
})
const fatalUtf8Decoder = new TextDecoder('utf-8', {
  fatal: true,
  ignoreBOM: true,
})

function success(values: number[]): ParseResult {
  return { ok: true, bytes: Uint8Array.from(values) }
}

export function parseHex(input: string): ParseResult {
  if (input.trim() === '') return success([])

  const values: number[] = []
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
          'Hex prefix at position ' +
          (tokenStart + 1) +
          ' is not followed by a byte.',
      }
    }

    for (let index = 0; index < digits.length; index += 1) {
      if (!/[0-9a-fA-F]/.test(digits[index] ?? '')) {
        return {
          ok: false,
          error:
            'Invalid hexadecimal character at position ' +
            (digitStart + index + 1) +
            '.',
        }
      }
    }

    if (digits.length % 2 !== 0) {
      return cursor === input.length
        ? { ok: false, error: 'Incomplete hex byte at the end of input.' }
        : {
            ok: false,
            error: 'Incomplete hex byte before position ' + (cursor + 1) + '.',
          }
    }

    for (let index = 0; index < digits.length; index += 2) {
      values.push(Number.parseInt(digits.slice(index, index + 2), 16))
    }
  }

  if (values.length === 0) {
    return { ok: false, error: 'Hex input contains no bytes.' }
  }

  return success(values)
}

export function parseBinary(input: string): ParseResult {
  if (input.trim() === '') return success([])

  const groups = input.trim().split(/\s+/)
  const values: number[] = []

  for (let index = 0; index < groups.length; index += 1) {
    const group = groups[index] ?? ''
    if (!/^[01]+$/.test(group)) {
      return {
        ok: false,
        error: `Invalid binary digit in byte ${index + 1}.`,
      }
    }
    if (group.length !== 8) {
      return {
        ok: false,
        error: `Byte ${index + 1} must contain exactly 8 bits.`,
      }
    }
    values.push(Number.parseInt(group, 2))
  }

  return success(values)
}

export function parseDecimal(input: string): ParseResult {
  if (input.trim() === '') return success([])

  const groups = input.trim().split(/[\s,]+/)
  const values: number[] = []

  for (let index = 0; index < groups.length; index += 1) {
    const group = groups[index] ?? ''
    if (!/^[+-]?\d+$/.test(group)) {
      return {
        ok: false,
        error: `Byte ${index + 1} must be an integer.`,
      }
    }

    const value = Number(group)
    if (value < 0 || value > 255) {
      return {
        ok: false,
        error: `Byte ${index + 1} is outside the valid range 0–255.`,
      }
    }
    values.push(value)
  }

  return success(values)
}

export function encodeText(input: string): Uint8Array {
  return utf8Encoder.encode(input)
}

export function decodeUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes)
}

export function isValidUtf8(bytes: Uint8Array): boolean {
  try {
    fatalUtf8Decoder.decode(bytes)
    return true
  } catch {
    return false
  }
}

export function parseBase64(input: string): ParseResult {
  if (input.trim() === '') return success([])

  for (let index = 0; index < input.length; index += 1) {
    const character = input[index] ?? ''
    if (!/\s|[A-Za-z0-9+/=_-]/.test(character)) {
      return {
        ok: false,
        error: 'Invalid Base64 character at position ' + (index + 1) + '.',
      }
    }
  }

  const compact = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  const paddingIndex = compact.indexOf('=')
  const unpadded = paddingIndex === -1 ? compact : compact.slice(0, paddingIndex)
  const padding = paddingIndex === -1 ? '' : compact.slice(paddingIndex)

  if ((!/^={1,2}$/.test(padding) && padding !== '') || unpadded.includes('=')) {
    return { ok: false, error: 'Base64 padding is only valid at the end.' }
  }
  if (padding !== '' && compact.length % 4 !== 0) {
    return { ok: false, error: 'Invalid Base64 padding.' }
  }
  if (unpadded.length % 4 === 1) {
    return { ok: false, error: 'Incomplete Base64 input.' }
  }

  const padded =
    unpadded + (padding || '='.repeat((4 - (unpadded.length % 4)) % 4))
  try {
    const decoded = atob(padded)
    return success(Array.from(decoded, (character) => character.charCodeAt(0)))
  } catch {
    return { ok: false, error: 'Invalid Base64 input.' }
  }
}

export function parseInput(input: string, mode: InputMode): ParseResult {
  switch (mode) {
    case 'hex':
      return parseHex(input)
    case 'binary':
      return parseBinary(input)
    case 'decimal':
      return parseDecimal(input)
    case 'text':
      return { ok: true, bytes: encodeText(input) }
    case 'base64':
      return parseBase64(input)
  }
}

export function formatHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) =>
    byte.toString(16).toUpperCase().padStart(2, '0'),
  ).join(' ')
}

export function formatBinary(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(2).padStart(8, '0')).join(
    ' ',
  )
}

export function formatDecimal(bytes: Uint8Array): string {
  return Array.from(bytes).join(' ')
}

export function formatBase64(bytes: Uint8Array): string {
  let binary = ''
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize))
  }
  return btoa(binary)
}

export function formatInput(bytes: Uint8Array, mode: InputMode): string {
  switch (mode) {
    case 'hex':
      return formatHex(bytes)
    case 'binary':
      return formatBinary(bytes)
    case 'decimal':
      return formatDecimal(bytes)
    case 'text':
      return decodeUtf8(bytes)
    case 'base64':
      return formatBase64(bytes)
  }
}

export function byteToAscii(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.'
}

export function formatAscii(bytes: Uint8Array): string {
  return Array.from(bytes, byteToAscii).join('')
}

export function formatUtf8Preview(bytes: Uint8Array): string {
  const decoded = decodeUtf8(bytes)
  let output = ''

  for (const character of decoded) {
    const codePoint = character.codePointAt(0) ?? 0
    if (character === '\\') output += '\\\\'
    else if (character === '\n') output += '\\n'
    else if (character === '\r') output += '\\r'
    else if (character === '\t') output += '\\t'
    else if (character === '\0') output += '\\0'
    else if (character === '\uFFFD') output += '\\uFFFD'
    else if (codePoint < 0x20 || codePoint === 0x7f) {
      output += `\\x${codePoint.toString(16).toUpperCase().padStart(2, '0')}`
    } else output += character
  }

  return output
}

export function unsignedBigEndian(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value
}

export function unsignedLittleEndian(bytes: Uint8Array): bigint {
  let value = 0n
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0)
  }
  return value
}

export function signedFromUnsigned(value: bigint, widthInBits: number): bigint {
  if (widthInBits <= 0) return 0n
  const signBit = 1n << BigInt(widthInBits - 1)
  const modulus = 1n << BigInt(widthInBits)
  const normalized = value & (modulus - 1n)
  return (normalized & signBit) === 0n ? normalized : normalized - modulus
}

export function signedBigEndian(bytes: Uint8Array): bigint {
  return signedFromUnsigned(unsignedBigEndian(bytes), bytes.length * 8)
}

export function signedLittleEndian(bytes: Uint8Array): bigint {
  return signedFromUnsigned(unsignedLittleEndian(bytes), bytes.length * 8)
}

export function getSelectionRange(
  selection: ByteSelection | null,
  byteLength: number,
): SelectionRange | null {
  if (selection === null || byteLength === 0) return null

  const anchor = Math.max(0, Math.min(byteLength - 1, selection.anchor))
  const focus = Math.max(0, Math.min(byteLength - 1, selection.focus))
  const start = Math.min(anchor, focus)
  const end = Math.max(anchor, focus)
  return { start, end, length: end - start + 1 }
}

export function sliceSelection(
  bytes: Uint8Array,
  selection: ByteSelection | null,
): Uint8Array {
  const range = getSelectionRange(selection, bytes.length)
  return range === null ? new Uint8Array() : bytes.slice(range.start, range.end + 1)
}

export function setByte(
  bytes: Uint8Array,
  index: number,
  value: number,
): Uint8Array {
  if (!Number.isInteger(index) || index < 0 || index >= bytes.length) {
    throw new RangeError('Byte index is outside the array.')
  }
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new RangeError('Byte value must be an integer from 0 to 255.')
  }

  const result = bytes.slice()
  result[index] = value
  return result
}

export function toggleBit(
  bytes: Uint8Array,
  index: number,
  bit: number,
): Uint8Array {
  if (!Number.isInteger(bit) || bit < 0 || bit > 7) {
    throw new RangeError('Bit index must be an integer from 0 to 7.')
  }
  const current = bytes[index]
  if (current === undefined) {
    throw new RangeError('Byte index is outside the array.')
  }
  return setByte(bytes, index, current ^ (1 << bit))
}
