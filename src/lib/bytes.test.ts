import { describe, expect, it } from 'vitest'
import {
  encodeText,
  decodeUtf8,
  formatAscii,
  formatBase64,
  formatBinary,
  formatDecimal,
  formatHex,
  formatUtf8Preview,
  isValidUtf8,
  getSelectionRange,
  parseBinary,
  parseBase64,
  parseDecimal,
  parseHex,
  signedBigEndian,
  signedLittleEndian,
  signedFromUnsigned,
  sliceSelection,
  toggleBit,
  unsignedBigEndian,
  unsignedLittleEndian,
} from './bytes'

function expectBytes(
  result: ReturnType<typeof parseHex>,
  expected: number[],
): void {
  expect(result.ok).toBe(true)
  if (result.ok) expect(Array.from(result.bytes)).toEqual(expected)
}

describe('hex parsing', () => {
  it('parses contiguous hex', () => {
    expectBytes(parseHex('deadbeef'), [0xde, 0xad, 0xbe, 0xef])
  })

  it('parses spaced hex', () => {
    expectBytes(parseHex('DE AD BE EF'), [0xde, 0xad, 0xbe, 0xef])
  })

  it('parses prefixed hex', () => {
    expectBytes(parseHex('0xDEADBEEF'), [0xde, 0xad, 0xbe, 0xef])
    expectBytes(parseHex('0xDE 0xAD 0xBE 0xEF'), [0xde, 0xad, 0xbe, 0xef])
  })

  it('accepts common separators', () => {
    expectBytes(parseHex('DE:AD-BE, EF'), [0xde, 0xad, 0xbe, 0xef])
  })

  it('rejects invalid and incomplete hex', () => {
    expect(parseHex('DE AG')).toEqual({
      ok: false,
      error: 'Invalid hexadecimal character at position 5.',
    })
    expect(parseHex('DEA')).toEqual({
      ok: false,
      error: 'Incomplete hex byte at the end of input.',
    })
    expect(parseHex('DE 0x')).toEqual({
      ok: false,
      error: 'Hex prefix at position 4 is not followed by a byte.',
    })
    expect(parseHex('DE0xAD')).toEqual({
      ok: false,
      error: 'Invalid hexadecimal character at position 4.',
    })
    expect(parseHex('D E')).toEqual({
      ok: false,
      error: 'Incomplete hex byte before position 2.',
    })
    expect(parseHex('::')).toEqual({
      ok: false,
      error: 'Hex input contains no bytes.',
    })
  })

  it('treats empty input as an empty byte array', () => {
    const result = parseHex('  ')
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.bytes).toHaveLength(0)
  })
})

describe('binary and decimal parsing', () => {
  it('parses complete binary bytes', () => {
    const result = parseBinary('11011110 10101101')
    expect(result.ok).toBe(true)
    if (result.ok) expect(Array.from(result.bytes)).toEqual([0xde, 0xad])
  })

  it('rejects malformed binary', () => {
    expect(parseBinary('101')).toEqual({
      ok: false,
      error: 'Byte 1 must contain exactly 8 bits.',
    })
    expect(parseBinary('1111111x')).toEqual({
      ok: false,
      error: 'Invalid binary digit in byte 1.',
    })
  })

  it('parses decimal bytes with spaces and commas', () => {
    const result = parseDecimal('222, 173 190,239')
    expect(result.ok).toBe(true)
    if (result.ok) expect(Array.from(result.bytes)).toEqual([222, 173, 190, 239])
  })

  it('rejects decimal bytes outside the valid range', () => {
    expect(parseDecimal('12 256')).toEqual({
      ok: false,
      error: 'Byte 2 is outside the valid range 0–255.',
    })
    expect(parseDecimal('-1')).toEqual({
      ok: false,
      error: 'Byte 1 is outside the valid range 0–255.',
    })
  })
})

describe('text and formatting', () => {
  it('encodes UTF-8 text', () => {
    expect(Array.from(encodeText('Aé'))).toEqual([0x41, 0xc3, 0xa9])
  })

  it('formats byte representations', () => {
    const bytes = Uint8Array.from([0xde, 0x20, 0x41])
    expect(formatHex(bytes)).toBe('DE 20 41')
    expect(formatBinary(bytes)).toBe('11011110 00100000 01000001')
    expect(formatDecimal(bytes)).toBe('222 32 65')
    expect(formatAscii(bytes)).toBe('. A')
  })

  it('escapes invalid UTF-8 replacement markers clearly', () => {
    expect(formatUtf8Preview(Uint8Array.from([0xff]))).toBe('\\uFFFD')
  })

  it('preserves UTF-8 BOM bytes and reports invalid sequences', () => {
    const bomText = Uint8Array.from([0xef, 0xbb, 0xbf, 0x41])
    expect(decodeUtf8(bomText)).toBe('\uFEFFA')
    expect(Array.from(encodeText(decodeUtf8(bomText)))).toEqual(Array.from(bomText))
    expect(isValidUtf8(bomText)).toBe(true)
    expect(isValidUtf8(Uint8Array.from([0xff]))).toBe(false)
    expect(isValidUtf8(Uint8Array.from([0xe2, 0x82]))).toBe(false)
  })
})

describe('Base64 parsing and formatting', () => {
  it('round-trips the default sample', () => {
    const bytes = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80])
    expect(formatBase64(bytes)).toBe('3q2+7wABf4A=')
    const result = parseBase64('3q2+7wABf4A=')
    expect(result.ok).toBe(true)
    if (result.ok) expect(Array.from(result.bytes)).toEqual(Array.from(bytes))
  })

  it('accepts whitespace and unpadded URL-safe input', () => {
    const spaced = parseBase64('3q2+\n7wABf4A=')
    expect(spaced.ok).toBe(true)
    const urlSafe = parseBase64('3q2-7wABf4A')
    expect(urlSafe.ok).toBe(true)
    if (urlSafe.ok) {
      expect(Array.from(urlSafe.bytes)).toEqual([
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80,
      ])
    }
  })

  it('round-trips every byte value', () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, index) => index)
    const result = parseBase64(formatBase64(bytes))
    expect(result.ok).toBe(true)
    if (result.ok) expect(Array.from(result.bytes)).toEqual(Array.from(bytes))
  })

  it('rejects malformed Base64', () => {
    expect(parseBase64('A')).toEqual({
      ok: false,
      error: 'Incomplete Base64 input.',
    })
    expect(parseBase64('AA=A')).toEqual({
      ok: false,
      error: 'Base64 padding is only valid at the end.',
    })
    expect(parseBase64('AA$=')).toEqual({
      ok: false,
      error: 'Invalid Base64 character at position 3.',
    })
  })
})

describe('integer interpretation', () => {
  const deadbeef = Uint8Array.from([0xde, 0xad, 0xbe, 0xef])

  it('matches known DEADBEEF endian conversions', () => {
    expect(unsignedBigEndian(deadbeef)).toBe(3735928559n)
    expect(signedBigEndian(deadbeef)).toBe(-559038737n)
    expect(unsignedLittleEndian(deadbeef)).toBe(4022250974n)
    expect(signedLittleEndian(deadbeef)).toBe(-272716322n)
  })

  it('uses two’s-complement for signed values', () => {
    expect(signedBigEndian(Uint8Array.from([0xff]))).toBe(-1n)
    expect(signedBigEndian(Uint8Array.from([0x80, 0x00]))).toBe(-32768n)
    expect(signedLittleEndian(Uint8Array.from([0x00, 0x80]))).toBe(-32768n)
    expect(signedFromUnsigned(0x1ffn, 8)).toBe(-1n)
  })

  it('preserves full uint64 precision with BigInt', () => {
    const maximum = Uint8Array.from([
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ])
    expect(unsignedBigEndian(maximum)).toBe(18446744073709551615n)
    expect(unsignedBigEndian(maximum).toString()).toBe('18446744073709551615')
    expect(signedBigEndian(maximum)).toBe(-1n)
  })
})

describe('selection and mutation', () => {
  it('normalizes and slices a reversed selection', () => {
    const bytes = Uint8Array.from([10, 20, 30, 40])
    expect(getSelectionRange({ anchor: 3, focus: 1 }, bytes.length)).toEqual({
      start: 1,
      end: 3,
      length: 3,
    })
    expect(Array.from(sliceSelection(bytes, { anchor: 3, focus: 1 }))).toEqual([
      20, 30, 40,
    ])
  })

  it('toggles a bit without mutating the source array', () => {
    const source = Uint8Array.from([0x00, 0xaa])
    const changed = toggleBit(source, 0, 7)
    expect(Array.from(changed)).toEqual([0x80, 0xaa])
    expect(Array.from(source)).toEqual([0x00, 0xaa])
  })
})
