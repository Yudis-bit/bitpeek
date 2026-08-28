import { describe, expect, it } from 'vitest'
import {
  crc16CcittFalse,
  crc32Ieee,
  detectFileSignature,
  findBytePattern,
  formatFloat,
  parseHexPattern,
  parseOffset,
  readFloat16,
  readFloat32,
  readFloat64,
  shannonEntropy,
  sum8,
  xor8,
} from './analysis'
import { encodeText } from './bytes'

describe('byte pattern search', () => {
  it('finds overlapping matches', () => {
    const parsed = parseHexPattern('AA AA')
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(
      findBytePattern(Uint8Array.from([0xaa, 0xaa, 0xaa]), parsed.pattern),
    ).toEqual({ offsets: [0, 1], truncated: false })
  })

  it('supports byte and nibble wildcards', () => {
    const parsed = parseHexPattern('D? AD ?? EF')
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(
      findBytePattern(
        Uint8Array.from([0xde, 0xad, 0x00, 0xef, 0xdf, 0xad, 0xff, 0xef]),
        parsed.pattern,
      ).offsets,
    ).toEqual([0, 4])
  })

  it('reports malformed patterns and truncates large result sets', () => {
    expect(parseHexPattern('DE A')).toEqual({
      ok: false,
      error: 'Search pattern must contain complete bytes.',
    })
    const parsed = parseHexPattern('??')
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(findBytePattern(Uint8Array.from([1, 2, 3]), parsed.pattern, 2)).toEqual({
      offsets: [0, 1],
      truncated: true,
    })
  })
})

describe('offset parsing', () => {
  it('accepts decimal and prefixed hexadecimal offsets', () => {
    expect(parseOffset('15', 32)).toEqual({ ok: true, value: 15 })
    expect(parseOffset('0x1F', 32)).toEqual({ ok: true, value: 31 })
  })

  it('rejects malformed and out-of-range offsets', () => {
    expect(parseOffset('FF', 32).ok).toBe(false)
    expect(parseOffset('32', 32)).toEqual({
      ok: false,
      error: 'Offset must be between 0 and 31.',
    })
  })
})

describe('floating-point interpretation', () => {
  it('reads float16 special and normal values', () => {
    expect(readFloat16(Uint8Array.from([0x3c, 0x00]), 'big')).toBe(1)
    expect(readFloat16(Uint8Array.from([0xc1, 0x00]), 'big')).toBe(-2.5)
    expect(readFloat16(Uint8Array.from([0x00, 0x01]), 'big')).toBe(2 ** -24)
    expect(Object.is(readFloat16(Uint8Array.from([0x80, 0x00]), 'big'), -0)).toBe(true)
  })

  it('reads float32 and float64 in both byte orders', () => {
    expect(readFloat32(Uint8Array.from([0x3f, 0x80, 0x00, 0x00]), 'big')).toBe(1)
    expect(readFloat32(Uint8Array.from([0x00, 0x00, 0x80, 0x3f]), 'little')).toBe(1)
    expect(
      readFloat64(
        Uint8Array.from([0x3f, 0xf0, 0, 0, 0, 0, 0, 0]),
        'big',
      ),
    ).toBe(1)
  })

  it('formats non-finite values and negative zero explicitly', () => {
    expect(formatFloat(Number.NaN)).toBe('NaN')
    expect(formatFloat(Infinity)).toBe('+Infinity')
    expect(formatFloat(-Infinity)).toBe('-Infinity')
    expect(formatFloat(-0)).toBe('-0')
  })
})

describe('checksums and entropy', () => {
  const bytes = encodeText('123456789')

  it('matches standard checksum vectors', () => {
    expect(crc32Ieee(bytes).toString(16).toUpperCase()).toBe('CBF43926')
    expect(crc16CcittFalse(bytes).toString(16).toUpperCase()).toBe('29B1')
    expect(sum8(bytes).toString(16).toUpperCase()).toBe('DD')
    expect(xor8(bytes).toString(16).toUpperCase()).toBe('31')
  })

  it('computes bounded Shannon entropy', () => {
    expect(shannonEntropy(new Uint8Array(32))).toBe(0)
    expect(shannonEntropy(Uint8Array.from({ length: 256 }, (_, index) => index))).toBe(8)
  })
})

describe('file signatures', () => {
  it('detects representative magic-byte formats', () => {
    expect(
      detectFileSignature(
        Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      ),
    ).toEqual({ name: 'PNG image', mime: 'image/png' })
    expect(detectFileSignature(encodeText('%PDF-1.7'))?.name).toBe('PDF document')
    expect(detectFileSignature(Uint8Array.from([1, 2, 3]))).toBeNull()
  })
})
