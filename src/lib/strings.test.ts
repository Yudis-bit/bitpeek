import { describe, expect, it } from 'vitest'
import { encodeText } from './bytes'
import { extractPrintableStrings, formatStringReport } from './strings'

describe('printable string extraction', () => {
  it('finds ASCII strings with byte offsets', () => {
    const bytes = Uint8Array.from([0, ...encodeText('bitpeek'), 0xff])
    const result = extractPrintableStrings(bytes, 4)
    expect(result.items).toContainEqual({
      offset: 1,
      byteLength: 7,
      characterLength: 7,
      encoding: 'ASCII',
      value: 'bitpeek',
    })
  })

  it('finds ASCII-like UTF-16 strings in both byte orders', () => {
    const bytes = Uint8Array.from([
      0x48, 0x00, 0x69, 0x00, 0x21, 0x00,
      0xff,
      0x00, 0x42, 0x00, 0x45, 0x00, 0x21,
    ])
    const result = extractPrintableStrings(bytes, 3)
    expect(result.items.some((item) => item.encoding === 'UTF-16LE' && item.value === 'Hi!')).toBe(true)
    expect(result.items.some((item) => item.encoding === 'UTF-16BE' && item.value === 'BE!')).toBe(true)
  })

  it('enforces result limits and formats a reproducible report', () => {
    const bytes = encodeText('first\0second\0third')
    const result = extractPrintableStrings(bytes, 4, 2)
    expect(result.truncated).toBe(true)
    expect(result.items).toHaveLength(2)
    expect(formatStringReport(result.items)).toContain('0x000000\tASCII')
  })

  it('handles a document-sized printable string without overflowing the stack', () => {
    const bytes = new Uint8Array(256 * 1024).fill(0x41)
    const result = extractPrintableStrings(bytes, 4)
    expect(result.items[0]?.value.length).toBe(bytes.length)
  })
})
