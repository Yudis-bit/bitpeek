import { describe, expect, it } from 'vitest'
import { BoundedCheckedReader } from './reader'
import { MemoryByteSource } from './byte-source'

describe('BoundedCheckedReader (AC001, AC002, AC006, AC007, AC033, AC061)', () => {
  it('reads endian-specific scalars with exact precision', async () => {
    const bytes = Uint8Array.from([
      0x01, 0x02, 0x03, 0x04,
      0x05, 0x06, 0x07, 0x08,
      0xfe, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff,
    ])
    const reader = new BoundedCheckedReader(bytes)

    expect(await reader.readU8()).toBe(0x01)
    expect(await reader.readU16('le')).toBe(0x0302)
    expect(await reader.readU32('be')).toBe(0x04050607)
    expect(await reader.readU64('le')).toBe(0xfffffffffffffe08n)
  })

  it('reads float32 and float64 preserving raw bits, NaN, -0.0, and subnormals (AC007)', async () => {
    // 0x80000000 is -0.0 in IEEE-754 float32
    // 0x7fc00000 is quiet NaN
    const f32Buffer = new Uint8Array(8)
    const view = new DataView(f32Buffer.buffer)
    view.setUint32(0, 0x80000000, false) // -0.0 big-endian
    view.setUint32(4, 0x7fc00000, false) // NaN big-endian

    const reader = new BoundedCheckedReader(f32Buffer)
    const negZero = await reader.readFloat32('be')
    expect(negZero.isNegative).toBe(true)
    expect(negZero.isZero).toBe(true)
    expect(negZero.rawBits).toBe('0x80000000')
    expect(negZero.display).toBe('-0.0')

    const nanVal = await reader.readFloat32('be')
    expect(nanVal.isNaN).toBe(true)
    expect(nanVal.rawBits).toBe('0x7fc00000')
    expect(nanVal.display).toBe('NaN')
  })

  it('decodes LEB128 varints and enforces canonical encoding (AC033)', async () => {
    // Canonical 624485 in LEB128: 0xe5 0x8e 0x26
    const valid = Uint8Array.from([0xe5, 0x8e, 0x26])
    const r1 = new BoundedCheckedReader(valid)
    const res1 = await r1.readVarint()
    expect(res1.value).toBe(624485n)
    expect(res1.byteLength).toBe(3)

    // Non-canonical overlong 1 in LEB128: 0x81 0x00
    const nonCanonical = Uint8Array.from([0x81, 0x00])
    const r2 = new BoundedCheckedReader(nonCanonical)
    await expect(r2.readVarint(10, true)).rejects.toThrow(/Non-canonical varint/)
  })

  it('decodes Bitcoin CompactSize and detects non-canonical widths (AC061)', async () => {
    // Canonical 1-byte
    const r1 = new BoundedCheckedReader(Uint8Array.from([0xfc]))
    expect((await r1.readCompactSize()).value).toBe(252n)

    // Canonical 3-byte (253 prefix + 0xfd 0x00)
    const r2 = new BoundedCheckedReader(Uint8Array.from([0xfd, 0xfd, 0x00]))
    expect((await r2.readCompactSize()).value).toBe(253n)

    // Non-canonical 3-byte encoding a value < 253 (e.g. 100)
    const r3 = new BoundedCheckedReader(Uint8Array.from([0xfd, 0x64, 0x00]))
    await expect(r3.readCompactSize()).rejects.toThrow(/Non-canonical CompactSize/)
  })

  it('enforces fuel limits and detects truncated input', async () => {
    const bytes = Uint8Array.from([0x01, 0x02])
    const reader = new BoundedCheckedReader(bytes, {
      budget: { maxNodes: 2 },
    })

    await reader.readU8()
    await reader.readU8()
    // Exceeds maxNodes budget
    await expect(reader.readU8()).rejects.toThrow()
  })

  it('slices child readers with bounded limits and recursion depth', async () => {
    const bytes = Uint8Array.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    const reader = new BoundedCheckedReader(new MemoryByteSource(bytes))

    const child = reader.slice(4) // child has 4 bytes
    expect(child.remaining).toBe(4)
    expect(await child.readU8()).toBe(0x00)
    expect(await child.readU8()).toBe(0x11)
    expect(await child.readU16('be')).toBe(0x2233)
    // Child is at limit 4, reading more should throw TRUNCATED_INPUT
    await expect(child.readU8()).rejects.toThrow(/Unexpected end of input/)

    // Parent cursor advanced by 4 bytes, 2 bytes remaining
    expect(reader.remaining).toBe(2)
    expect(await reader.readU16('be')).toBe(0x4455)
  })
})
