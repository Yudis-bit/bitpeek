import { describe, expect, it } from 'vitest'
import { MemoryByteSource } from './byte-source'
import {
  crc32Stream,
  crc16Stream,
  entropyStream,
  findBytePatternStream,
  extractPrintableStringsStream,
  diffSourceStream,
} from './streaming'
import { sha256Hex, sha256Stream } from './crypto'
import { PieceTable } from './piece-table'
import { createTransformMapping } from './transforms'

describe('Streaming Algorithms & Piece Table (DATA-01, DATA-02, DATA-03, DATA-04, DATA-05, DATA-06)', () => {
  it('streaming SHA-256 matches independent vectors across chunk partitions (AC011)', async () => {
    const data = new Uint8Array(10_000)
    for (let i = 0; i < data.length; i++) data[i] = (i * 31) & 0xff

    const expectedHash = sha256Hex(data)
    const source = new MemoryByteSource(data)

    // Stream with small 256-byte chunks
    const streamedHash = await sha256Stream(source.chunks(undefined, 256))
    expect(streamedHash).toBe(expectedHash)

    // Stream CRC32 & CRC16
    const crc32Val = await crc32Stream(source.chunks(undefined, 512))
    expect(crc32Val).toBeGreaterThan(0)
    const crc16Val = await crc16Stream(source.chunks(undefined, 512))
    expect(crc16Val).toBeGreaterThan(0)

    // Entropy calculation
    const entropyRes = await entropyStream(source.chunks(undefined, 1024))
    expect(entropyRes.totalBytes).toBe(10_000)
    expect(entropyRes.entropy).toBeGreaterThan(7.0) // high pseudo-random entropy
  })

  it('findBytePatternStream detects pattern spanning across chunk boundary without duplicate (AC012)', async () => {
    // 20 bytes total. Chunks of size 4.
    // Pattern "DEADBEEF" (4 bytes) placed across boundary between chunk 1 (offset 0..3) and chunk 2 (offset 4..7)
    // E.g. at offset 2: bytes[2]=DE, bytes[3]=AD, bytes[4]=BE, bytes[5]=EF
    const data = new Uint8Array(20).fill(0x00)
    data[2] = 0xde
    data[3] = 0xad
    data[4] = 0xbe
    data[5] = 0xef

    const pattern = {
      values: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
      masks: Uint8Array.from([0xff, 0xff, 0xff, 0xff]),
    }

    const source = new MemoryByteSource(data)
    const matches = await findBytePatternStream(source, pattern, { chunkSize: 4 })

    expect(matches.offsets).toEqual([2])
    expect(matches.truncated).toBe(false)
  })

  it('extractPrintableStringsStream preserves strings across chunk boundaries and bounds length (AC013)', async () => {
    // String "HELLO_WORLD_AGY" placed across chunk boundary (chunk size 4)
    const text = 'HELLO_WORLD_AGY'
    const bytes = new TextEncoder().encode(text)
    const source = new MemoryByteSource(bytes)

    const result = await extractPrintableStringsStream(source, {
      chunkSize: 4,
      minimumLength: 4,
      maxStringLength: 8,
    })

    expect(result.items).toHaveLength(1)
    const item = result.items[0]!
    expect(item.byteLength).toBe(bytes.length)
    expect(item.value).toContain('HELLO_WO… [truncated]')
  })

  it('diffSourceStream bounds memory on alternating-byte inputs (AC014)', async () => {
    // Alternating bytes: ref has all 0x00, cur has 0x00 0x01 alternating
    const length = 1000
    const ref = new Uint8Array(length).fill(0x00)
    const cur = new Uint8Array(length)
    for (let i = 0; i < length; i++) cur[i] = i % 2 === 0 ? 0x00 : 0x01

    const diff = await diffSourceStream(
      new MemoryByteSource(cur),
      new MemoryByteSource(ref),
      { maxDifferences: 50, chunkSize: 128 },
    )

    expect(diff.modified).toBe(500)
    // Results must be capped at 50 to avoid memory exhaustion
    expect(diff.offsets.length).toBe(50)
    expect(diff.ranges.length).toBeLessThanOrEqual(50)
  })

  it('PieceTable supports transactional insert, delete, replace, undo, redo and chunk export (AC015, AC016)', async () => {
    const initial = Uint8Array.from([0x10, 0x20, 0x30, 0x40])
    const pt = new PieceTable(initial)

    // Insert [0xaa, 0xbb] at offset 2 -> [0x10, 0x20, 0xaa, 0xbb, 0x30, 0x40]
    pt.insert(2, Uint8Array.from([0xaa, 0xbb]))
    expect(pt.size).toBe(6)
    expect(Array.from(await pt.read(0, 6))).toEqual([0x10, 0x20, 0xaa, 0xbb, 0x30, 0x40])

    // Replace 2 bytes at offset 4 with [0x99, 0x88] -> [0x10, 0x20, 0xaa, 0xbb, 0x99, 0x88]
    pt.replace(4, Uint8Array.from([0x99, 0x88]))
    expect(pt.size).toBe(6)
    expect(Array.from(await pt.read(0, 6))).toEqual([0x10, 0x20, 0xaa, 0xbb, 0x99, 0x88])

    // Delete 3 bytes at offset 1 -> [0x10, 0x99, 0x88]
    pt.delete(1, 3)
    expect(pt.size).toBe(3)
    expect(Array.from(await pt.read(0, 3))).toEqual([0x10, 0x99, 0x88])

    // Undo delete -> [0x10, 0x20, 0xaa, 0xbb, 0x99, 0x88]
    expect(pt.undo()).toBe(true)
    expect(pt.size).toBe(6)
    expect(Array.from(await pt.read(0, 6))).toEqual([0x10, 0x20, 0xaa, 0xbb, 0x99, 0x88])

    // Undo replace -> [0x10, 0x20, 0xaa, 0xbb, 0x30, 0x40]
    expect(pt.undo()).toBe(true)
    expect(Array.from(await pt.read(0, 6))).toEqual([0x10, 0x20, 0xaa, 0xbb, 0x30, 0x40])

    // Redo replace -> [0x10, 0x20, 0xaa, 0xbb, 0x99, 0x88]
    expect(pt.redo()).toBe(true)
    expect(Array.from(await pt.read(0, 6))).toEqual([0x10, 0x20, 0xaa, 0xbb, 0x99, 0x88])

    // Export chunks
    const exported: number[] = []
    for await (const chunk of pt.chunks(undefined, 2)) {
      exported.push(...Array.from(chunk))
    }
    expect(exported).toEqual([0x10, 0x20, 0xaa, 0xbb, 0x99, 0x88])
  })

  it('TransformMapping computes exact forward and inverse coordinates (AC021)', () => {
    // Reverse [10, 20)
    const revMap = createTransformMapping('s1', 't1', 10, 20, 'reverse')
    expect(revMap.forwardMap(10)).toBe(19)
    expect(revMap.forwardMap(19)).toBe(10)
    expect(revMap.inverseMap(10)).toBe(19)

    // Byteswap 2-byte groups [0, 4)
    const swapMap = createTransformMapping('s1', 't1', 0, 4, 'byteswap', { groupWidth: 2 })
    expect(swapMap.forwardMap(0)).toBe(1)
    expect(swapMap.forwardMap(1)).toBe(0)
    expect(swapMap.forwardMap(2)).toBe(3)
    expect(swapMap.forwardMap(3)).toBe(2)
  })
})
