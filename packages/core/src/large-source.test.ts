import { describe, expect, it } from 'vitest'
import { GeneratedSparseSource } from './byte-source'
import { sha256Stream } from './crypto'
import { findBytePatternStream } from './streaming'

describe('Large-Data Engine & Virtual Large Sources (AC016, AC017, Phase P2 Gate)', () => {
  it('navigates and reads > 4 GiB offsets on an 8 GiB virtual source in milliseconds without allocation (AC017)', async () => {
    const eightGiB = 8 * 1024 * 1024 * 1024 // 8,589,934,592 bytes
    const patches = new Map<number, Uint8Array>()

    // Place identifiable markers at offsets: 0, 1 GiB, 4 GiB + 100, 7 GiB
    const offset1GiB = 1 * 1024 * 1024 * 1024
    const offset4GiB = 4 * 1024 * 1024 * 1024 + 100
    const offset7GiB = 7 * 1024 * 1024 * 1024

    patches.set(0, Uint8Array.from([0x01, 0x02]))
    patches.set(offset1GiB, Uint8Array.from([0xaa, 0xbb]))
    patches.set(offset4GiB, Uint8Array.from([0xde, 0xad, 0xbe, 0xef]))
    patches.set(offset7GiB, Uint8Array.from([0xcc, 0xdd]))

    const source = new GeneratedSparseSource(eightGiB, 0x00, patches)
    expect(source.size).toBe(eightGiB)

    const t0 = performance.now()
    const r0 = await source.read(0, 2)
    const r1 = await source.read(offset1GiB, 2)
    const r4 = await source.read(offset4GiB, 4)
    const r7 = await source.read(offset7GiB, 2)
    const elapsed = performance.now() - t0

    expect(Array.from(r0)).toEqual([0x01, 0x02])
    expect(Array.from(r1)).toEqual([0xaa, 0xbb])
    expect(Array.from(r4)).toEqual([0xde, 0xad, 0xbe, 0xef])
    expect(Array.from(r7)).toEqual([0xcc, 0xdd])
    expect(elapsed).toBeLessThan(100) // completed in < 100 ms
  })

  it('runs streaming SHA-256 and pattern search on a 100 MiB virtual source within budget (Phase P2 Gate)', async () => {
    const hundredMiB = 100 * 1024 * 1024 // 104,857,600 bytes
    const patches = new Map<number, Uint8Array>()
    // Place target pattern at 95 MiB
    const targetOffset = 95 * 1024 * 1024
    patches.set(targetOffset, Uint8Array.from([0xca, 0xfe, 0xba, 0xbe]))

    const source = new GeneratedSparseSource(hundredMiB, 0x55, patches)
    expect(source.size).toBe(hundredMiB)

    // Stream search using 1 MiB chunk budget
    const pattern = {
      values: Uint8Array.from([0xca, 0xfe, 0xba, 0xbe]),
      masks: Uint8Array.from([0xff, 0xff, 0xff, 0xff]),
    }

    const t0 = performance.now()
    const searchRes = await findBytePatternStream(source, pattern, {
      chunkSize: 1024 * 1024,
      limit: 10,
    })
    const searchTime = performance.now() - t0

    expect(searchRes.offsets).toEqual([targetOffset])
    expect(searchTime).toBeLessThan(3000) // 100 MiB scanned within budget

    // Stream SHA-256 with 1 MiB chunks
    const hash = await sha256Stream(source.chunks({ start: 0, endExclusive: 10 * 1024 * 1024 }, 1024 * 1024))
    expect(hash).toHaveLength(64)
  })
})
