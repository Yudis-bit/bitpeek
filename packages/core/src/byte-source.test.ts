import { describe, expect, it } from 'vitest'
import {
  MemoryByteSource,
  SliceByteSource,
  GeneratedSparseSource,
  checkChunkSize,
} from './byte-source'

describe('ByteSource Contracts (AC001, AC002, AC004, AC017)', () => {
  it('MemoryByteSource defensively copies buffers so external mutation cannot alter it (AC004)', async () => {
    const original = Uint8Array.from([0xaa, 0xbb, 0xcc])
    const source = new MemoryByteSource(original)

    // Mutate original externally
    original[0] = 0x00
    original[1] = 0x00

    // Source must retain original data
    const read = await source.read(0, 3)
    expect(read[0]).toBe(0xaa)
    expect(read[1]).toBe(0xbb)
    expect(read[2]).toBe(0xcc)
  })

  it('rejects invalid, zero, or non-finite chunk sizes (AC001)', () => {
    expect(() => checkChunkSize(0)).toThrow(/positive safe integer/)
    expect(() => checkChunkSize(-1024)).toThrow(/positive safe integer/)
    expect(() => checkChunkSize(NaN)).toThrow(/positive safe integer/)
    expect(() => checkChunkSize(Infinity)).toThrow(/positive safe integer/)
    expect(() => checkChunkSize(1024.5)).toThrow(/positive safe integer/)
  })

  it('chunks iterator handles length-0 range cleanly without hanging (AC001)', async () => {
    const source = new MemoryByteSource(Uint8Array.from([1, 2, 3]))
    const chunks: Uint8Array[] = []
    for await (const chunk of source.chunks({ start: 1, endExclusive: 1 })) {
      chunks.push(chunk)
    }
    expect(chunks).toHaveLength(0)
  })

  it('SliceByteSource maps parent bounds accurately', async () => {
    const parent = new MemoryByteSource(Uint8Array.from([10, 20, 30, 40, 50]))
    const slice = new SliceByteSource(parent, 1, 3) // [20, 30, 40]

    expect(slice.size).toBe(3)
    const data = await slice.read(0, 3)
    expect(Array.from(data)).toEqual([20, 30, 40])

    const chunkList: Uint8Array[] = []
    for await (const c of slice.chunks(undefined, 2)) {
      chunkList.push(c)
    }
    expect(chunkList).toHaveLength(2)
    expect(Array.from(chunkList[0]!)).toEqual([20, 30])
    expect(Array.from(chunkList[1]!)).toEqual([40])
  })

  it('GeneratedSparseSource represents > 4 GiB offsets without large allocation (AC017)', async () => {
    // 8 GiB virtual file
    const eightGiB = 8 * 1024 * 1024 * 1024
    const patches = new Map<number, Uint8Array>()
    // Place a marker at 6 GiB offset (6 * 1024 * 1024 * 1024 = 6442450944)
    const markerOffset = 6 * 1024 * 1024 * 1024
    patches.set(markerOffset, Uint8Array.from([0xde, 0xad, 0xbe, 0xef]))

    const sparse = new GeneratedSparseSource(eightGiB, 0x00, patches)
    expect(sparse.size).toBe(eightGiB)

    // Reading normal unpatched area returns zero-filled bytes
    const zeros = await sparse.read(0, 4)
    expect(Array.from(zeros)).toEqual([0, 0, 0, 0])

    // Reading at 6 GiB returns the marker!
    const marker = await sparse.read(markerOffset, 4)
    expect(Array.from(marker)).toEqual([0xde, 0xad, 0xbe, 0xef])
  })
})
