import { describe, expect, it } from 'vitest'
import { alignedDiff } from './aligned-diff'
const data = (length: number) =>
  Uint8Array.from({ length }, (_, i) => ((i * 71) ^ (i >>> 8) ^ (i >>> 16)) & 255)
describe('bounded aligned binary comparison', () => {
  it('isolates an insertion instead of cascading differences to EOF', async () => {
    const original = data(150000)
    const modified = new Uint8Array(original.length + 3)
    modified.set(original.subarray(0, 65535))
    modified.set([7, 8, 9], 65535)
    modified.set(original.subarray(65535), 65538)
    const result = await alignedDiff(new Blob([modified]), new Blob([original]))
    expect(result.inserted).toBe(3)
    expect(result.modified).toBe(0)
    expect(result.deleted).toBe(0)
    expect(result.changes).toEqual([
      {
        kind: 'inserted',
        currentStart: 65535,
        referenceStart: 65535,
        currentLength: 3,
        referenceLength: 0,
      },
    ])
  })
  it('handles deletion, modification, empty inputs, and trailing bytes', async () => {
    const original = data(400)
    const shorter = new Uint8Array(398)
    shorter.set(original.subarray(0, 100))
    shorter.set(original.subarray(102), 100)
    const deleted = await alignedDiff(new Blob([shorter]), new Blob([original]))
    expect(deleted.deleted).toBe(2)
    expect(deleted.modified).toBe(0)
    const changed = original.slice()
    changed[90] = changed[90]! ^ 0xff
    expect((await alignedDiff(new Blob([changed]), new Blob([original]))).modified).toBe(1)
    expect((await alignedDiff(new Blob(['ABC']), new Blob([]))).inserted).toBe(3)
    expect((await alignedDiff(new Blob([]), new Blob(['ABC']))).deleted).toBe(3)
    expect((await alignedDiff(new Blob([]), new Blob([]))).changes).toEqual([])
    const tail = original.slice()
    tail[tail.length - 3] = tail[tail.length - 3]! ^ 0xff
    expect((await alignedDiff(new Blob([tail]), new Blob([original]))).modified).toBe(1)
    expect((await alignedDiff(new Blob(['ABXCDE']), new Blob(['ABCDE']))).inserted).toBe(1)
  })
})
