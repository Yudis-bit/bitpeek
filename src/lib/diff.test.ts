import { describe, expect, it } from 'vitest'
import {
  applyOffsetPatch,
  createOffsetPatch,
  diffBytes,
  serializeOffsetPatch,
} from './diff'

describe('offset-aligned binary diff', () => {
  it('counts modified and unequal-length bytes', () => {
    const current = Uint8Array.from([0xde, 0xad, 0xfa, 0xce, 0x01])
    const reference = Uint8Array.from([0xde, 0xad, 0xbe, 0xef])
    const result = diffBytes(current, reference)

    expect(result.offsets).toEqual([2, 3, 4])
    expect(result.modified).toBe(2)
    expect(result.currentOnly).toBe(1)
    expect(result.referenceOnly).toBe(0)
    expect(result.ranges).toEqual([
      { start: 2, end: 3, length: 2, kind: 'modified' },
      { start: 4, end: 4, length: 1, kind: 'current-only' },
    ])
  })

  it('reports bytes that exist only in the reference', () => {
    const result = diffBytes(
      Uint8Array.from([1]),
      Uint8Array.from([1, 2, 3]),
    )
    expect(result.offsets).toEqual([1, 2])
    expect(result.referenceOnly).toBe(2)
  })

  it('creates a deterministic patch that reconstructs the current bytes', () => {
    const reference = Uint8Array.from([0x10, 0x20, 0x30, 0x40])
    const current = Uint8Array.from([0x10, 0xff, 0x30, 0x41, 0x50])
    const patch = createOffsetPatch(reference, current, {
      referenceName: 'before.bin',
      currentName: 'after.bin',
      referenceSha256: 'source-hash',
      currentSha256: 'target-hash',
    })

    expect(Array.from(applyOffsetPatch(reference, patch))).toEqual(
      Array.from(current),
    )
    expect(serializeOffsetPatch(patch)).toContain('"bitpeek-offset-patch"')
    expect(patch.source.sha256).toBe('source-hash')
    expect(patch.target.sha256).toBe('target-hash')
  })

  it('rejects a patch when the reference precondition does not match', () => {
    const reference = Uint8Array.from([1, 2, 3])
    const current = Uint8Array.from([1, 9, 3])
    const patch = createOffsetPatch(reference, current)
    expect(() => applyOffsetPatch(Uint8Array.from([1, 8, 3]), patch)).toThrow(
      'Reference bytes do not match',
    )
  })
})
