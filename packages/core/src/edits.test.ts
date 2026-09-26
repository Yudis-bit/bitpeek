import { describe, expect, it } from 'vitest'
import {
  transformRange,
  createEmptyHistory,
  pushTransaction,
  applyUndo,
  applyRedo,
  createPatch,
} from './edits'

describe('Core range transforms and unified history', () => {
  it('performs XOR mask transformation repeating across range', () => {
    const bytes = Uint8Array.from([0x00, 0x11, 0x22, 0x33, 0x44])
    const mask = Uint8Array.from([0xff, 0xaa])
    const result = transformRange(bytes, 1, 4, 'xor-mask', { xorMask: mask })
    // index 1: 0x11 ^ 0xff = 0xee
    // index 2: 0x22 ^ 0xaa = 0x88
    // index 3: 0x33 ^ 0xff = 0xcc
    // index 4: 0x44 ^ 0xaa = 0xee
    expect(Array.from(result)).toEqual([0x00, 0xee, 0x88, 0xcc, 0xee])
  })

  it('performs fill transformation', () => {
    const bytes = Uint8Array.from([1, 2, 3, 4, 5])
    const result = transformRange(bytes, 1, 3, 'fill', { fillByte: 0xaa })
    expect(Array.from(result)).toEqual([1, 0xaa, 0xaa, 0xaa, 5])
  })

  it('performs byteswap transformation on 2, 4, and 8-byte groups', () => {
    const bytes2 = Uint8Array.from([0x12, 0x34, 0x56, 0x78])
    const res2 = transformRange(bytes2, 0, 3, 'byteswap', { groupWidth: 2 })
    expect(Array.from(res2)).toEqual([0x34, 0x12, 0x78, 0x56])

    const bytes4 = Uint8Array.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    const res4 = transformRange(bytes4, 0, 7, 'byteswap', { groupWidth: 4 })
    expect(Array.from(res4)).toEqual([0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05])
  })

  it('rejects byteswap when range length is not a multiple of groupWidth', () => {
    const bytes = Uint8Array.from([1, 2, 3])
    expect(() => transformRange(bytes, 0, 2, 'byteswap', { groupWidth: 2 })).toThrow(
      'must be a multiple of group width',
    )
  })

  it('manages unified document transactions across patches and replacements', () => {
    let history = createEmptyHistory()
    const doc0 = Uint8Array.from([1, 2, 3])
    const doc1 = Uint8Array.from([1, 99, 3])
    const patch1 = createPatch(doc0, doc1, 1, 1, 'Edit byte')

    history = pushTransaction(history, { type: 'patch', patch: patch1, label: 'Edit byte' })

    const doc2 = Uint8Array.from([10, 20, 30, 40])
    history = pushTransaction(history, {
      type: 'replace',
      before: doc1,
      after: doc2,
      label: 'Paste new input',
    })

    // Undo replace
    const undo1 = applyUndo(doc2, history)
    expect(undo1).not.toBeNull()
    if (undo1) {
      expect(Array.from(undo1.nextBytes)).toEqual([1, 99, 3])
      history = undo1.history
    }

    // Undo patch
    const undo2 = applyUndo(doc1, history)
    expect(undo2).not.toBeNull()
    if (undo2) {
      expect(Array.from(undo2.nextBytes)).toEqual([1, 2, 3])
      history = undo2.history
    }

    // Redo patch
    const redo1 = applyRedo(doc0, history)
    expect(redo1).not.toBeNull()
    if (redo1) {
      expect(Array.from(redo1.nextBytes)).toEqual([1, 99, 3])
      expect(redo1.history.undo.length).toBe(1)
    }
  })
})
