import { describe, expect, it } from 'vitest'
import {
  appendPatch,
  applyPatch,
  createPatch,
  transformRange,
} from './edits'

describe('range edits and history patches', () => {
  it('reverses and inverts ranges immutably', () => {
    const source = Uint8Array.from([0x00, 0x12, 0x34, 0xff])
    expect(Array.from(transformRange(source, 1, 3, 'reverse'))).toEqual([
      0x00, 0xff, 0x34, 0x12,
    ])
    expect(Array.from(transformRange(source, 1, 2, 'invert'))).toEqual([
      0x00, 0xed, 0xcb, 0xff,
    ])
    expect(Array.from(source)).toEqual([0x00, 0x12, 0x34, 0xff])
  })

  it('applies compact undo and redo patches', () => {
    const before = Uint8Array.from([1, 2, 3])
    const after = Uint8Array.from([1, 9, 3])
    const patch = createPatch(before, after, 1, 1, 'Edit byte')
    expect(Array.from(applyPatch(after, patch, 'undo'))).toEqual([1, 2, 3])
    expect(Array.from(applyPatch(before, patch, 'redo'))).toEqual([1, 9, 3])
  })

  it('bounds retained history by patch payload size', () => {
    const source = new Uint8Array(4)
    const first = createPatch(source, Uint8Array.from([1, 1, 1, 1]), 0, 3, 'First')
    const second = createPatch(source, Uint8Array.from([2, 2, 2, 2]), 0, 3, 'Second')
    expect(appendPatch([first], second, 8)).toEqual([second])
  })
})
