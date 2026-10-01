import { describe, expect, it } from 'vitest'
import { PieceTable } from './piece-table'
import { BlobByteSource } from './byte-source'
import { extractPrintableStringsStream } from './streaming'
import { runRecipe, validateRecipe } from './recipe'

describe('browser file editing', () => {
  it('exports spans and treats a length-changing splice as one undo transaction', async () => {
    const source = new Blob([Uint8Array.of(1, 2, 3, 4, 5)])
    const table = new PieceTable(new BlobByteSource(source))
    table.splice(1, 2, Uint8Array.of(10, 11, 12), 'Replace selection')
    const output = new Blob(
      table
        .exportSegments()
        .map((s) => (s.added ? (s.added as BlobPart) : source.slice(s.start, s.start + s.length))),
    )
    expect(new Uint8Array(await output.arrayBuffer())).toEqual(Uint8Array.of(1, 10, 11, 12, 4, 5))
    expect(table.undo()).toBe(true)
    expect(await table.read(0, table.size)).toEqual(Uint8Array.of(1, 2, 3, 4, 5))
    expect(table.canUndo()).toBe(false)
    expect(table.redo()).toBe(true)
    expect(await table.read(0, table.size)).toEqual(Uint8Array.of(1, 10, 11, 12, 4, 5))
    table.splice(0, table.size, new Uint8Array())
    expect(table.size).toBe(0)
    table.undo()
    expect(table.size).toBe(6)
  })
  it('paginates strings across chunk boundaries with absolute offsets', async () => {
    const source = new BlobByteSource(new Blob(['first\0second\0third']))
    const first = await extractPrintableStringsStream(source, { chunkSize: 3, limit: 1 })
    const second = await extractPrintableStringsStream(source, {
      chunkSize: 3,
      limit: 1,
      startOffset: first.nextCursor,
    })
    const third = await extractPrintableStringsStream(source, {
      chunkSize: 3,
      startOffset: second.nextCursor,
    })
    expect(first.items[0]?.value).toBe('first')
    expect(second.items[0]?.offset).toBe(6)
    expect(third.items[0]?.value).toBe('third')
    expect(third.items[0]?.offset).toBe(13)
  })
  it('rejects bad recipes and ranges, and supports auto structure parsing', () => {
    expect(validateRecipe({ schemaVersion: 1, recipeId: 'r', inputs: [null], steps: [] }).ok).toBe(
      false,
    )
    expect(
      validateRecipe({
        schemaVersion: 1,
        recipeId: 'r',
        inputs: [],
        steps: [{ id: 's', operation: 'hash' }],
        expectedOutputs: [{ stepId: 's', checks: null }],
      }).ok,
    ).toBe(false)
    const result = runRecipe(
      {
        schemaVersion: 1,
        recipeId: 'r',
        inputs: [{ id: 'input' }],
        steps: [{ id: 's', operation: 'hash', range: { start: 0, end: 100 } }],
      },
      { input: Uint8Array.of(1) },
    )
    expect(result.ok).toBe(false)
    const wasm = runRecipe(
      {
        schemaVersion: 1,
        recipeId: 'r',
        inputs: [{ id: 'input' }],
        steps: [{ id: 's', operation: 'parse-structure', parameters: { format: 'auto' } }],
      },
      { input: Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0) },
    )
    expect(wasm.ok).toBe(true)
  })
})
