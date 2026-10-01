import { BlobByteSource } from '../../packages/core/src/byte-source'
import { Sha256 } from '../../packages/core/src/crypto'
import { parseSearchPattern, shannonEntropy } from '../../packages/core/src/analysis'
import {
  findBytePatternStream,
  extractPrintableStringsStream,
} from '../../packages/core/src/streaming'
import { parseStructureByFormat } from '../../packages/core/src/structures'
import { runRecipe, validateRecipe } from '../../packages/core/src/recipe'
import { alignedDiff } from '../lib/aligned-diff'

const report = (progress: number) => self.postMessage({ progress })
self.onmessage = async (event) => {
  try {
    const { task, blob, reference, query, mode, format, schema, recipe } = event.data
    const source = new BlobByteSource(blob)
    let result: unknown
    if (task === 'map') {
      const frequencies = new Uint32Array(256),
        blocks: { start: number; length: number; entropy: number }[] = []
      const blockSize = Math.max(4096, Math.ceil(blob.size / 256))
      const hash = new Sha256()
      let offset = 0
      for await (const chunk of source.chunks(undefined, blockSize)) {
        hash.update(chunk)
        for (const byte of chunk) frequencies[byte]!++
        blocks.push({ start: offset, length: chunk.length, entropy: shannonEntropy(chunk) })
        offset += chunk.length
        report(offset / Math.max(1, blob.size))
      }
      result = {
        blocks,
        frequencies: Array.from(frequencies),
        sha256: hash.digestHex(),
        size: blob.size,
      }
    } else if (task === 'search') {
      const parsed = parseSearchPattern(query, mode)
      if (!parsed.ok) throw new Error(parsed.error)
      result = {
        ...(await findBytePatternStream(source, parsed.pattern, {
          startOffset: event.data.cursor ?? 0,
        })),
        patternLength: parsed.pattern.values.length,
      }
    } else if (task === 'strings') {
      result = await extractPrintableStringsStream(source, {
        minimumLength: event.data.minLength ?? 4,
        startOffset: event.data.cursor ?? 0,
      })
    } else if (task === 'diff') {
      result = await alignedDiff(blob, reference, report)
    } else if (task === 'structure') {
      if (blob.size > 64 * 1024 * 1024)
        throw new Error(
          'Structure parsing supports files up to 64 MiB. Use byte inspection or CLI for larger files.',
        )
      result = parseStructureByFormat(
        new Uint8Array(await blob.arrayBuffer()),
        format ?? 'auto',
        schema,
      )
    } else if (task === 'recipe') {
      if (blob.size > 16 * 1024 * 1024)
        throw new Error('Recipe preview supports up to 16 MiB per input.')
      const validated = validateRecipe(recipe)
      if (!validated.ok) throw new Error(validated.error)
      if (
        validated.recipe.steps.length > 100 ||
        blob.size * Math.max(1, validated.recipe.steps.length) > 128 * 1024 * 1024
      )
        throw new Error(
          'Recipe exceeds the browser processing budget. Use fewer steps or a smaller input.',
        )
      const input = new Uint8Array(await blob.arrayBuffer())
      const output = runRecipe(validated.recipe, { input }, { includeOutputHex: false })
      const firstChanges: { offset: number; before: number | null; after: number | null }[] = []
      let changedBytes = 0
      if (output.finalBytes) {
        for (let i = 0; i < Math.max(input.length, output.finalBytes.length); i++) {
          if (input[i] !== output.finalBytes[i]) {
            changedBytes++
            if (firstChanges.length < 64)
              firstChanges.push({
                offset: i,
                before: input[i] ?? null,
                after: output.finalBytes[i] ?? null,
              })
          }
        }
      }
      result = { ...output, preview: { changedBytes, firstChanges } }
    } else throw new Error('Unknown background operation.')
    self.postMessage({ result })
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : String(error) })
  }
}
