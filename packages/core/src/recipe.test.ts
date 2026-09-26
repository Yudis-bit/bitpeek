import { describe, expect, it } from 'vitest'
import { runRecipe, type RecipeFile } from './recipe'
import { sha256Hex } from './crypto'

describe('Recipe Engine v1 (R11.1, R11.2)', () => {
  it('executes the masterplan acceptance recipe deterministically', () => {
    // Input hex: DE AD BE EF 00 01 7F 80
    const input = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80])
    const inputHash = sha256Hex(input)

    const recipe: RecipeFile = {
      schemaVersion: 1,
      recipeId: 'acceptance-example',
      inputs: [
        {
          id: 'sample',
          byteLength: 8,
          sha256: inputHash,
        },
      ],
      steps: [
        {
          id: 'step1-inspect',
          operation: 'inspect-scalar',
          input: 'sample',
          range: { start: 0, end: 4 },
          parameters: { type: 'u32', endian: 'big' },
        },
        {
          id: 'step2-reverse',
          operation: 'reverse',
          range: { start: 0, end: 4 },
        },
      ],
      expectedOutputs: [
        {
          stepId: 'step1-inspect',
          checks: { outputValue: '3735928559' }, // 0xDEADBEEF = 3735928559
        },
        {
          stepId: 'step2-reverse',
          checks: { outputHex: 'EFBEADDE00017F80' },
        },
      ],
    }

    const result = runRecipe(recipe, { sample: input })
    expect(result.ok).toBe(true)
    expect(result.stepResults[0]?.outputValue).toBe('3735928559')
    expect(result.stepResults[1]?.outputHex).toBe('EFBEADDE00017F80')
    expect(result.finalBytes).toBeDefined()
    if (result.finalBytes) {
      expect(Array.from(result.finalBytes)).toEqual([
        0xef, 0xbe, 0xad, 0xde, 0x00, 0x01, 0x7f, 0x80,
      ])
    }
  })

  it('rejects recipe run when input hash does not match', () => {
    const input = Uint8Array.from([0x00, 0x01])
    const recipe: RecipeFile = {
      schemaVersion: 1,
      recipeId: 'hash-check',
      inputs: [{ id: 'doc', sha256: '0000000000000000000000000000000000000000000000000000000000000000' }],
      steps: [{ id: 'noop', operation: 'hash', parameters: { algorithm: 'sha256' } }],
    }
    const result = runRecipe(recipe, { doc: input })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('SHA-256 mismatch')
  })
})
