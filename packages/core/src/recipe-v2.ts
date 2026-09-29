import { BitpeekError } from './errors'
import { sha256Hex } from './crypto'

export interface RecipeStepV2 {
  readonly id: string
  readonly operation: 'slice' | 'reverse' | 'invert' | 'xor-mask' | 'byteswap' | 'sha256'
  readonly inputs: readonly string[]
  readonly parameters?: Record<string, unknown>
  readonly expectedSha256?: string
}

export interface RecipeV2 {
  readonly recipeId: string
  readonly version: 2
  readonly inputs: readonly string[]
  readonly steps: readonly RecipeStepV2[]
}

/**
 * Validates Recipe v2 for cycle-freedom, supported pure operations, and budget safety (AC040).
 */
export function validateRecipeV2(recipe: RecipeV2): void {
  if (recipe.version !== 2) {
    throw new BitpeekError('INVALID_INPUT', `Recipe version must be 2, got ${recipe.version}.`)
  }

  const stepIds = new Set<string>()
  const stepMap = new Map<string, RecipeStepV2>()

  for (const step of recipe.steps) {
    if (stepIds.has(step.id)) {
      throw new BitpeekError('INVALID_INPUT', `Duplicate step ID: ${step.id}`)
    }
    stepIds.add(step.id)
    stepMap.set(step.id, step)
  }

  // Cycle detection
  const visited = new Set<string>()
  const inStack = new Set<string>()

  function checkCycle(stepId: string) {
    if (inStack.has(stepId)) {
      throw new BitpeekError('INVALID_INPUT', `Cycle detected in recipe steps involving step ${stepId}.`)
    }
    if (visited.has(stepId)) return

    visited.add(stepId)
    inStack.add(stepId)

    const step = stepMap.get(stepId)
    if (step) {
      for (const parentId of step.inputs) {
        if (stepMap.has(parentId)) {
          checkCycle(parentId)
        }
      }
    }

    inStack.delete(stepId)
  }

  for (const stepId of stepIds) {
    checkCycle(stepId)
  }
}

export interface ReplayStepResult {
  stepId: string
  operation: string
  outputBytes?: Uint8Array
  outputSha256: string
  matchesExpected?: boolean
}

export interface ReplayRecipeV2Result {
  ok: boolean
  recipeId: string
  results: Record<string, ReplayStepResult>
  error?: string
}

/**
 * Executes a pure deterministic Recipe v2 without process execution or hardware effects (AC040, AC083).
 */
export function replayRecipeV2(
  recipe: RecipeV2,
  initialInputs: Record<string, Uint8Array>,
): ReplayRecipeV2Result {
  validateRecipeV2(recipe)
  const results: Record<string, ReplayStepResult> = {}
  const dataStore = new Map<string, Uint8Array>()

  for (const [id, buf] of Object.entries(initialInputs)) {
    dataStore.set(id, new Uint8Array(buf))
  }

  for (const step of recipe.steps) {
    const inputBuf = dataStore.get(step.inputs[0] ?? '')
    if (!inputBuf) {
      return {
        ok: false,
        recipeId: recipe.recipeId,
        results,
        error: `Step "${step.id}" missing input buffer for "${step.inputs[0]}".`,
      }
    }

    let out: Uint8Array

    switch (step.operation) {
      case 'reverse': {
        out = new Uint8Array(inputBuf)
        out.reverse()
        break
      }

      case 'invert': {
        out = new Uint8Array(inputBuf.length)
        for (let i = 0; i < inputBuf.length; i++) {
          out[i] = inputBuf[i]! ^ 0xff
        }
        break
      }

      case 'slice': {
        const start = Number(step.parameters?.['start'] ?? 0)
        const length = Number(step.parameters?.['length'] ?? inputBuf.length)
        out = inputBuf.slice(start, start + length)
        break
      }

      default: {
        return {
          ok: false,
          recipeId: recipe.recipeId,
          results,
          error: `Unsupported pure operation in Recipe v2: ${step.operation}`,
        }
      }
    }

    const outputSha256 = sha256Hex(out).toLowerCase()
    let matchesExpected: boolean | undefined
    if (step.expectedSha256) {
      matchesExpected = outputSha256 === step.expectedSha256.toLowerCase()
      if (!matchesExpected) {
        return {
          ok: false,
          recipeId: recipe.recipeId,
          results,
          error: `Step "${step.id}" SHA-256 mismatch: expected ${step.expectedSha256}, got ${outputSha256}.`,
        }
      }
    }

    dataStore.set(step.id, out)
    results[step.id] = {
      stepId: step.id,
      operation: step.operation,
      outputBytes: out,
      outputSha256,
      matchesExpected,
    }
  }

  return {
    ok: true,
    recipeId: recipe.recipeId,
    results,
  }
}
