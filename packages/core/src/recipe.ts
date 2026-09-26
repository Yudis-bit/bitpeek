import { BitpeekError } from './errors'
import { sha256Hex, crc32, crc16 } from './crypto'
import { transformRange } from './edits'
import { diffBytes, applyVerifiedPatch } from './diff'
import { parsePng } from './structures/png'
import { parseElf } from './structures/elf'
import { parseCustomStructure, type CustomStructureSchema } from './structures/schema'
import { findBytePattern, parseSearchPattern } from './analysis'
import { extractPrintableStrings } from './strings'
import { formatHexBytes, parseHexBytes } from './patch'

export type RecipeOperationName =
  | 'inspect-scalar'
  | 'reverse'
  | 'invert'
  | 'xor-mask'
  | 'fill'
  | 'byteswap'
  | 'find-pattern'
  | 'extract-strings'
  | 'hash'
  | 'parse-structure'
  | 'diff'
  | 'apply-patch'

export interface RecipeInput {
  id: string
  byteLength?: number
  sha256?: string
}

export interface RecipeStep {
  id: string
  operation: RecipeOperationName
  input?: string // refers to input id, default to active document from previous step
  range?: {
    start: number
    end: number // end-exclusive [start, end)
  }
  parameters?: Record<string, unknown>
}

export interface RecipeExpectedOutput {
  stepId: string
  checks: Record<string, unknown>
}

export interface RecipeFile {
  schemaVersion: 1
  recipeId: string
  title?: string
  description?: string
  engineCompatibility?: string
  inputs: RecipeInput[]
  steps: RecipeStep[]
  expectedOutputs?: RecipeExpectedOutput[]
}

export interface RecipeStepResult {
  stepId: string
  operation: RecipeOperationName
  status: 'success' | 'failed'
  outputValue?: unknown
  outputHex?: string
  error?: string
}

export interface RecipeRunResult {
  ok: boolean
  recipeId: string
  stepResults: RecipeStepResult[]
  finalBytes?: Uint8Array
  error?: string
}

export function validateRecipe(obj: unknown): { ok: true; recipe: RecipeFile } | { ok: false; error: string } {
  if (typeof obj !== 'object' || obj === null) {
    return { ok: false, error: 'Recipe must be a valid JSON object.' }
  }
  const r = obj as Record<string, unknown>
  if (r['schemaVersion'] !== 1) {
    return { ok: false, error: 'Unsupported recipe schemaVersion (expected 1).' }
  }
  if (typeof r['recipeId'] !== 'string' || !r['recipeId']) {
    return { ok: false, error: 'Recipe must include a non-empty recipeId.' }
  }
  if (!Array.isArray(r['inputs'])) {
    return { ok: false, error: 'Recipe inputs must be an array.' }
  }
  if (!Array.isArray(r['steps'])) {
    return { ok: false, error: 'Recipe steps must be an array.' }
  }
  return { ok: true, recipe: obj as RecipeFile }
}

export function runRecipe(
  recipe: RecipeFile,
  inputBuffers: Record<string, Uint8Array>,
  options: { dryRun?: boolean } = {},
): RecipeRunResult {
  const stepResults: RecipeStepResult[] = []

  // 1. Verify inputs
  for (const inputDef of recipe.inputs) {
    const buf = inputBuffers[inputDef.id]
    if (!buf) {
      return {
        ok: false,
        recipeId: recipe.recipeId,
        stepResults,
        error: `Missing required input buffer: "${inputDef.id}".`,
      }
    }
    if (inputDef.byteLength !== undefined && buf.length !== inputDef.byteLength) {
      return {
        ok: false,
        recipeId: recipe.recipeId,
        stepResults,
        error: `Input "${inputDef.id}" length mismatch: expected ${inputDef.byteLength}, got ${buf.length}.`,
      }
    }
    if (inputDef.sha256) {
      const actualHash = sha256Hex(buf).toLowerCase()
      if (actualHash !== inputDef.sha256.toLowerCase()) {
        return {
          ok: false,
          recipeId: recipe.recipeId,
          stepResults,
          error: `Input "${inputDef.id}" SHA-256 mismatch: expected ${inputDef.sha256}, got ${actualHash}.`,
        }
      }
    }
  }

  // Work with active document copy
  const firstInputId = recipe.inputs[0]?.id
  let currentBytes = firstInputId && inputBuffers[firstInputId] ? inputBuffers[firstInputId]!.slice() : new Uint8Array(0)

  // 2. Execute steps in order
  for (const step of recipe.steps) {
    if (step.input && inputBuffers[step.input]) {
      currentBytes = inputBuffers[step.input]!.slice()
    }

    const start = step.range?.start ?? 0
    const end = step.range?.end ?? currentBytes.length
    const endInclusive = end - 1

    try {
      switch (step.operation) {
        case 'inspect-scalar': {
          const type = (step.parameters?.['type'] as string) ?? 'u32'
          const endian = (step.parameters?.['endian'] as string) === 'little' ? 'little' : 'big'
          const le = endian === 'little'
          const view = new DataView(currentBytes.buffer, currentBytes.byteOffset, currentBytes.byteLength)

          let value: string | number
          if (type === 'u8') value = currentBytes[start] ?? 0
          else if (type === 'i8') value = view.getInt8(start)
          else if (type === 'u16') value = view.getUint16(start, le)
          else if (type === 'i16') value = view.getInt16(start, le)
          else if (type === 'u32') value = view.getUint32(start, le)
          else if (type === 'i32') value = view.getInt32(start, le)
          else if (type === 'u64') value = view.getBigUint64(start, le).toString(10)
          else if (type === 'i64') value = view.getBigInt64(start, le).toString(10)
          else throw new BitpeekError('INVALID_INPUT', `Unknown scalar type: ${type}`)

          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputValue: String(value),
          })
          break
        }

        case 'reverse': {
          currentBytes = transformRange(currentBytes, start, endInclusive, 'reverse')
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputHex: formatHexBytes(currentBytes),
          })
          break
        }

        case 'invert': {
          currentBytes = transformRange(currentBytes, start, endInclusive, 'invert')
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputHex: formatHexBytes(currentBytes),
          })
          break
        }

        case 'xor-mask': {
          const rawMask = step.parameters?.['mask']
          let mask: Uint8Array
          if (typeof rawMask === 'string') {
            mask = parseHexBytes(rawMask.replace(/\s+/g, ''))
          } else if (Array.isArray(rawMask)) {
            mask = Uint8Array.from(rawMask as number[])
          } else {
            throw new BitpeekError('INVALID_INPUT', 'xor-mask operation requires a "mask" parameter.')
          }
          currentBytes = transformRange(currentBytes, start, endInclusive, 'xor-mask', { xorMask: mask })
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputHex: formatHexBytes(currentBytes),
          })
          break
        }

        case 'fill': {
          const fillByte = Number(step.parameters?.['fillByte'] ?? 0)
          currentBytes = transformRange(currentBytes, start, endInclusive, 'fill', { fillByte })
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputHex: formatHexBytes(currentBytes),
          })
          break
        }

        case 'byteswap': {
          const groupWidth = (Number(step.parameters?.['groupWidth'] ?? 2) as 2 | 4 | 8)
          currentBytes = transformRange(currentBytes, start, endInclusive, 'byteswap', { groupWidth })
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputHex: formatHexBytes(currentBytes),
          })
          break
        }

        case 'hash': {
          const algo = ((step.parameters?.['algorithm'] as string) ?? 'sha256').toLowerCase()
          const slice = currentBytes.slice(start, end)
          let digest = ''
          if (algo === 'sha256') digest = sha256Hex(slice)
          else if (algo === 'crc32') digest = crc32(slice).toString(16).toUpperCase().padStart(8, '0')
          else if (algo === 'crc16') digest = crc16(slice).toString(16).toUpperCase().padStart(4, '0')
          else throw new BitpeekError('INVALID_INPUT', `Unsupported hash algorithm: ${algo}`)

          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputValue: digest,
          })
          break
        }

        case 'find-pattern': {
          const query = (step.parameters?.['pattern'] as string) ?? ''
          const mode = (step.parameters?.['mode'] as 'hex' | 'text') ?? 'hex'
          const parsed = parseSearchPattern(query, mode)
          if (!parsed.ok) throw new BitpeekError('INVALID_INPUT', parsed.error)
          const matches = findBytePattern(currentBytes.slice(start, end), parsed.pattern)
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputValue: matches.offsets.map((o) => o + start),
          })
          break
        }

        case 'extract-strings': {
          const minLen = Number(step.parameters?.['minLength'] ?? 4)
          const results = extractPrintableStrings(currentBytes.slice(start, end), minLen)
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputValue: results.items.map((i) => ({ ...i, offset: i.offset + start })),
          })
          break
        }

        case 'parse-structure': {
          const format = (step.parameters?.['format'] as string) ?? 'auto'
          let res
          if (format === 'elf') res = parseElf(currentBytes)
          else if (format === 'png') res = parsePng(currentBytes)
          else if (format === 'custom-schema') {
            const schema = step.parameters?.['schema'] as CustomStructureSchema
            if (!schema) throw new BitpeekError('INVALID_INPUT', 'Missing schema parameter for custom-schema.')
            res = parseCustomStructure(currentBytes, schema)
          } else throw new BitpeekError('INVALID_INPUT', `Unsupported structure format: ${format}`)

          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputValue: { status: res.status, fieldsCount: res.fields.length, warnings: res.warnings },
          })
          break
        }

        case 'diff': {
          const refId = step.parameters?.['referenceInput'] as string
          const refBuf = refId ? inputBuffers[refId] : undefined
          if (!refBuf) throw new BitpeekError('INVALID_INPUT', `Diff reference input "${refId}" not found.`)
          const diffResult = diffBytes(currentBytes, refBuf)
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputValue: {
              modified: diffResult.modified,
              currentOnly: diffResult.currentOnly,
              referenceOnly: diffResult.referenceOnly,
              rangesCount: diffResult.ranges.length,
            },
          })
          break
        }

        case 'apply-patch': {
          const patch = step.parameters?.['patch'] as Parameters<typeof applyVerifiedPatch>[1]
          if (!patch) throw new BitpeekError('INVALID_INPUT', 'Missing patch in parameters.')
          const applied = applyVerifiedPatch(currentBytes, patch)
          if (!applied.ok) throw new BitpeekError('PRECONDITION_FAILED', applied.error)
          currentBytes = applied.target
          stepResults.push({
            stepId: step.id,
            operation: step.operation,
            status: 'success',
            outputHex: formatHexBytes(currentBytes),
          })
          break
        }
      }
    } catch (err: unknown) {
      stepResults.push({
        stepId: step.id,
        operation: step.operation,
        status: 'failed',
        error: String(err),
      })
      return {
        ok: false,
        recipeId: recipe.recipeId,
        stepResults,
        error: `Step "${step.id}" failed: ${String(err)}`,
      }
    }
  }

  // 3. Verify expected outputs if defined
  if (recipe.expectedOutputs) {
    for (const expected of recipe.expectedOutputs) {
      const match = stepResults.find((s) => s.stepId === expected.stepId)
      if (!match || match.status !== 'success') {
        return {
          ok: false,
          recipeId: recipe.recipeId,
          stepResults,
          error: `Verification check failed: step "${expected.stepId}" was not successful.`,
        }
      }
      for (const [key, expVal] of Object.entries(expected.checks)) {
        const actualVal =
          key === 'outputValue' ? match.outputValue : key === 'outputHex' ? match.outputHex : undefined
        if (actualVal !== expVal) {
          return {
            ok: false,
            recipeId: recipe.recipeId,
            stepResults,
            error: `Expected check failed for step "${expected.stepId}": ${key} expected "${expVal}", got "${actualVal}".`,
          }
        }
      }
    }
  }

  return {
    ok: true,
    recipeId: recipe.recipeId,
    stepResults,
    finalBytes: options.dryRun ? undefined : currentBytes,
  }
}
