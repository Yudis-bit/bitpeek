import { parsePng } from './png'
import { parseElf } from './elf'
import { parseCustomStructure, type CustomStructureSchema } from './schema'
import type { StructureParseResult } from './types'

export * from './types'
export * from './png'
export * from './elf'
export * from './schema'

export function autoDetectAndParseStructure(
  bytes: Uint8Array,
  customSchema?: CustomStructureSchema,
): StructureParseResult | null {
  if (customSchema) {
    return parseCustomStructure(bytes, customSchema)
  }

  // Check PNG magic
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47
  ) {
    return parsePng(bytes)
  }

  // Check ELF magic
  if (
    bytes.length >= 4 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46
  ) {
    return parseElf(bytes)
  }

  return null
}
