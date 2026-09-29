import { parsePng } from './png'
import { parseElf } from './elf'
import { parsePe } from './pe'
import { parseWasm } from './wasm'
import { parseZip } from './zip'
import { parseGpt } from './gpt'
import { parseUbi } from './ubi'
import { parseSquashfs } from './squashfs'
import { parseCustomStructure, type CustomStructureSchema } from './schema'
import { parseCustomStructureV2, type CustomStructureSchemaV2 } from './schema-v2'
import type { StructureParseResult } from './types'

export * from './types'
export * from './png'
export * from './elf'
export * from './pe'
export * from './wasm'
export * from './zip'
export * from './gpt'
export * from './ubi'
export * from './squashfs'
export * from './schema'
export * from './schema-v2'

export function autoDetectAndParseStructure(
  bytes: Uint8Array,
  customSchema?: CustomStructureSchema | CustomStructureSchemaV2,
): StructureParseResult | null {
  if (customSchema) {
    if (customSchema.schemaVersion === 2) {
      return parseCustomStructureV2(bytes, customSchema)
    }
    return parseCustomStructure(bytes, customSchema)
  }

  // 1. PNG magic: 0x89 'P' 'N' 'G'
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47
  ) {
    return parsePng(bytes)
  }

  // 2. ELF magic: 0x7F 'E' 'L' 'F'
  if (
    bytes.length >= 4 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46
  ) {
    return parseElf(bytes)
  }

  // 3. WebAssembly magic: 0x00 'a' 's' 'm'
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x00 &&
    bytes[1] === 0x61 &&
    bytes[2] === 0x73 &&
    bytes[3] === 0x6d
  ) {
    return parseWasm(bytes)
  }

  // 4. PE / COFF magic: "MZ"
  if (bytes.length >= 64 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
    const pe = parsePe(bytes)
    if (pe) return pe
  }

  // 5. ZIP archive magic: "PK\x03\x04"
  if (bytes.length >= 22 && bytes[0] === 0x50 && bytes[1] === 0x4b) {
    const zip = parseZip(bytes)
    if (zip) return zip
  }

  // 6. UBI headers: "UBI#" or "UBI!"
  if (
    bytes.length >= 64 &&
    bytes[0] === 0x55 &&
    bytes[1] === 0x42 &&
    bytes[2] === 0x49 &&
    (bytes[3] === 0x23 || bytes[3] === 0x21)
  ) {
    const ubi = parseUbi(bytes)
    if (ubi) return ubi
  }

  // 7. SquashFS magic: "sqsh" (0x73717368)
  if (
    bytes.length >= 96 &&
    bytes[0] === 0x68 &&
    bytes[1] === 0x73 &&
    bytes[2] === 0x71 &&
    bytes[3] === 0x73
  ) {
    const sq = parseSquashfs(bytes)
    if (sq) return sq
  }

  // 8. GPT Header at offset 512
  if (bytes.length >= 1024) {
    const gpt = parseGpt(bytes)
    if (gpt) return gpt
  }

  return null
}
