import { parsePng } from './png'
import { parseElf } from './elf'
import { parsePe } from './pe'
import { parseWasm } from './wasm'
import { parseZip } from './zip'
import { parseGpt } from './gpt'
import { parseUbi } from './ubi'
import { parseSquashfs } from './squashfs'
import { parseSafeTensors } from './safetensors'
import { parseBitcoinTx } from './bitcoin'
import { parseEthereumTx } from './ethereum'
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
export * from './safetensors'
export * from './bitcoin'
export * from './ethereum'
export * from './schema'
export * from './schema-v2'

export const SUPPORTED_STRUCTURE_FORMATS = [
  { id: 'auto', label: 'Auto Detect' },
  { id: 'elf', label: 'ELF Executable (Linux/BSD)' },
  { id: 'pe', label: 'PE / COFF (Windows EXE/DLL)' },
  { id: 'wasm', label: 'WebAssembly Binary (WASM)' },
  { id: 'png', label: 'PNG Image' },
  { id: 'zip', label: 'ZIP Archive (ZIP/JAR/APK)' },
  { id: 'gpt', label: 'GPT Partition Table' },
  { id: 'ubi', label: 'UBI / UBIFS Volume' },
  { id: 'squashfs', label: 'SquashFS Superblock' },
  { id: 'safetensors', label: 'SafeTensors Weights' },
  { id: 'bitcoin', label: 'Bitcoin Raw Transaction' },
  { id: 'ethereum', label: 'Ethereum RLP Transaction' },
  { id: 'custom-schema', label: 'Custom JSON Schema' },
] as const

export function parseStructureByFormat(
  bytes: Uint8Array,
  format: string,
  customSchema?: CustomStructureSchema | CustomStructureSchemaV2,
): StructureParseResult | null {
  if (format === 'auto') {
    return autoDetectAndParseStructure(bytes, customSchema)
  }

  switch (format) {
    case 'elf':
      return parseElf(bytes)
    case 'pe':
      return parsePe(bytes)
    case 'wasm':
      return parseWasm(bytes)
    case 'png':
      return parsePng(bytes)
    case 'zip':
      return parseZip(bytes)
    case 'gpt':
      return parseGpt(bytes)
    case 'ubi':
      return parseUbi(bytes)
    case 'squashfs':
      return parseSquashfs(bytes)
    case 'safetensors':
      return parseSafeTensors(bytes)
    case 'bitcoin':
      return parseBitcoinTx(bytes)
    case 'ethereum':
      return parseEthereumTx(bytes)
    case 'custom-schema':
      if (customSchema) {
        if (customSchema.schemaVersion === 2) {
          return parseCustomStructureV2(bytes, customSchema)
        }
        return parseCustomStructure(bytes, customSchema)
      }
      return null
    default:
      return autoDetectAndParseStructure(bytes, customSchema)
  }
}

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

  // 6. SafeTensors magic: uint64 LE header size followed by '{'
  if (bytes.length >= 10 && bytes[8]! === 0x7b) {
    const st = parseSafeTensors(bytes)
    if (st) return st
  }

  // 7. UBI headers: "UBI#" or "UBI!"
  if (
    bytes.length >= 64 &&
    bytes[0]! === 0x55 &&
    bytes[1]! === 0x42 &&
    bytes[2]! === 0x49 &&
    (bytes[3]! === 0x23 || bytes[3]! === 0x21)
  ) {
    const ubi = parseUbi(bytes)
    if (ubi) return ubi
  }

  // 8. SquashFS magic: "sqsh" (0x73717368)
  if (
    bytes.length >= 96 &&
    bytes[0]! === 0x68 &&
    bytes[1]! === 0x73 &&
    bytes[2]! === 0x71 &&
    bytes[3]! === 0x73
  ) {
    const sq = parseSquashfs(bytes)
    if (sq) return sq
  }

  // 9. GPT Header at offset 512
  if (bytes.length >= 1024) {
    const gpt = parseGpt(bytes)
    if (gpt) return gpt
  }

  // 10. Ethereum Typed Transaction or RLP list
  const b0 = bytes[0]!
  if (bytes.length >= 8 && (b0 === 0x01 || b0 === 0x02 || b0 >= 0xc0)) {
    const eth = parseEthereumTx(bytes)
    if (eth) return eth
  }

  // 11. Bitcoin Transaction (version 1 or 2)
  if (bytes.length >= 60 && (b0 === 0x01 || b0 === 0x02) && bytes[1]! === 0x00 && bytes[2]! === 0x00 && bytes[3]! === 0x00) {
    const btc = parseBitcoinTx(bytes)
    if (btc) return btc
  }

  return null
}
