import { type StructureParseResult, type StructureField, toStructureField } from './types'
import { BoundedCheckedReader } from '../reader'

export interface PeRvaMapping {
  rva: number
  type: 'file-backed' | 'zero-fill' | 'unmapped'
  status?: 'file-backed' | 'zero-fill' | 'unmapped'
  fileOffset?: number
  sectionName?: string
}

export interface PeParseResult extends StructureParseResult {
  isPe32Plus: boolean
  entryPointRva: number
  imageBase: bigint
  sections: Array<{
    name: string
    virtualAddress: number
    virtualSize: number
    rawOffset: number
    rawSize: number
    characteristics: number
  }>
  overlay: {
    startOffset: number
    length: number
  }
  rvaToOffset(rva: number): PeRvaMapping
  rvaToFileOffset?(rva: number): PeRvaMapping
}

export function parsePe(bytes: Uint8Array): PeParseResult | null {
  if (bytes.length < 64) return null
  // Check DOS magic "MZ"
  if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) return null

  const reader = new BoundedCheckedReader(bytes)
  const fields: StructureField[] = []
  const warnings: string[] = []

  fields.push(
    toStructureField({
      name: 'e_magic',
      offset: 0,
      length: 2,
      value: 'MZ',
      interpretation: 'DOS Header Signature',
      valid: true,
    }),
  )

  // Read e_lfanew at offset 0x3C
  reader.seek(0x3c)
  const peOffset = reader.readU32Sync('le')
  fields.push(
    toStructureField({
      name: 'e_lfanew',
      offset: 0x3c,
      length: 4,
      value: `0x${peOffset.toString(16)}`,
      interpretation: 'Offset to PE Header',
      valid: peOffset < bytes.length,
    }),
  )

  if (peOffset + 24 > bytes.length) {
    return {
      format: 'pe',
      valid: false,
      status: 'invalid',
      error: 'PE header offset exceeds file boundaries.',
      fields,
      warnings: ['PE header offset exceeds file boundaries.'],
      isPe32Plus: false,
      entryPointRva: 0,
      imageBase: 0n,
      sections: [],
      overlay: { startOffset: bytes.length, length: 0 },
      rvaToOffset: () => ({ rva: 0, type: 'unmapped' }),
      rvaToFileOffset: () => ({ rva: 0, type: 'unmapped' }),
    }
  }

  reader.seek(peOffset)
  // Check PE Signature "PE\0\0" (0x50, 0x45, 0x00, 0x00)
  const peSig = reader.readU32Sync('be')
  if (peSig !== 0x50450000) {
    return {
      format: 'pe',
      valid: false,
      status: 'invalid',
      error: 'Invalid PE signature at e_lfanew.',
      fields,
      warnings: ['Invalid PE signature at e_lfanew.'],
      isPe32Plus: false,
      entryPointRva: 0,
      imageBase: 0n,
      sections: [],
      overlay: { startOffset: bytes.length, length: 0 },
      rvaToOffset: () => ({ rva: 0, type: 'unmapped' }),
      rvaToFileOffset: () => ({ rva: 0, type: 'unmapped' }),
    }
  }

  fields.push(
    toStructureField({
      name: 'Signature',
      offset: peOffset,
      length: 4,
      value: 'PE\\0\\0',
      interpretation: 'PE Signature',
      valid: true,
    }),
  )

  // COFF File Header (20 bytes)
  const machine = reader.readU16Sync('le')
  const numSections = reader.readU16Sync('le')
  const _timeDateStamp = reader.readU32Sync('le')
  reader.skip(8) // pointerToSymbolTable, numberOfSymbols
  const _sizeOfOptionalHeader = reader.readU16Sync('le')
  const _characteristics = reader.readU16Sync('le')
  void _timeDateStamp
  void _sizeOfOptionalHeader
  void _characteristics

  fields.push(
    toStructureField({
      name: 'Machine',
      offset: peOffset + 4,
      length: 2,
      value: `0x${machine.toString(16)}`,
      interpretation:
        machine === 0x8664
          ? 'AMD64 (x64)'
          : machine === 0x14c
          ? 'Intel 386'
          : machine === 0xaa64
          ? 'ARM64'
          : 'Unknown',
      valid: true,
    }),
  )
  fields.push(
    toStructureField({
      name: 'NumberOfSections',
      offset: peOffset + 6,
      length: 2,
      value: numSections,
      interpretation: `${numSections} sections`,
      valid: true,
    }),
  )

  // Optional Header
  const optHeaderOffset = peOffset + 24
  reader.seek(optHeaderOffset)
  const optMagic = reader.readU16Sync('le')
  const isPe32Plus = optMagic === 0x20b // PE32+ (64-bit)

  reader.skip(14) // major/minor linker, code/data sizes
  const entryPointRva = reader.readU32Sync('le')
  reader.skip(4) // baseOfCode

  let imageBase: bigint
  if (isPe32Plus) {
    imageBase = reader.readU64Sync('le')
  } else {
    imageBase = BigInt(reader.readU32Sync('le'))
  }

  // Section Table
  const sectionTableOffset = optHeaderOffset + (isPe32Plus ? 240 : 224)
  reader.seek(sectionTableOffset)

  const sections: PeParseResult['sections'] = []
  let maxRawEnd = 0

  for (let i = 0; i < numSections; i++) {
    if (reader.position + 40 > bytes.length) {
      warnings.push(`Section ${i} header truncated`)
      break
    }

    const secStart = reader.position
    const nameBytes = reader.readBytesSync(8)
    const nullIdx = nameBytes.indexOf(0)
    const nameStr = new TextDecoder('utf-8', { fatal: false }).decode(
      nullIdx >= 0 ? nameBytes.subarray(0, nullIdx) : nameBytes,
    )
    const virtualSize = reader.readU32Sync('le')
    const virtualAddress = reader.readU32Sync('le')
    const sizeOfRawData = reader.readU32Sync('le')
    const pointerToRawData = reader.readU32Sync('le')
    reader.skip(12) // relocs, line numbers, characteristics
    const secCharacteristics = reader.readU32Sync('le')

    sections.push({
      name: nameStr,
      virtualAddress,
      virtualSize,
      rawOffset: pointerToRawData,
      rawSize: sizeOfRawData,
      characteristics: secCharacteristics,
    })

    if (pointerToRawData + sizeOfRawData > maxRawEnd) {
      maxRawEnd = pointerToRawData + sizeOfRawData
    }

    fields.push(
      toStructureField({
        name: `Section[${nameStr}]`,
        offset: secStart,
        length: 40,
        value: nameStr,
        interpretation: `RVA 0x${virtualAddress.toString(16)} (size 0x${virtualSize.toString(16)}), Raw 0x${pointerToRawData.toString(16)} (size 0x${sizeOfRawData.toString(16)})`,
        valid: true,
      }),
    )
  }

  // Calculate overlay
  const overlayStart = maxRawEnd > 0 ? maxRawEnd : bytes.length
  const overlayLength = Math.max(0, bytes.length - overlayStart)

  function rvaToOffset(rva: number): PeRvaMapping {
    for (const sec of sections) {
      if (
        rva >= sec.virtualAddress &&
        rva < sec.virtualAddress + Math.max(sec.virtualSize, sec.rawSize)
      ) {
        const offsetInSection = rva - sec.virtualAddress
        if (offsetInSection < sec.rawSize) {
          return {
            rva,
            type: 'file-backed',
            status: 'file-backed',
            fileOffset: sec.rawOffset + offsetInSection,
            sectionName: sec.name,
          }
        }
        return {
          rva,
          type: 'zero-fill',
          status: 'zero-fill',
          sectionName: sec.name,
        }
      }
    }
    return { rva, type: 'unmapped', status: 'unmapped' }
  }

  return {
    format: 'pe',
    confidence: 1.0,
    valid: true,
    status: 'valid',
    fields,
    warnings,
    isPe32Plus,
    entryPointRva,
    imageBase,
    sections,
    overlay: {
      startOffset: overlayStart,
      length: overlayLength,
    },
    rvaToOffset,
    rvaToFileOffset: rvaToOffset,
  }
}
