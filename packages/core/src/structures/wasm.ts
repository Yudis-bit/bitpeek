import { type StructureParseResult, type StructureField, toStructureField } from './types'
import { BoundedCheckedReader } from '../reader'

const WASM_SECTION_NAMES: Record<number, string> = {
  0: 'Custom',
  1: 'Type',
  2: 'Import',
  3: 'Function',
  4: 'Table',
  5: 'Memory',
  6: 'Global',
  7: 'Export',
  8: 'Start',
  9: 'Element',
  10: 'Code',
  11: 'Data',
  12: 'DataCount',
}

export function parseWasm(bytes: Uint8Array): StructureParseResult | null {
  if (bytes.length < 8) return null
  // Check magic "\0asm" (0x00, 0x61, 0x73, 0x6d)
  if (bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
    return null
  }

  const reader = new BoundedCheckedReader(bytes)
  const fields: StructureField[] = []
  const warnings: string[] = []

  reader.skip(4)
  fields.push(
    toStructureField({
      name: 'Magic',
      label: 'Magic',
      offset: 0,
      length: 4,
      value: '\\0asm',
      interpretedValue: '\\0asm',
      interpretation: 'WebAssembly Binary Magic',
      valid: true,
    }),
  )

  const version = reader.readU32Sync('le')
  fields.push(
    toStructureField({
      name: 'Version',
      label: 'Version',
      offset: 4,
      length: 4,
      value: version,
      interpretedValue: version,
      interpretation: version === 1 ? 'Wasm MVP / Core Version 1' : `Unknown version ${version}`,
      valid: version === 1,
    }),
  )

  // Parse section framing
  let sectionIndex = 0
  while (reader.position < bytes.length) {
    const secOffset = reader.position
    const secId = reader.readU8Sync()
    const secName = WASM_SECTION_NAMES[secId] ?? `Section_${secId}`

    // Read LEB128 section size synchronously from buffer
    let size = 0
    let shift = 0
    let count = 0
    let validLeb = false

    while (count < 5 && reader.position < bytes.length) {
      const b = reader.readU8Sync()
      count += 1
      size |= (b & 0x7f) << shift
      shift += 7
      if ((b & 0x80) === 0) {
        validLeb = true
        break
      }
    }

    if (!validLeb) {
      warnings.push(`Malformed LEB128 section length at offset ${secOffset}`)
      fields.push(
        toStructureField({
          name: `${secName}[${sectionIndex}]`,
          label: `${secName} Section`,
          offset: secOffset,
          length: reader.position - secOffset,
          value: 'Malformed LEB128',
          interpretation: 'Invalid section length encoding',
          valid: false,
        }),
      )
      return {
        format: 'wasm',
        valid: false,
        status: 'invalid',
        error: `Malformed LEB128 section length at offset ${secOffset}.`,
        fields,
        warnings,
      }
    }

    const payloadOffset = reader.position
    const isTruncated = payloadOffset + size > bytes.length

    fields.push(
      toStructureField({
        name: `${secName}[${sectionIndex}]`,
        label: `${secName} Section`,
        offset: secOffset,
        length: (reader.position - secOffset) + Math.min(size, bytes.length - payloadOffset),
        value: `id=${secId}, size=${size}`,
        interpretation: `${secName} section (${size} bytes)`,
        valid: !isTruncated,
      }),
    )

    if (isTruncated) {
      warnings.push(`Section ${secName} (id ${secId}) declared size ${size} exceeds file bounds`)
      return {
        format: 'wasm',
        valid: false,
        status: 'partial',
        error: `Section ${secName} (id ${secId}) declared size ${size} exceeds file bounds.`,
        fields,
        warnings,
      }
    }

    reader.skip(size)
    sectionIndex += 1
  }

  return {
    format: 'wasm',
    valid: true,
    status: 'valid',
    fields,
    warnings,
  }
}
