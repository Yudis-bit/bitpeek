import type { StructureParseResult, StructureField } from './types'
import { BoundedCheckedReader } from '../reader'

export function parseZip(bytes: Uint8Array): StructureParseResult | null {
  if (bytes.length < 22) return null
  // Check if starts with Local Header PK\x03\x04 or contains EOCD PK\x05\x06
  const isPkStart = bytes[0] === 0x50 && bytes[1] === 0x4b
  if (!isPkStart) return null

  const fields: StructureField[] = []
  const reader = new BoundedCheckedReader(bytes)

  // Scan local file headers from beginning
  let entryIndex = 0
  let isClean = true
  let errorMsg: string | undefined

  while (reader.position + 4 <= bytes.length) {
    const headerStart = reader.position
    const sig = reader.readU32Sync('be')
    if (sig === 0x504b0304) {
      // Local File Header
      reader.skip(2) // version needed
      reader.skip(2) // flags
      reader.skip(2) // compression
      reader.skip(4) // mod time & date
      const crc32Val = reader.readU32Sync('le')
      const compressedSize = reader.readU32Sync('le')
      const uncompressedSize = reader.readU32Sync('le')
      const fileNameLen = reader.readU16Sync('le')
      const extraFieldLen = reader.readU16Sync('le')

      let fileName: string
      if (reader.position + fileNameLen <= bytes.length) {
        const nameBytes = reader.readBytesSync(fileNameLen)
        fileName = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes)
      } else {
        fileName = '[truncated]'
        isClean = false
        errorMsg = 'Local file header file name exceeds file boundaries.'
      }

      reader.skip(extraFieldLen)
      const dataOffset = reader.position
      const totalEntryLen = (dataOffset - headerStart) + compressedSize

      fields.push({
        id: `entry_${entryIndex}`,
        name: `Entry[${entryIndex}]: ${fileName}`,
        label: `Entry[${entryIndex}]: ${fileName}`,
        offset: headerStart,
        length: Math.min(totalEntryLen, bytes.length - headerStart),
        range: { start: headerStart, end: Math.min(headerStart + totalEntryLen, bytes.length) },
        rawHex: '',
        value: fileName,
        interpretedValue: fileName,
        type: 'zip_entry',
        status: dataOffset + compressedSize <= bytes.length ? 'valid' : 'truncated',
        interpretation: `Compressed: ${compressedSize} B, Uncompressed: ${uncompressedSize} B, CRC: 0x${crc32Val.toString(16)}`,
        valid: dataOffset + compressedSize <= bytes.length,
      })

      if (dataOffset + compressedSize > bytes.length) {
        isClean = false
        errorMsg = `Compressed payload for "${fileName}" exceeds file boundaries.`
        break
      }

      reader.skip(compressedSize)
      entryIndex += 1
    } else if (sig === 0x504b0102) {
      // Central Directory Header (46 bytes fixed)
      reader.seek(headerStart + 28)
      const cdFileNameLen = reader.readU16Sync('le')
      const cdExtraLen = reader.readU16Sync('le')
      const cdCommentLen = reader.readU16Sync('le')
      const cdEntryLen = 46 + cdFileNameLen + cdExtraLen + cdCommentLen

      fields.push({
        id: `cd_${entryIndex}`,
        name: `CentralDirectory[${entryIndex}]`,
        label: `Central Directory Record ${entryIndex}`,
        offset: headerStart,
        length: cdEntryLen,
        range: { start: headerStart, end: Math.min(headerStart + cdEntryLen, bytes.length) },
        rawHex: '',
        value: 'PK\\x01\\x02',
        interpretedValue: 'PK\\x01\\x02',
        type: 'zip_cd',
        status: 'valid',
        interpretation: 'Central Directory Record',
        valid: true,
      })
      reader.seek(headerStart + cdEntryLen)
      entryIndex += 1
    } else if (sig === 0x504b0506) {
      // End of Central Directory
      fields.push({
        id: 'eocd',
        name: 'EOCD',
        label: 'EOCD (End of Central Directory)',
        offset: headerStart,
        length: 22,
        range: { start: headerStart, end: Math.min(headerStart + 22, bytes.length) },
        rawHex: '',
        value: 'PK\\x05\\x06',
        interpretedValue: 'PK\\x05\\x06',
        type: 'zip_eocd',
        status: 'valid',
        interpretation: 'End of Central Directory Record',
        valid: true,
      })
      break
    } else {
      // Other segment
      break
    }
  }

  return {
    format: 'zip',
    valid: isClean,
    status: isClean ? 'valid' : 'partial',
    error: errorMsg,
    fields,
    warnings: errorMsg ? [errorMsg] : [],
  }
}
