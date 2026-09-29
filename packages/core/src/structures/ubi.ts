import { type StructureParseResult, type StructureField, toStructureField } from './types'
import { BoundedCheckedReader } from '../reader'
import { crc32 } from '../crypto'

export interface UbiParseResult extends StructureParseResult {
  headerType: 'EC' | 'VID'
  version: number
  eraseCounter?: bigint
  volumeId?: number
  logicalEraseblock?: number
  crcMatches: boolean
}

export function parseUbi(bytes: Uint8Array): UbiParseResult | null {
  if (bytes.length < 64) return null

  const reader = new BoundedCheckedReader(bytes)
  const magic = reader.readU32Sync('be')

  // EC Header magic: 0x55424923 ("UBI#")
  // VID Header magic: 0x55424921 ("UBI!")
  if (magic !== 0x55424923 && magic !== 0x55424921) {
    return null
  }

  const isEc = magic === 0x55424923
  const headerType = isEc ? 'EC' : 'VID'
  const fields: StructureField[] = []
  const warnings: string[] = []

  fields.push(
    toStructureField({
      name: 'Magic',
      label: 'Magic',
      offset: 0,
      length: 4,
      value: isEc ? 'UBI#' : 'UBI!',
      interpretation: isEc ? 'UBI Erase Counter Header' : 'UBI Volume Identifier Header',
      valid: true,
    }),
  )

  const version = reader.readU8Sync()
  fields.push(
    toStructureField({
      name: 'Version',
      label: 'Version',
      offset: 4,
      length: 1,
      value: version,
      interpretation: `UBI Version ${version}`,
      valid: version === 1,
    }),
  )

  reader.skip(3) // padding

  let eraseCounter: bigint | undefined

  if (isEc) {
    eraseCounter = reader.readU64Sync('be')
    const vidHdrOffset = reader.readU32Sync('be')
    const _dataOffset = reader.readU32Sync('be')
    const _imageSeq = reader.readU32Sync('be')
    void _dataOffset
    void _imageSeq
    reader.seek(60)
    const storedCrc = reader.readU32Sync('be')

    // Compute CRC32 over 60 bytes with CRC field excluded
    const computedCrc = crc32(bytes.subarray(0, 60))
    const crcMatches = computedCrc === storedCrc
    if (!crcMatches) {
      warnings.push(`UBI EC header CRC mismatch: stored 0x${storedCrc.toString(16)}, computed 0x${computedCrc.toString(16)}`)
    }

    fields.push(
      toStructureField({
        name: 'Erase Counter',
        label: 'Erase Counter',
        offset: 8,
        length: 8,
        value: eraseCounter,
        interpretedValue: eraseCounter,
        interpretation: `Erase Count: ${eraseCounter}`,
        valid: true,
      }),
    )
    fields.push(
      toStructureField({
        name: 'VidHdrOffset',
        label: 'VID Header Offset',
        offset: 16,
        length: 4,
        value: vidHdrOffset,
        interpretation: `VID Header Offset: 0x${vidHdrOffset.toString(16)}`,
        valid: true,
      }),
    )
    fields.push(
      toStructureField({
        name: 'HeaderCRC',
        label: 'Header CRC',
        offset: 60,
        length: 4,
        value: `0x${storedCrc.toString(16)}`,
        interpretation: crcMatches
          ? 'CRC32 verified successfully'
          : `CRC32 mismatch: stored 0x${storedCrc.toString(16)}, computed 0x${computedCrc.toString(16)}`,
        valid: crcMatches,
      }),
    )

    return {
      format: 'ubi',
      valid: crcMatches,
      status: crcMatches ? 'valid' : 'partial',
      error: crcMatches ? undefined : 'UBI EC header CRC mismatch.',
      fields,
      warnings,
      headerType,
      version,
      eraseCounter,
      crcMatches,
    }
  }

  // VID Header
  const _volType = reader.readU8Sync()
  const _copyFlag = reader.readU8Sync()
  const _compat = reader.readU8Sync()
  void _volType
  void _copyFlag
  void _compat

  const volumeId = reader.readU32Sync('be')
  const logicalEraseblock = reader.readU32Sync('be')
  reader.skip(4) // reserved
  const dataSize = reader.readU32Sync('be')
  reader.seek(60)
  const storedCrc = reader.readU32Sync('be')

  const computedCrc = crc32(bytes.subarray(0, 60))
  const crcMatches = computedCrc === storedCrc
  if (!crcMatches) {
    warnings.push(`UBI VID header CRC mismatch: stored 0x${storedCrc.toString(16)}, computed 0x${computedCrc.toString(16)}`)
  }

  fields.push(
    toStructureField({
      name: 'VolumeID',
      label: 'Volume ID',
      offset: 8,
      length: 4,
      value: volumeId,
      interpretation: `Volume ID: ${volumeId}`,
      valid: true,
    }),
  )
  fields.push(
    toStructureField({
      name: 'LogicalEraseblock',
      label: 'Logical Eraseblock',
      offset: 12,
      length: 4,
      value: logicalEraseblock,
      interpretation: `LEB: ${logicalEraseblock}`,
      valid: true,
    }),
  )
  fields.push(
    toStructureField({
      name: 'DataSize',
      label: 'Data Size',
      offset: 20,
      length: 4,
      value: dataSize,
      interpretation: `Data Size: ${dataSize} B`,
      valid: true,
    }),
  )
  fields.push(
    toStructureField({
      name: 'HeaderCRC',
      label: 'Header CRC',
      offset: 60,
      length: 4,
      value: `0x${storedCrc.toString(16)}`,
      interpretation: crcMatches ? 'CRC32 verified' : 'CRC32 mismatch',
      valid: crcMatches,
    }),
  )

  return {
    format: 'ubi',
    valid: crcMatches,
    status: crcMatches ? 'valid' : 'partial',
    error: crcMatches ? undefined : 'UBI VID header CRC mismatch.',
    fields,
    warnings,
    headerType,
    version,
    volumeId,
    logicalEraseblock,
    crcMatches,
  }
}
