import { type StructureParseResult, type StructureField, toStructureField } from './types'
import { BoundedCheckedReader } from '../reader'
import { crc32 } from '../crypto'

export interface GptParseResult extends StructureParseResult {
  headerCrcMatches: boolean
  currentLba: bigint
  backupLba: bigint
  firstUsableLba: bigint
  lastUsableLba: bigint
  numPartitionEntries: number
}

export function parseGpt(bytes: Uint8Array, sectorSize = 512): GptParseResult | null {
  if (bytes.length < sectorSize * 2) return null

  // Check GPT Header at LBA 1 (offset sectorSize)
  const gptOffset = sectorSize
  const gptSig = new TextDecoder('ascii').decode(bytes.subarray(gptOffset, gptOffset + 8))
  if (gptSig !== 'EFI PART') {
    return null
  }

  const reader = new BoundedCheckedReader(bytes)
  reader.seek(gptOffset)

  const fields: StructureField[] = []
  const warnings: string[] = []

  fields.push(
    toStructureField({
      name: 'Signature',
      label: 'Signature',
      offset: gptOffset,
      length: 8,
      value: 'EFI PART',
      interpretation: 'GPT Signature',
      valid: true,
    }),
  )

  reader.skip(8) // Signature
  const _revision = reader.readU32Sync('le')
  const headerSize = reader.readU32Sync('le')
  const storedCrc = reader.readU32Sync('le')
  reader.skip(4) // reserved 0

  const currentLba = reader.readU64Sync('le')
  const backupLba = reader.readU64Sync('le')
  const firstUsableLba = reader.readU64Sync('le')
  const lastUsableLba = reader.readU64Sync('le')
  reader.skip(16) // disk GUID
  const _partitionEntryLba = reader.readU64Sync('le')
  const numPartitionEntries = reader.readU32Sync('le')
  const _partitionEntrySize = reader.readU32Sync('le')
  const _partitionEntriesCrc = reader.readU32Sync('le')

  void _revision
  void _partitionEntryLba
  void _partitionEntrySize
  void _partitionEntriesCrc

  fields.push(
    toStructureField({
      name: 'Header Size',
      label: 'Header Size',
      offset: gptOffset + 12,
      length: 4,
      value: headerSize,
      interpretedValue: headerSize,
      interpretation: `${headerSize} bytes`,
      valid: headerSize >= 92,
    }),
  )

  // Calculate CRC32 of header with CRC field zeroed (AC034)
  const headerCopy = new Uint8Array(bytes.subarray(gptOffset, gptOffset + headerSize))
  if (headerCopy.length >= 20) {
    headerCopy[16] = 0
    headerCopy[17] = 0
    headerCopy[18] = 0
    headerCopy[19] = 0
  }
  const computedCrc = crc32(headerCopy)
  const headerCrcMatches = computedCrc === storedCrc
  if (!headerCrcMatches) {
    warnings.push(`GPT Header CRC32 checksum mismatch: stored 0x${storedCrc.toString(16)}, computed 0x${computedCrc.toString(16)}`)
  }

  fields.push(
    toStructureField({
      name: 'HeaderCRC32',
      label: 'Header CRC32',
      offset: gptOffset + 16,
      length: 4,
      value: `0x${storedCrc.toString(16)}`,
      interpretation: headerCrcMatches
        ? 'CRC32 verified successfully'
        : `CRC32 mismatch: stored 0x${storedCrc.toString(16)}, computed 0x${computedCrc.toString(16)}`,
      valid: headerCrcMatches,
    }),
  )

  fields.push(
    toStructureField({
      name: 'CurrentLBA',
      label: 'Current LBA',
      offset: gptOffset + 24,
      length: 8,
      value: currentLba.toString(),
      interpretation: `Current LBA: ${currentLba}`,
      valid: currentLba === 1n,
    }),
  )

  fields.push(
    toStructureField({
      name: 'PartitionEntriesCount',
      label: 'Partition Entries Count',
      offset: gptOffset + 80,
      length: 4,
      value: numPartitionEntries,
      interpretation: `${numPartitionEntries} partition entries allowed`,
      valid: numPartitionEntries > 0,
    }),
  )

  return {
    format: 'gpt',
    valid: headerCrcMatches,
    status: headerCrcMatches ? 'valid' : 'partial',
    error: headerCrcMatches ? undefined : 'GPT Header CRC32 checksum mismatch.',
    fields,
    warnings,
    headerCrcMatches,
    currentLba,
    backupLba,
    firstUsableLba,
    lastUsableLba,
    numPartitionEntries,
  }
}
