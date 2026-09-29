import { type StructureParseResult, type StructureField, toStructureField } from './types'
import { BoundedCheckedReader } from '../reader'

const SQUASHFS_COMPRESSIONS: Record<number, string> = {
  1: 'GZIP',
  2: 'LZMA',
  3: 'LZO',
  4: 'XZ',
  5: 'LZ4',
  6: 'ZSTD',
}

export interface SquashfsSuperblockResult extends StructureParseResult {
  inodes: number
  blockSize: number
  compression: string
  majorVersion: number
  minorVersion: number
  bytesUsed: bigint
}

export function parseSquashfs(bytes: Uint8Array): SquashfsSuperblockResult | null {
  if (bytes.length < 96) return null

  // Magic 0x73717368 ("sqsh") little-endian
  const magic = (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0
  if (magic !== 0x73717368) {
    return null
  }

  const reader = new BoundedCheckedReader(bytes)
  const fields: StructureField[] = []
  const warnings: string[] = []

  reader.skip(4)
  fields.push(
    toStructureField({
      name: 's_magic',
      label: 'Magic',
      offset: 0,
      length: 4,
      value: 'sqsh',
      interpretation: 'SquashFS Superblock Magic',
      valid: true,
    }),
  )

  const inodes = reader.readU32Sync('le')
  const _mkfsTime = reader.readU32Sync('le')
  const blockSize = reader.readU32Sync('le')
  const _fragments = reader.readU32Sync('le')
  const compressionId = reader.readU16Sync('le')
  const blockLog = reader.readU16Sync('le')
  const _flags = reader.readU16Sync('le')
  const _idCount = reader.readU16Sync('le')
  const majorVersion = reader.readU16Sync('le')
  const minorVersion = reader.readU16Sync('le')
  const _rootInode = reader.readU64Sync('le')
  const bytesUsed = reader.readU64Sync('le')

  void _mkfsTime
  void _fragments
  void _flags
  void _idCount
  void _rootInode

  const compression = SQUASHFS_COMPRESSIONS[compressionId] ?? `UNKNOWN(${compressionId})`
  const isVersion4 = majorVersion === 4 && minorVersion === 0
  if (!isVersion4) {
    warnings.push(`Unsupported SquashFS version ${majorVersion}.${minorVersion}. Expected 4.0.`)
  }

  fields.push(
    toStructureField({
      name: 'Inodes Count',
      label: 'Inodes Count',
      offset: 4,
      length: 4,
      value: inodes,
      interpretedValue: inodes,
      interpretation: `${inodes} inodes`,
      valid: true,
    }),
  )
  fields.push(
    toStructureField({
      name: 'Block Size',
      label: 'Block Size',
      offset: 12,
      length: 4,
      value: blockSize,
      interpretation: `${blockSize} bytes/block (2^${blockLog})`,
      valid: blockSize > 0,
    }),
  )
  fields.push(
    toStructureField({
      name: 'Compression',
      label: 'Compression',
      offset: 20,
      length: 2,
      value: compression,
      interpretedValue: compression,
      interpretation: `Compression algorithm: ${compression}`,
      valid: compressionId >= 1 && compressionId <= 6,
    }),
  )
  fields.push(
    toStructureField({
      name: 'Version',
      label: 'Version',
      offset: 28,
      length: 4,
      value: `${majorVersion}.${minorVersion}`,
      interpretation: isVersion4 ? 'SquashFS 4.0' : `Legacy version ${majorVersion}.${minorVersion}`,
      valid: isVersion4,
    }),
  )
  fields.push(
    toStructureField({
      name: 'Bytes Used',
      label: 'Bytes Used',
      offset: 40,
      length: 8,
      value: bytesUsed.toString(),
      interpretation: `Filesystem size: ${bytesUsed} bytes`,
      valid: bytesUsed <= BigInt(bytes.length),
    }),
  )

  return {
    format: 'squashfs',
    valid: isVersion4,
    status: isVersion4 ? 'valid' : 'partial',
    error: isVersion4 ? undefined : `Unsupported SquashFS version ${majorVersion}.${minorVersion}. Expected 4.0.`,
    fields,
    warnings,
    inodes,
    blockSize,
    compression,
    majorVersion,
    minorVersion,
    bytesUsed,
  }
}
