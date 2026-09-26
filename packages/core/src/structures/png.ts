import type { StructureField, StructureParseResult } from './types'
import { crc32 } from '../crypto'
import { formatHex } from '../bytes'

const PNG_SPEC_URL = 'https://www.w3.org/TR/png-3/'

function formatHexSlice(bytes: Uint8Array, start: number, end: number): string {
  return formatHex(bytes.slice(start, end))
}

const COLOR_TYPES: Record<number, string> = {
  0: 'Grayscale',
  2: 'Truecolor (RGB)',
  3: 'Indexed-color',
  4: 'Grayscale with alpha',
  6: 'Truecolor with alpha (RGBA)',
}

export function parsePng(bytes: Uint8Array): StructureParseResult {
  const fields: StructureField[] = []
  const warnings: string[] = []
  let totalBytesParsed: number
  let status: 'valid' | 'partial' | 'invalid' = 'valid'

  // 1. Signature
  if (bytes.length < 8) {
    fields.push({
      id: 'png.signature',
      label: 'PNG Signature',
      range: { start: 0, end: bytes.length },
      rawHex: formatHexSlice(bytes, 0, bytes.length),
      interpretedValue: 'Truncated signature',
      type: 'bytes[8]',
      status: 'truncated',
      reason: `Expected 8-byte PNG signature, got ${bytes.length} bytes.`,
      specLink: PNG_SPEC_URL + '#5PNG-file-signature',
    })
    return {
      format: 'png',
      status: 'invalid',
      fields,
      warnings: ['File is smaller than the 8-byte PNG signature.'],
      totalBytesParsed: bytes.length,
    }
  }

  const expectedSignature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
  const signatureMatches = expectedSignature.every((b, i) => bytes[i] === b)

  fields.push({
    id: 'png.signature',
    label: 'PNG Signature',
    range: { start: 0, end: 8 },
    rawHex: formatHexSlice(bytes, 0, 8),
    interpretedValue: signatureMatches ? 'Valid PNG signature (\u0089PNG\\r\\n\\x1A\\n)' : 'Invalid signature',
    type: 'bytes[8]',
    status: signatureMatches ? 'valid' : 'inconsistent',
    reason: signatureMatches ? undefined : 'Bytes 0x00–0x07 do not match PNG magic bytes.',
    specLink: PNG_SPEC_URL + '#5PNG-file-signature',
  })

  if (!signatureMatches) {
    return {
      format: 'png',
      status: 'invalid',
      fields,
      warnings: ['Leading bytes do not match PNG signature.'],
      totalBytesParsed: 8,
    }
  }

  totalBytesParsed = 8
  let offset = 8
  let chunkIndex = 0
  let seenIhdr = false
  let seenIend = false

  while (offset < bytes.length) {
    const chunkStart = offset
    chunkIndex++

    if (offset + 8 > bytes.length) {
      status = 'partial'
      warnings.push(`Truncated chunk header at offset ${offset}.`)
      fields.push({
        id: `png.chunk[${chunkIndex}].truncated`,
        label: `Truncated Chunk Header #${chunkIndex}`,
        range: { start: offset, end: bytes.length },
        rawHex: formatHexSlice(bytes, offset, bytes.length),
        interpretedValue: 'Truncated header',
        type: 'chunk_header',
        status: 'truncated',
        reason: 'Unexpected EOF while reading 8-byte chunk length and type.',
        specLink: PNG_SPEC_URL + '#5Chunk-layout',
      })
      totalBytesParsed = bytes.length
      break
    }

    // 4-byte BE length
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    const dataLength = view.getUint32(offset, false)
    const typeBytes = bytes.slice(offset + 4, offset + 8)
    const typeStr = Array.from(typeBytes, (b) => String.fromCharCode(b)).join('')
    const isAncillary = (typeBytes[0]! & 0x20) !== 0

    if (chunkIndex === 1 && typeStr !== 'IHDR') {
      warnings.push('First PNG chunk must be IHDR.')
      status = 'partial'
    }

    const chunkChildren: StructureField[] = []

    // Length field
    chunkChildren.push({
      id: `png.chunk[${chunkIndex}].length`,
      label: 'Data Length',
      range: { start: offset, end: offset + 4 },
      rawHex: formatHexSlice(bytes, offset, offset + 4),
      interpretedValue: dataLength,
      type: 'u32',
      endian: 'big',
      status: 'valid',
      specLink: PNG_SPEC_URL + '#5Chunk-layout',
    })

    // Type field
    chunkChildren.push({
      id: `png.chunk[${chunkIndex}].type`,
      label: 'Chunk Type',
      range: { start: offset + 4, end: offset + 8 },
      rawHex: formatHexSlice(bytes, offset + 4, offset + 8),
      interpretedValue: `${typeStr} (${isAncillary ? 'ancillary' : 'critical'})`,
      type: 'ascii[4]',
      status: 'valid',
      specLink: PNG_SPEC_URL + '#5Chunk-layout',
    })

    const dataStart = offset + 8
    const dataEnd = dataStart + dataLength

    if (dataEnd > bytes.length) {
      status = 'partial'
      warnings.push(`Chunk ${typeStr} declares ${dataLength} bytes but file ends early.`)
      chunkChildren.push({
        id: `png.chunk[${chunkIndex}].data_truncated`,
        label: `${typeStr} Data (Truncated)`,
        range: { start: dataStart, end: bytes.length },
        rawHex: formatHexSlice(bytes, dataStart, Math.min(bytes.length, dataStart + 16)),
        interpretedValue: `Available ${bytes.length - dataStart} of ${dataLength} bytes`,
        type: `bytes[${dataLength}]`,
        status: 'truncated',
        reason: 'File ended before declared chunk data completed.',
        specLink: PNG_SPEC_URL + '#5Chunk-layout',
      })

      fields.push({
        id: `png.chunk[${chunkIndex}]`,
        label: `Chunk ${typeStr} (Truncated)`,
        range: { start: chunkStart, end: bytes.length },
        rawHex: formatHexSlice(bytes, chunkStart, Math.min(bytes.length, chunkStart + 8)),
        interpretedValue: `${typeStr} [${dataLength} bytes declared]`,
        type: 'chunk',
        status: 'truncated',
        children: chunkChildren,
      })
      totalBytesParsed = bytes.length
      break
    }

    // Parse IHDR specific fields if applicable
    if (typeStr === 'IHDR') {
      seenIhdr = true
      if (dataLength !== 13) {
        warnings.push(`IHDR data length must be 13, got ${dataLength}.`)
        status = 'partial'
      } else {
        const width = view.getUint32(dataStart, false)
        const height = view.getUint32(dataStart + 4, false)
        const bitDepth = bytes[dataStart + 8] ?? 0
        const colorType = bytes[dataStart + 9] ?? 0
        const compression = bytes[dataStart + 10] ?? 0
        const filter = bytes[dataStart + 11] ?? 0
        const interlace = bytes[dataStart + 12] ?? 0

        const widthValid = width > 0 && width <= 0x7fffffff
        const heightValid = height > 0 && height <= 0x7fffffff

        chunkChildren.push({
          id: 'png.ihdr.width',
          label: 'Width',
          range: { start: dataStart, end: dataStart + 4 },
          rawHex: formatHexSlice(bytes, dataStart, dataStart + 4),
          interpretedValue: width,
          type: 'u32',
          endian: 'big',
          status: widthValid ? 'valid' : 'inconsistent',
          reason: widthValid ? undefined : 'Width must be greater than zero and <= 2^31-1.',
          specLink: PNG_SPEC_URL + '#11IHDR',
        })

        chunkChildren.push({
          id: 'png.ihdr.height',
          label: 'Height',
          range: { start: dataStart + 4, end: dataStart + 8 },
          rawHex: formatHexSlice(bytes, dataStart + 4, dataStart + 8),
          interpretedValue: height,
          type: 'u32',
          endian: 'big',
          status: heightValid ? 'valid' : 'inconsistent',
          reason: heightValid ? undefined : 'Height must be greater than zero and <= 2^31-1.',
          specLink: PNG_SPEC_URL + '#11IHDR',
        })

        chunkChildren.push({
          id: 'png.ihdr.bit_depth',
          label: 'Bit Depth',
          range: { start: dataStart + 8, end: dataStart + 9 },
          rawHex: formatHexSlice(bytes, dataStart + 8, dataStart + 9),
          interpretedValue: `${bitDepth} bits per sample/palette index`,
          type: 'u8',
          status: [1, 2, 4, 8, 16].includes(bitDepth) ? 'valid' : 'inconsistent',
          specLink: PNG_SPEC_URL + '#11IHDR',
        })

        chunkChildren.push({
          id: 'png.ihdr.color_type',
          label: 'Color Type',
          range: { start: dataStart + 9, end: dataStart + 10 },
          rawHex: formatHexSlice(bytes, dataStart + 9, dataStart + 10),
          interpretedValue: COLOR_TYPES[colorType] ?? `Unknown color type (${colorType})`,
          type: 'u8',
          status: COLOR_TYPES[colorType] ? 'valid' : 'inconsistent',
          specLink: PNG_SPEC_URL + '#11IHDR',
        })

        chunkChildren.push({
          id: 'png.ihdr.compression',
          label: 'Compression Method',
          range: { start: dataStart + 10, end: dataStart + 11 },
          rawHex: formatHexSlice(bytes, dataStart + 10, dataStart + 11),
          interpretedValue: compression === 0 ? 'Deflate/Inflate (0)' : `Unknown (${compression})`,
          type: 'u8',
          status: compression === 0 ? 'valid' : 'inconsistent',
          specLink: PNG_SPEC_URL + '#11IHDR',
        })

        chunkChildren.push({
          id: 'png.ihdr.filter',
          label: 'Filter Method',
          range: { start: dataStart + 11, end: dataStart + 12 },
          rawHex: formatHexSlice(bytes, dataStart + 11, dataStart + 12),
          interpretedValue: filter === 0 ? 'Adaptive filtering (0)' : `Unknown (${filter})`,
          type: 'u8',
          status: filter === 0 ? 'valid' : 'inconsistent',
          specLink: PNG_SPEC_URL + '#11IHDR',
        })

        chunkChildren.push({
          id: 'png.ihdr.interlace',
          label: 'Interlace Method',
          range: { start: dataStart + 12, end: dataStart + 13 },
          rawHex: formatHexSlice(bytes, dataStart + 12, dataStart + 13),
          interpretedValue: interlace === 0 ? 'No interlace (0)' : interlace === 1 ? 'Adam7 interlace (1)' : `Unknown (${interlace})`,
          type: 'u8',
          status: interlace === 0 || interlace === 1 ? 'valid' : 'inconsistent',
          specLink: PNG_SPEC_URL + '#11IHDR',
        })
      }
    } else {
      // Generic chunk data field
      if (dataLength > 0) {
        chunkChildren.push({
          id: `png.chunk[${chunkIndex}].data`,
          label: `${typeStr} Data`,
          range: { start: dataStart, end: dataEnd },
          rawHex: formatHexSlice(bytes, dataStart, Math.min(dataEnd, dataStart + 16)) + (dataLength > 16 ? '...' : ''),
          interpretedValue: `${dataLength} bytes`,
          type: `bytes[${dataLength}]`,
          status: 'valid',
          specLink: PNG_SPEC_URL + '#5Chunk-layout',
        })
      }
    }

    // CRC check
    const crcOffset = dataEnd
    if (crcOffset + 4 > bytes.length) {
      status = 'partial'
      warnings.push(`Truncated CRC field for chunk ${typeStr}.`)
      fields.push({
        id: `png.chunk[${chunkIndex}]`,
        label: `Chunk ${typeStr} (Truncated CRC)`,
        range: { start: chunkStart, end: bytes.length },
        rawHex: formatHexSlice(bytes, chunkStart, Math.min(bytes.length, chunkStart + 8)),
        interpretedValue: `${typeStr}`,
        type: 'chunk',
        status: 'truncated',
        children: chunkChildren,
      })
      totalBytesParsed = bytes.length
      break
    }

    const declaredCrc = view.getUint32(crcOffset, false)
    const crcData = bytes.slice(offset + 4, dataEnd)
    const computedCrc = crc32(crcData)
    const crcMatches = declaredCrc === computedCrc

    if (!crcMatches) {
      status = 'partial'
      warnings.push(
        `CRC mismatch in chunk ${typeStr} at offset ${crcOffset}: declared 0x${declaredCrc.toString(16).toUpperCase().padStart(8, '0')}, computed 0x${computedCrc.toString(16).toUpperCase().padStart(8, '0')}.`,
      )
    }

    chunkChildren.push({
      id: `png.chunk[${chunkIndex}].crc`,
      label: 'CRC-32',
      range: { start: crcOffset, end: crcOffset + 4 },
      rawHex: formatHexSlice(bytes, crcOffset, crcOffset + 4),
      interpretedValue: `0x${declaredCrc.toString(16).toUpperCase().padStart(8, '0')} (${crcMatches ? 'valid' : 'mismatch'})`,
      type: 'u32',
      endian: 'big',
      status: crcMatches ? 'valid' : 'inconsistent',
      reason: crcMatches
        ? undefined
        : `CRC mismatch: computed 0x${computedCrc.toString(16).toUpperCase().padStart(8, '0')}.`,
      specLink: PNG_SPEC_URL + '#5CRC-calculation',
    })

    const chunkEnd = crcOffset + 4
    fields.push({
      id: `png.chunk[${chunkIndex}]`,
      label: `Chunk ${typeStr}`,
      range: { start: chunkStart, end: chunkEnd },
      rawHex: formatHexSlice(bytes, chunkStart, Math.min(chunkEnd, chunkStart + 8)),
      interpretedValue: `${typeStr} (${dataLength} data bytes)`,
      type: 'chunk',
      status: crcMatches ? 'valid' : 'inconsistent',
      reason: crcMatches ? undefined : 'Chunk contains CRC error.',
      children: chunkChildren,
    })

    offset = chunkEnd
    totalBytesParsed = offset

    if (typeStr === 'IEND') {
      seenIend = true
      break
    }
  }

  if (!seenIhdr && status === 'valid') {
    status = 'partial'
    warnings.push('PNG datastream missing mandatory IHDR chunk.')
  }
  if (!seenIend && status === 'valid') {
    status = 'partial'
    warnings.push('PNG datastream missing mandatory IEND chunk.')
  }

  // Trailing bytes after IEND
  if (offset < bytes.length) {
    const trailingCount = bytes.length - offset
    warnings.push(`File contains ${trailingCount} trailing bytes after IEND chunk.`)
    fields.push({
      id: 'png.trailing_data',
      label: 'Trailing Data',
      range: { start: offset, end: bytes.length },
      rawHex: formatHexSlice(bytes, offset, Math.min(bytes.length, offset + 16)) + (trailingCount > 16 ? '...' : ''),
      interpretedValue: `${trailingCount} unparsed bytes`,
      type: `bytes[${trailingCount}]`,
      status: 'unknown',
      reason: 'Bytes located after terminal IEND chunk.',
    })
  }

  return {
    format: 'png',
    status,
    fields,
    warnings,
    totalBytesParsed,
    trailingBytes: offset < bytes.length ? bytes.length - offset : undefined,
  }
}
