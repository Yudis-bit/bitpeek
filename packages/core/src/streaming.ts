import { BitpeekError } from './errors'
import type { ByteSource } from './byte-source'
import { Crc32, Crc16Ccitt } from './crypto'
import type { BytePattern, PatternMatches } from './analysis'
import type { ExtractedString, StringScanResult } from './strings'
import type { DifferenceRange, ByteDiff } from './diff'

// ==========================================
// 1. STREAMING HASH / CHECKSUM / ENTROPY (DATA-01)
// ==========================================

export async function crc32Stream(
  chunks: AsyncIterable<Uint8Array>,
  signal?: AbortSignal,
): Promise<number> {
  const crc = new Crc32()
  for await (const chunk of chunks) {
    if (signal?.aborted) throw new BitpeekError('CANCELLED', 'CRC32 stream was aborted.')
    crc.update(chunk)
  }
  return crc.digest()
}

export async function crc16Stream(
  chunks: AsyncIterable<Uint8Array>,
  signal?: AbortSignal,
): Promise<number> {
  const crc = new Crc16Ccitt()
  for await (const chunk of chunks) {
    if (signal?.aborted) throw new BitpeekError('CANCELLED', 'CRC16 stream was aborted.')
    crc.update(chunk)
  }
  return crc.digest()
}

export interface EntropyStreamResult {
  entropy: number
  totalBytes: number
  frequencies: Uint32Array
}

export async function entropyStream(
  chunks: AsyncIterable<Uint8Array>,
  signal?: AbortSignal,
): Promise<EntropyStreamResult> {
  const frequencies = new Uint32Array(256)
  let totalBytes = 0

  for await (const chunk of chunks) {
    if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Entropy calculation was aborted.')
    totalBytes += chunk.length
    for (let i = 0; i < chunk.length; i++) {
      frequencies[chunk[i]!]! += 1
    }
  }

  if (totalBytes === 0) {
    return { entropy: 0, totalBytes: 0, frequencies }
  }

  let entropy = 0
  for (let i = 0; i < 256; i++) {
    const count = frequencies[i]!
    if (count > 0) {
      const p = count / totalBytes
      entropy -= p * Math.log2(p)
    }
  }

  return { entropy, totalBytes, frequencies }
}

// ==========================================
// 2. STREAMING PATTERN SEARCH (DATA-02, AC012)
// ==========================================

export interface StreamingSearchOptions {
  startOffset?: number
  limit?: number
  chunkSize?: number
  signal?: AbortSignal
  maxScanBytes?: number
}

export async function findBytePatternStream(
  source: ByteSource,
  pattern: BytePattern,
  options: StreamingSearchOptions = {},
): Promise<PatternMatches> {
  const patternLen = pattern.values.length
  if (patternLen === 0) {
    return { offsets: [], truncated: false, scannedBytes: 0 }
  }

  const startOffset = Math.max(0, options.startOffset ?? 0)
  const limit = options.limit ?? 1000
  const chunkSize = options.chunkSize ?? 64 * 1024
  const signal = options.signal

  const offsets: number[] = []
  let scannedBytes = 0
  let overlap = new Uint8Array(0)
  let overlapAbsoluteStart = startOffset

  const chunksIter = source.chunks(
    { start: startOffset, endExclusive: source.size },
    chunkSize,
    signal,
  )

  for await (const chunk of chunksIter) {
    if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Search was aborted.')

    // Combine overlap from previous chunk with current chunk
    const combined = new Uint8Array(overlap.length + chunk.length)
    combined.set(overlap, 0)
    combined.set(chunk, overlap.length)

    const searchLimit = combined.length - patternLen
    // Scan matching positions
    for (let i = 0; i <= searchLimit; i++) {
      const absOffset = overlapAbsoluteStart + i

      let matches = true
      for (let p = 0; p < patternLen; p++) {
        const mask = pattern.masks[p] ?? 0
        if (((combined[i + p]! ^ pattern.values[p]!) & mask) !== 0) {
          matches = false
          break
        }
      }

      if (matches) {
        // Prevent duplicate match if it was already recorded
        if (offsets.length === 0 || offsets[offsets.length - 1] !== absOffset) {
          offsets.push(absOffset)
          if (offsets.length >= limit) {
            return {
              offsets,
              truncated: true,
              scannedBytes: absOffset + patternLen,
              nextCursor: absOffset + 1,
            }
          }
        }
      }
    }

    scannedBytes += chunk.length
    // Prepare overlap for next chunk: keep the last (patternLen - 1) bytes
    const keepLen = Math.min(patternLen - 1, combined.length)
    overlap = combined.slice(combined.length - keepLen)
    overlapAbsoluteStart = startOffset + scannedBytes - keepLen

    if (options.maxScanBytes && scannedBytes >= options.maxScanBytes) {
      return {
        offsets,
        truncated: true,
        scannedBytes,
        nextCursor: startOffset + scannedBytes,
      }
    }
  }

  return {
    offsets,
    truncated: false,
    scannedBytes,
  }
}

// ==========================================
// 3. STREAMING STRING EXTRACTION (DATA-03, AC013)
// ==========================================

export interface StreamingStringsOptions {
  startOffset?: number
  minimumLength?: number
  limit?: number
  chunkSize?: number
  maxStringLength?: number
  signal?: AbortSignal
}

function isPrintableAscii(b: number): boolean {
  return b >= 0x20 && b <= 0x7e
}

export async function extractPrintableStringsStream(
  source: ByteSource,
  options: StreamingStringsOptions = {},
): Promise<StringScanResult> {
  const minLen = options.minimumLength ?? 4
  const limit = options.limit ?? 1000
  const maxStrLen = options.maxStringLength ?? 4096
  const signal = options.signal

  const items: ExtractedString[] = []
  let currentChars: number[] = []
  let currentStart = -1
  let globalOffset = options.startOffset ?? 0

  for await (const chunk of source.chunks(
    { start: globalOffset },
    options.chunkSize ?? 64 * 1024,
    signal,
  )) {
    if (signal?.aborted) throw new BitpeekError('CANCELLED', 'String extraction was aborted.')

    for (let i = 0; i < chunk.length; i++) {
      const b = chunk[i]!
      const bytePos = globalOffset + i

      if (isPrintableAscii(b)) {
        if (currentStart === -1) {
          currentStart = bytePos
        }
        if (currentChars.length < maxStrLen) {
          currentChars.push(b)
        }
      } else {
        if (currentStart !== -1) {
          const charLen = bytePos - currentStart
          if (charLen >= minLen) {
            const rawStr = String.fromCharCode(...currentChars)
            items.push({
              offset: currentStart,
              byteLength: charLen,
              characterLength: charLen,
              encoding: 'ASCII',
              value: charLen > maxStrLen ? `${rawStr}… [truncated]` : rawStr,
            })
            if (items.length >= limit) {
              return { items, truncated: true, nextCursor: bytePos + 1 }
            }
          }
          currentStart = -1
          currentChars = []
        }
      }
    }

    globalOffset += chunk.length
  }

  // Handle trailing string at EOF
  if (currentStart !== -1) {
    const charLen = globalOffset - currentStart
    if (charLen >= minLen) {
      const rawStr = String.fromCharCode(...currentChars)
      items.push({
        offset: currentStart,
        byteLength: charLen,
        characterLength: charLen,
        encoding: 'ASCII',
        value: charLen > maxStrLen ? `${rawStr}… [truncated]` : rawStr,
      })
    }
  }

  return { items, truncated: false }
}

// ==========================================
// 4. BOUNDED DIFFERENCE STREAMING (DATA-04, AC014)
// ==========================================

export interface StreamingDiffOptions {
  maxDifferences?: number
  chunkSize?: number
  signal?: AbortSignal
}

export async function diffSourceStream(
  current: ByteSource,
  reference: ByteSource,
  options: StreamingDiffOptions = {},
): Promise<ByteDiff> {
  const maxDiff = options.maxDifferences ?? 10_000
  const chunkSize = options.chunkSize ?? 64 * 1024
  const signal = options.signal

  const offsets: number[] = []
  const ranges: DifferenceRange[] = []
  let modified = 0
  let currentOnly = 0
  let referenceOnly = 0
  let activeRange: DifferenceRange | null = null

  const totalLength = Math.max(current.size, reference.size)
  let offset = 0

  while (offset < totalLength) {
    if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Diff stream was aborted.')

    const len = Math.min(chunkSize, totalLength - offset)
    const curLen = Math.max(0, Math.min(len, current.size - offset))
    const refLen = Math.max(0, Math.min(len, reference.size - offset))

    const [curChunk, refChunk] = await Promise.all([
      curLen > 0 ? current.read(offset, curLen, signal) : Promise.resolve(new Uint8Array(0)),
      refLen > 0 ? reference.read(offset, refLen, signal) : Promise.resolve(new Uint8Array(0)),
    ])

    for (let i = 0; i < len; i++) {
      const pos = offset + i
      let kind: DifferenceRange['kind'] | null = null

      if (pos >= reference.size) {
        kind = 'current-only'
      } else if (pos >= current.size) {
        kind = 'reference-only'
      } else if (curChunk[i] !== refChunk[i]) {
        kind = 'modified'
      }

      if (kind !== null) {
        if (kind === 'modified') modified += 1
        else if (kind === 'current-only') currentOnly += 1
        else referenceOnly += 1

        if (offsets.length < maxDiff) {
          offsets.push(pos)
        }

        if (activeRange && activeRange.kind === kind && activeRange.end === pos - 1) {
          activeRange.end = pos
          activeRange.length += 1
        } else {
          if (activeRange && ranges.length < maxDiff) {
            ranges.push(activeRange)
          }
          activeRange = {
            start: pos,
            end: pos,
            length: 1,
            kind,
          }
        }
      } else if (activeRange) {
        if (ranges.length < maxDiff) {
          ranges.push(activeRange)
        }
        activeRange = null
      }
    }

    offset += len
  }

  if (activeRange && ranges.length < maxDiff) {
    ranges.push(activeRange)
  }

  return {
    offsets,
    ranges,
    modified,
    currentOnly,
    referenceOnly,
  }
}
