/**
 * Bitpeek Ultra - NAND Multi-Read Analysis & Majority Reconstruction
 *
 * Implements Section 13 (NAND-03, AC046):
 * - Bit variability comparison across multiple physical acquisitions
 * - Majority voting reconstruction with confidence and conflict tracking
 * - Provenance preservation of all contributing reads
 */

export interface BitVariabilityMap {
  totalBytes: number
  variableByteCount: number
  variableBitCount: number
  variableIndices: Array<{
    byteOffset: number
    conflictingBitsMask: number
    onesCountPerBit: number[]
  }>
}

export interface MajorityVoteResult {
  reconstructed: Uint8Array
  unanimousBitRatio: number // 0.0 to 1.0
  conflictByteOffsets: number[]
  totalBytes: number
  provenance: {
    contributingReadCount: number
    readIds?: string[]
    timestamp: string
  }
}

export class MultiReadAnalyzer {
  /**
   * Compares 2 or more reads of the same size and generates a bit variability map.
   */
  public static analyzeVariability(reads: Uint8Array[]): BitVariabilityMap {
    if (reads.length < 2) {
      throw new Error(`Multi-read analysis requires at least 2 reads, got ${reads.length}`)
    }

    const len = reads[0]!.length
    for (let r = 1; r < reads.length; r++) {
      if (reads[r]!.length !== len) {
        throw new Error(`Read length mismatch: read 0 is ${len} bytes, read ${r} is ${reads[r]!.length} bytes`)
      }
    }

    const variableIndices: BitVariabilityMap['variableIndices'] = []
    let variableBitCount = 0

    for (let i = 0; i < len; i++) {
      const firstByte = reads[0]![i]!
      let diffMask = 0
      const onesCount = new Array<number>(8).fill(0)

      for (let r = 0; r < reads.length; r++) {
        const b = reads[r]![i]!
        diffMask |= firstByte ^ b
        for (let bit = 0; bit < 8; bit++) {
          if ((b & (1 << bit)) !== 0) {
            onesCount[bit]!++
          }
        }
      }

      if (diffMask !== 0) {
        let bitFlipsInByte = 0
        for (let bit = 0; bit < 8; bit++) {
          if ((diffMask & (1 << bit)) !== 0) {
            bitFlipsInByte++
          }
        }
        variableBitCount += bitFlipsInByte
        variableIndices.push({
          byteOffset: i,
          conflictingBitsMask: diffMask,
          onesCountPerBit: onesCount,
        })
      }
    }

    return {
      totalBytes: len,
      variableByteCount: variableIndices.length,
      variableBitCount,
      variableIndices,
    }
  }

  /**
   * Performs majority bit voting across reads to reconstruct the most probable data.
   */
  public static reconstructMajority(
    reads: Uint8Array[],
    readIds?: string[],
  ): MajorityVoteResult {
    if (reads.length < 2) {
      throw new Error(`Majority voting requires at least 2 reads, got ${reads.length}`)
    }

    const len = reads[0]!.length
    const numReads = reads.length
    const half = numReads / 2

    const reconstructed = new Uint8Array(len)
    const conflictByteOffsets: number[] = []
    let unanimousBits = 0
    const totalBits = len * 8

    for (let i = 0; i < len; i++) {
      let reconstructedByte = 0
      let hasConflictInByte = false

      for (let bit = 0; bit < 8; bit++) {
        let ones = 0
        for (let r = 0; r < numReads; r++) {
          if ((reads[r]![i]! & (1 << bit)) !== 0) {
            ones++
          }
        }

        if (ones === numReads || ones === 0) {
          unanimousBits++
        }

        if (ones === half) {
          // Exact tie!
          hasConflictInByte = true
        }

        if (ones > half) {
          reconstructedByte |= 1 << bit
        }
      }

      reconstructed[i] = reconstructedByte
      if (hasConflictInByte) {
        conflictByteOffsets.push(i)
      }
    }

    return {
      reconstructed,
      unanimousBitRatio: unanimousBits / totalBits,
      conflictByteOffsets,
      totalBytes: len,
      provenance: {
        contributingReadCount: numReads,
        readIds,
        timestamp: new Date().toISOString(),
      },
    }
  }
}
