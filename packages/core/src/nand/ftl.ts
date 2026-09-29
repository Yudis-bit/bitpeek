/**
 * Bitpeek Ultra - Synthetic FTL & Logical Storage Reconstruction
 *
 * Implements Section 13 (NAND-05, AC047):
 * - Pure FTL translation and block/page reconstruction from OOB metadata
 * - Resolves sequence numbers, stale pages, and version conflicts
 * - Explicitly tracks holes / unmapped LBAs without silent zero-fill
 */

import { NandGeometryManager, type NandPageSpan } from './geometry'
import { crc16 } from '../crypto'

export interface SyntheticOobHeader {
  magic: number // 0x5446 ("FT")
  lba: number
  sequence: number
  flags: number // 0x01: valid, 0x02: stale
  crc: number
  isValidCrc: boolean
}

export interface FtlPageCandidate {
  lba: number
  sequence: number
  flags: number
  pageSpan: NandPageSpan
  dataSlice: Uint8Array
  isStale: boolean
}

export interface FtlReconstructionResult {
  totalPhysicalPagesScanned: number
  validPagesFound: number
  uniqueLbas: number
  maxLba: number
  missingLbas: number[]
  lbaMap: Map<number, FtlPageCandidate>
  staleCandidates: FtlPageCandidate[]
  logicalImage: Uint8Array
  holesCount: number
}

export class SyntheticFtlReconstructor {
  constructor(private readonly geom: NandGeometryManager) {}

  /**
   * Parses the synthetic FTL header from the OOB area of a page.
   */
  public parseOobHeader(oob: Uint8Array): SyntheticOobHeader | null {
    if (oob.length < 13) return null

    // Magic: 0x46, 0x54 ("FT")
    if (oob[0] !== 0x46 || oob[1] !== 0x54) {
      return null
    }

    const view = new DataView(oob.buffer, oob.byteOffset, oob.byteLength)
    const lba = view.getUint32(2, true)
    const sequence = view.getUint32(6, true)
    const flags = oob[10]!
    const storedCrc = view.getUint16(11, true)

    // Compute CRC16 over first 11 bytes
    const computedCrc = crc16(oob.subarray(0, 11))
    const isValidCrc = computedCrc === storedCrc

    return {
      magic: 0x5446,
      lba,
      sequence,
      flags,
      crc: storedCrc,
      isValidCrc,
    }
  }

  /**
   * Reconstructs the logical disk image from a physical NAND dump.
   */
  public reconstruct(dump: Uint8Array): FtlReconstructionResult {
    const rawPageSize = this.geom.getRawPageSize()
    const totalPages = Math.floor(dump.length / rawPageSize)

    const candidatesByLba = new Map<number, FtlPageCandidate[]>()
    let validPagesFound = 0

    // Scan all pages in the dump
    for (let p = 0; p < totalPages; p++) {
      const offset = p * rawPageSize
      const phys = this.geom.offsetToPhysical(offset)
      const pageSpan = this.geom.getPageSpan(phys.chip, phys.lun, phys.block, phys.page)

      const oobSlice = dump.subarray(pageSpan.oobStartOffset, pageSpan.oobStartOffset + pageSpan.oobLength)
      const header = this.parseOobHeader(oobSlice)

      if (header && header.isValidCrc) {
        validPagesFound++
        const dataSlice = dump.subarray(pageSpan.dataStartOffset, pageSpan.dataStartOffset + pageSpan.dataLength)

        const candidate: FtlPageCandidate = {
          lba: header.lba,
          sequence: header.sequence,
          flags: header.flags,
          pageSpan,
          dataSlice,
          isStale: (header.flags & 0x02) !== 0,
        }

        const list = candidatesByLba.get(header.lba) ?? []
        list.push(candidate)
        candidatesByLba.set(header.lba, list)
      }
    }

    // Resolve conflicts and select highest sequence non-stale candidate per LBA
    const lbaMap = new Map<number, FtlPageCandidate>()
    const staleCandidates: FtlPageCandidate[] = []

    let maxLba = -1
    for (const [lba, candidates] of candidatesByLba.entries()) {
      // Sort descending by sequence
      candidates.sort((a, b) => b.sequence - a.sequence)

      // Find highest sequence non-stale candidate
      let winner: FtlPageCandidate | undefined
      for (const cand of candidates) {
        if (!cand.isStale && !winner) {
          winner = cand
        } else {
          staleCandidates.push(cand)
        }
      }

      if (winner) {
        lbaMap.set(lba, winner)
        if (lba > maxLba) {
          maxLba = lba
        }
      }
    }

    // Identify holes / missing LBAs from 0 to maxLba
    const missingLbas: number[] = []
    const pageSize = this.geom.profile.dataBytesPerPage
    const logicalSize = maxLba >= 0 ? (maxLba + 1) * pageSize : 0
    const logicalImage = new Uint8Array(logicalSize)

    for (let lba = 0; lba <= maxLba; lba++) {
      const page = lbaMap.get(lba)
      if (page) {
        logicalImage.set(page.dataSlice, lba * pageSize)
      } else {
        missingLbas.push(lba)
      }
    }

    return {
      totalPhysicalPagesScanned: totalPages,
      validPagesFound,
      uniqueLbas: lbaMap.size,
      maxLba: Math.max(0, maxLba),
      missingLbas,
      lbaMap,
      staleCandidates,
      logicalImage,
      holesCount: missingLbas.length,
    }
  }
}
