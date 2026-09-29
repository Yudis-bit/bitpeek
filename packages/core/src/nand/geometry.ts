/**
 * Bitpeek Ultra - NAND Geometry & Coordinate Mapping
 *
 * Implements Section 13 (NAND-01, NAND-02, AC041, AC042):
 * - Physical NAND address mapping (chip, LUN, block, page, column, OOB)
 * - Raw dump offset to physical coordinates and reverse
 * - Profile validation & bad-block marker checking
 * - Reference synthetic lab profile & ONFI profile
 */

export interface NandGeometryProfile {
  profileId: string
  name: string
  version: string
  sourceKind: 'synthetic' | 'raw_physical' | 'logical_controller'
  dataBytesPerPage: number
  oobBytesPerPage: number
  pagesPerBlock: number
  blocksPerLun: number
  lunsPerChip?: number
  chipsPerArray?: number
  badBlockMarkerOffset: number // offset in page (usually dataBytesPerPage or dataBytesPerPage + 5)
  badBlockMarkerPages: number[] // pages in block where marker is written (e.g. [0, 1])
  eccStepSize?: number
  eccParityBytes?: number
  description?: string
}

export interface NandPhysicalAddress {
  chip: number
  lun: number
  block: number
  page: number
  column: number
  isOob: boolean
}

export interface NandPageSpan {
  chip: number
  lun: number
  block: number
  page: number
  rawStartOffset: number
  dataStartOffset: number
  dataLength: number
  oobStartOffset: number
  oobLength: number
  rawLength: number
}

/**
 * Standard synthetic laboratory test profile:
 * 512 bytes data + 16 bytes OOB per page, 32 pages per block, 1024 blocks.
 * Total page size: 528 bytes. Block size: 16,896 bytes.
 */
export const SYNTHETIC_LAB_NAND_PROFILE: NandGeometryProfile = {
  profileId: 'lab-synth-512-16',
  name: 'Synthetic Lab 512+16 Profile',
  version: '1.0.0',
  sourceKind: 'synthetic',
  dataBytesPerPage: 512,
  oobBytesPerPage: 16,
  pagesPerBlock: 32,
  blocksPerLun: 1024,
  lunsPerChip: 1,
  chipsPerArray: 1,
  badBlockMarkerOffset: 512 + 5, // byte 5 of OOB
  badBlockMarkerPages: [0, 1],
  eccStepSize: 256,
  eccParityBytes: 3,
  description: 'Deterministic test fixture profile for laboratory NAND ECC & geometry testing',
}

/**
 * Common ONFI 2KB+64B page profile (e.g. Micron / Samsung SLC/MLC).
 */
export const ONFI_2K_64_PROFILE: NandGeometryProfile = {
  profileId: 'onfi-2048-64',
  name: 'ONFI 2048+64 SLC Profile',
  version: '1.0.0',
  sourceKind: 'raw_physical',
  dataBytesPerPage: 2048,
  oobBytesPerPage: 64,
  pagesPerBlock: 64,
  blocksPerLun: 2048,
  lunsPerChip: 1,
  chipsPerArray: 1,
  badBlockMarkerOffset: 2048, // byte 0 of OOB
  badBlockMarkerPages: [0, 1],
  eccStepSize: 512,
  eccParityBytes: 7,
  description: 'Documented 2KB+64B SLC NAND layout with 64 pages/block',
}

export class NandGeometryManager {
  private readonly rawPageSize: number
  private readonly rawBlockSize: number
  private readonly rawLunSize: number
  private readonly rawChipSize: number
  private readonly lunsPerChip: number
  private readonly chipsPerArray: number

  constructor(public readonly profile: NandGeometryProfile) {
    this.validateProfile(profile)
    this.rawPageSize = profile.dataBytesPerPage + profile.oobBytesPerPage
    this.rawBlockSize = this.rawPageSize * profile.pagesPerBlock
    this.lunsPerChip = profile.lunsPerChip ?? 1
    this.chipsPerArray = profile.chipsPerArray ?? 1
    this.rawLunSize = this.rawBlockSize * profile.blocksPerLun
    this.rawChipSize = this.rawLunSize * this.lunsPerChip
  }

  private validateProfile(p: NandGeometryProfile): void {
    if (p.dataBytesPerPage <= 0 || p.oobBytesPerPage < 0 || p.pagesPerBlock <= 0 || p.blocksPerLun <= 0) {
      throw new Error(`Invalid NAND profile dimensions: ${JSON.stringify(p)}`)
    }
  }

  public getRawPageSize(): number {
    return this.rawPageSize
  }

  public getRawBlockSize(): number {
    return this.rawBlockSize
  }

  /**
   * Converts a raw byte offset in the physical dump into physical coordinates.
   */
  public offsetToPhysical(offset: number): NandPhysicalAddress {
    if (offset < 0) {
      throw new RangeError(`Negative offset: ${offset}`)
    }

    const chip = Math.floor(offset / this.rawChipSize)
    const chipRem = offset % this.rawChipSize

    const lun = Math.floor(chipRem / this.rawLunSize)
    const lunRem = chipRem % this.rawLunSize

    const block = Math.floor(lunRem / this.rawBlockSize)
    const blockRem = lunRem % this.rawBlockSize

    const page = Math.floor(blockRem / this.rawPageSize)
    const column = blockRem % this.rawPageSize

    const isOob = column >= this.profile.dataBytesPerPage

    return {
      chip,
      lun,
      block,
      page,
      column,
      isOob,
    }
  }

  /**
   * Converts physical coordinates into a raw dump byte offset.
   */
  public physicalToOffset(addr: NandPhysicalAddress): number {
    const chipOffset = addr.chip * this.rawChipSize
    const lunOffset = addr.lun * this.rawLunSize
    const blockOffset = addr.block * this.rawBlockSize
    const pageOffset = addr.page * this.rawPageSize
    return chipOffset + lunOffset + blockOffset + pageOffset + addr.column
  }

  /**
   * Gets the physical spans (data and OOB) for a specific page.
   */
  public getPageSpan(chip: number, lun: number, block: number, page: number): NandPageSpan {
    const rawStart = this.physicalToOffset({ chip, lun, block, page, column: 0, isOob: false })
    return {
      chip,
      lun,
      block,
      page,
      rawStartOffset: rawStart,
      dataStartOffset: rawStart,
      dataLength: this.profile.dataBytesPerPage,
      oobStartOffset: rawStart + this.profile.dataBytesPerPage,
      oobLength: this.profile.oobBytesPerPage,
      rawLength: this.rawPageSize,
    }
  }

  /**
   * Checks if a block is marked bad in a physical dump buffer.
   */
  public isBlockBad(dump: Uint8Array, block: number, chip = 0, lun = 0): boolean {
    for (const page of this.profile.badBlockMarkerPages) {
      const pageSpan = this.getPageSpan(chip, lun, block, page)
      const markerOffset = pageSpan.rawStartOffset + this.profile.badBlockMarkerOffset
      if (markerOffset < dump.length) {
        const val = dump[markerOffset]!
        // In SLC/MLC NAND, factory bad blocks have marker byte != 0xFF
        if (val !== 0xff) {
          return true
        }
      }
    }
    return false
  }
}
