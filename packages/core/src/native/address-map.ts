/**
 * Bitpeek Ultra - Native Address Space Mapping
 *
 * Implements Section 10 (NATIVE-01, AC051):
 * - Multi-space address mapping (File Offset <-> Virtual Address <-> Physical)
 * - Module identity, ASLR slide / epoch, segments, BSS zero-fill
 * - Handles ambiguous / overlapping candidate mappings
 */

export interface AddressRange {
  start: bigint
  size: bigint
  permissions?: 'r' | 'w' | 'x' | 'rw' | 'rx' | 'rwx'
  kind: 'file-backed' | 'zero-fill' | 'unmapped' | 'mmio'
  fileOffset?: number
  name?: string
}

export interface ModuleMapping {
  moduleId: string
  name: string
  preferredBase: bigint
  actualBase: bigint
  aslrSlide: bigint
  ranges: AddressRange[]
}

export interface AddressTranslationResult {
  status: 'file-backed' | 'zero-fill' | 'unmapped'
  virtualAddress: bigint
  fileOffset?: number
  module?: ModuleMapping
  range?: AddressRange
  isAmbiguous?: boolean
}

export class NativeAddressSpace {
  private modules = new Map<string, ModuleMapping>()

  constructor(
    public readonly pointerWidthBits: 32 | 64 = 64,
    public readonly endian: 'little' | 'big' = 'little',
  ) {}

  public registerModule(module: ModuleMapping): void {
    this.modules.set(module.moduleId, module)
  }

  public getModules(): ModuleMapping[] {
    return Array.from(this.modules.values())
  }

  /**
   * Translates a runtime virtual address to a file offset and mapping range.
   */
  public translateVirtualAddress(va: bigint): AddressTranslationResult {
    const candidates: Array<{ module: ModuleMapping; range: AddressRange }> = []

    for (const mod of this.modules.values()) {
      for (const range of mod.ranges) {
        if (va >= range.start && va < range.start + range.size) {
          candidates.push({ module: mod, range })
        }
      }
    }

    if (candidates.length === 0) {
      return {
        status: 'unmapped',
        virtualAddress: va,
      }
    }

    const { module, range } = candidates[0]!
    const offsetInRange = Number(va - range.start)

    if (range.kind === 'file-backed' && range.fileOffset !== undefined) {
      return {
        status: 'file-backed',
        virtualAddress: va,
        fileOffset: range.fileOffset + offsetInRange,
        module,
        range,
        isAmbiguous: candidates.length > 1,
      }
    }

    if (range.kind === 'zero-fill') {
      return {
        status: 'zero-fill',
        virtualAddress: va,
        module,
        range,
        isAmbiguous: candidates.length > 1,
      }
    }

    return {
      status: 'unmapped',
      virtualAddress: va,
      module,
      range,
      isAmbiguous: candidates.length > 1,
    }
  }

  /**
   * Translates a file offset in a specific module to its virtual address.
   */
  public fileOffsetToVirtualAddress(moduleId: string, fileOffset: number): bigint | null {
    const mod = this.modules.get(moduleId)
    if (!mod) return null

    for (const range of mod.ranges) {
      if (
        range.kind === 'file-backed' &&
        range.fileOffset !== undefined &&
        fileOffset >= range.fileOffset &&
        fileOffset < range.fileOffset + Number(range.size)
      ) {
        const delta = BigInt(fileOffset - range.fileOffset)
        return range.start + delta
      }
    }

    return null
  }
}
