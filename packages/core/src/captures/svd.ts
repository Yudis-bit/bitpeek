/**
 * Bitpeek Ultra - CMSIS-SVD Microcontroller Register Parser
 *
 * Implements Section 14 (CAP-03, AC050):
 * - CMSIS-SVD XML format parser
 * - Peripheral base addresses, registers, bitfields, and access semantics
 * - Strictly read-only viewing model (no side-effecting reads)
 */

export type RegisterAccess = 'read-only' | 'write-only' | 'read-write'

export interface SvdField {
  name: string
  description?: string
  bitOffset: number
  bitWidth: number
  access?: RegisterAccess
}

export interface SvdRegister {
  name: string
  displayName?: string
  description?: string
  addressOffset: number
  sizeBits: number // e.g. 8, 16, 32
  access: RegisterAccess
  resetValue?: number
  fields: SvdField[]
}

export interface SvdPeripheral {
  name: string
  description?: string
  baseAddress: number
  registers: SvdRegister[]
}

export interface SvdDevice {
  name: string
  description?: string
  peripherals: SvdPeripheral[]
}

export class CmsisSvdParser {
  /**
   * Parses CMSIS-SVD XML text into structured device/peripheral/register descriptions.
   */
  public static parse(xmlText: string): SvdDevice {
    const deviceName = this.extractTag(xmlText, 'name') ?? 'UnknownDevice'
    const deviceDesc = this.extractTag(xmlText, 'description')

    const peripherals: SvdPeripheral[] = []
    const periphRegex = /<peripheral>([\s\S]*?)<\/peripheral>/g
    let periphMatch: RegExpExecArray | null

    while ((periphMatch = periphRegex.exec(xmlText)) !== null) {
      const pXml = periphMatch[1]!
      const pName = this.extractTag(pXml, 'name') ?? 'Periph'
      const pDesc = this.extractTag(pXml, 'description')
      const baseAddrStr = this.extractTag(pXml, 'baseAddress') ?? '0'
      const baseAddress = this.parseNumeric(baseAddrStr)

      const registers: SvdRegister[] = []
      const regRegex = /<register>([\s\S]*?)<\/register>/g
      let regMatch: RegExpExecArray | null

      while ((regMatch = regRegex.exec(pXml)) !== null) {
        const rXml = regMatch[1]!
        const rName = this.extractTag(rXml, 'name') ?? 'Reg'
        const rDesc = this.extractTag(rXml, 'description')
        const offsetStr = this.extractTag(rXml, 'addressOffset') ?? '0'
        const addressOffset = this.parseNumeric(offsetStr)
        const sizeStr = this.extractTag(rXml, 'size') ?? '32'
        const sizeBits = parseInt(sizeStr, 10)
        const accessStr = (this.extractTag(rXml, 'access') ?? 'read-write').toLowerCase()
        const access: RegisterAccess =
          accessStr === 'read-only'
            ? 'read-only'
            : accessStr === 'write-only'
            ? 'write-only'
            : 'read-write'

        const fields: SvdField[] = []
        const fieldRegex = /<field>([\s\S]*?)<\/field>/g
        let fieldMatch: RegExpExecArray | null

        while ((fieldMatch = fieldRegex.exec(rXml)) !== null) {
          const fXml = fieldMatch[1]!
          const fName = this.extractTag(fXml, 'name') ?? 'Field'
          const fDesc = this.extractTag(fXml, 'description')

          let bitOffset = 0
          let bitWidth = 1

          const offsetTag = this.extractTag(fXml, 'bitOffset')
          const widthTag = this.extractTag(fXml, 'bitWidth')

          if (offsetTag !== undefined && widthTag !== undefined) {
            bitOffset = parseInt(offsetTag, 10)
            bitWidth = parseInt(widthTag, 10)
          } else {
            // Check for <bitRange>[msb:lsb]</bitRange>
            const bitRange = this.extractTag(fXml, 'bitRange')
            if (bitRange) {
              const rangeMatch = bitRange.match(/\[([0-9]+):([0-9]+)\]/)
              if (rangeMatch) {
                const msb = parseInt(rangeMatch[1]!, 10)
                const lsb = parseInt(rangeMatch[2]!, 10)
                bitOffset = lsb
                bitWidth = msb - lsb + 1
              }
            }
          }

          fields.push({
            name: fName,
            description: fDesc,
            bitOffset,
            bitWidth,
          })
        }

        registers.push({
          name: rName,
          description: rDesc,
          addressOffset,
          sizeBits,
          access,
          fields,
        })
      }

      peripherals.push({
        name: pName,
        description: pDesc,
        baseAddress,
        registers,
      })
    }

    return {
      name: deviceName,
      description: deviceDesc,
      peripherals,
    }
  }

  /**
   * Safely reads and extracts a register bitfield from an in-memory snapshot buffer.
   * Safety constraint (AC050): viewing is strictly read-only and validates bounds.
   */
  public static readRegisterValue(
    snapshot: Uint8Array,
    peripheral: SvdPeripheral,
    register: SvdRegister,
  ): number {
    const absAddress = peripheral.baseAddress + register.addressOffset
    const bytesNeeded = register.sizeBits / 8

    if (absAddress + bytesNeeded > snapshot.length) {
      throw new RangeError(`Register address 0x${absAddress.toString(16)} is out of snapshot bounds (${snapshot.length} bytes)`)
    }

    const view = new DataView(snapshot.buffer, snapshot.byteOffset, snapshot.byteLength)
    if (register.sizeBits === 8) {
      return snapshot[absAddress]!
    } else if (register.sizeBits === 16) {
      return view.getUint16(absAddress, true)
    } else {
      return view.getUint32(absAddress, true)
    }
  }

  /**
   * Extracts a specific named bitfield value from a raw register integer value.
   */
  public static extractFieldValue(registerValue: number, field: SvdField): number {
    const mask = (1 << field.bitWidth) - 1
    return (registerValue >>> field.bitOffset) & mask
  }

  private static extractTag(xml: string, tag: string): string | undefined {
    const regex = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`)
    const match = regex.exec(xml)
    return match ? match[1]!.trim() : undefined
  }

  private static parseNumeric(val: string): number {
    const cleaned = val.trim()
    if (cleaned.startsWith('0x') || cleaned.startsWith('0X')) {
      return parseInt(cleaned, 16)
    }
    return parseInt(cleaned, 10)
  }
}
