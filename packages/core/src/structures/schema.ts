import type { StructureField, StructureParseResult } from './types'
import { formatHex } from '../bytes'

export type Endian = 'big' | 'little'

export interface BaseFieldDef {
  id: string
  label: string
  offset: number
  description?: string
  specLink?: string
}

export type ScalarFieldType =
  | 'u8'
  | 'i8'
  | 'u16'
  | 'i16'
  | 'u32'
  | 'i32'
  | 'u64'
  | 'i64'
  | 'f32'
  | 'f64'

export interface ScalarFieldDef extends BaseFieldDef {
  type: ScalarFieldType
  endian?: Endian
}

export interface BytesFieldDef extends BaseFieldDef {
  type: 'bytes' | 'ascii' | 'utf8'
  length: number
}

export interface BitfieldDef extends BaseFieldDef {
  type: 'bitfield'
  containerType: 'u8' | 'u16' | 'u32' | 'u64'
  lsb: number
  width: number
  endian?: Endian
}

export interface StructFieldDef extends BaseFieldDef {
  type: 'struct'
  fields: CustomFieldDef[]
}

export interface ArrayFieldDef extends BaseFieldDef {
  type: 'array'
  count: number
  itemType: ScalarFieldType | 'bytes' | 'ascii'
  itemLength?: number
  endian?: Endian
}

export type CustomFieldDef =
  | ScalarFieldDef
  | BytesFieldDef
  | BitfieldDef
  | StructFieldDef
  | ArrayFieldDef

export interface CustomStructureSchema {
  schemaVersion: 1
  name: string
  description?: string
  defaultEndian?: Endian
  fields: CustomFieldDef[]
}

function formatHexSlice(bytes: Uint8Array, start: number, end: number): string {
  return formatHex(bytes.slice(start, Math.min(bytes.length, end)))
}

function fieldSize(field: CustomFieldDef): number {
  switch (field.type) {
    case 'u8':
    case 'i8':
      return 1
    case 'u16':
    case 'i16':
      return 2
    case 'u32':
    case 'i32':
    case 'f32':
      return 4
    case 'u64':
    case 'i64':
    case 'f64':
      return 8
    case 'bytes':
    case 'ascii':
    case 'utf8':
      return field.length
    case 'bitfield': {
      if (field.containerType === 'u8') return 1
      if (field.containerType === 'u16') return 2
      if (field.containerType === 'u32') return 4
      return 8
    }
    case 'struct': {
      let maxEnd = 0
      for (const child of field.fields) {
        maxEnd = Math.max(maxEnd, child.offset + fieldSize(child))
      }
      return maxEnd
    }
    case 'array': {
      const itemSz =
        field.itemType === 'bytes' || field.itemType === 'ascii'
          ? (field.itemLength ?? 1)
          : fieldSize({ id: '', label: '', offset: 0, type: field.itemType })
      return itemSz * field.count
    }
  }
}

export function parseCustomStructure(
  bytes: Uint8Array,
  schema: CustomStructureSchema,
): StructureParseResult {
  const fields: StructureField[] = []
  const warnings: string[] = []
  const defaultEndian = schema.defaultEndian ?? 'big'
  const seenIds = new Set<string>()

  function parseField(
    def: CustomFieldDef,
    baseOffset = 0,
  ): StructureField {
    if (seenIds.has(def.id)) {
      warnings.push(`Duplicate field ID: "${def.id}".`)
    }
    seenIds.add(def.id)

    const absOffset = baseOffset + def.offset
    const size = fieldSize(def)
    const endExclusive = absOffset + size
    const endian = ('endian' in def && def.endian) ? def.endian : defaultEndian
    const le = endian === 'little'

    if (absOffset >= bytes.length) {
      return {
        id: def.id,
        label: def.label,
        range: { start: absOffset, end: endExclusive },
        rawHex: '',
        interpretedValue: 'Out of bounds',
        type: def.type,
        endian,
        status: 'truncated',
        reason: `Field offset 0x${absOffset.toString(16)} is beyond file length (${bytes.length} bytes).`,
        specLink: def.specLink,
      }
    }

    if (endExclusive > bytes.length) {
      warnings.push(`Field "${def.label}" is truncated by end of document.`)
      return {
        id: def.id,
        label: def.label,
        range: { start: absOffset, end: bytes.length },
        rawHex: formatHexSlice(bytes, absOffset, bytes.length),
        interpretedValue: 'Truncated data',
        type: def.type,
        endian,
        status: 'truncated',
        reason: `Expected ${size} bytes, file ends after ${bytes.length - absOffset} bytes.`,
        specLink: def.specLink,
      }
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    const rawHex = formatHexSlice(bytes, absOffset, endExclusive)

    switch (def.type) {
      case 'u8':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: bytes[absOffset] ?? 0,
          type: 'u8',
          status: 'valid',
          specLink: def.specLink,
        }
      case 'i8':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: view.getInt8(absOffset),
          type: 'i8',
          status: 'valid',
          specLink: def.specLink,
        }
      case 'u16':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: view.getUint16(absOffset, le),
          type: 'u16',
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      case 'i16':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: view.getInt16(absOffset, le),
          type: 'i16',
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      case 'u32':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: view.getUint32(absOffset, le),
          type: 'u32',
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      case 'i32':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: view.getInt32(absOffset, le),
          type: 'i32',
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      case 'u64': {
        const val = view.getBigUint64(absOffset, le)
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: val.toString(10),
          type: 'u64',
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      }
      case 'i64': {
        const val = view.getBigInt64(absOffset, le)
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: val.toString(10),
          type: 'i64',
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      }
      case 'f32':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: view.getFloat32(absOffset, le),
          type: 'f32',
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      case 'f64':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: view.getFloat64(absOffset, le),
          type: 'f64',
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      case 'ascii': {
        const text = new TextDecoder('ascii', { fatal: false }).decode(
          bytes.subarray(absOffset, endExclusive),
        )
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: `"${text}"`,
          type: `ascii[${def.length}]`,
          status: 'valid',
          specLink: def.specLink,
        }
      }
      case 'utf8': {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(
          bytes.subarray(absOffset, endExclusive),
        )
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: `"${text}"`,
          type: `utf8[${def.length}]`,
          status: 'valid',
          specLink: def.specLink,
        }
      }
      case 'bytes':
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: `${def.length} bytes`,
          type: `bytes[${def.length}]`,
          status: 'valid',
          specLink: def.specLink,
        }
      case 'bitfield': {
        let containerVal: bigint
        if (def.containerType === 'u8') {
          containerVal = BigInt(bytes[absOffset] ?? 0)
        } else if (def.containerType === 'u16') {
          containerVal = BigInt(view.getUint16(absOffset, le))
        } else if (def.containerType === 'u32') {
          containerVal = BigInt(view.getUint32(absOffset, le))
        } else {
          containerVal = view.getBigUint64(absOffset, le)
        }

        const mask = (1n << BigInt(def.width)) - 1n
        const extracted = (containerVal >> BigInt(def.lsb)) & mask

        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: `0x${extracted.toString(16)} (${extracted.toString(10)}) [bits ${def.lsb + def.width - 1}..${def.lsb}]`,
          type: `bitfield<${def.containerType}, lsb=${def.lsb}, w=${def.width}>`,
          endian,
          status: 'valid',
          specLink: def.specLink,
        }
      }
      case 'struct': {
        const children = def.fields.map((childDef) => parseField(childDef, absOffset))
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: `struct (${def.fields.length} fields)`,
          type: 'struct',
          status: 'valid',
          children,
          specLink: def.specLink,
        }
      }
      case 'array': {
        const itemSz =
          def.itemType === 'bytes' || def.itemType === 'ascii'
            ? (def.itemLength ?? 1)
            : fieldSize({ id: '', label: '', offset: 0, type: def.itemType })

        const children: StructureField[] = []
        for (let i = 0; i < def.count; i++) {
          const itemDef: CustomFieldDef =
            def.itemType === 'bytes' || def.itemType === 'ascii'
              ? {
                  id: `${def.id}[${i}]`,
                  label: `${def.label}[${i}]`,
                  offset: i * itemSz,
                  type: def.itemType,
                  length: def.itemLength ?? 1,
                }
              : {
                  id: `${def.id}[${i}]`,
                  label: `${def.label}[${i}]`,
                  offset: i * itemSz,
                  type: def.itemType,
                  endian,
                }
          children.push(parseField(itemDef, absOffset))
        }
        return {
          id: def.id,
          label: def.label,
          range: { start: absOffset, end: endExclusive },
          rawHex,
          interpretedValue: `${def.itemType}[${def.count}]`,
          type: `array[${def.count}]`,
          status: 'valid',
          children,
          specLink: def.specLink,
        }
      }
    }
  }

  for (const def of schema.fields) {
    fields.push(parseField(def, 0))
  }

  return {
    format: 'custom-schema',
    status: warnings.length > 0 ? 'partial' : 'valid',
    fields,
    warnings,
    totalBytesParsed: bytes.length,
  }
}
