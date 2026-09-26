export type FieldStatus =
  | 'valid'
  | 'truncated'
  | 'unsupported'
  | 'inconsistent'
  | 'unknown'

export interface StructureField {
  id: string
  label: string
  range: {
    start: number
    end: number // end-exclusive [start, end)
  }
  rawHex: string
  interpretedValue: string | number | boolean
  type: string
  endian?: 'little' | 'big'
  status: FieldStatus
  reason?: string
  specLink?: string
  children?: StructureField[]
}

export type StructureFormat = 'elf' | 'png' | 'custom-schema'

export interface StructureParseResult {
  format: StructureFormat
  status: 'valid' | 'partial' | 'invalid'
  fields: StructureField[]
  warnings: string[]
  totalBytesParsed: number
  trailingBytes?: number
}
