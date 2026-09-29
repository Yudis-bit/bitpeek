export type FieldStatus =
  | 'valid'
  | 'truncated'
  | 'unsupported'
  | 'inconsistent'
  | 'unknown'
  | 'invalid'

export interface StructureField {
  id: string
  label: string
  name?: string
  offset?: number
  length?: number
  value?: any
  interpretation?: string
  range: {
    start: number
    end: number // end-exclusive [start, end)
  }
  rawHex: string
  interpretedValue: string | number | boolean | bigint
  type: string
  endian?: 'little' | 'big'
  status: FieldStatus
  valid?: boolean
  reason?: string
  specLink?: string
  children?: StructureField[]
}

export type StructureFormat =
  | 'elf'
  | 'png'
  | 'pe'
  | 'wasm'
  | 'zip'
  | 'gpt'
  | 'ubi'
  | 'squashfs'
  | 'safetensors'
  | 'onnx'
  | 'bitcoin'
  | 'ethereum'
  | 'custom-schema'
  | string

export interface StructureParseResult {
  format: StructureFormat
  status?: 'valid' | 'partial' | 'invalid'
  valid?: boolean
  error?: string
  confidence?: number
  fields: StructureField[]
  warnings: string[]
  diagnostics?: any[]
  totalBytesParsed?: number
  trailingBytes?: number
}

export function toStructureField(params: {
  id?: string
  label?: string
  name?: string
  offset: number
  length: number
  value?: any
  interpretedValue?: string | number | boolean | bigint
  interpretation?: string
  type?: string
  endian?: 'little' | 'big'
  status?: FieldStatus
  valid?: boolean
  reason?: string
  specLink?: string
  children?: StructureField[]
}): StructureField {
  const start = params.offset
  const end = params.offset + params.length
  const label = params.label ?? params.name ?? params.id ?? 'Field'
  const id = params.id ?? params.name ?? label
  const status: FieldStatus = params.status ?? (params.valid === false ? 'invalid' : 'valid')
  const interpreted =
    params.interpretedValue ??
    params.interpretation ??
    (params.value !== undefined ? (typeof params.value === 'bigint' ? params.value : String(params.value)) : '')

  return {
    id,
    label,
    name: params.name ?? label,
    offset: start,
    length: params.length,
    range: { start, end },
    rawHex: '',
    value: params.value,
    interpretedValue: interpreted,
    interpretation: params.interpretation ?? String(interpreted),
    type: params.type ?? 'bytes',
    endian: params.endian,
    status,
    valid: status === 'valid',
    reason: params.reason,
    specLink: params.specLink,
    children: params.children,
  }
}
