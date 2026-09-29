import { type StructureParseResult, type StructureField, toStructureField } from './types'
import { SafeTensorsParser } from '../ai/safetensors'

export function parseSafeTensors(bytes: Uint8Array): StructureParseResult | null {
  if (bytes.length < 10) return null

  // Fast check: bytes 0..7 must be header length, byte 8 must be '{' (0x7B)
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const headerLenBig = view.getBigUint64(0, true)
  if (headerLenBig <= 0n || headerLenBig > 50n * 1024n * 1024n || bytes[8] !== 0x7b) {
    return null
  }

  try {
    const model = SafeTensorsParser.parse(bytes)
    const headerLen = model.headerLength
    const fields: StructureField[] = []
    const warnings: string[] = []

    fields.push(
      toStructureField({
        name: 'header_length',
        offset: 0,
        length: 8,
        value: headerLen,
        interpretation: `Header Length: ${headerLen} bytes`,
        endian: 'little',
        valid: true,
      }),
    )

    const tensorFields: StructureField[] = []
    for (const [name, entry] of model.tensors.entries()) {
      const shapeStr = `[${entry.shape.join(', ')}]`
      const children: StructureField[] = []

      const hasPayload = entry.fileEndOffset <= bytes.length
      if (hasPayload) {
        children.push(
          toStructureField({
            name: `${name}.payload`,
            offset: entry.fileStartOffset,
            length: entry.byteLength,
            value: entry.dtype,
            interpretation: `${entry.elementCount} elements (${entry.byteLength} bytes)`,
            valid: true,
          }),
        )
      }

      tensorFields.push(
        toStructureField({
          name,
          offset: entry.fileStartOffset,
          length: Math.max(0, Math.min(entry.byteLength, bytes.length - entry.fileStartOffset)),
          value: entry.dtype,
          interpretation: `${entry.dtype} ${shapeStr} (${entry.elementCount} elements)`,
          valid: true,
          children: children.length > 0 ? children : undefined,
        }),
      )
    }

    fields.push(
      toStructureField({
        name: 'header_json',
        offset: 8,
        length: headerLen,
        value: `${model.tensors.size} tensors`,
        interpretation: `SafeTensors JSON Metadata (${model.tensors.size} tensors)`,
        valid: true,
        children: tensorFields,
      }),
    )

    return {
      format: 'safetensors',
      status: 'valid',
      fields,
      warnings,
      totalBytesParsed: bytes.length,
    }
  } catch {
    return null
  }
}
