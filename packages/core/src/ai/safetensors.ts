/**
 * Bitpeek Ultra - SafeTensors Header Parser & Element Mapper
 *
 * Implements Section 16 (AI-01, AC068):
 * - SafeTensors 8-byte LE header length and JSON header inspection
 * - Bounded validation of tensor shape, dtype, and byte spans
 * - Exact multidimensional element coordinate to file byte span mapping
 */

export const SAFETENSORS_DTYPE_SIZES: Record<string, number> = {
  F64: 8,
  I64: 8,
  U64: 8,
  F32: 4,
  I32: 4,
  U32: 4,
  F16: 2,
  BF16: 2,
  I16: 2,
  U16: 2,
  I8: 1,
  U8: 1,
  BOOL: 1,
}

export interface SafeTensorEntry {
  name: string
  dtype: string
  shape: number[]
  dataOffsets: [number, number] // relative to header end
  fileStartOffset: number
  fileEndOffset: number
  byteLength: number
  elementCount: number
}

export interface SafeTensorsModel {
  headerLength: number
  headerJson: Record<string, any>
  metadata?: Record<string, string>
  tensors: Map<string, SafeTensorEntry>
  totalDataBytes: number
}

export class SafeTensorsParser {
  /**
   * Parses a SafeTensors file buffer without allocating tensor payloads.
   */
  public static parse(bytes: Uint8Array, maxHeaderBytes = 50 * 1024 * 1024): SafeTensorsModel {
    if (bytes.length < 8) {
      throw new Error(`File too small for SafeTensors: ${bytes.length} bytes`)
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    const headerLenBig = view.getBigUint64(0, true)

    if (headerLenBig > BigInt(maxHeaderBytes)) {
      throw new Error(`SafeTensors header size ${headerLenBig} exceeds quota limit (${maxHeaderBytes} bytes)`)
    }

    const headerLen = Number(headerLenBig)
    if (8 + headerLen > bytes.length) {
      throw new Error(`SafeTensors header truncated: declared ${headerLen} bytes, file has ${bytes.length - 8}`)
    }

    const headerBytes = bytes.subarray(8, 8 + headerLen)
    const headerStr = new TextDecoder('utf-8').decode(headerBytes)
    const headerJson = JSON.parse(headerStr)

    const tensors = new Map<string, SafeTensorEntry>()
    let metadata: Record<string, string> | undefined
    let maxOffset = 0

    const dataStart = 8 + headerLen

    for (const [key, val] of Object.entries(headerJson)) {
      if (key === '__metadata__') {
        metadata = val as Record<string, string>
        continue
      }

      const t = val as { dtype: string; shape: number[]; data_offsets: [number, number] }
      if (!t.dtype || !Array.isArray(t.shape) || !Array.isArray(t.data_offsets) || t.data_offsets.length !== 2) {
        throw new Error(`Invalid tensor entry structure for "${key}"`)
      }

      const dtypeSize = SAFETENSORS_DTYPE_SIZES[t.dtype]
      if (!dtypeSize) {
        throw new Error(`Unsupported SafeTensors dtype "${t.dtype}" in tensor "${key}"`)
      }

      let numel = 1
      for (const dim of t.shape) {
        if (dim < 0) throw new Error(`Negative dimension in tensor "${key}": ${dim}`)
        numel *= dim
      }

      const expectedBytes = numel * dtypeSize
      const declaredBytes = t.data_offsets[1] - t.data_offsets[0]

      if (declaredBytes !== expectedBytes) {
        throw new Error(
          `Shape/byte mismatch for tensor "${key}": shape ${JSON.stringify(t.shape)} of ${t.dtype} requires ${expectedBytes} bytes, but offsets declare ${declaredBytes} bytes`,
        )
      }

      const fileStartOffset = dataStart + t.data_offsets[0]
      const fileEndOffset = dataStart + t.data_offsets[1]

      if (fileEndOffset > bytes.length) {
        throw new Error(`Tensor "${key}" data range [${fileStartOffset}, ${fileEndOffset}) exceeds file bounds (${bytes.length})`)
      }

      if (t.data_offsets[1] > maxOffset) {
        maxOffset = t.data_offsets[1]
      }

      tensors.set(key, {
        name: key,
        dtype: t.dtype,
        shape: t.shape,
        dataOffsets: t.data_offsets,
        fileStartOffset,
        fileEndOffset,
        byteLength: declaredBytes,
        elementCount: numel,
      })
    }

    return {
      headerLength: headerLen,
      headerJson,
      metadata,
      tensors,
      totalDataBytes: maxOffset,
    }
  }

  /**
   * Maps an element coordinate (e.g. [row, col]) to exact file byte span.
   */
  public static mapElementToFileSpan(
    tensor: SafeTensorEntry,
    indices: number[],
  ): { fileOffset: number; byteLength: number } {
    if (indices.length !== tensor.shape.length) {
      throw new Error(`Index rank mismatch: tensor rank ${tensor.shape.length}, indices provided ${indices.length}`)
    }

    const dtypeSize = SAFETENSORS_DTYPE_SIZES[tensor.dtype]!
    let linearIndex = 0
    let stride = 1

    for (let d = tensor.shape.length - 1; d >= 0; d--) {
      const idx = indices[d]!
      const dim = tensor.shape[d]!
      if (idx < 0 || idx >= dim) {
        throw new RangeError(`Index ${idx} out of bounds for dimension ${d} (size ${dim})`)
      }
      linearIndex += idx * stride
      stride *= dim
    }

    const fileOffset = tensor.fileStartOffset + linearIndex * dtypeSize
    return {
      fileOffset,
      byteLength: dtypeSize,
    }
  }
}
