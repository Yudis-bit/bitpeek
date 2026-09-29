import { describe, it, expect } from 'vitest'
import {
  SafeTensorsParser,
  TensorBoundsEngine,
  OnnxProtobufParser,
  GpuSanitizerParser,
} from './ai'

describe('Phase P8 - AI Model, Tensor, and GPU Diagnostics', () => {
  describe('SafeTensors Parser & Element Mapper (AI-01, AC068)', () => {
    it('parses SafeTensors header and maps element coordinates to exact file byte spans', () => {
      // Create minimal SafeTensors file:
      // Tensor "weight": shape [2, 3], dtype "F32" -> 6 elements * 4 = 24 bytes
      // data_offsets: [0, 24]
      const headerJson = {
        weight: {
          dtype: 'F32',
          shape: [2, 3],
          data_offsets: [0, 24],
        },
        __metadata__: {
          framework: 'pytorch',
        },
      }

      const headerBytes = new TextEncoder().encode(JSON.stringify(headerJson))
      const totalLen = 8 + headerBytes.length + 24
      const fileBytes = new Uint8Array(totalLen)
      const view = new DataView(fileBytes.buffer)

      // Set 8-byte LE header length
      view.setBigUint64(0, BigInt(headerBytes.length), true)
      fileBytes.set(headerBytes, 8)

      // Payload starts at 8 + headerBytes.length
      const payloadStart = 8 + headerBytes.length
      for (let i = 0; i < 6; i++) {
        view.setFloat32(payloadStart + i * 4, i + 1.0, true)
      }

      const model = SafeTensorsParser.parse(fileBytes)
      expect(model.headerLength).toBe(headerBytes.length)
      expect(model.metadata?.framework).toBe('pytorch')
      expect(model.tensors.has('weight')).toBe(true)

      const tensor = model.tensors.get('weight')!
      expect(tensor.elementCount).toBe(6)
      expect(tensor.byteLength).toBe(24)

      // Map element [1, 2] (value 6.0): row 1, col 2 -> linear index = 1*3 + 2 = 5
      const span = SafeTensorsParser.mapElementToFileSpan(tensor, [1, 2])
      expect(span.fileOffset).toBe(payloadStart + 5 * 4)
      expect(span.byteLength).toBe(4)

      // Verify the value at that exact file offset
      const mappedVal = view.getFloat32(span.fileOffset, true)
      expect(mappedVal).toBe(6.0)
    })

    it('rejects malformed SafeTensors with shape/byte count mismatch without large allocation', () => {
      const headerJson = {
        corrupted: {
          dtype: 'F32',
          shape: [100, 100], // 10000 elements * 4 = 40,000 bytes required
          data_offsets: [0, 100], // only 100 bytes declared -> mismatch!
        },
      }
      const headerBytes = new TextEncoder().encode(JSON.stringify(headerJson))
      const buf = new Uint8Array(8 + headerBytes.length)
      new DataView(buf.buffer).setBigUint64(0, BigInt(headerBytes.length), true)
      buf.set(headerBytes, 8)

      expect(() => SafeTensorsParser.parse(buf)).toThrow(/Shape\/byte mismatch/)
    })
  })

  describe('Tensor Bounds Engine (AI-04, AC069, AC070)', () => {
    it('computes exact bounds for contiguous, transposed, and broadcast zero-stride views', () => {
      // 1. Contiguous 2D tensor: shape [3, 4], dtype F32 (4 bytes)
      const t1 = new TensorBoundsEngine({
        shape: [3, 4],
        dtype: 'F32',
      })
      const b1 = t1.computeBounds()
      expect(b1.isContiguous).toBe(true)
      expect(b1.spanSizeBytes).toBe(12 * 4)
      expect(t1.offsetOf([0, 0])).toBe(0)
      expect(t1.offsetOf([2, 3])).toBe(11 * 4)

      // 2. Transposed view: shape [4, 3], strides [1, 4]
      const tTrans = new TensorBoundsEngine({
        shape: [4, 3],
        strides: [1, 4],
        dtype: 'F32',
      })
      const bTrans = tTrans.computeBounds()
      expect(bTrans.spanSizeBytes).toBe(12 * 4)
      // Element [3, 2] -> 3*1 + 2*4 = 11 elements * 4 = 44 bytes
      expect(tTrans.offsetOf([3, 2])).toBe(44)

      // 3. Broadcast view: shape [3, 4], strides [0, 1] (row broadcast)
      const tBroad = new TensorBoundsEngine({
        shape: [3, 4],
        strides: [0, 1],
        dtype: 'F32',
      })
      const bBroad = tBroad.computeBounds()
      expect(bBroad.isOverlapping).toBe(true)
      // Only 4 distinct elements reached: span = 4 * 4 = 16 bytes
      expect(bBroad.spanSizeBytes).toBe(16)
    })

    it('computes exact extrema for negative strides and handles empty tensors without underflow (AC070)', () => {
      // Negative stride view:
      // A 1D array of 5 elements reversed:
      // storageOffset = 16 (points to element 4), stride = -1, shape = [5]
      // Reachable indices: 0 -> offset 16; 4 -> offset 0
      const tNeg = new TensorBoundsEngine({
        shape: [5],
        strides: [-1],
        dtype: 'F32',
        storageOffsetBytes: 16,
      })

      const bNeg = tNeg.computeBounds()
      expect(bNeg.minReachableOffsetBytes).toBe(0)
      expect(bNeg.maxReachableOffsetBytes).toBe(20) // 16 + 4
      expect(bNeg.spanSizeBytes).toBe(20)

      // Verify offsets
      expect(tNeg.offsetOf([0])).toBe(16)
      expect(tNeg.offsetOf([4])).toBe(0)

      // Empty tensor: shape [0, 10]
      const tEmpty = new TensorBoundsEngine({
        shape: [0, 10],
        dtype: 'F32',
      })
      const bEmpty = tEmpty.computeBounds()
      expect(bEmpty.isEmpty).toBe(true)
      expect(bEmpty.spanSizeBytes).toBe(0)
      expect(() => tEmpty.offsetOf([0, 0])).toThrow(/empty tensor/)
    })
  })

  describe('ONNX Protobuf Metadata Parser (AI-02, AC071)', () => {
    it('parses ONNX ModelProto with ir_version and producer metadata', () => {
      // Craft minimal Protobuf wire format for ModelProto:
      // Field 1 (ir_version, int64): wire 0 -> tag = (1 << 3) | 0 = 0x08, val = 8
      // Field 2 (producer_name, string): wire 2 -> tag = (2 << 3) | 2 = 0x12, len = 7, 'pytorch'
      const name = new TextEncoder().encode('pytorch')
      const buf = new Uint8Array([
        0x08, 0x08, // ir_version = 8
        0x12, name.length, ...name,
      ])

      const model = OnnxProtobufParser.parse(buf)
      expect(model.irVersion).toBe(8)
      expect(model.producerName).toBe('pytorch')
    })
  })

  describe('GPU Compute Sanitizer & Tensor Correlator (AI-06, AC073)', () => {
    it('parses CUDA memory check log and correlates out-of-bounds access with declared tensor allocation', () => {
      const log = `
========= CUDA-MEMCHECK
========= Invalid __global__ read of size 4 bytes
=========     at 0x0000007f90001004 in vector_add_kernel
=========     by thread (0,0,0) in block (1,0,0)
=========     Saved host backtrace /src/kernels/vector_add.cu:42
=========
`
      // Declared GPU tensor "input_b": starts at 0x7f90000000, size 4096 bytes (0x1000)
      // The access is at 0x7f90001004 -> exactly 4 bytes past the 4096-byte tensor!
      const declaredTensors = [
        {
          name: 'input_b',
          deviceAddress: 0x7f90000000n,
          sizeBytes: 4096n, // 0x1000
        },
      ]

      const diag = GpuSanitizerParser.parse(log, declaredTensors)
      expect(diag).not.toBeNull()
      expect(diag!.errorKind).toBe('Invalid __global__ read')
      expect(diag!.accessSizeBytes).toBe(4)
      expect(diag!.deviceAddress).toBe(0x7f90001004n)
      expect(diag!.kernelName).toBe('vector_add_kernel')
      expect(diag!.sourceLocation).toBe('/src/kernels/vector_add.cu:42')

      // Correlated tensor inspection
      expect(diag!.correlatedTensor).toBeDefined()
      expect(diag!.correlatedTensor?.tensorName).toBe('input_b')
      expect(diag!.correlatedTensor?.isOutOfBounds).toBe(true)
      expect(diag!.correlatedTensor?.overflowBytes).toBe(4n) // 4 bytes past the end!
    })
  })
})
