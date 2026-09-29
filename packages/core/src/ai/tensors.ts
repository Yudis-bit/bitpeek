/**
 * Bitpeek Ultra - Exact Tensor Address & Bounds Engine
 *
 * Implements Section 16 (AI-04, AC069, AC070):
 * - Arbitrary signed strides: contiguous, transposed, broadcast (0 stride), negative strides
 * - Exact reachable address extrema (minReachableOffset / maxReachableOffset)
 * - Empty tensor handling without underflow
 * - Multidimensional coordinate to byte offset translation
 */

import { SAFETENSORS_DTYPE_SIZES } from './safetensors'

export interface TensorViewSpec {
  shape: number[]
  strides?: number[] // in elements (signed!)
  dtype: string
  storageOffsetBytes?: number
}

export interface TensorReachableBounds {
  minReachableOffsetBytes: number
  maxReachableOffsetBytes: number
  spanSizeBytes: number
  isEmpty: boolean
  isContiguous: boolean
  isOverlapping: boolean
}

export class TensorBoundsEngine {
  public readonly shape: number[]
  public readonly strides: number[]
  public readonly dtype: string
  public readonly elementSizeBytes: number
  public readonly storageOffsetBytes: number
  public readonly numElements: number
  public readonly isEmpty: boolean

  constructor(spec: TensorViewSpec) {
    this.shape = [...spec.shape]
    this.dtype = spec.dtype
    this.storageOffsetBytes = spec.storageOffsetBytes ?? 0
    this.elementSizeBytes = SAFETENSORS_DTYPE_SIZES[spec.dtype] ?? 4

    // Calculate total elements and check empty
    let numel = 1
    let empty = false
    for (const d of this.shape) {
      if (d < 0) throw new Error(`Negative dimension: ${d}`)
      if (d === 0) empty = true
      numel *= d
    }
    this.numElements = empty ? 0 : numel
    this.isEmpty = empty

    // Compute standard default row-major contiguous strides if not provided
    if (spec.strides) {
      if (spec.strides.length !== this.shape.length) {
        throw new Error(`Strides length ${spec.strides.length} does not match shape rank ${this.shape.length}`)
      }
      this.strides = [...spec.strides]
    } else {
      this.strides = this.computeContiguousStrides(this.shape)
    }
  }

  private computeContiguousStrides(shape: number[]): number[] {
    const rank = shape.length
    const st = new Array<number>(rank)
    let cur = 1
    for (let d = rank - 1; d >= 0; d--) {
      st[d] = cur
      cur *= shape[d]!
    }
    return st
  }

  /**
   * Computes exact reachable storage offset range [min, max].
   * Handles negative strides and broadcast zero-strides rigorously (AC070).
   */
  public computeBounds(): TensorReachableBounds {
    if (this.isEmpty || this.shape.length === 0) {
      return {
        minReachableOffsetBytes: this.storageOffsetBytes,
        maxReachableOffsetBytes: this.storageOffsetBytes,
        spanSizeBytes: 0,
        isEmpty: true,
        isContiguous: true,
        isOverlapping: false,
      }
    }

    let minElementOffset = 0
    let maxElementOffset = 0
    let hasZeroStride = false

    for (let d = 0; d < this.shape.length; d++) {
      const dim = this.shape[d]!
      const stride = this.strides[d]!

      if (stride === 0) {
        hasZeroStride = true
        continue
      }

      if (stride > 0) {
        // Minimum reached at index 0 (0 * stride = 0)
        // Maximum reached at index (dim - 1)
        maxElementOffset += (dim - 1) * stride
      } else {
        // Negative stride:
        // Minimum reached at index (dim - 1)
        // Maximum reached at index 0 (0 * stride = 0)
        minElementOffset += (dim - 1) * stride
      }
    }

    const minReachableOffsetBytes = this.storageOffsetBytes + minElementOffset * this.elementSizeBytes
    const maxReachableOffsetBytes =
      this.storageOffsetBytes + maxElementOffset * this.elementSizeBytes + this.elementSizeBytes
    const spanSizeBytes = maxReachableOffsetBytes - minReachableOffsetBytes

    const expectedSpan = this.numElements * this.elementSizeBytes
    const isContiguous = spanSizeBytes === expectedSpan && !hasZeroStride && minElementOffset === 0
    const isOverlapping = hasZeroStride || spanSizeBytes < expectedSpan

    return {
      minReachableOffsetBytes,
      maxReachableOffsetBytes,
      spanSizeBytes,
      isEmpty: false,
      isContiguous,
      isOverlapping,
    }
  }

  /**
   * Maps an element multidimensional coordinate to its storage byte offset.
   */
  public offsetOf(indices: number[]): number {
    if (indices.length !== this.shape.length) {
      throw new Error(`Indices rank mismatch: expected ${this.shape.length}, got ${indices.length}`)
    }
    if (this.isEmpty) {
      throw new RangeError('Cannot access element of empty tensor')
    }

    let elementOffset = 0
    for (let d = 0; d < this.shape.length; d++) {
      const idx = indices[d]!
      const dim = this.shape[d]!
      if (idx < 0 || idx >= dim) {
        throw new RangeError(`Index ${idx} out of bounds for dimension ${d} (size ${dim})`)
      }
      elementOffset += idx * this.strides[d]!
    }

    return this.storageOffsetBytes + elementOffset * this.elementSizeBytes
  }
}
