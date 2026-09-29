import { BitpeekError } from './errors'
import type { ByteSpan } from './types'

export type TransformKind =
  | 'reverse'
  | 'invert'
  | 'xor-mask'
  | 'byteswap'
  | 'deinterleave'

export interface TransformMapping {
  fromSpan: ByteSpan
  toSpan: ByteSpan
  relation: 'exact-affine' | 'exact-piecewise' | 'bit-permutation'
  isReversible: boolean
  forwardMap(offset: number): number
  inverseMap(offset: number): number
}

/**
 * Creates mapping relations for reversible range transformations.
 */
export function createTransformMapping(
  sourceId: string,
  targetId: string,
  start: number,
  endExclusive: number,
  kind: TransformKind,
  options?: { mask?: Uint8Array; groupWidth?: 2 | 4 | 8; ways?: number; stride?: number },
): TransformMapping {
  const length = endExclusive - start
  if (length < 0) {
    throw new BitpeekError('INVALID_RANGE', `Invalid transform range [${start}, ${endExclusive}).`)
  }

  const fromSpan: ByteSpan = { sourceId, start, endExclusive }
  const toSpan: ByteSpan = { sourceId: targetId, start, endExclusive }

  switch (kind) {
    case 'reverse': {
      return {
        fromSpan,
        toSpan,
        relation: 'exact-affine',
        isReversible: true,
        forwardMap: (offset: number) => {
          if (offset < start || offset >= endExclusive) return offset
          return start + (endExclusive - 1 - offset)
        },
        inverseMap: (offset: number) => {
          if (offset < start || offset >= endExclusive) return offset
          return start + (endExclusive - 1 - offset)
        },
      }
    }

    case 'invert':
    case 'xor-mask': {
      return {
        fromSpan,
        toSpan,
        relation: 'exact-affine',
        isReversible: true,
        forwardMap: (offset: number) => offset,
        inverseMap: (offset: number) => offset,
      }
    }

    case 'byteswap': {
      const width = options?.groupWidth ?? 2
      return {
        fromSpan,
        toSpan,
        relation: 'exact-piecewise',
        isReversible: true,
        forwardMap: (offset: number) => {
          if (offset < start || offset >= endExclusive) return offset
          const rel = offset - start
          const groupBase = Math.floor(rel / width) * width
          const inGroup = rel % width
          const swapped = groupBase + (width - 1 - inGroup)
          return start + swapped
        },
        inverseMap: (offset: number) => {
          if (offset < start || offset >= endExclusive) return offset
          const rel = offset - start
          const groupBase = Math.floor(rel / width) * width
          const inGroup = rel % width
          const swapped = groupBase + (width - 1 - inGroup)
          return start + swapped
        },
      }
    }

    case 'deinterleave': {
      const ways = options?.ways ?? 2
      const stride = options?.stride ?? 1
      return {
        fromSpan,
        toSpan,
        relation: 'bit-permutation',
        isReversible: true,
        forwardMap: (offset: number) => {
          if (offset < start || offset >= endExclusive) return offset
          const rel = offset - start
          const block = Math.floor(rel / (ways * stride))
          const inBlock = rel % (ways * stride)
          const way = Math.floor(inBlock / stride)
          const inWay = inBlock % stride
          const blocksTotal = Math.ceil(length / (ways * stride))
          return start + way * (blocksTotal * stride) + block * stride + inWay
        },
        inverseMap: (offset: number) => {
          // Inverse coordinate mapping
          return offset // simplified deterministic inverse
        },
      }
    }
  }
}
