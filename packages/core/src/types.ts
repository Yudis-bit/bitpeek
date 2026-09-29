import { BitpeekError } from './errors'

export type ArtifactId = string
export type SnapshotId = string
export type SourceId = string
export type OperationId = string
export type ProfileId = string
export type FindingId = string
export type JobId = string

export type AddressSpaceKind =
  | 'file'
  | 'virtual'
  | 'physical'
  | 'gpu'
  | 'nand'
  | 'register'

export interface AddressSpaceId {
  kind: AddressSpaceKind
  targetId: string
  architecture?: string
  moduleId?: string
  loadEpoch?: string
}

export interface ByteSpan {
  sourceId: SourceId
  start: number
  endExclusive: number
}

export function validateByteSpan(span: ByteSpan, sourceSize?: number): void {
  if (!Number.isSafeInteger(span.start) || span.start < 0) {
    throw new BitpeekError(
      'INVALID_RANGE',
      `ByteSpan start must be a non-negative safe integer, got ${span.start}.`,
    )
  }
  if (!Number.isSafeInteger(span.endExclusive) || span.endExclusive < span.start) {
    throw new BitpeekError(
      'INVALID_RANGE',
      `ByteSpan endExclusive (${span.endExclusive}) must be >= start (${span.start}).`,
    )
  }
  if (sourceSize !== undefined && span.endExclusive > sourceSize) {
    throw new BitpeekError(
      'INVALID_RANGE',
      `ByteSpan endExclusive (${span.endExclusive}) exceeds source size (${sourceSize}).`,
    )
  }
}

export interface BitSpan {
  sourceId: SourceId
  byteOffset: number
  lsb: number
  width: number
  bitOrder: 'lsb-first' | 'msb-first'
}

export interface Address {
  spaceId: AddressSpaceId
  value: bigint
  widthBits: number
}

export interface SourceIdentity {
  algorithm: 'sha256'
  digest: string
  byteLength: number
  acquisitionId?: string
}

export interface ClockDomain {
  id: string
  unitNumerator: bigint
  unitDenominator: bigint
  epochKind: string
}

export interface TaggedFloat {
  kind: 'f16' | 'bf16' | 'f32' | 'f64'
  rawBits: string // hex representation of raw bits, e.g. "0x7ff0000000000000"
  isNaN: boolean
  isInfinity: boolean
  isNegative: boolean
  isZero: boolean
  isSubnormal: boolean
  display: string
  numericValue: number
}

export interface Diagnostic {
  code: string
  message: string
  severity: 'info' | 'warning' | 'error'
  span?: ByteSpan
  relatedSpans?: ByteSpan[]
  ruleId?: string
  specReference?: string
}

export interface ResultEnvelope<T = unknown> {
  schemaVersion: number
  operationId: string
  operationVersion: number
  jobId?: string
  inputSnapshotIds: SnapshotId[]
  resultArtifactIds: ArtifactId[]
  data?: T
  outcome: 'success' | 'partial' | 'failed' | 'cancelled'
  completeness: 'complete' | 'paged' | 'truncated' | 'unknown'
  diagnostics: Diagnostic[]
  limitsApplied: Record<string, number>
  counters: Record<string, number>
  nextCursor?: string
  deterministicContentId?: string
  provenanceRootId?: string
}

/**
 * BigInt-safe JSON serialization utilities preserving exact large integers.
 */
export function safeJsonStringify(obj: unknown, space?: number): string {
  return JSON.stringify(
    obj,
    (_key, value) => {
      if (typeof value === 'bigint') {
        return value.toString(10)
      }
      return value
    },
    space,
  )
}

export function serializeBigInt(value: bigint): string {
  return value.toString(10)
}

export function deserializeBigInt(val: string | number | bigint): bigint {
  if (typeof val === 'bigint') return val
  if (typeof val === 'number') {
    if (!Number.isSafeInteger(val)) {
      throw new BitpeekError(
        'INVALID_INPUT',
        `Unsafe number cannot be reliably converted to BigInt: ${val}`,
      )
    }
    return BigInt(val)
  }
  if (typeof val === 'string') {
    const trimmed = val.trim()
    if (/^-?\d+$/.test(trimmed)) {
      return BigInt(trimmed)
    }
    if (/^0x[0-9a-fA-F]+$/i.test(trimmed)) {
      return BigInt(trimmed)
    }
    throw new BitpeekError(
      'INVALID_INPUT',
      `Cannot parse string as BigInt: ${val}`,
    )
  }
  throw new BitpeekError(
    'INVALID_INPUT',
    `Unsupported value type for BigInt conversion: ${typeof val}`,
  )
}
