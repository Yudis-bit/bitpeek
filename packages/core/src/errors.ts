export type BitpeekErrorCode =
  | 'INVALID_INPUT'
  | 'INVALID_RANGE'
  | 'UNSUPPORTED_FORMAT'
  | 'TRUNCATED_INPUT'
  | 'LIMIT_EXCEEDED'
  | 'RESOURCE_LIMIT'
  | 'INTERNAL_ERROR'
  | 'INVALID_FORMAT'
  | 'CANCELLED'
  | 'SOURCE_CHANGED'
  | 'PRECONDITION_FAILED'
  | 'HASH_MISMATCH'
  | 'UNSUPPORTED_VERSION'
  | 'IO_ERROR'

export interface BitpeekErrorDetails {
  readonly [key: string]: unknown
}

export class BitpeekError extends Error {
  readonly code: BitpeekErrorCode
  readonly details?: BitpeekErrorDetails

  constructor(code: BitpeekErrorCode, message: string, details?: BitpeekErrorDetails) {
    super(message)
    this.name = 'BitpeekError'
    this.code = code
    this.details = details
  }

  toJSON() {
    return {
      code: this.code,
      message: this.message,
      ...(this.details ? { details: this.details } : {}),
    }
  }
}

export interface OperationSuccess<T> {
  schemaVersion: 1
  operation: string
  documentRevision?: string | number
  range?: { start: number; end: number }
  result: T
  warnings?: string[]
}

export interface OperationFailure {
  schemaVersion: 1
  error: {
    code: BitpeekErrorCode
    message: string
    details?: BitpeekErrorDetails
  }
}

export type OperationResult<T> = OperationSuccess<T> | OperationFailure
