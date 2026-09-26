import { BitpeekError } from './errors'

export interface ByteRange {
  start: number
  endExclusive: number
}

export interface ByteSource {
  readonly size: number
  readonly revision: string
  read(offset: number, length: number, signal?: AbortSignal): Promise<Uint8Array>
  chunks(
    range?: { start: number; endExclusive?: number },
    chunkSize?: number,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array>
  close(): Promise<void> | void
}

function checkRange(offset: number, length: number, size: number): void {
  if (!Number.isSafeInteger(offset) || offset < 0) {
    throw new BitpeekError(
      'INVALID_RANGE',
      `Offset must be a non-negative safe integer, got ${offset}.`,
    )
  }
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new BitpeekError(
      'INVALID_RANGE',
      `Length must be a non-negative safe integer, got ${length}.`,
    )
  }
  if (offset + length > size) {
    throw new BitpeekError(
      'INVALID_RANGE',
      `Requested range [${offset}, ${offset + length}) exceeds source size ${size}.`,
    )
  }
}

export class MemoryByteSource implements ByteSource {
  readonly size: number
  readonly revision: string
  private buffer: Uint8Array

  constructor(bytes: Uint8Array, revision = 'rev-0') {
    this.buffer = bytes
    this.size = bytes.length
    this.revision = revision
  }

  async read(
    offset: number,
    length: number,
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    if (signal?.aborted) {
      throw new BitpeekError('CANCELLED', 'Operation was aborted.')
    }
    checkRange(offset, length, this.size)
    // Return a copy so caller mutations do not alter internal state
    return this.buffer.slice(offset, offset + length)
  }

  async *chunks(
    range?: { start: number; endExclusive?: number },
    chunkSize = 64 * 1024,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array> {
    const start = range?.start ?? 0
    const end = range?.endExclusive ?? this.size
    checkRange(start, end - start, this.size)

    let cursor = start
    while (cursor < end) {
      if (signal?.aborted) {
        throw new BitpeekError('CANCELLED', 'Operation was aborted.')
      }
      const len = Math.min(chunkSize, end - cursor)
      yield this.buffer.slice(cursor, cursor + len)
      cursor += len
    }
  }

  close(): void {
    // No-op for in-memory buffer
  }
}

export class BlobByteSource implements ByteSource {
  readonly size: number
  readonly revision: string
  private blob: Blob

  constructor(blob: Blob, revision = 'blob-rev-0') {
    this.blob = blob
    this.size = blob.size
    this.revision = revision
  }

  async read(
    offset: number,
    length: number,
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    if (signal?.aborted) {
      throw new BitpeekError('CANCELLED', 'Operation was aborted.')
    }
    checkRange(offset, length, this.size)
    if (length === 0) return new Uint8Array(0)

    try {
      const slice = this.blob.slice(offset, offset + length)
      const buffer = await slice.arrayBuffer()
      return new Uint8Array(buffer)
    } catch (err: unknown) {
      if (signal?.aborted) {
        throw new BitpeekError('CANCELLED', 'Operation was aborted.')
      }
      throw new BitpeekError(
        'IO_ERROR',
        `Failed to read blob slice [${offset}, ${offset + length}): ${String(err)}`,
      )
    }
  }

  async *chunks(
    range?: { start: number; endExclusive?: number },
    chunkSize = 1024 * 1024,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array> {
    const start = range?.start ?? 0
    const end = range?.endExclusive ?? this.size
    checkRange(start, end - start, this.size)

    let cursor = start
    while (cursor < end) {
      if (signal?.aborted) {
        throw new BitpeekError('CANCELLED', 'Operation was aborted.')
      }
      const len = Math.min(chunkSize, end - cursor)
      const chunk = await this.read(cursor, len, signal)
      yield chunk
      cursor += len
    }
  }

  close(): void {
    // Release reference
    this.blob = new Blob([], { type: 'application/octet-stream' })
  }
}
