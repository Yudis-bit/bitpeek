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

export function checkRange(offset: number, length: number, size: number): void {
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

export function checkChunkSize(chunkSize: number): void {
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new BitpeekError(
      'INVALID_RANGE',
      `chunkSize must be a positive safe integer, got ${chunkSize}.`,
    )
  }
}

export class MemoryByteSource implements ByteSource {
  readonly size: number
  readonly revision: string
  private buffer: Uint8Array | null

  constructor(bytes: Uint8Array, revision = 'rev-0') {
    // Defensive copy: caller mutations to original buffer cannot alter immutable source
    this.buffer = new Uint8Array(bytes)
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
    if (!this.buffer) {
      throw new BitpeekError('IO_ERROR', 'MemoryByteSource is closed.')
    }
    checkRange(offset, length, this.size)
    if (length === 0) return new Uint8Array(0)
    // Return a copy so caller mutations do not alter internal state
    return this.buffer.slice(offset, offset + length)
  }

  async *chunks(
    range?: { start: number; endExclusive?: number },
    chunkSize = 64 * 1024,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array> {
    checkChunkSize(chunkSize)
    if (!this.buffer) {
      throw new BitpeekError('IO_ERROR', 'MemoryByteSource is closed.')
    }

    const start = range?.start ?? 0
    const end = range?.endExclusive ?? this.size

    if (!Number.isSafeInteger(start) || start < 0) {
      throw new BitpeekError('INVALID_RANGE', `start must be a non-negative safe integer: ${start}`)
    }
    if (!Number.isSafeInteger(end) || end < start || end > this.size) {
      throw new BitpeekError('INVALID_RANGE', `endExclusive must be between start and size [${start}, ${this.size}]: ${end}`)
    }

    if (start === end) {
      return
    }

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
    this.buffer = null
  }
}

export class BlobByteSource implements ByteSource {
  readonly size: number
  readonly revision: string
  private blob: Blob | null

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
    if (!this.blob) {
      throw new BitpeekError('IO_ERROR', 'BlobByteSource is closed.')
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
    checkChunkSize(chunkSize)
    if (!this.blob) {
      throw new BitpeekError('IO_ERROR', 'BlobByteSource is closed.')
    }

    const start = range?.start ?? 0
    const end = range?.endExclusive ?? this.size

    if (!Number.isSafeInteger(start) || start < 0) {
      throw new BitpeekError('INVALID_RANGE', `start must be a non-negative safe integer: ${start}`)
    }
    if (!Number.isSafeInteger(end) || end < start || end > this.size) {
      throw new BitpeekError('INVALID_RANGE', `endExclusive must be between start and size [${start}, ${this.size}]: ${end}`)
    }

    if (start === end) {
      return
    }

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
    this.blob = null
  }
}

export class SliceByteSource implements ByteSource {
  readonly size: number
  readonly revision: string
  private parent: ByteSource | null
  private readonly offset: number

  constructor(parent: ByteSource, offset: number, length: number, revision?: string) {
    checkRange(offset, length, parent.size)
    this.parent = parent
    this.offset = offset
    this.size = length
    this.revision = revision ?? `${parent.revision}:slice[${offset},${offset + length})`
  }

  async read(offset: number, length: number, signal?: AbortSignal): Promise<Uint8Array> {
    if (!this.parent) throw new BitpeekError('IO_ERROR', 'SliceByteSource is closed.')
    checkRange(offset, length, this.size)
    return this.parent.read(this.offset + offset, length, signal)
  }

  async *chunks(
    range?: { start: number; endExclusive?: number },
    chunkSize = 64 * 1024,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array> {
    checkChunkSize(chunkSize)
    if (!this.parent) throw new BitpeekError('IO_ERROR', 'SliceByteSource is closed.')

    const start = range?.start ?? 0
    const end = range?.endExclusive ?? this.size
    if (!Number.isSafeInteger(start) || start < 0) {
      throw new BitpeekError('INVALID_RANGE', `start must be a non-negative safe integer: ${start}`)
    }
    if (!Number.isSafeInteger(end) || end < start || end > this.size) {
      throw new BitpeekError('INVALID_RANGE', `endExclusive must be between start and size: ${end}`)
    }

    yield* this.parent.chunks(
      { start: this.offset + start, endExclusive: this.offset + end },
      chunkSize,
      signal,
    )
  }

  close(): void {
    this.parent = null
  }
}

/**
 * Virtual large source capable of representing gigabytes or petabytes of sparse data
 * with deterministic patterns and patches without allocating full file memory.
 */
export class GeneratedSparseSource implements ByteSource {
  readonly size: number
  readonly revision: string
  private readonly defaultByte: number
  private readonly patches: Map<number, Uint8Array>
  private closed = false

  constructor(
    size: number,
    defaultByte = 0x00,
    patches: Map<number, Uint8Array> = new Map(),
    revision = 'sparse-v1',
  ) {
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new BitpeekError('INVALID_RANGE', `Sparse source size must be a non-negative safe integer: ${size}`)
    }
    this.size = size
    this.defaultByte = defaultByte & 0xff
    this.patches = patches
    this.revision = revision
  }

  async read(offset: number, length: number, signal?: AbortSignal): Promise<Uint8Array> {
    if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Operation was aborted.')
    if (this.closed) throw new BitpeekError('IO_ERROR', 'GeneratedSparseSource is closed.')
    checkRange(offset, length, this.size)
    if (length === 0) return new Uint8Array(0)

    const buffer = new Uint8Array(length)
    if (this.defaultByte !== 0) {
      buffer.fill(this.defaultByte)
    }

    const readEnd = offset + length
    for (const [patchOffset, patchBytes] of this.patches.entries()) {
      const patchEnd = patchOffset + patchBytes.length
      if (patchEnd > offset && patchOffset < readEnd) {
        // Intersects
        const copyStartSrc = Math.max(0, offset - patchOffset)
        const copyStartDst = Math.max(0, patchOffset - offset)
        const copyLen = Math.min(
          patchBytes.length - copyStartSrc,
          length - copyStartDst,
        )
        buffer.set(patchBytes.subarray(copyStartSrc, copyStartSrc + copyLen), copyStartDst)
      }
    }

    return buffer
  }

  async *chunks(
    range?: { start: number; endExclusive?: number },
    chunkSize = 1024 * 1024,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array> {
    checkChunkSize(chunkSize)
    if (this.closed) throw new BitpeekError('IO_ERROR', 'GeneratedSparseSource is closed.')

    const start = range?.start ?? 0
    const end = range?.endExclusive ?? this.size
    if (!Number.isSafeInteger(start) || start < 0) {
      throw new BitpeekError('INVALID_RANGE', `start must be a non-negative safe integer: ${start}`)
    }
    if (!Number.isSafeInteger(end) || end < start || end > this.size) {
      throw new BitpeekError('INVALID_RANGE', `endExclusive must be between start and size: ${end}`)
    }

    let cursor = start
    while (cursor < end) {
      if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Operation was aborted.')
      const len = Math.min(chunkSize, end - cursor)
      yield await this.read(cursor, len, signal)
      cursor += len
    }
  }

  close(): void {
    this.closed = true
    this.patches.clear()
  }
}
