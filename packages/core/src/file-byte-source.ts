import { open, stat, type FileHandle } from 'node:fs/promises'
import { BitpeekError } from './errors'
import type { ByteSource } from './byte-source'

export class FileByteSource implements ByteSource {
  readonly size: number
  readonly revision: string
  readonly path: string
  private handle: FileHandle | null = null

  private constructor(path: string, size: number, mtimeMs: number, handle: FileHandle) {
    this.path = path
    this.size = size
    this.revision = `${mtimeMs}-${size}`
    this.handle = handle
  }

  static async open(filePath: string): Promise<FileByteSource> {
    try {
      const fileStat = await stat(filePath)
      if (!fileStat.isFile()) {
        throw new BitpeekError('INVALID_INPUT', `Path is not a regular file: ${filePath}`)
      }
      const handle = await open(filePath, 'r')
      return new FileByteSource(filePath, fileStat.size, fileStat.mtimeMs, handle)
    } catch (err: unknown) {
      if (err instanceof BitpeekError) throw err
      throw new BitpeekError('IO_ERROR', `Failed to open file ${filePath}: ${String(err)}`)
    }
  }

  async read(offset: number, length: number, signal?: AbortSignal): Promise<Uint8Array> {
    if (signal?.aborted) {
      throw new BitpeekError('CANCELLED', 'Operation was aborted.')
    }
    if (!this.handle) {
      throw new BitpeekError('IO_ERROR', 'FileByteSource is closed.')
    }
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new BitpeekError('INVALID_RANGE', `Offset must be a non-negative safe integer: ${offset}`)
    }
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new BitpeekError('INVALID_RANGE', `Length must be a non-negative safe integer: ${length}`)
    }
    if (offset + length > this.size) {
      throw new BitpeekError(
        'INVALID_RANGE',
        `Requested range [${offset}, ${offset + length}) exceeds file size ${this.size}.`,
      )
    }
    if (length === 0) return new Uint8Array(0)

    const buffer = new Uint8Array(length)
    try {
      const { bytesRead } = await this.handle.read(buffer, 0, length, offset)
      if (bytesRead !== length) {
        throw new BitpeekError(
          'TRUNCATED_INPUT',
          `Expected ${length} bytes at offset ${offset}, but only read ${bytesRead} bytes.`,
        )
      }
      return buffer
    } catch (err: unknown) {
      if (signal?.aborted) {
        throw new BitpeekError('CANCELLED', 'Operation was aborted.')
      }
      if (err instanceof BitpeekError) throw err
      throw new BitpeekError('IO_ERROR', `File read failed: ${String(err)}`)
    }
  }

  async *chunks(
    range?: { start: number; endExclusive?: number },
    chunkSize = 1024 * 1024,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array> {
    const start = range?.start ?? 0
    const end = range?.endExclusive ?? this.size
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

  async close(): Promise<void> {
    if (this.handle) {
      await this.handle.close()
      this.handle = null
    }
  }
}
