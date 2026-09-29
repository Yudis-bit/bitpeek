import { open, type FileHandle } from 'node:fs/promises'
import { BitpeekError, type ByteSource, checkRange, checkChunkSize } from '../../core/src/index'

export class NodeFileByteSource implements ByteSource {
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

  static async open(filePath: string): Promise<NodeFileByteSource> {
    try {
      const handle = await open(filePath, 'r')
      const fileStat = await handle.stat()
      if (!fileStat.isFile()) {
        await handle.close()
        throw new BitpeekError('INVALID_INPUT', `Path is not a regular file: ${filePath}`)
      }
      return new NodeFileByteSource(filePath, fileStat.size, fileStat.mtimeMs, handle)
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
    checkRange(offset, length, this.size)
    if (length === 0) return new Uint8Array(0)

    const buffer = new Uint8Array(length)
    let totalRead = 0

    try {
      while (totalRead < length) {
        if (signal?.aborted) {
          throw new BitpeekError('CANCELLED', 'Operation was aborted.')
        }
        const { bytesRead } = await this.handle.read(
          buffer,
          totalRead,
          length - totalRead,
          offset + totalRead,
        )
        if (bytesRead === 0) {
          // True unexpected EOF
          throw new BitpeekError(
            'TRUNCATED_INPUT',
            `Expected ${length} bytes at offset ${offset}, but reached EOF after ${totalRead} bytes.`,
          )
        }
        totalRead += bytesRead
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
    checkChunkSize(chunkSize)
    if (!this.handle) {
      throw new BitpeekError('IO_ERROR', 'FileByteSource is closed.')
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

  async close(): Promise<void> {
    if (this.handle) {
      const h = this.handle
      this.handle = null
      await h.close()
    }
  }
}
