import { BitpeekError } from './errors'
import { type ByteSource, MemoryByteSource, checkRange, checkChunkSize } from './byte-source'

export interface Piece {
  readonly source: 'original' | 'added'
  readonly start: number
  readonly length: number
}

export interface PieceTableSnapshot {
  readonly pieces: readonly Piece[]
  readonly length: number
}

export interface PieceTableEdit {
  readonly description: string
  readonly before: PieceTableSnapshot
  readonly after: PieceTableSnapshot
}

export class PieceTable implements ByteSource {
  readonly revision: string
  private readonly original: ByteSource
  private readonly addedBuffers: Uint8Array[] = []
  private addedTotalBytes = 0
  private pieces: Piece[] = []
  private currentLength = 0

  private undoStack: PieceTableEdit[] = []
  private redoStack: PieceTableEdit[] = []
  private editRevisionCounter = 0

  constructor(original: ByteSource | Uint8Array, revision = 'pt-0') {
    if (original instanceof Uint8Array) {
      this.original = new MemoryByteSource(original)
    } else {
      this.original = original
    }
    this.revision = revision
    this.currentLength = this.original.size
    if (this.currentLength > 0) {
      this.pieces.push({
        source: 'original',
        start: 0,
        length: this.currentLength,
      })
    }
  }

  get size(): number {
    return this.currentLength
  }

  private snapshot(): PieceTableSnapshot {
    return {
      pieces: [...this.pieces],
      length: this.currentLength,
    }
  }

  private commitEdit(description: string, before: PieceTableSnapshot): void {
    const after = this.snapshot()
    this.undoStack.push({ description, before, after })
    this.redoStack = [] // clear redo branch on new edit
    this.editRevisionCounter += 1
  }

  canUndo(): boolean {
    return this.undoStack.length > 0
  }

  canRedo(): boolean {
    return this.redoStack.length > 0
  }

  undo(): boolean {
    const edit = this.undoStack.pop()
    if (!edit) return false
    this.redoStack.push(edit)
    this.pieces = [...edit.before.pieces]
    this.currentLength = edit.before.length
    this.editRevisionCounter += 1
    return true
  }

  redo(): boolean {
    const edit = this.redoStack.pop()
    if (!edit) return false
    this.undoStack.push(edit)
    this.pieces = [...edit.after.pieces]
    this.currentLength = edit.after.length
    this.editRevisionCounter += 1
    return true
  }

  private findPiece(offset: number): { pieceIndex: number; pieceOffset: number } {
    let accumulated = 0
    for (let i = 0; i < this.pieces.length; i++) {
      const piece = this.pieces[i]!
      if (offset < accumulated + piece.length) {
        return { pieceIndex: i, pieceOffset: offset - accumulated }
      }
      accumulated += piece.length
    }
    return { pieceIndex: this.pieces.length, pieceOffset: 0 }
  }

  insert(offset: number, bytes: Uint8Array, description = 'Insert bytes'): void {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > this.currentLength) {
      throw new BitpeekError(
        'INVALID_RANGE',
        `Insert offset ${offset} is outside document range [0, ${this.currentLength}].`,
      )
    }
    if (bytes.length === 0) return

    const before = this.snapshot()
    const addedBufferIndex = this.addedTotalBytes
    this.addedBuffers.push(new Uint8Array(bytes))
    this.addedTotalBytes += bytes.length

    const newPiece: Piece = {
      source: 'added',
      start: addedBufferIndex,
      length: bytes.length,
    }

    if (offset === 0) {
      this.pieces.unshift(newPiece)
    } else if (offset === this.currentLength) {
      this.pieces.push(newPiece)
    } else {
      const { pieceIndex, pieceOffset } = this.findPiece(offset)
      const target = this.pieces[pieceIndex]!

      if (pieceOffset === 0) {
        this.pieces.splice(pieceIndex, 0, newPiece)
      } else {
        const left: Piece = {
          source: target.source,
          start: target.start,
          length: pieceOffset,
        }
        const right: Piece = {
          source: target.source,
          start: target.start + pieceOffset,
          length: target.length - pieceOffset,
        }
        this.pieces.splice(pieceIndex, 1, left, newPiece, right)
      }
    }

    this.currentLength += bytes.length
    this.commitEdit(description, before)
  }

  delete(offset: number, length: number, description = 'Delete bytes'): void {
    checkRange(offset, length, this.currentLength)
    if (length === 0) return

    const before = this.snapshot()
    const deleteEnd = offset + length
    const newPieces: Piece[] = []
    let cursor = 0

    for (const piece of this.pieces) {
      const pieceEnd = cursor + piece.length

      if (pieceEnd <= offset || cursor >= deleteEnd) {
        // Fully outside deleted interval
        newPieces.push(piece)
      } else {
        // Intersects deleted interval
        if (cursor < offset) {
          // Keep left slice
          newPieces.push({
            source: piece.source,
            start: piece.start,
            length: offset - cursor,
          })
        }
        if (pieceEnd > deleteEnd) {
          // Keep right slice
          const rightOffsetInPiece = deleteEnd - cursor
          newPieces.push({
            source: piece.source,
            start: piece.start + rightOffsetInPiece,
            length: piece.length - rightOffsetInPiece,
          })
        }
      }
      cursor = pieceEnd
    }

    this.pieces = newPieces
    this.currentLength -= length
    this.commitEdit(description, before)
  }

  replace(offset: number, bytes: Uint8Array, description = 'Replace bytes'): void {
    checkRange(offset, bytes.length, this.currentLength)
    if (bytes.length === 0) return

    const before = this.snapshot()
    // Perform delete + insert under one atomic transaction
    this.delete(offset, bytes.length, description)
    this.insert(offset, bytes, description)

    // Merge the two edits in the undo stack so undo acts as a single step
    this.undoStack.pop() // remove insert edit
    this.undoStack.pop() // remove delete edit
    this.commitEdit(description, before)
  }

  private readFromAdded(start: number, length: number): Uint8Array {
    const result = new Uint8Array(length)
    let copied = 0
    let accumulated = 0

    for (const buf of this.addedBuffers) {
      const bufEnd = accumulated + buf.length
      if (bufEnd > start && accumulated < start + length) {
        const sliceStart = Math.max(0, start - accumulated)
        const sliceEnd = Math.min(buf.length, start + length - accumulated)
        const count = sliceEnd - sliceStart
        result.set(buf.subarray(sliceStart, sliceEnd), copied)
        copied += count
      }
      accumulated = bufEnd
      if (copied >= length) break
    }

    return result
  }

  async read(offset: number, length: number, signal?: AbortSignal): Promise<Uint8Array> {
    if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Operation was aborted.')
    checkRange(offset, length, this.currentLength)
    if (length === 0) return new Uint8Array(0)

    const result = new Uint8Array(length)
    let destOffset = 0
    let pieceCursor = 0
    const readEnd = offset + length

    for (const piece of this.pieces) {
      if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Operation was aborted.')
      const pieceEnd = pieceCursor + piece.length

      if (pieceEnd > offset && pieceCursor < readEnd) {
        const overlapStart = Math.max(offset, pieceCursor)
        const overlapEnd = Math.min(readEnd, pieceEnd)
        const count = overlapEnd - overlapStart
        const offsetInPiece = overlapStart - pieceCursor

        if (piece.source === 'original') {
          const slice = await this.original.read(piece.start + offsetInPiece, count, signal)
          result.set(slice, destOffset)
        } else {
          const slice = this.readFromAdded(piece.start + offsetInPiece, count)
          result.set(slice, destOffset)
        }

        destOffset += count
      }
      pieceCursor = pieceEnd
      if (destOffset >= length) break
    }

    return result
  }

  async *chunks(
    range?: { start: number; endExclusive?: number },
    chunkSize = 64 * 1024,
    signal?: AbortSignal,
  ): AsyncIterable<Uint8Array> {
    checkChunkSize(chunkSize)
    const start = range?.start ?? 0
    const end = range?.endExclusive ?? this.currentLength
    checkRange(start, end - start, this.currentLength)

    let cursor = start
    while (cursor < end) {
      if (signal?.aborted) throw new BitpeekError('CANCELLED', 'Operation was aborted.')
      const len = Math.min(chunkSize, end - cursor)
      const chunk = await this.read(cursor, len, signal)
      yield chunk
      cursor += len
    }
  }

  close(): void {
    this.original.close()
    this.pieces = []
    this.addedBuffers.length = 0
  }
}
