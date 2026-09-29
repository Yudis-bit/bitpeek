import { BitpeekError } from './errors'
import type { ByteSource } from './byte-source'
import type { ByteSpan, TaggedFloat } from './types'

export interface ReaderBudget {
  maxNodes: number
  maxDepth: number
  maxBytes: number
  nodesRead: number
  currentDepth: number
  bytesRead: number
}

export interface ReaderOptions {
  signal?: AbortSignal
  budget?: Partial<ReaderBudget>
  sourceId?: string
}

export class BoundedCheckedReader {
  readonly source: ByteSource | null
  readonly buffer: Uint8Array | null
  readonly baseOffset: number
  readonly limit: number
  private cursor: number
  private readonly signal?: AbortSignal
  readonly budget: ReaderBudget
  readonly sourceId: string

  constructor(
    input: ByteSource | Uint8Array,
    options: ReaderOptions = {},
    baseOffset = 0,
    limit?: number,
  ) {
    this.signal = options.signal
    this.sourceId = options.sourceId ?? 'source-0'
    this.baseOffset = baseOffset

    if (input instanceof Uint8Array) {
      this.buffer = input
      this.source = null
      this.limit = limit !== undefined ? Math.min(limit, input.length) : input.length
    } else {
      this.buffer = null
      this.source = input
      this.limit = limit !== undefined ? Math.min(limit, input.size) : input.size
    }

    this.cursor = this.baseOffset
    this.budget = {
      maxNodes: options.budget?.maxNodes ?? 50_000,
      maxDepth: options.budget?.maxDepth ?? 64,
      maxBytes: options.budget?.maxBytes ?? 64 * 1024 * 1024,
      nodesRead: options.budget?.nodesRead ?? 0,
      currentDepth: options.budget?.currentDepth ?? 0,
      bytesRead: options.budget?.bytesRead ?? 0,
    }
  }

  get position(): number {
    return this.cursor
  }

  get remaining(): number {
    return Math.max(0, this.limit - this.cursor)
  }

  seek(position: number): void {
    if (!Number.isSafeInteger(position) || position < this.baseOffset || position > this.limit) {
      throw new BitpeekError(
        'INVALID_RANGE',
        `Seek offset ${position} is outside legal reader bounds [${this.baseOffset}, ${this.limit}].`,
      )
    }
    this.cursor = position
  }

  skip(count: number): void {
    this.seek(this.cursor + count)
  }

  private checkBudget(bytesToRead: number): void {
    if (this.signal?.aborted) {
      throw new BitpeekError('CANCELLED', 'Operation was aborted.')
    }
    this.budget.nodesRead += 1
    if (this.budget.nodesRead > this.budget.maxNodes) {
      throw new BitpeekError(
        'RESOURCE_LIMIT',
        `Exceeded maximum reader node budget of ${this.budget.maxNodes} items.`,
      )
    }
    this.budget.bytesRead += bytesToRead
    if (this.budget.bytesRead > this.budget.maxBytes) {
      throw new BitpeekError(
        'RESOURCE_LIMIT',
        `Exceeded maximum reader byte allocation budget of ${this.budget.maxBytes} bytes.`,
      )
    }
  }

  private checkAvailable(length: number): void {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new BitpeekError(
        'INVALID_RANGE',
        `Read length must be a non-negative safe integer: ${length}`,
      )
    }
    if (this.cursor + length > this.limit) {
      throw new BitpeekError(
        'TRUNCATED_INPUT',
        `Unexpected end of input: requested ${length} bytes at ${this.cursor}, but limit is ${this.limit}.`,
      )
    }
    this.checkBudget(length)
  }

  async readBytes(length: number): Promise<Uint8Array> {
    this.checkAvailable(length)
    if (length === 0) return new Uint8Array(0)

    let result: Uint8Array
    if (this.buffer) {
      result = this.buffer.slice(this.cursor, this.cursor + length)
    } else if (this.source) {
      result = await this.source.read(this.cursor, length, this.signal)
    } else {
      throw new BitpeekError('INTERNAL_ERROR', 'No underlying data buffer or source available.')
    }

    this.cursor += length
    return result
  }

  readBytesSync(length: number): Uint8Array {
    if (!this.buffer) {
      throw new BitpeekError('INTERNAL_ERROR', 'readBytesSync requires an in-memory Uint8Array buffer.')
    }
    this.checkAvailable(length)
    if (length === 0) return new Uint8Array(0)
    const result = this.buffer.slice(this.cursor, this.cursor + length)
    this.cursor += length
    return result
  }

  async readU8(): Promise<number> {
    const bytes = await this.readBytes(1)
    return bytes[0]!
  }

  readU8Sync(): number {
    const bytes = this.readBytesSync(1)
    return bytes[0]!
  }

  async readI8(): Promise<number> {
    const u8 = await this.readU8()
    return (u8 << 24) >> 24
  }

  readI8Sync(): number {
    const u8 = this.readU8Sync()
    return (u8 << 24) >> 24
  }

  async readU16(endian: 'le' | 'be'): Promise<number> {
    const b = await this.readBytes(2)
    return endian === 'le' ? (b[0]! | (b[1]! << 8)) : ((b[0]! << 8) | b[1]!)
  }

  readU16Sync(endian: 'le' | 'be'): number {
    const b = this.readBytesSync(2)
    return endian === 'le' ? (b[0]! | (b[1]! << 8)) : ((b[0]! << 8) | b[1]!)
  }

  async readI16(endian: 'le' | 'be'): Promise<number> {
    const u16 = await this.readU16(endian)
    return (u16 << 16) >> 16
  }

  readI16Sync(endian: 'le' | 'be'): number {
    const u16 = this.readU16Sync(endian)
    return (u16 << 16) >> 16
  }

  async readU32(endian: 'le' | 'be'): Promise<number> {
    const b = await this.readBytes(4)
    if (endian === 'le') {
      return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0
    }
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0
  }

  readU32Sync(endian: 'le' | 'be'): number {
    const b = this.readBytesSync(4)
    if (endian === 'le') {
      return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0
    }
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0
  }

  async readI32(endian: 'le' | 'be'): Promise<number> {
    const b = await this.readBytes(4)
    if (endian === 'le') {
      return b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)
    }
    return (b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!
  }

  readI32Sync(endian: 'le' | 'be'): number {
    const b = this.readBytesSync(4)
    if (endian === 'le') {
      return b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)
    }
    return (b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!
  }

  async readU64(endian: 'le' | 'be'): Promise<bigint> {
    const b = await this.readBytes(8)
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
    return view.getBigUint64(0, endian === 'le')
  }

  readU64Sync(endian: 'le' | 'be'): bigint {
    const b = this.readBytesSync(8)
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
    return view.getBigUint64(0, endian === 'le')
  }

  async readI64(endian: 'le' | 'be'): Promise<bigint> {
    const b = await this.readBytes(8)
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
    return view.getBigInt64(0, endian === 'le')
  }

  readI64Sync(endian: 'le' | 'be'): bigint {
    const b = this.readBytesSync(8)
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength)
    return view.getBigInt64(0, endian === 'le')
  }

  async readFloat32(endian: 'le' | 'be'): Promise<TaggedFloat> {
    const bytes = await this.readBytes(4)
    const view = new DataView(bytes.buffer, bytes.byteOffset, 4)
    const num = view.getFloat32(0, endian === 'le')
    const rawBitsNum = view.getUint32(0, endian === 'le')
    const rawHex = '0x' + rawBitsNum.toString(16).padStart(8, '0')

    const isNaN = Number.isNaN(num)
    const isInfinity = num === Infinity || num === -Infinity
    const isNegative = Object.is(num, -0) || num < 0
    const isZero = num === 0
    const exponent = (rawBitsNum >> 23) & 0xff
    const mantissa = rawBitsNum & 0x7fffff
    const isSubnormal = exponent === 0 && mantissa !== 0

    let display = num.toString()
    if (isNaN) display = 'NaN'
    else if (num === Infinity) display = '+Infinity'
    else if (num === -Infinity) display = '-Infinity'
    else if (Object.is(num, -0)) display = '-0.0'

    return {
      kind: 'f32',
      rawBits: rawHex,
      isNaN,
      isInfinity,
      isNegative,
      isZero,
      isSubnormal,
      display,
      numericValue: num,
    }
  }

  async readFloat64(endian: 'le' | 'be'): Promise<TaggedFloat> {
    const bytes = await this.readBytes(8)
    const view = new DataView(bytes.buffer, bytes.byteOffset, 8)
    const num = view.getFloat64(0, endian === 'le')
    const rawBig = view.getBigUint64(0, endian === 'le')
    const rawHex = '0x' + rawBig.toString(16).padStart(16, '0')

    const isNaN = Number.isNaN(num)
    const isInfinity = num === Infinity || num === -Infinity
    const isNegative = Object.is(num, -0) || num < 0
    const isZero = num === 0
    const exponent = Number((rawBig >> 52n) & 0x7ffn)
    const mantissa = rawBig & 0x000fffffffffffffn
    const isSubnormal = exponent === 0 && mantissa !== 0n

    let display = num.toString()
    if (isNaN) display = 'NaN'
    else if (num === Infinity) display = '+Infinity'
    else if (num === -Infinity) display = '-Infinity'
    else if (Object.is(num, -0)) display = '-0.0'

    return {
      kind: 'f64',
      rawBits: rawHex,
      isNaN,
      isInfinity,
      isNegative,
      isZero,
      isSubnormal,
      display,
      numericValue: num,
    }
  }

  /**
   * Decodes unsigned LEB128/Varint with maximum width and canonicality checks.
   * Throws INVALID_FORMAT on overlong non-canonical encodings if canonical=true.
   */
  async readVarint(maxBytes = 10, canonical = true): Promise<{ value: bigint; byteLength: number }> {
    let result = 0n
    let shift = 0n
    let count = 0

    while (count < maxBytes) {
      const b = await this.readU8()
      count += 1
      const val = BigInt(b & 0x7f)
      result |= val << shift
      shift += 7n

      if ((b & 0x80) === 0) {
        if (canonical && count > 1 && b === 0x00 && result !== 0n) {
          throw new BitpeekError(
            'INVALID_FORMAT',
            'Non-canonical varint: redundant trailing zero byte detected.',
          )
        }
        return { value: result, byteLength: count }
      }
    }

    throw new BitpeekError(
      'INVALID_FORMAT',
      `Varint exceeded maximum width limit of ${maxBytes} bytes.`,
    )
  }

  /**
   * Decodes Bitcoin CompactSize integer format with strict canonicality checking (BIP-144).
   */
  async readCompactSize(): Promise<{ value: bigint; byteLength: number }> {
    const first = await this.readU8()
    if (first < 253) {
      return { value: BigInt(first), byteLength: 1 }
    }
    if (first === 253) {
      const val = await this.readU16('le')
      if (val < 253) {
        throw new BitpeekError(
          'INVALID_FORMAT',
          `Non-canonical CompactSize: value ${val} encoded in 3 bytes instead of 1.`,
        )
      }
      return { value: BigInt(val), byteLength: 3 }
    }
    if (first === 254) {
      const val = await this.readU32('le')
      if (val <= 0xffff) {
        throw new BitpeekError(
          'INVALID_FORMAT',
          `Non-canonical CompactSize: value ${val} encoded in 5 bytes instead of 3.`,
        )
      }
      return { value: BigInt(val), byteLength: 5 }
    }
    // first === 255
    const val = await this.readU64('le')
    if (val <= 0xffffffffn) {
      throw new BitpeekError(
        'INVALID_FORMAT',
        `Non-canonical CompactSize: value ${val} encoded in 9 bytes instead of 5.`,
      )
    }
    return { value: val, byteLength: 9 }
  }

  /**
   * Slices the current reader to create a constrained child reader for nested structures.
   */
  slice(length: number): BoundedCheckedReader {
    this.checkAvailable(length)
    if (this.budget.currentDepth + 1 > this.budget.maxDepth) {
      throw new BitpeekError(
        'RESOURCE_LIMIT',
        `Exceeded maximum reader recursion depth of ${this.budget.maxDepth}.`,
      )
    }

    const childBudget: ReaderBudget = {
      ...this.budget,
      currentDepth: this.budget.currentDepth + 1,
    }

    const start = this.cursor
    const child = this.buffer
      ? new BoundedCheckedReader(this.buffer, { signal: this.signal, budget: childBudget, sourceId: this.sourceId }, start, start + length)
      : new BoundedCheckedReader(this.source!, { signal: this.signal, budget: childBudget, sourceId: this.sourceId }, start, start + length)

    this.cursor += length
    return child
  }

  currentSpan(length: number): ByteSpan {
    return {
      sourceId: this.sourceId,
      start: this.cursor,
      endExclusive: this.cursor + length,
    }
  }
}
