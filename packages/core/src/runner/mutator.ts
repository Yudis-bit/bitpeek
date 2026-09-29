/**
 * Bitpeek Ultra - Deterministic Byte Mutator
 *
 * Implements Section 12 (RUN-03, AC060):
 * - Deterministic bit/byte flips, boundary integers, insert/delete
 * - Pure, reproducible mutations driven by explicit seed
 */

const BOUNDARY_INTS = [
  0,
  1,
  -1,
  0x7f,
  0x80,
  0xff,
  0x7fff,
  0x8000,
  0xffff,
  0x7fffffff,
  0x80000000,
]

export type MutationStrategy =
  | 'bit_flip'
  | 'byte_flip'
  | 'boundary_int'
  | 'insert_byte'
  | 'delete_byte'

export class DeterministicMutator {
  private state: number

  constructor(seed: number) {
    this.state = seed >>> 0
  }

  // 32-bit LCG PRNG
  private nextRand(): number {
    this.state = (Math.imul(this.state, 1664525) + 1013904223) >>> 0
    return this.state
  }

  private randInt(max: number): number {
    if (max <= 0) return 0
    return this.nextRand() % max
  }

  /**
   * Mutates a byte buffer deterministically according to chosen or random strategy.
   */
  public mutate(input: Uint8Array, strategy?: MutationStrategy): Uint8Array {
    if (input.length === 0) {
      return new Uint8Array([0])
    }

    const strategies: MutationStrategy[] = [
      'bit_flip',
      'byte_flip',
      'boundary_int',
      'insert_byte',
      'delete_byte',
    ]

    const strat = strategy ?? strategies[this.randInt(strategies.length)]!
    const output = new Uint8Array(input)

    switch (strat) {
      case 'bit_flip': {
        const offset = this.randInt(output.length)
        const bit = this.randInt(8)
        output[offset] ^= 1 << bit
        return output
      }

      case 'byte_flip': {
        const offset = this.randInt(output.length)
        output[offset] = output[offset]! ^ 0xff
        return output
      }

      case 'boundary_int': {
        const val = BOUNDARY_INTS[this.randInt(BOUNDARY_INTS.length)]!
        const width = [1, 2, 4][this.randInt(3)]!
        const maxOffset = Math.max(0, output.length - width)
        const offset = this.randInt(maxOffset + 1)
        const view = new DataView(output.buffer, output.byteOffset, output.byteLength)

        if (width === 1 && offset < output.length) {
          view.setUint8(offset, val & 0xff)
        } else if (width === 2 && offset + 2 <= output.length) {
          view.setUint16(offset, val & 0xffff, true)
        } else if (width === 4 && offset + 4 <= output.length) {
          view.setInt32(offset, val, true)
        }
        return output
      }

      case 'insert_byte': {
        const offset = this.randInt(output.length + 1)
        const newBuf = new Uint8Array(output.length + 1)
        newBuf.set(output.subarray(0, offset), 0)
        newBuf[offset] = this.randInt(256)
        newBuf.set(output.subarray(offset), offset + 1)
        return newBuf
      }

      case 'delete_byte': {
        if (output.length <= 1) return output
        const offset = this.randInt(output.length)
        const newBuf = new Uint8Array(output.length - 1)
        newBuf.set(output.subarray(0, offset), 0)
        newBuf.set(output.subarray(offset + 1), offset)
        return newBuf
      }
    }
  }
}
