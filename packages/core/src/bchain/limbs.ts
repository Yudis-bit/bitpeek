/**
 * Bitpeek Ultra - Cryptographic Multi-Precision Limb Views
 *
 * Implements Section 15 (BCHAIN-04, AC066):
 * - 256-bit BigInt decomposition into 64-bit and 32-bit limbs
 * - Support for little-endian and big-endian limb layouts
 * - Multi-limb addition with carry & constant-time comparison
 */

export class CryptoLimbEngine {
  /**
   * Decomposes a 256-bit integer into 4 x 64-bit limbs.
   * Default limb ordering is little-endian (lowest 64 bits at index 0).
   */
  public static toLimbs64(val: bigint, endian: 'little' | 'big' = 'little'): bigint[] {
    const mask64 = 0xffffffffffffffffn
    const l0 = val & mask64
    const l1 = (val >> 64n) & mask64
    const l2 = (val >> 128n) & mask64
    const l3 = (val >> 192n) & mask64

    const limbs = [l0, l1, l2, l3]
    return endian === 'little' ? limbs : limbs.reverse()
  }

  /**
   * Reconstitutes a 256-bit integer from 4 x 64-bit limbs.
   */
  public static fromLimbs64(limbs: bigint[], endian: 'little' | 'big' = 'little'): bigint {
    if (limbs.length !== 4) {
      throw new Error(`Expected 4 limbs for 256-bit integer, got ${limbs.length}`)
    }

    const ordered = endian === 'little' ? limbs : [...limbs].reverse()
    return (
      (ordered[0]! & 0xffffffffffffffffn) |
      ((ordered[1]! & 0xffffffffffffffffn) << 64n) |
      ((ordered[2]! & 0xffffffffffffffffn) << 128n) |
      ((ordered[3]! & 0xffffffffffffffffn) << 192n)
    )
  }

  /**
   * Adds two 4-limb integers with carry propagation.
   */
  public static addLimbs64(a: bigint[], b: bigint[]): { result: bigint[]; carryOut: number } {
    const mask64 = 0xffffffffffffffffn
    const result: bigint[] = []
    let carry = 0n

    for (let i = 0; i < 4; i++) {
      const sum = a[i]! + b[i]! + carry
      result.push(sum & mask64)
      carry = sum >> 64n
    }

    return {
      result,
      carryOut: Number(carry),
    }
  }

  /**
   * Constant-time equality comparison between two 4-limb arrays.
   */
  public static constantTimeEqual(a: bigint[], b: bigint[]): boolean {
    if (a.length !== b.length) return false
    let diff = 0n
    for (let i = 0; i < a.length; i++) {
      diff |= a[i]! ^ b[i]!
    }
    return diff === 0n
  }
}
