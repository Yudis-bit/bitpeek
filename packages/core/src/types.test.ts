import { describe, expect, it } from 'vitest'
import {
  validateByteSpan,
  serializeBigInt,
  deserializeBigInt,
  safeJsonStringify,
} from './types'

describe('Exact Coordinate & Precision Types (AC006, AC008)', () => {
  it('validates half-open byte spans correctly', () => {
    expect(() => validateByteSpan({ sourceId: 's1', start: 0, endExclusive: 10 }, 20)).not.toThrow()
    expect(() => validateByteSpan({ sourceId: 's1', start: 10, endExclusive: 10 }, 20)).not.toThrow() // empty span is legal
    expect(() => validateByteSpan({ sourceId: 's1', start: -1, endExclusive: 10 })).toThrow(/non-negative/)
    expect(() => validateByteSpan({ sourceId: 's1', start: 15, endExclusive: 10 })).toThrow(/>= start/)
    expect(() => validateByteSpan({ sourceId: 's1', start: 0, endExclusive: 25 }, 20)).toThrow(/exceeds source size/)
  })

  it('handles u64 max, u128, and u256 exact values through BigInt serialization (AC006)', () => {
    const u64Max = 18446744073709551615n
    const u256Val = 115792089237316195423570985008687907853269984665640564039457584007913129639935n // 2^256 - 1

    expect(serializeBigInt(u64Max)).toBe('18446744073709551615')
    expect(deserializeBigInt('18446744073709551615')).toBe(u64Max)
    expect(deserializeBigInt('0xffffffffffffffff')).toBe(u64Max)

    expect(serializeBigInt(u256Val)).toBe('115792089237316195423570985008687907853269984665640564039457584007913129639935')
    expect(deserializeBigInt('115792089237316195423570985008687907853269984665640564039457584007913129639935')).toBe(u256Val)

    // JSON safe roundtrip without precision loss
    const payload = { address: u64Max, hash: u256Val }
    const json = safeJsonStringify(payload)
    expect(json).toContain('"18446744073709551615"')
    const parsed = JSON.parse(json)
    expect(deserializeBigInt(parsed.address)).toBe(u64Max)
    expect(deserializeBigInt(parsed.hash)).toBe(u256Val)
  })

  it('rejects unsafe number coercion to BigInt', () => {
    expect(() => deserializeBigInt(Number.MAX_SAFE_INTEGER + 100)).toThrow(/Unsafe number/)
  })
})
