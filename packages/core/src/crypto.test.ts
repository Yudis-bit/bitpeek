import { describe, expect, it } from 'vitest'
import { sha256Hex, sha256Stream, crc32, crc16 } from './crypto'

describe('Sha256', () => {
  it('computes empty string SHA-256 vector', () => {
    expect(sha256Hex(new Uint8Array(0))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })

  it('computes "abc" NIST vector', () => {
    const input = new TextEncoder().encode('abc')
    expect(sha256Hex(input)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })

  it('computes multi-block input spanning across 64-byte chunks matching Node crypto', () => {
    const text = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    const input = new TextEncoder().encode(text)
    expect(sha256Hex(input)).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    )
  })

  it('streams chunks producing exact same hash as one-shot', async () => {
    async function* makeChunks() {
      yield new Uint8Array([0xde, 0xad])
      yield new Uint8Array([0xbe, 0xef])
      yield new Uint8Array([0x00, 0x01, 0x7f, 0x80])
    }
    const streamed = await sha256Stream(makeChunks())
    const oneshot = sha256Hex(new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80]))
    expect(streamed).toBe(oneshot)
  })
})

describe('CRC implementations', () => {
  it('computes standard CRC-32 for "123456789"', () => {
    const input = new TextEncoder().encode('123456789')
    expect(crc32(input)).toBe(0xcbf43926)
  })

  it('computes standard CRC-16 CCITT-FALSE for "123456789"', () => {
    const input = new TextEncoder().encode('123456789')
    expect(crc16(input)).toBe(0x29b1)
  })
})
