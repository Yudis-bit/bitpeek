import { describe, expect, it } from 'vitest'
import { encodeText } from './bytes'
import { digestHex } from './crypto'

describe('Web Crypto digests', () => {
  it('matches SHA-256 and SHA-512 known vectors', async () => {
    const bytes = encodeText('abc')
    await expect(digestHex(bytes, 'SHA-256')).resolves.toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
    await expect(digestHex(bytes, 'SHA-512')).resolves.toBe(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    )
  })
})
