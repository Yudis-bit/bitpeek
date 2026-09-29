/**
 * Bitpeek Ultra - Ethereum RLP Decoder & Typed Transaction Envelopes
 *
 * Implements Section 15 (BCHAIN-02, AC063):
 * - Recursive Length Prefix (RLP) parser with strict canonicality checks
 * - Rejects non-minimal integer and length encodings
 * - EIP-2718 typed transaction envelopes (Legacy, Type 1, Type 2 EIP-1559)
 */

import { formatHex } from '../bytes'

export type RlpItem =
  | { type: 'bytes'; data: Uint8Array; hex: string }
  | { type: 'list'; items: RlpItem[] }

export interface DecodedEthereumTx {
  envelopeType: 'legacy' | 'eip2930' | 'eip1559'
  typeByte?: number
  chainId?: bigint
  nonce: bigint
  gasPrice?: bigint
  maxPriorityFeePerGas?: bigint
  maxFeePerGas?: bigint
  gasLimit: bigint
  to?: string
  value: bigint
  data: Uint8Array
  v?: bigint
  r?: bigint
  s?: bigint
}

export class RlpDecoder {
  /**
   * Decodes an RLP-encoded byte buffer. Enforces canonical minimal encodings.
   */
  public static decode(bytes: Uint8Array, offset = 0): { item: RlpItem; bytesConsumed: number } {
    if (offset >= bytes.length) {
      throw new Error(`RLP decode offset out of bounds: ${offset} >= ${bytes.length}`)
    }

    const prefix = bytes[offset]!

    // 1. Single byte in range [0x00..0x7f]
    if (prefix <= 0x7f) {
      const data = bytes.subarray(offset, offset + 1)
      return {
        item: { type: 'bytes', data, hex: formatHex(data).replace(/\s+/g, '') },
        bytesConsumed: 1,
      }
    }

    // 2. Short string [0x80..0xb7]: length is 0..55
    if (prefix <= 0xb7) {
      const len = prefix - 0x80
      if (offset + 1 + len > bytes.length) {
        throw new Error(`RLP short string truncated: expected ${len} bytes`)
      }
      // Canonicality check: single byte < 0x80 must not be encoded with 0x81 prefix
      if (len === 1 && bytes[offset + 1]! < 0x80) {
        throw new Error(`Non-canonical RLP: single byte 0x${bytes[offset + 1]!.toString(16)} encoded as short string`)
      }

      const data = bytes.subarray(offset + 1, offset + 1 + len)
      return {
        item: { type: 'bytes', data, hex: formatHex(data).replace(/\s+/g, '') },
        bytesConsumed: 1 + len,
      }
    }

    // 3. Long string [0xb8..0xbf]: length prefix length 1..8
    if (prefix <= 0xbf) {
      const lenOfLen = prefix - 0xb7
      if (offset + 1 + lenOfLen > bytes.length) {
        throw new Error(`RLP long string length header truncated`)
      }
      // Canonicality check: length prefix must not have leading zero
      if (bytes[offset + 1] === 0x00) {
        throw new Error(`Non-canonical RLP: length prefix has leading zero`)
      }

      let len = 0
      for (let i = 0; i < lenOfLen; i++) {
        len = (len * 256) + bytes[offset + 1 + i]!
      }

      if (len <= 55) {
        throw new Error(`Non-canonical RLP: string length ${len} must be encoded with short prefix`)
      }

      const payloadStart = offset + 1 + lenOfLen
      if (payloadStart + len > bytes.length) {
        throw new Error(`RLP long string payload truncated`)
      }

      const data = bytes.subarray(payloadStart, payloadStart + len)
      return {
        item: { type: 'bytes', data, hex: formatHex(data).replace(/\s+/g, '') },
        bytesConsumed: 1 + lenOfLen + len,
      }
    }

    // 4. Short list [0xc0..0xf7]: payload length 0..55
    if (prefix <= 0xf7) {
      const payloadLen = prefix - 0xc0
      if (offset + 1 + payloadLen > bytes.length) {
        throw new Error(`RLP short list truncated: expected ${payloadLen} bytes`)
      }

      const items: RlpItem[] = []
      let cur = offset + 1
      const end = cur + payloadLen

      while (cur < end) {
        const decoded = this.decode(bytes, cur)
        items.push(decoded.item)
        cur += decoded.bytesConsumed
      }

      if (cur !== end) {
        throw new Error(`RLP short list items do not match declared payload length`)
      }

      return {
        item: { type: 'list', items },
        bytesConsumed: 1 + payloadLen,
      }
    }

    // 5. Long list [0xf8..0xff]: length prefix length 1..8
    const lenOfLen = prefix - 0xf7
    if (offset + 1 + lenOfLen > bytes.length) {
      throw new Error(`RLP long list length header truncated`)
    }
    if (bytes[offset + 1] === 0x00) {
      throw new Error(`Non-canonical RLP: list length prefix has leading zero`)
    }

    let payloadLen = 0
    for (let i = 0; i < lenOfLen; i++) {
      payloadLen = (payloadLen * 256) + bytes[offset + 1 + i]!
    }

    if (payloadLen <= 55) {
      throw new Error(`Non-canonical RLP: list length ${payloadLen} must be encoded with short prefix`)
    }

    const payloadStart = offset + 1 + lenOfLen
    if (payloadStart + payloadLen > bytes.length) {
      throw new Error(`RLP long list payload truncated`)
    }

    const items: RlpItem[] = []
    let cur = payloadStart
    const end = cur + payloadLen

    while (cur < end) {
      const decoded = this.decode(bytes, cur)
      items.push(decoded.item)
      cur += decoded.bytesConsumed
    }

    return {
      item: { type: 'list', items },
      bytesConsumed: 1 + lenOfLen + payloadLen,
    }
  }

  /**
   * Parses an Ethereum transaction buffer (Legacy or EIP-2718 typed envelope).
   */
  public static parseTransaction(bytes: Uint8Array): DecodedEthereumTx {
    if (bytes.length === 0) {
      throw new Error('Empty transaction buffer')
    }

    const firstByte = bytes[0]!

    // Check for EIP-2718 typed envelopes
    if (firstByte === 0x01) {
      // EIP-2930 Access List Tx: 0x01 || rlp([...])
      const decoded = this.decode(bytes, 1)
      if (decoded.item.type !== 'list') throw new Error('Expected RLP list inside Type 1 envelope')
      const items = decoded.item.items
      return {
        envelopeType: 'eip2930',
        typeByte: 1,
        chainId: this.bytesToBigInt(items[0]),
        nonce: this.bytesToBigInt(items[1]),
        gasPrice: this.bytesToBigInt(items[2]),
        gasLimit: this.bytesToBigInt(items[3]),
        to: this.formatAddress(items[4]),
        value: this.bytesToBigInt(items[5]),
        data: this.itemToBytes(items[6]),
      }
    }

    if (firstByte === 0x02) {
      // EIP-1559 Dynamic Fee Tx: 0x02 || rlp([...])
      const decoded = this.decode(bytes, 1)
      if (decoded.item.type !== 'list') throw new Error('Expected RLP list inside Type 2 envelope')
      const items = decoded.item.items
      return {
        envelopeType: 'eip1559',
        typeByte: 2,
        chainId: this.bytesToBigInt(items[0]),
        nonce: this.bytesToBigInt(items[1]),
        maxPriorityFeePerGas: this.bytesToBigInt(items[2]),
        maxFeePerGas: this.bytesToBigInt(items[3]),
        gasLimit: this.bytesToBigInt(items[4]),
        to: this.formatAddress(items[5]),
        value: this.bytesToBigInt(items[6]),
        data: this.itemToBytes(items[7]),
      }
    }

    // Legacy Transaction: raw RLP list [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    const decoded = this.decode(bytes, 0)
    if (decoded.item.type !== 'list') {
      throw new Error('Expected RLP list for legacy Ethereum transaction')
    }
    const items = decoded.item.items
    return {
      envelopeType: 'legacy',
      nonce: this.bytesToBigInt(items[0]),
      gasPrice: this.bytesToBigInt(items[1]),
      gasLimit: this.bytesToBigInt(items[2]),
      to: this.formatAddress(items[3]),
      value: this.bytesToBigInt(items[4]),
      data: this.itemToBytes(items[5]),
      v: this.bytesToBigInt(items[6]),
      r: this.bytesToBigInt(items[7]),
      s: this.bytesToBigInt(items[8]),
    }
  }

  private static bytesToBigInt(item?: RlpItem): bigint {
    if (!item || item.type !== 'bytes') return 0n
    if (item.data.length === 0) return 0n
    let res = 0n
    for (const b of item.data) {
      res = (res << 8n) | BigInt(b)
    }
    return res
  }

  private static formatAddress(item?: RlpItem): string | undefined {
    if (!item || item.type !== 'bytes') return undefined
    if (item.data.length === 0) return undefined
    return '0x' + formatHex(item.data).replace(/\s+/g, '')
  }

  private static itemToBytes(item?: RlpItem): Uint8Array {
    if (!item || item.type !== 'bytes') return new Uint8Array(0)
    return item.data
  }
}
