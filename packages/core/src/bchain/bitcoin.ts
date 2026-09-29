/**
 * Bitpeek Ultra - Bitcoin Binary Analysis & Transaction Parser
 *
 * Implements Section 15 (BCHAIN-01, AC061, AC062):
 * - Canonical Bitcoin CompactSize parsing with non-canonical rejection
 * - Transaction framing with SegWit support
 * - Exact Satoshi representation as BigInt (no floating point)
 * - Wire-order and display-order (reversed) double-SHA256 TXID calculation
 */

import { BoundedCheckedReader } from '../reader'
import { sha256 } from '../crypto'
import { formatHex } from '../bytes'

export interface BitcoinTxInput {
  txidWireHex: string
  txidDisplayHex: string
  vout: number
  scriptSig: Uint8Array
  sequence: number
  witness?: Uint8Array[]
}

export interface BitcoinTxOutput {
  valueSatoshis: bigint
  scriptPubKey: Uint8Array
}

export interface BitcoinTransaction {
  version: number
  isSegWit: boolean
  inputs: BitcoinTxInput[]
  outputs: BitcoinTxOutput[]
  locktime: number
  txidWire: string
  txidDisplay: string
  vsizeBytes: number
  weightUnits: number
  rawHex: string
}

export class BitcoinParser {
  /**
   * Reads a canonical CompactSize integer. Rejects non-canonical encodings.
   */
  public static readCanonicalCompactSize(reader: BoundedCheckedReader): number {
    const first = reader.readU8Sync()
    if (first < 0xfd) {
      return first
    }

    if (first === 0xfd) {
      const val = reader.readU16Sync('le')
      if (val < 0xfd) {
        throw new Error(`Non-canonical CompactSize: value ${val} encoded with 0xFD prefix`)
      }
      return val
    }

    if (first === 0xfe) {
      const val = reader.readU32Sync('le')
      if (val < 0x10000) {
        throw new Error(`Non-canonical CompactSize: value ${val} encoded with 0xFE prefix`)
      }
      return val
    }

    // 0xff: 64-bit int (safely constrained to JS MAX_SAFE_INTEGER for lengths)
    const val64 = reader.readU64Sync('le')
    if (val64 < 0x100000000n) {
      throw new Error(`Non-canonical CompactSize: value ${val64} encoded with 0xFF prefix`)
    }
    if (val64 > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`CompactSize value exceeds safe memory limit: ${val64}`)
    }
    return Number(val64)
  }

  /**
   * Parses a raw Bitcoin transaction buffer.
   */
  public static parseTransaction(bytes: Uint8Array): BitcoinTransaction {
    if (bytes.length < 10) {
      throw new Error(`Bitcoin transaction too short: ${bytes.length} bytes`)
    }

    const reader = new BoundedCheckedReader(bytes)
    const version = reader.readI32Sync('le')

    // Check SegWit marker & flag: 0x00, 0x01
    let isSegWit = false
    const peek0 = bytes[reader.position]
    const peek1 = bytes[reader.position + 1]

    if (peek0 === 0x00 && peek1 === 0x01) {
      isSegWit = true
      reader.skip(2) // skip marker and flag
    }

    // Parse Inputs
    const inCount = this.readCanonicalCompactSize(reader)
    const inputs: BitcoinTxInput[] = []

    for (let i = 0; i < inCount; i++) {
      const prevTxid = reader.readBytesSync(32)
      const vout = reader.readU32Sync('le')
      const scriptLen = this.readCanonicalCompactSize(reader)
      const scriptSig = reader.readBytesSync(scriptLen)
      const sequence = reader.readU32Sync('le')

      const wireHex = formatHex(prevTxid).replace(/\s+/g, '')
      // Display order is byte-reversed
      const reversed = new Uint8Array(prevTxid).reverse()
      const displayHex = formatHex(reversed).replace(/\s+/g, '')

      inputs.push({
        txidWireHex: wireHex,
        txidDisplayHex: displayHex,
        vout,
        scriptSig,
        sequence,
      })
    }

    // Parse Outputs
    const outCount = this.readCanonicalCompactSize(reader)
    const outputs: BitcoinTxOutput[] = []

    for (let i = 0; i < outCount; i++) {
      const valueSatoshis = reader.readU64Sync('le')
      const scriptLen = this.readCanonicalCompactSize(reader)
      const scriptPubKey = reader.readBytesSync(scriptLen)

      outputs.push({
        valueSatoshis,
        scriptPubKey,
      })
    }

    // Parse Witness data if SegWit
    if (isSegWit) {
      for (let i = 0; i < inCount; i++) {
        const itemStack: Uint8Array[] = []
        const numItems = this.readCanonicalCompactSize(reader)
        for (let j = 0; j < numItems; j++) {
          const itemLen = this.readCanonicalCompactSize(reader)
          const itemData = reader.readBytesSync(itemLen)
          itemStack.push(itemData)
        }
        inputs[i]!.witness = itemStack
      }
    }

    const locktime = reader.readU32Sync('le')

    // Double-SHA-256 for TXID:
    // If SegWit, TXID is calculated over the non-witness serialized format
    let txidSerialization = bytes
    if (isSegWit) {
      txidSerialization = this.serializeLegacy(version, inputs, outputs, locktime)
    }

    const hash1 = sha256(txidSerialization)
    const hash2 = sha256(hash1)
    const txidWire = formatHex(hash2).replace(/\s+/g, '')
    const txidDisplay = formatHex(new Uint8Array(hash2).reverse()).replace(/\s+/g, '')

    // Weight & vsize calculation
    const baseSize = isSegWit ? txidSerialization.length : bytes.length
    const totalSize = bytes.length
    const weightUnits = baseSize * 3 + totalSize
    const vsizeBytes = Math.ceil(weightUnits / 4)

    return {
      version,
      isSegWit,
      inputs,
      outputs,
      locktime,
      txidWire,
      txidDisplay,
      vsizeBytes,
      weightUnits,
      rawHex: formatHex(bytes).replace(/\s+/g, ''),
    }
  }

  private static serializeLegacy(
    version: number,
    inputs: BitcoinTxInput[],
    outputs: BitcoinTxOutput[],
    locktime: number,
  ): Uint8Array {
    // Estimate size and build legacy serialization for TXID
    const parts: Uint8Array[] = []

    // Version (4B)
    const vBuf = new Uint8Array(4)
    new DataView(vBuf.buffer).setInt32(0, version, true)
    parts.push(vBuf)

    // Input Count
    parts.push(this.encodeCompactSize(inputs.length))

    // Inputs
    for (const inp of inputs) {
      // 32B prevTxid (wire order)
      const txidBytes = new Uint8Array(32)
      for (let i = 0; i < 32; i++) {
        txidBytes[i] = parseInt(inp.txidWireHex.substring(i * 2, i * 2 + 2), 16)
      }
      parts.push(txidBytes)

      const voutBuf = new Uint8Array(4)
      new DataView(voutBuf.buffer).setUint32(0, inp.vout, true)
      parts.push(voutBuf)

      parts.push(this.encodeCompactSize(inp.scriptSig.length))
      parts.push(inp.scriptSig)

      const seqBuf = new Uint8Array(4)
      new DataView(seqBuf.buffer).setUint32(0, inp.sequence, true)
      parts.push(seqBuf)
    }

    // Output Count
    parts.push(this.encodeCompactSize(outputs.length))

    // Outputs
    for (const out of outputs) {
      const valBuf = new Uint8Array(8)
      new DataView(valBuf.buffer).setBigUint64(0, out.valueSatoshis, true)
      parts.push(valBuf)

      parts.push(this.encodeCompactSize(out.scriptPubKey.length))
      parts.push(out.scriptPubKey)
    }

    // Locktime (4B)
    const ltBuf = new Uint8Array(4)
    new DataView(ltBuf.buffer).setUint32(0, locktime, true)
    parts.push(ltBuf)

    const totalLen = parts.reduce((acc, p) => acc + p.length, 0)
    const res = new Uint8Array(totalLen)
    let off = 0
    for (const p of parts) {
      res.set(p, off)
      off += p.length
    }
    return res
  }

  private static encodeCompactSize(n: number): Uint8Array {
    if (n < 0xfd) {
      return new Uint8Array([n])
    }
    if (n <= 0xffff) {
      const b = new Uint8Array(3)
      b[0] = 0xfd
      new DataView(b.buffer).setUint16(1, n, true)
      return b
    }
    const b = new Uint8Array(5)
    b[0] = 0xfe
    new DataView(b.buffer).setUint32(1, n, true)
    return b
  }
}
