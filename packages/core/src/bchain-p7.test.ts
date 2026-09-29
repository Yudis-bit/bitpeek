import { describe, it, expect } from 'vitest'
import {
  BitcoinParser,
  RlpDecoder,
  EvmTraceParser,
  CryptoLimbEngine,
} from './bchain'
import { BoundedCheckedReader } from './reader'

describe('Phase P7 - Blockchain and Cryptographic Implementation Research', () => {
  describe('Bitcoin Binary Analysis (BCHAIN-01, AC061, AC062)', () => {
    it('enforces canonical CompactSize integers and rejects non-canonical representations', () => {
      // Canonical 1-byte: 42
      const r1 = new BoundedCheckedReader(new Uint8Array([42]))
      expect(BitcoinParser.readCanonicalCompactSize(r1)).toBe(42)

      // Canonical 3-byte: 0xfd, 0x01, 0x02 -> 0x0201 = 513
      const r2 = new BoundedCheckedReader(new Uint8Array([0xfd, 0x01, 0x02]))
      expect(BitcoinParser.readCanonicalCompactSize(r2)).toBe(513)

      // Non-canonical: 0xfd with value 42 (must have been encoded as 1-byte) -> throws!
      const rBad = new BoundedCheckedReader(new Uint8Array([0xfd, 42, 0]))
      expect(() => BitcoinParser.readCanonicalCompactSize(rBad)).toThrow(/Non-canonical CompactSize/)
    })

    it('parses valid Bitcoin transaction with exact Satoshis and wire vs display TXID (AC061, AC062)', () => {
      // Craft minimal Bitcoin transaction:
      // Version: 1 (4B, LE)
      // Input count: 1 (1B)
      // Input 0:
      //   prevTxid: 32 bytes of 0x01
      //   vout: 0 (4B, LE)
      //   scriptLen: 2 (1B)
      //   scriptSig: [0x51, 0x51] (OP_1, OP_1)
      //   sequence: 0xffffffff (4B, LE)
      // Output count: 1 (1B)
      // Output 0:
      //   valueSatoshis: 5,000,000,000 satoshis (50 BTC = 0x000000012a05f200n)
      //   scriptLen: 1 (1B)
      //   scriptPubKey: [0x51] (OP_1)
      // Locktime: 0 (4B, LE)
      const txBuf = new Uint8Array(64)
      const view = new DataView(txBuf.buffer)

      view.setInt32(0, 1, true) // Version 1
      txBuf[4] = 1 // 1 input
      txBuf.subarray(5, 37).fill(0x01) // prevTxid (all 0x01)
      view.setUint32(37, 0, true) // vout = 0
      txBuf[41] = 2 // scriptLen = 2
      txBuf[42] = 0x51
      txBuf[43] = 0x51
      view.setUint32(44, 0xffffffff, true) // sequence

      txBuf[48] = 1 // 1 output
      view.setBigUint64(49, 5000000000n, true) // 50 BTC in satoshis!
      txBuf[57] = 1 // scriptLen = 1
      txBuf[58] = 0x51
      view.setUint32(59, 0, true) // locktime = 0

      const parsed = BitcoinParser.parseTransaction(txBuf.subarray(0, 63))
      expect(parsed.version).toBe(1)
      expect(parsed.isSegWit).toBe(false)
      expect(parsed.inputs.length).toBe(1)
      expect(parsed.outputs.length).toBe(1)

      // Satoshis must be exact BigInt without float precision loss
      expect(parsed.outputs[0]!.valueSatoshis).toBe(5000000000n)

      // TXID must be non-empty 64-character hex strings
      expect(parsed.txidWire.length).toBe(64)
      expect(parsed.txidDisplay.length).toBe(64)
      // Display TXID is byte-reversed relative to wire TXID
      expect(parsed.txidDisplay).not.toBe(parsed.txidWire)
    })
  })

  describe('Ethereum RLP & Typed Envelopes (BCHAIN-02, AC063)', () => {
    it('decodes RLP structures and enforces canonical minimal encodings', () => {
      // 1. Single byte: 0x42 ('B')
      const d1 = RlpDecoder.decode(new Uint8Array([0x42]))
      expect(d1.item.type).toBe('bytes')
      if (d1.item.type === 'bytes') {
        expect(d1.item.hex).toBe('42')
      }

      // 2. Short string: "dog" -> 0x83, 'd', 'o', 'g'
      const d2 = RlpDecoder.decode(new Uint8Array([0x83, 0x64, 0x6f, 0x67]))
      expect(d2.item.type).toBe('bytes')
      if (d2.item.type === 'bytes') {
        expect(new TextDecoder().decode(d2.item.data)).toBe('dog')
      }

      // 3. Short list: ["cat", "dog"] -> 0xc8, 0x83, 'c','a','t', 0x83, 'd','o','g'
      const dList = RlpDecoder.decode(new Uint8Array([0xc8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67]))
      expect(dList.item.type).toBe('list')
      if (dList.item.type === 'list') {
        expect(dList.item.items.length).toBe(2)
      }

      // 4. Non-canonical check: 0x81 0x05 (single byte < 0x80 encoded with 0x81 prefix) -> throws!
      expect(() => RlpDecoder.decode(new Uint8Array([0x81, 0x05]))).toThrow(/Non-canonical RLP/)
    })

    it('parses legacy and EIP-1559 typed transaction envelopes', () => {
      // Craft minimal Legacy Tx: RLP list with 9 items [nonce=0, gasPrice=1, gasLimit=21000, to="", value=1000, data="", v=27, r=0, s=0]
      // RLP bytes:
      // nonce: 0x80 (empty bytes = 0)
      // gasPrice: 0x01 (1)
      // gasLimit: 0x82, 0x52, 0x08 (21000 = 0x5208)
      // to: 0x80 (empty)
      // value: 0x82, 0x03, 0xe8 (1000 = 0x03e8)
      // data: 0x80 (empty)
      // v: 0x1b (27)
      // r: 0x80
      // s: 0x80
      const payload = new Uint8Array([0x80, 0x01, 0x82, 0x52, 0x08, 0x80, 0x82, 0x03, 0xe8, 0x80, 0x1b, 0x80, 0x80])
      const legacyTx = new Uint8Array(1 + payload.length)
      legacyTx[0] = 0xc0 + payload.length
      legacyTx.set(payload, 1)

      const parsedLegacy = RlpDecoder.parseTransaction(legacyTx)
      expect(parsedLegacy.envelopeType).toBe('legacy')
      expect(parsedLegacy.gasPrice).toBe(1n)
      expect(parsedLegacy.gasLimit).toBe(21000n)
      expect(parsedLegacy.value).toBe(1000n)
      expect(parsedLegacy.v).toBe(27n)

      // Type 2 EIP-1559 Tx: 0x02 || rlp([chainId=1, nonce=0, maxPriority=2, maxFee=5, gasLimit=21000, to="", value=100, data=""])
      const eipPayload = new Uint8Array([0x01, 0x80, 0x02, 0x05, 0x82, 0x52, 0x08, 0x80, 0x64, 0x80])
      const eipTx = new Uint8Array(2 + eipPayload.length)
      eipTx[0] = 0x02 // Type 2 envelope prefix
      eipTx[1] = 0xc0 + eipPayload.length
      eipTx.set(eipPayload, 2)

      const parsedEip = RlpDecoder.parseTransaction(eipTx)
      expect(parsedEip.envelopeType).toBe('eip1559')
      expect(parsedEip.typeByte).toBe(2)
      expect(parsedEip.chainId).toBe(1n)
      expect(parsedEip.maxPriorityFeePerGas).toBe(2n)
      expect(parsedEip.maxFeePerGas).toBe(5n)
    })
  })

  describe('EVM Trace Adapter (BCHAIN-03, AC064)', () => {
    it('normalizes EVM execution traces and parses 256-bit stack words as BigInt', () => {
      const rawSteps = [
        {
          pc: 0,
          op: 'PUSH1',
          gas: '1000000',
          cost: 3,
          stack: [],
        },
        {
          pc: 2,
          op: 'PUSH32',
          gas: '999997',
          cost: 3,
          stack: ['0x2a'],
        },
        {
          pc: 35,
          op: 'ADD',
          gas: '999994',
          cost: 3,
          stack: [
            '0x2a',
            '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          ],
        },
      ]

      const trace = EvmTraceParser.parseTrace(rawSteps)
      expect(trace.length).toBe(3)
      expect(trace[0]!.op).toBe('PUSH1')
      expect(trace[0]!.gas).toBe(1000000n)
      expect(trace[2]!.stack.length).toBe(2)
      expect(trace[2]!.stack[0]).toBe(42n)
      expect(trace[2]!.stack[1]).toBe(
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
      )
    })
  })

  describe('Cryptographic Multi-Precision Limb Views (BCHAIN-04, AC066)', () => {
    it('decomposes 256-bit BigInt into 64-bit limbs and performs addition with carry', () => {
      const val = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20n
      const limbsLe = CryptoLimbEngine.toLimbs64(val, 'little')
      expect(limbsLe.length).toBe(4)

      // Reconstruct
      const reconstituted = CryptoLimbEngine.fromLimbs64(limbsLe, 'little')
      expect(reconstituted).toBe(val)

      // Multi-limb addition test with carry
      const maxLimb = 0xffffffffffffffffn
      const a = [maxLimb, 0n, 0n, 0n] // 2^64 - 1
      const b = [1n, 0n, 0n, 0n] // 1

      const addRes = CryptoLimbEngine.addLimbs64(a, b)
      expect(addRes.result[0]).toBe(0n)
      expect(addRes.result[1]).toBe(1n) // carry propagated to limb 1!
      expect(addRes.carryOut).toBe(0)

      // Constant time equality
      expect(CryptoLimbEngine.constantTimeEqual(limbsLe, limbsLe)).toBe(true)
      expect(CryptoLimbEngine.constantTimeEqual(limbsLe, a)).toBe(false)
    })
  })
})
