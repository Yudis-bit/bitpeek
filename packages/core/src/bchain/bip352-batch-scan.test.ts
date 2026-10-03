import { createECDH } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { Secp256k1Engine as Engine, SECP256K1_N as N, SECP256K1_P as P } from './secp256k1'
import type { SilentPaymentLabelDefinition, SilentPaymentScanMatch, SilentPaymentScanParams, SilentPaymentScanResult } from '../index'

const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'))
const be = (value: bigint) => hex(value.toString(16).padStart(64, '0'))
function nativeKey(scalar: bigint): Uint8Array {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(be(scalar))
  return Uint8Array.from(ecdh.getPublicKey(undefined, 'compressed'))
}

// Independent OpenSSL fixtures: B_spend=3G, t_k=1, hence P_unlabeled=4G.
// The even output is 15G with odd-Y label point 11G; the odd output is 6G
// with even-Y label point 2G, so output parity cannot be inferred from label parity.
const labels: SilentPaymentLabelDefinition[] = [
  { labelIndex: 0, labelTweak32: be(11n), labelPubKey33: nativeKey(11n) },
  { labelIndex: 7, labelTweak32: be(2n), labelPubKey33: nativeKey(2n) },
]
const evenOutput = nativeKey(15n).slice(1)
const oddOutput = nativeKey(6n).slice(1)
const unlabeledOutput = nativeKey(4n).slice(1)
const filler = nativeKey(1000n).slice(1)
const base: SilentPaymentScanParams = { txOutputs: [], spendPubKey: nativeKey(3n), scanPrivKey32: be(42n), sharedSecretTweak: 1n, labels }
const outputs = (count: number) => Array.from({ length: count }, () => filler.slice())

interface LabelVector {
  comment: string
  scanPrivKey: string
  index: number
  tweak: string
  spendPubKey: string
}
interface OutputVector { comment: string; tweak: string; outputKey: string; parity: number }
const published = JSON.parse(readFileSync(new URL('./fixtures/bip352-reference.json', import.meta.url), 'utf8')) as {
  labels: LabelVector[]; outputs: OutputVector[]
}

describe('BIP-352 candidate slot to transaction-output mapping', () => {
  it.each([
    [0, 0, 0, 0], [0, 3, 1, 1], [50, 0, 50, 25], [50, 1, 50, 25],
    [50, 74, 87, 62], [50, 75, 87, 62], [100, 5, 102, 52],
  ])('maps batch start %s slot %s to output %s and detects mutant %s', (start, slot, correct, mutant) => {
    expect(Engine.verifySilentPaymentBatchMapping(start!, slot!)).toEqual({ correctIndex: correct, mutantIndex: mutant, isEquiv: correct === mutant })
  })

  it.each([-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects malformed batch offsets or slots (%s)', value => {
    expect(() => Engine.verifySilentPaymentBatchMapping(value, 0)).toThrow(RangeError)
    expect(() => Engine.verifySilentPaymentBatchMapping(0, value)).toThrow(RangeError)
  })

  it('rejects a sum that would lose integer precision', () => {
    expect(() => Engine.verifySilentPaymentBatchMapping(Number.MAX_SAFE_INTEGER, 1)).toThrow(RangeError)
  })
})

describe('BIP-352 reference recipient output scanner', () => {
  it.each(published.labels.filter(label => label.comment.startsWith('Receiving with labels:')))(
    'matches the published output for $comment across batches', label => {
      const output = published.outputs.find(vector => vector.comment === label.comment)!
      // The existing fixture records the combined t_k + label scalar; recover t_k.
      const t = (BigInt(`0x${output.tweak}`) - BigInt(`0x${label.tweak}`) + N) % N
      const txOutputs = outputs(120)
      txOutputs[87] = hex(output.outputKey)
      const result = Engine.scanSilentPaymentOutputs({ txOutputs, spendPubKey: hex(label.spendPubKey),
        scanPrivKey32: hex(label.scanPrivKey), sharedSecretTweak: be(t),
        labels: [{ labelIndex: label.index, labelTweak32: hex(label.tweak) }] })
      expect(result).toMatchObject({ valid: true, totalOutputsScanned: 120, batchCount: 3 })
      expect(result.matches).toEqual([{ outputIndex: 87, outputKey32: hex(output.outputKey), isLabeled: true,
        labelIndex: label.index, labelTweak32: hex(label.tweak), candidateSlotParity: output.parity, batchIndex: 1, batchOffset: 50 }])
    },
  )

  it.each([1, 2, 7, 50, 100])('preserves output indices and candidate parity with batch size %s', batchSize => {
    const txOutputs = outputs(125)
    const expectedPositions = [0, 49, 50, 51, 99, 100, 124]
    const expectedKeys = [unlabeledOutput, evenOutput, oddOutput, evenOutput, oddOutput, unlabeledOutput, evenOutput]
    expectedPositions.forEach((position, index) => { txOutputs[position] = expectedKeys[index]!.slice() })
    const result: SilentPaymentScanResult = Engine.scanSilentPaymentOutputs({ ...base, txOutputs, batchSize })
    expect(result.valid).toBe(true)
    expect(result.totalOutputsScanned).toBe(125)
    expect(result.batchCount).toBe(Math.ceil(125 / batchSize))
    expect(result.matches.map(match => match.outputIndex)).toEqual(expectedPositions)
    const expected: SilentPaymentScanMatch[] = expectedPositions.map((position, index) => ({
      outputIndex: position, outputKey32: expectedKeys[index]!, isLabeled: ![0, 5].includes(index),
      ...([0, 5].includes(index) ? {} : { labelIndex: [2, 4].includes(index) ? 7 : 0,
        labelTweak32: [2, 4].includes(index) ? be(2n) : be(11n) }),
      candidateSlotParity: [2, 4].includes(index) ? 1 : 0,
      batchIndex: Math.floor(position / batchSize), batchOffset: Math.floor(position / batchSize) * batchSize,
    }))
    expect(result.matches).toEqual(expected)
  })

  it.each([[evenOutput, 0], [oddOutput, 1]] as const)('checks the absolute index for a single match in a higher batch (parity %s)', (output, parity) => {
    const txOutputs = outputs(101)
    txOutputs[87] = output.slice()
    const result = Engine.scanSilentPaymentOutputs({ ...base, txOutputs })
    expect(result.matches).toHaveLength(1)
    expect(result.matches[0]).toMatchObject({ outputIndex: 87, outputKey32: txOutputs[87],
      candidateSlotParity: parity, batchIndex: 1, batchOffset: 50 })
    const mapping = Engine.verifySilentPaymentBatchMapping(50, 2 * 37 + parity)
    expect(mapping.isEquiv).toBe(false)
    expect(result.matches[0]!.outputIndex).not.toBe(mapping.mutantIndex)
    expect(txOutputs[result.matches[0]!.outputIndex]).toEqual(output)
  })

  it('uses output-lift parity independently of the label-point parity', () => {
    expect(nativeKey(15n)[0]).toBe(2)
    expect(labels[0]!.labelPubKey33![0]).toBe(3)
    expect(nativeKey(6n)[0]).toBe(3)
    expect(labels[1]!.labelPubKey33![0]).toBe(2)
    const result = Engine.scanSilentPaymentOutputs({ ...base, txOutputs: [evenOutput, oddOutput] })
    expect(result.matches.map(match => [match.labelIndex, match.candidateSlotParity])).toEqual([[0, 0], [7, 1]])
  })

  it('produces identical matches with scalar-derived and precomputed label points', () => {
    const params = { ...base, txOutputs: [oddOutput, evenOutput] }
    const uncached = labels.map(({ labelIndex, labelTweak32 }) => ({ labelIndex, labelTweak32 }))
    expect(Engine.scanSilentPaymentOutputs({ ...params, labels: uncached })).toEqual(Engine.scanSilentPaymentOutputs(params))
  })

  it('retains label-point Y parity in the lookup key', () => {
    const negativeLabel = labels[0]!.labelPubKey33!.slice()
    negativeLabel[0] = 2
    const result = Engine.scanSilentPaymentOutputs({ ...base, txOutputs: [evenOutput],
      labels: [{ ...labels[0]!, labelPubKey33: negativeLabel }] })
    expect(result.matches).toEqual([])
  })

  it('preserves compressed odd-Y spend keys and accepts x-only even-Y keys', () => {
    const oddSpend = nativeKey(6n)
    expect(Engine.scanSilentPaymentOutputs({ ...base, labels: [], spendPubKey: oddSpend, txOutputs: [nativeKey(7n).slice(1)] }).matches)
      .toMatchObject([{ outputIndex: 0, isLabeled: false, candidateSlotParity: 0 }])
    expect(Engine.scanSilentPaymentOutputs({ ...base, labels: [], spendPubKey: oddSpend.slice(1), txOutputs: [nativeKey(7n).slice(1)] }).matches).toEqual([])
    expect(Engine.scanSilentPaymentOutputs({ ...base, spendPubKey: base.spendPubKey.slice(1), txOutputs: [unlabeledOutput] }).matches)
      .toMatchObject([{ outputIndex: 0, isLabeled: false }])
  })

  it('reports odd unlabeled output parity and retains repeated transaction positions', () => {
    const result = Engine.scanSilentPaymentOutputs({ ...base, sharedSecretTweak: 3n, labels: [], txOutputs: [oddOutput, oddOutput] })
    expect(result.matches.map(match => [match.outputIndex, match.candidateSlotParity, match.isLabeled])).toEqual([[0, 1, false], [1, 1, false]])
  })

  it('skips malformed and non-curve output keys without compacting transaction indices', () => {
    const txOutputs = [new Uint8Array(31), oddOutput, be(P), be(0n), new Uint8Array(33), evenOutput]
    const result = Engine.scanSilentPaymentOutputs({ ...base, txOutputs, batchSize: 2 })
    expect(result).toMatchObject({ valid: true, totalOutputsScanned: 6, batchCount: 3 })
    expect(result.matches.map(match => match.outputIndex)).toEqual([1, 5])
  })

  it('handles empty inputs and an absent label cache', () => {
    expect(Engine.scanSilentPaymentOutputs(base)).toMatchObject({ valid: true, matches: [], totalOutputsScanned: 0, batchCount: 1 })
    expect(Engine.scanSilentPaymentOutputs({ ...base, labels: undefined, txOutputs: [evenOutput, unlabeledOutput] }).matches)
      .toMatchObject([{ outputIndex: 1, isLabeled: false }])
  })

  it.each([0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects invalid batch size %s', batchSize => {
    expect(Engine.scanSilentPaymentOutputs({ ...base, batchSize })).toEqual({ valid: false,
      matches: [], totalOutputsScanned: 0, batchCount: 0, reason: 'batchSize must be a positive safe integer' })
  })

  it.each([new Uint8Array(31), be(0n), be(N), be(N + 1n)])('rejects an invalid scan key %s', scanPrivKey32 => {
    expect(Engine.scanSilentPaymentOutputs({ ...base, scanPrivKey32 })).toMatchObject({ valid: false, matches: [], totalOutputsScanned: 0, batchCount: 0 })
  })

  it.each([-1n, 0n, N, N + 1n, new Uint8Array(31)])('rejects noncanonical tweaks %s', sharedSecretTweak => {
    expect(Engine.scanSilentPaymentOutputs({ ...base, sharedSecretTweak }).valid).toBe(false)
  })

  it('rejects an invalid spend key and a tweak cancelling the spend key', () => {
    expect(Engine.scanSilentPaymentOutputs({ ...base, spendPubKey: be(0n) }).reason).toBe('Invalid spend public key')
    expect(Engine.scanSilentPaymentOutputs({ ...base, spendPubKey: nativeKey(1n), sharedSecretTweak: N - 1n }).reason).toBe('Unlabeled point is infinity')
  })

  it.each([
    { labelIndex: -1 }, { labelIndex: 0x100000000 }, { labelIndex: 0.5 },
    { labelTweak32: new Uint8Array(31) }, { labelTweak32: be(0n) }, { labelTweak32: be(N) },
    { labelPubKey33: new Uint8Array(32) }, { labelPubKey33: new Uint8Array(33) },
  ])('reports invalid label definitions %j', invalid => {
    expect(Engine.scanSilentPaymentOutputs({ ...base, labels: [{ ...labels[0]!, ...invalid }] }).valid).toBe(false)
  })

  it('does not modify the caller output, key or label buffers', () => {
    const params = { ...base, txOutputs: [evenOutput.slice(), oddOutput.slice()] }
    const copies = [...params.txOutputs, params.spendPubKey, params.scanPrivKey32, ...labels.flatMap(label => [label.labelTweak32, label.labelPubKey33!])].map(bytes => bytes.slice())
    Engine.scanSilentPaymentOutputs(params)
    expect([...params.txOutputs, params.spendPubKey, params.scanPrivKey32, ...labels.flatMap(label => [label.labelTweak32, label.labelPubKey33!])]).toEqual(copies)
  })
})
