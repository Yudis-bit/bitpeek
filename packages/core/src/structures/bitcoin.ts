import { type StructureParseResult, type StructureField, toStructureField } from './types'
import { BitcoinParser } from '../bchain/bitcoin'

export function parseBitcoinTx(bytes: Uint8Array): StructureParseResult | null {
  if (bytes.length < 10) return null

  // Fast check: Bitcoin transactions typically use version 1 or 2
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const version = view.getInt32(0, true)
  if (version !== 1 && version !== 2) {
    return null
  }

  try {
    const tx = BitcoinParser.parseTransaction(bytes)
    const fields: StructureField[] = []
    let cursor = 0

    // Version
    fields.push(
      toStructureField({
        name: 'version',
        offset: 0,
        length: 4,
        value: tx.version,
        interpretation: `Bitcoin Tx Version ${tx.version}`,
        endian: 'little',
        valid: true,
      }),
    )
    cursor = 4

    // SegWit marker & flag
    if (tx.isSegWit) {
      fields.push(
        toStructureField({
          name: 'segwit_marker_flag',
          offset: cursor,
          length: 2,
          value: '0x0001',
          interpretation: 'BIP141 SegWit Marker & Flag',
          valid: true,
        }),
      )
      cursor += 2
    }

    // Input summary
    const inputFields: StructureField[] = []
    for (let i = 0; i < tx.inputs.length; i++) {
      const inp = tx.inputs[i]!
      inputFields.push(
        toStructureField({
          name: `input_${i}`,
          offset: cursor,
          length: 32 + 4 + inp.scriptSig.length + 4,
          value: `vout ${inp.vout}`,
          interpretation: `Prev Tx: ${inp.txidDisplayHex.slice(0, 16)}...:${inp.vout} (seq: 0x${inp.sequence.toString(16)})`,
          valid: true,
        }),
      )
    }

    fields.push(
      toStructureField({
        name: 'inputs',
        offset: cursor,
        length: Math.max(1, tx.inputs.length),
        value: `${tx.inputs.length} inputs`,
        interpretation: `Transaction Inputs (${tx.inputs.length})`,
        valid: true,
        children: inputFields,
      }),
    )

    // Output summary
    const outputFields: StructureField[] = []
    let totalSatoshis = 0n
    for (let i = 0; i < tx.outputs.length; i++) {
      const out = tx.outputs[i]!
      totalSatoshis += out.valueSatoshis
      const btc = Number(out.valueSatoshis) / 100_000_000
      outputFields.push(
        toStructureField({
          name: `output_${i}`,
          offset: cursor,
          length: 8 + out.scriptPubKey.length,
          value: `${out.valueSatoshis} satoshis`,
          interpretation: `${btc.toFixed(8)} BTC (${out.valueSatoshis.toLocaleString()} satoshis)`,
          valid: true,
        }),
      )
    }

    fields.push(
      toStructureField({
        name: 'outputs',
        offset: cursor,
        length: Math.max(1, tx.outputs.length),
        value: `${tx.outputs.length} outputs`,
        interpretation: `Outputs (${tx.outputs.length}, Total: ${(Number(totalSatoshis) / 1e8).toFixed(8)} BTC)`,
        valid: true,
        children: outputFields,
      }),
    )

    // Locktime
    fields.push(
      toStructureField({
        name: 'locktime',
        offset: Math.max(0, bytes.length - 4),
        length: 4,
        value: tx.locktime,
        interpretation: `Locktime: ${tx.locktime}`,
        endian: 'little',
        valid: true,
      }),
    )

    // TXID
    fields.push(
      toStructureField({
        name: 'txid_display',
        offset: 0,
        length: bytes.length,
        value: tx.txidDisplay,
        interpretation: `Display TXID: ${tx.txidDisplay}`,
        valid: true,
      }),
    )

    return {
      format: 'bitcoin',
      status: 'valid',
      fields,
      warnings: [],
      totalBytesParsed: bytes.length,
    }
  } catch {
    return null
  }
}
