import { type StructureParseResult, type StructureField, toStructureField } from './types'
import { RlpDecoder } from '../bchain/ethereum'

export function parseEthereumTx(bytes: Uint8Array): StructureParseResult | null {
  if (bytes.length < 5) return null

  // Fast check: Must either start with 0x01/0x02 envelope or RLP list prefix (0xc0 - 0xff)
  const first = bytes[0]!
  const isTypedEnvelope = first === 0x01 || first === 0x02
  const isRlpList = first >= 0xc0 && first <= 0xff

  if (!isTypedEnvelope && !isRlpList) {
    return null
  }

  try {
    const tx = RlpDecoder.parseTransaction(bytes)
    const fields: StructureField[] = []

    fields.push(
      toStructureField({
        name: 'envelope_type',
        offset: 0,
        length: isTypedEnvelope ? 1 : 0,
        value: tx.envelopeType,
        interpretation: `Ethereum Envelope: ${tx.envelopeType.toUpperCase()}${tx.typeByte !== undefined ? ` (Type 0x0${tx.typeByte})` : ''}`,
        valid: true,
      }),
    )

    if (tx.chainId !== undefined) {
      fields.push(
        toStructureField({
          name: 'chain_id',
          offset: 1,
          length: 4,
          value: tx.chainId.toString(),
          interpretation: `Chain ID: ${tx.chainId}`,
          valid: true,
        }),
      )
    }

    fields.push(
      toStructureField({
        name: 'nonce',
        offset: 0,
        length: 4,
        value: tx.nonce.toString(),
        interpretation: `Nonce: ${tx.nonce}`,
        valid: true,
      }),
    )

    if (tx.gasPrice !== undefined) {
      const gwei = Number(tx.gasPrice) / 1e9
      fields.push(
        toStructureField({
          name: 'gas_price',
          offset: 0,
          length: 4,
          value: `${gwei} Gwei`,
          interpretation: `Gas Price: ${tx.gasPrice} wei (${gwei} Gwei)`,
          valid: true,
        }),
      )
    }

    if (tx.maxFeePerGas !== undefined) {
      const gwei = Number(tx.maxFeePerGas) / 1e9
      fields.push(
        toStructureField({
          name: 'max_fee_per_gas',
          offset: 0,
          length: 4,
          value: `${gwei} Gwei`,
          interpretation: `Max Fee: ${tx.maxFeePerGas} wei (${gwei} Gwei)`,
          valid: true,
        }),
      )
    }

    fields.push(
      toStructureField({
        name: 'gas_limit',
        offset: 0,
        length: 4,
        value: tx.gasLimit.toString(),
        interpretation: `Gas Limit: ${tx.gasLimit.toLocaleString()}`,
        valid: true,
      }),
    )

    fields.push(
      toStructureField({
        name: 'to',
        offset: 0,
        length: 20,
        value: tx.to ?? '(Contract Creation)',
        interpretation: `Recipient: ${tx.to ?? 'Contract Creation'}`,
        valid: true,
      }),
    )

    const eth = Number(tx.value) / 1e18
    fields.push(
      toStructureField({
        name: 'value',
        offset: 0,
        length: 8,
        value: `${eth} ETH`,
        interpretation: `Value: ${eth.toFixed(6)} ETH (${tx.value} wei)`,
        valid: true,
      }),
    )

    fields.push(
      toStructureField({
        name: 'calldata',
        offset: 0,
        length: tx.data.length,
        value: `${tx.data.length} bytes`,
        interpretation: `Calldata: ${tx.data.length} bytes${tx.data.length >= 4 ? ` (Selector: 0x${Array.from(tx.data.subarray(0, 4)).map((b) => b.toString(16).padStart(2, '0')).join('')})` : ''}`,
        valid: true,
      }),
    )

    return {
      format: 'ethereum',
      status: 'valid',
      fields,
      warnings: [],
      totalBytesParsed: bytes.length,
    }
  } catch {
    return null
  }
}
