import { describe, expect, it } from 'vitest'
import {
  ETHEREUM_ADDRESS,
  ETHEREUM_CHAIN_ID,
  ETHEREUM_PAYMENT_URI,
  ETHERSCAN_ADDRESS_URL,
  isEthereumAddress,
} from './support'

describe('support destination integrity', () => {
  it('keeps the supplied Ethereum address exact in every destination', () => {
    expect(ETHEREUM_ADDRESS).toBe(
      '0xb9030ab08Fb47b310aBe3D4Be7680807C10deba5',
    )
    expect(ETHEREUM_CHAIN_ID).toBe(1)
    expect(ETHEREUM_PAYMENT_URI).toBe(
      'ethereum:0xb9030ab08Fb47b310aBe3D4Be7680807C10deba5@1',
    )
    expect(ETHERSCAN_ADDRESS_URL.endsWith(ETHEREUM_ADDRESS)).toBe(true)
    expect(isEthereumAddress(ETHEREUM_ADDRESS)).toBe(true)
  })

  it('rejects malformed addresses', () => {
    expect(isEthereumAddress('0x1234')).toBe(false)
    expect(isEthereumAddress(ETHEREUM_ADDRESS + '00')).toBe(false)
  })
})
