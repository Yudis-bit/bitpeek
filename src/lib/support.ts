export const ETHEREUM_ADDRESS = '0xb9030ab08Fb47b310aBe3D4Be7680807C10deba5'
export const ETHEREUM_CHAIN_ID = 1
export const ETHEREUM_NETWORK = 'Ethereum Mainnet'
export const ETHEREUM_PAYMENT_URI =
  'ethereum:' + ETHEREUM_ADDRESS + '@' + ETHEREUM_CHAIN_ID
export const ETHERSCAN_ADDRESS_URL =
  'https://etherscan.io/address/' + ETHEREUM_ADDRESS

export function isEthereumAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value)
}
