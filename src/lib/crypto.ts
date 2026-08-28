export type DigestAlgorithm = 'SHA-256' | 'SHA-512'

export async function digestHex(
  bytes: Uint8Array,
  algorithm: DigestAlgorithm,
): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is unavailable in this browser.')
  }
  const input = bytes.slice().buffer
  const digest = await globalThis.crypto.subtle.digest(algorithm, input)
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
}
