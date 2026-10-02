import { unsignedBigEndian } from '../bytes'

export const SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
export const SECP256K1_HALF_N = SECP256K1_N / 2n
export const SECP256K1_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
export const SECP256K1_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n

export type Secp256k1PubKeyFormat = 'compressed' | 'uncompressed' | 'x-only-bip340' | 'invalid'

export interface Secp256k1PubKeyInspection {
  format: Secp256k1PubKeyFormat
  isValid: boolean
  x: bigint
  y?: bigint
  rawHex: string
  rejectionReason?: string
}

export interface Secp256k1SignatureInspection {
  isDer: boolean
  isCompact64: boolean
  r: bigint
  s: bigint
  isLowS: boolean
  isCanonicalR: boolean
  isCanonicalS: boolean
  isStrictlyValid: boolean
  rejectionReason?: string
}

function signatureResult(
  r: bigint,
  s: bigint,
  isDer: boolean,
  isCompact64: boolean,
  encodingError?: string,
): Secp256k1SignatureInspection {
  const isCanonicalR = r > 0n && r < SECP256K1_N
  const isCanonicalS = s > 0n && s < SECP256K1_N
  const isLowS = s <= SECP256K1_HALF_N
  const rejectionReason = encodingError
    ?? (!isCanonicalR ? 'R must satisfy 0 < r < n' : undefined)
    ?? (!isCanonicalS ? 'S must satisfy 0 < s < n' : undefined)
    ?? (!isLowS ? 'High-S signature is malleable; low-S policy requires s <= n/2' : undefined)
  return {
    isDer, isCompact64, r, s, isLowS, isCanonicalR, isCanonicalS,
    isStrictlyValid: !rejectionReason && (isDer || isCompact64),
    ...(rejectionReason ? { rejectionReason } : {}),
  }
}

/** Public-data encoding and curve checks; these methods do not verify a signed message. */
export class Secp256k1Engine {
  public static validateScalar(scalar: bigint): { valid: boolean; reason?: string } {
    if (scalar <= 0n) return { valid: false, reason: 'Scalar must be positive' }
    if (scalar >= SECP256K1_N) return { valid: false, reason: 'Scalar overflow (k >= n)' }
    return { valid: true }
  }

  public static validateFieldElement(elem: bigint): { valid: boolean; reason?: string } {
    if (elem < 0n) return { valid: false, reason: 'Field element must be non-negative' }
    if (elem >= SECP256K1_P) return { valid: false, reason: 'Field element overflow (element >= p)' }
    return { valid: true }
  }

  /** Fixed 256-round exponentiation. JavaScript BigInt arithmetic has no constant-time guarantee. */
  public static sqrtModP(a: bigint): bigint | null {
    const base = ((a % SECP256K1_P) + SECP256K1_P) % SECP256K1_P
    const exponent = (SECP256K1_P + 1n) / 4n
    let root = 1n
    for (let bit = 255n; bit >= 0n; bit--) {
      root = root * root % SECP256K1_P
      // The branch depends only on the fixed, public exponent.
      if (((exponent >> bit) & 1n) !== 0n) root = root * base % SECP256K1_P
    }
    return root * root % SECP256K1_P === base ? root : null
  }

  public static inspectPubKey(bytes: Uint8Array): Secp256k1PubKeyInspection {
    const rawHex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
    let format: Secp256k1PubKeyFormat = 'invalid'
    if (bytes.length === 32) format = 'x-only-bip340'
    else if (bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3)) format = 'compressed'
    else if (bytes.length === 65 && bytes[0] === 4) format = 'uncompressed'
    if (format === 'invalid') {
      return { format, isValid: false, x: 0n, rawHex, rejectionReason: 'Invalid public key length or prefix' }
    }

    const x = unsignedBigEndian(bytes.subarray(format === 'x-only-bip340' ? 0 : 1, format === 'x-only-bip340' ? 32 : 33))
    const result: Secp256k1PubKeyInspection = { format, isValid: false, x, rawHex }
    if (format === 'uncompressed') result.y = unsignedBigEndian(bytes.subarray(33))
    if (x >= SECP256K1_P) return { ...result, rejectionReason: 'Field element overflow (x >= p)' }
    if (result.y !== undefined && result.y >= SECP256K1_P) {
      return { ...result, rejectionReason: 'Field element overflow (y >= p)' }
    }
    const rhs = (x * x % SECP256K1_P * x + 7n) % SECP256K1_P
    if (format === 'uncompressed') {
      if (result.y! * result.y! % SECP256K1_P !== rhs) {
        return { ...result, rejectionReason: 'Point not on secp256k1 curve' }
      }
    } else {
      const root = this.sqrtModP(rhs)
      if (root === null) return { ...result, rejectionReason: 'Point not on secp256k1 curve' }
      const parity = format === 'compressed' ? BigInt(bytes[0]! & 1) : 0n
      result.y = (root & 1n) === parity ? root : (SECP256K1_P - root) % SECP256K1_P
      if ((result.y & 1n) !== parity) return { ...result, rejectionReason: 'Invalid compressed Y parity' }
    }
    return { ...result, isValid: true }
  }

  /** Strict DER without Bitcoin's trailing sighash byte: 8..72 bytes. */
  public static inspectSignatureDER(bytes: Uint8Array): Secp256k1SignatureInspection {
    const fail = (reason: string) => signatureResult(0n, 0n, false, false, reason)
    if (bytes.length < 8 || bytes.length > 72) return fail('DER signature must contain 8..72 bytes')
    if (bytes[0] !== 0x30) return fail('Invalid DER sequence tag')
    if (bytes[1] !== bytes.length - 2) return fail('Invalid DER sequence length')
    if (bytes[2] !== 0x02) return fail('Invalid DER R integer tag')
    const rLength = bytes[3]!
    const sTag = 4 + rLength
    if (rLength === 0 || sTag + 2 >= bytes.length) return fail('Invalid or truncated DER R length')
    if (bytes[sTag] !== 0x02) return fail('Invalid DER S integer tag')
    const sLength = bytes[sTag + 1]!
    if (sLength === 0 || sTag + 2 + sLength !== bytes.length) return fail('Invalid or truncated DER S length')
    for (const [name, start, length] of [['R', 4, rLength], ['S', sTag + 2, sLength]] as const) {
      if ((bytes[start]! & 0x80) !== 0) return fail(`Negative DER ${name} integer`)
      if (length > 1 && bytes[start] === 0 && (bytes[start + 1]! & 0x80) === 0) {
        return fail(`Excessive DER ${name} leading padding`)
      }
    }
    return signatureResult(
      unsignedBigEndian(bytes.subarray(4, sTag)),
      unsignedBigEndian(bytes.subarray(sTag + 2)),
      true, false,
    )
  }

  /** Compact ECDSA r || s, not BIP-340 Schnorr or recoverable signatures. */
  public static inspectCompactSignature(bytes: Uint8Array): Secp256k1SignatureInspection {
    if (bytes.length !== 64) return signatureResult(0n, 0n, false, false, 'Compact ECDSA signature must contain exactly 64 bytes')
    return signatureResult(unsignedBigEndian(bytes.subarray(0, 32)), unsignedBigEndian(bytes.subarray(32)), false, true)
  }
}
