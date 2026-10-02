import { createECDH } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  Secp256k1Engine as Engine, SECP256K1_P as P, SECP256K1_N as N,
  SECP256K1_HALF_N as HALF_N, SECP256K1_GX as GX, SECP256K1_GY as GY,
} from './secp256k1'

function be(value: bigint): Uint8Array {
  return Uint8Array.from(Buffer.from(value.toString(16).padStart(64, '0'), 'hex'))
}

function der(r: bigint, s: bigint): Uint8Array {
  const integer = (value: bigint) => {
    let hex = value.toString(16)
    if (hex.length % 2) hex = `0${hex}`
    if (parseInt(hex.slice(0, 2), 16) >= 128) hex = `00${hex}`
    const bytes = Buffer.from(hex, 'hex')
    return [2, bytes.length, ...bytes]
  }
  const body = [...integer(r), ...integer(s)]
  return Uint8Array.from([0x30, body.length, ...body])
}

describe('secp256k1 domain boundaries', () => {
  it('matches the published curve domain and generator equation', () => {
    expect(P).toBe(2n ** 256n - 2n ** 32n - 977n)
    expect(HALF_N).toBe(N / 2n)
    expect(GY * GY % P).toBe((GX ** 3n + 7n) % P)
  })
  it.each([[-1n, false], [0n, false], [1n, true], [N - 1n, true], [N, false], [N + 1n, false]] as const)(
    'scalar %s validity is %s', (value, valid) => {
      const result = Engine.validateScalar(value)
      expect(result.valid).toBe(valid)
      expect(Boolean(result.reason)).toBe(!valid)
    },
  )
  it.each([[-1n, false], [0n, true], [1n, true], [P - 1n, true], [P, false], [P + 1n, false]] as const)(
    'field element %s validity is %s', (value, valid) => {
      const result = Engine.validateFieldElement(value)
      expect(result.valid).toBe(valid)
      expect(Boolean(result.reason)).toBe(!valid)
    },
  )
  it.each([0n, 1n, 4n, GY * GY, P + 4n, -P + 4n])('returns a modular square root for %s', value => {
    const root = Engine.sqrtModP(value)
    expect(root).not.toBeNull()
    expect(root! * root! % P).toBe(((value % P) + P) % P)
    expect(root! >= 0n && root! < P).toBe(true)
  })
  it('rejects a non-residue including negative modular input', () => {
    expect(Engine.sqrtModP(P - 1n)).toBeNull()
    expect(Engine.sqrtModP(-1n)).toBeNull()
  })
})

describe('secp256k1 public key inspection', () => {
  it.each([2, 3])('lifts the generator with compressed prefix %s', prefix => {
    const bytes = Uint8Array.from([prefix, ...be(GX)])
    const result = Engine.inspectPubKey(bytes)
    expect(result).toMatchObject({ format: 'compressed', isValid: true, x: GX, y: prefix === 2 ? GY : P - GY })
    expect(result.rawHex).toBe(Buffer.from(bytes).toString('hex'))
    expect(result.rejectionReason).toBeUndefined()
  })
  it('accepts uncompressed generator', () => {
    expect(Engine.inspectPubKey(Uint8Array.from([4, ...be(GX), ...be(GY)]))).toMatchObject({
      format: 'uncompressed', isValid: true, x: GX, y: GY,
    })
  })
  it('lifts the published BIP-340 vector 0 public key with even Y', () => {
    const key = Uint8Array.from(Buffer.from('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9', 'hex'))
    const result = Engine.inspectPubKey(key)
    expect(result.isValid).toBe(true)
    expect(result.format).toBe('x-only-bip340')
    expect(result.y! & 1n).toBe(0n)
    expect(result.y! ** 2n % P).toBe((result.x ** 3n + 7n) % P)
  })
  it.each([1n, 2n, 3n, 42n, N - 1n])('matches OpenSSL public key generation for scalar %s', scalar => {
    const ecdh = createECDH('secp256k1')
    ecdh.setPrivateKey(be(scalar))
    const compressed = Engine.inspectPubKey(ecdh.getPublicKey(undefined, 'compressed'))
    const uncompressed = Engine.inspectPubKey(ecdh.getPublicKey(undefined, 'uncompressed'))
    const xOnly = Engine.inspectPubKey(ecdh.getPublicKey(undefined, 'compressed').subarray(1))
    expect(compressed.isValid && uncompressed.isValid && xOnly.isValid).toBe(true)
    expect(compressed.x).toBe(uncompressed.x)
    expect(compressed.y).toBe(uncompressed.y)
    expect(xOnly.x).toBe(compressed.x)
    expect(xOnly.y! & 1n).toBe(0n)
  })
  it('identifies parity-only collision between 02X and 03X as equivalent BIP-340/Tapscript x-only keys', () => {
    const xHex = '6116733562ba4df653e4ec6b98c904c8dd3c677428264d33f4ae0089b72abaa4'
    const pk02 = Engine.inspectPubKey(Uint8Array.from(Buffer.from(`02${xHex}`, 'hex')))
    const pk03 = Engine.inspectPubKey(Uint8Array.from(Buffer.from(`03${xHex}`, 'hex')))
    const pkXOnly = Engine.inspectPubKey(Uint8Array.from(Buffer.from(xHex, 'hex')))

    expect(pk02.isValid && pk03.isValid && pkXOnly.isValid).toBe(true)
    expect(pk02.x).toBe(pk03.x)
    expect(pk02.x).toBe(pkXOnly.x)
    expect(pk02.y).toBe(P - pk03.y!)
    // In Tapscript (BIP-340/342/379), keys serialize to 32 bytes without parity, collapsing 02X and 03X
    const toTapscriptBytes = (pk: typeof pk02) => pk.x.toString(16).padStart(64, '0')
    expect(toTapscriptBytes(pk02)).toBe(toTapscriptBytes(pk03))
    expect(toTapscriptBytes(pk02)).toBe(xHex)
  })
  it.each([0, 1, 4, 5, 6, 7, 255])('rejects invalid compressed prefix %s', prefix => {
    expect(Engine.inspectPubKey(Uint8Array.from([prefix, ...be(GX)])).isValid).toBe(false)
  })
  it.each([0, 1, 2, 3, 6, 7, 255])('rejects invalid uncompressed prefix %s', prefix => {
    expect(Engine.inspectPubKey(Uint8Array.from([prefix, ...be(GX), ...be(GY)])).format).toBe('invalid')
  })
  it.each([0, 1, 31, 34, 64, 66])('rejects invalid key length %s', length => {
    expect(Engine.inspectPubKey(new Uint8Array(length)).isValid).toBe(false)
  })
  it.each([P, P + 1n, 2n ** 256n - 1n])('rejects overflowing X %s in every encoding', x => {
    for (const bytes of [be(x), Uint8Array.from([2, ...be(x)]), Uint8Array.from([4, ...be(x), ...be(GY)])]) {
      expect(Engine.inspectPubKey(bytes).rejectionReason).toBe('Field element overflow (x >= p)')
    }
  })
  it('rejects overflowing Y', () => {
    expect(Engine.inspectPubKey(Uint8Array.from([4, ...be(GX), ...be(P)])).rejectionReason).toBe('Field element overflow (y >= p)')
  })
  it('rejects an uncompressed point off the curve', () => {
    expect(Engine.inspectPubKey(Uint8Array.from([4, ...be(GX), ...be(GY + 1n)])).rejectionReason).toBe('Point not on secp256k1 curve')
  })
  it('rejects X=0, whose curve RHS is a non-residue', () => {
    expect(Engine.sqrtModP(7n)).toBeNull()
    for (const bytes of [be(0n), Uint8Array.from([2, ...be(0n)]), Uint8Array.from([3, ...be(0n)])]) {
      expect(Engine.inspectPubKey(bytes).rejectionReason).toBe('Point not on secp256k1 curve')
    }
  })
})

describe('strict DER and compact ECDSA inspections', () => {
  it.each([[1n, 1n], [128n, 255n], [N - 1n, HALF_N]] as const)('accepts canonical low-S r=%s s=%s', (r, s) => {
    expect(Engine.inspectSignatureDER(der(r, s))).toMatchObject({
      isDer: true, isCompact64: false, r, s, isLowS: true,
      isCanonicalR: true, isCanonicalS: true, isStrictlyValid: true,
    })
    expect(Engine.inspectCompactSignature(Uint8Array.from([...be(r), ...be(s)]))).toMatchObject({
      isCompact64: true, isDer: false, r, s, isStrictlyValid: true,
    })
  })
  it.each([HALF_N + 1n, N - 1n])('flags high-S %s as malleable', s => {
    for (const result of [Engine.inspectSignatureDER(der(1n, s)), Engine.inspectCompactSignature(Uint8Array.from([...be(1n), ...be(s)]))]) {
      expect(result).toMatchObject({ isLowS: false, isCanonicalS: true, isStrictlyValid: false })
      expect(result.rejectionReason).toContain('malleable')
    }
    expect(Engine.inspectSignatureDER(der(1n, N - s)).isStrictlyValid).toBe(true)
  })
  it.each([[0n, 1n], [N, 1n], [N + 1n, 1n], [1n, 0n], [1n, N], [1n, N + 1n]] as const)(
    'rejects signature scalar bounds r=%s s=%s', (r, s) => {
      for (const result of [Engine.inspectSignatureDER(der(r, s)), Engine.inspectCompactSignature(Uint8Array.from([...be(r), ...be(s)]))]) {
        expect(result.isStrictlyValid).toBe(false)
        expect(result.isCanonicalR).toBe(r > 0n && r < N)
        expect(result.isCanonicalS).toBe(s > 0n && s < N)
      }
    },
  )
  it.each([
    '', '3006020101020101ff', '3106020101020101', '3007020101020101',
    '308106020101020101', '3006030101020101', '3006020101030101',
    '300602008002020101', '30060201010200', '3006020180020101',
    '3006020101020180', '300702020001020101', '300702010102020001',
    '30080203000080020101', '30080201010203000080', '3006027f01020101',
  ])('rejects malformed DER %s', hex => {
    const result = Engine.inspectSignatureDER(Uint8Array.from(Buffer.from(hex, 'hex')))
    expect(result.isDer).toBe(false)
    expect(result.isStrictlyValid).toBe(false)
    expect(result.rejectionReason).toBeDefined()
  })
  it('rejects every truncation of a valid DER signature', () => {
    const valid = der(N - 1n, HALF_N)
    for (let length = 0; length < valid.length; length++) {
      expect(Engine.inspectSignatureDER(valid.subarray(0, length)).isStrictlyValid).toBe(false)
    }
  })
  it.each([0, 32, 63, 65, 72])('rejects compact signature length %s', length => {
    const result = Engine.inspectCompactSignature(new Uint8Array(length))
    expect(result.isCompact64).toBe(false)
    expect(result.isStrictlyValid).toBe(false)
  })
  it('handles nonzero byte offsets and does not mutate input', () => {
    const signature = der(128n, 255n)
    const container = Uint8Array.from([255, ...signature, 255])
    const before = container.slice()
    expect(Engine.inspectSignatureDER(container.subarray(1, -1)).isStrictlyValid).toBe(true)
    expect(container).toEqual(before)
  })
})
