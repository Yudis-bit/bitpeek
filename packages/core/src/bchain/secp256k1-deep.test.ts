import { createECDH, createHash } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as crypto from '../crypto'
import { unsignedBigEndian } from '../bytes'
import { Secp256k1Engine as Engine, pointAdd, pointDouble, scalarMul, liftX,
  SECP256K1_P as P, SECP256K1_N as N, SECP256K1_GX as GX, SECP256K1_GY as GY } from './secp256k1'
import type { Point } from './secp256k1'

const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'))
const be = (value: bigint) => hex(value.toString(16).padStart(64, '0'))
const G = { x: GX, y: GY }
const KEY = hex('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9')
const SIG = hex('E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0')
const MSG = new Uint8Array(32)

// Published BIP-374 verification vectors 0 (custom generator/message) and 5 (no message).
// https://github.com/bitcoin/bips/blob/master/bip-0374/test_vectors_verify_proof.csv
const DLEQ_VECTORS = [
  [
    '02cef38f55e78b321a1f785cb1c6e33dfcef9784c18bdc4e279801c449ccdfb88e',
    '02b540b22c2c5ef0dc886abdaad27498453d893265560bc08a187319af6f845f58',
    '02dad4b35c2379ba8334c9a5dda8f6e6d5cd575a7cc9d3ca4faaac51839daaa30f',
    '03fefe00951dcd0ef10b12523393c2b8113119de4fdeeab320694e96bdccd2775b',
    '7e7e934169e0bf4706e6b29e5a621c7fe199a524744a25af80071e111c0e2e94118e730d8add118dd2ee4f7d1cc183e1b87168362d1a6f85c16d8671a3fc7a8a',
    'efb07d4b382d3da1079fbf24df623ba6c2e4c764993bbfa6dd7a4fe4aaf33859',
  ],
  [
    `02${GX.toString(16)}`,
    '02637b2c3ea8ca80b9caecc50f4134c86ae9cf7a269133e7afc71f30e3a3cda60c',
    '034bccb1c570ac1f3bc42d61fe35de605b99626501ccb20297e1acbbf2d7152aa1',
    '0285b826c8dd175805901906b6c9b4140a30cbcc94c6e7dcf36476038bf90d4718',
    '503562d36910cd2d61a4d07c8ff680265c713e63dde0dcb88e6ea3c58597bdc05b86db9af95eccc475ce2177f941c118fefed20227d4ce8ce9557cb008758de6',
    '',
  ],
] as const

function point(value: string) {
  const inspection = Engine.inspectPubKey(hex(value))
  if (!inspection.isValid || inspection.y === undefined) throw new Error('Invalid vector point')
  return { x: inspection.x, y: inspection.y }
}

afterEach(() => vi.restoreAllMocks())

describe('tagged hashes and secp256k1 arithmetic', () => {
  it('matches native SHA-256 for mixed UTF-8, empty and multi-block inputs', () => {
    for (const messages of [[], [''], ['é', new Uint8Array(200).fill(42), '支付']] as (string | Uint8Array)[][]) {
      const tagHash = createHash('sha256').update('test/タグ').digest()
      const expected = createHash('sha256').update(tagHash).update(tagHash)
      for (const message of messages) expected.update(message)
      expect(Buffer.from(crypto.taggedHash('test/タグ', ...messages))).toEqual(expected.digest())
    }
  })
  it('handles infinity, inverse points, doubling and scalar reduction', () => {
    expect(pointAdd(G, null)).toEqual(G)
    expect(pointAdd(null, G)).toEqual(G)
    expect(pointAdd(null, null)).toBeNull()
    expect(pointAdd(G, { x: GX, y: P - GY })).toBeNull()
    expect(pointDouble(null)).toBeNull()
    expect(pointDouble({ x: 0n, y: 0n })).toBeNull()
    expect(pointAdd(G, G)).toEqual(pointDouble(G))
    expect(scalarMul(0n, G)).toBeNull()
    expect(scalarMul(N, G)).toBeNull()
    expect(scalarMul(42n, null)).toBeNull()
    expect(scalarMul(N + 1n, G)).toEqual(G)
    expect(scalarMul(-1n, G)).toEqual({ x: GX, y: P - GY })
    expect(Engine.pointDouble(G)).toEqual(Engine.pointAdd(G, G))
    expect(Engine.scalarMul(2n, G)).toEqual(pointDouble(G))
  })
  it.each([1n, 2n, 3n, 42n, 0x123456789abcdefn, N - 1n])('matches independent OpenSSL multiplication for %s', scalar => {
    const ecdh = createECDH('secp256k1')
    ecdh.setPrivateKey(be(scalar))
    const key = ecdh.getPublicKey(undefined, 'uncompressed')
    expect(scalarMul(scalar, G)).toEqual({ x: unsignedBigEndian(key.subarray(1, 33)), y: unsignedBigEndian(key.subarray(33)) })
  })
  it('checks addition independently with a native combined scalar', () => {
    const ecdh = createECDH('secp256k1')
    ecdh.setPrivateKey(be(43n))
    expect(pointAdd(scalarMul(17n, G), scalarMul(26n, G))).toEqual(point(ecdh.getPublicKey(undefined, 'compressed').toString('hex')))
  })
  it('lifts X to even Y and rejects lengths, overflow and non-residues', () => {
    expect(liftX(be(GX))).toEqual(G)
    expect(Engine.liftX(KEY)!.y & 1n).toBe(0n)
    for (const bytes of [new Uint8Array(31), new Uint8Array(33), be(P), be(0n)]) expect(liftX(bytes)).toBeNull()
  })
})

describe('BIP-340 Schnorr verification (32-byte messages)', () => {
  // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv (vectors 0, 1, 3, 4).
  it.each([
    [Buffer.from(KEY).toString('hex'), '00'.repeat(32), Buffer.from(SIG).toString('hex')],
    ['DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'],
    ['25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517', 'FF'.repeat(32), '7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3'],
    ['D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9', '4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703', '00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4'],
  ])('accepts published vector for key %s', (key, message, signature) => {
    expect(Engine.verifySchnorr(hex(key), hex(message), hex(signature))).toEqual({ valid: true })
  })
  it('rejects r >= p and s >= n without reducing either scalar', () => {
    const signature = SIG.slice()
    signature.set(be(P))
    expect(Engine.verifySchnorr(KEY, MSG, signature).reason).toBe('r >= p')
    signature.set(SIG)
    signature.set(be(N), 32)
    expect(Engine.verifySchnorr(KEY, MSG, signature).reason).toBe('s >= n')
  })
  it('rejects corrupted signatures, messages and public keys', () => {
    const signature = SIG.slice()
    signature[10] = signature[10]! ^ 1
    const message = MSG.slice()
    message[0] = 1
    expect(Engine.verifySchnorr(KEY, MSG, signature).valid).toBe(false)
    expect(Engine.verifySchnorr(KEY, message, SIG).valid).toBe(false)
    expect(Engine.verifySchnorr(be(P), MSG, SIG).reason).toBe('Invalid public key X coordinate')
    expect(Engine.verifySchnorr(be(0n), MSG, SIG).valid).toBe(false)
  })
  it.each([
    ['FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2', 'R has odd Y coordinate'],
    ['0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051', 'R is infinity'],
    ['4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B', 'Signature verification equation failed (Rx != r)'],
  ])('rejects published invalid vector: %s', (signature, reason) => {
    expect(Engine.verifySchnorr(hex('DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'),
      hex('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89'), hex(signature))).toEqual({ valid: false, reason })
  })
  it('rejects malformed input lengths', () => {
    expect(Engine.verifySchnorr(KEY.subarray(1), MSG, SIG).valid).toBe(false)
    expect(Engine.verifySchnorr(KEY, new Uint8Array(0), SIG).valid).toBe(false)
    expect(Engine.verifySchnorr(KEY, MSG, SIG.subarray(1)).valid).toBe(false)
  })
})

describe('BIP-374 DLEQ proof verification', () => {
  it.each(DLEQ_VECTORS)('accepts published vector with generator %s', (g, a, b, c, proof, message) => {
    expect(Engine.verifyDLEQ(point(g), point(a), point(b), point(c), hex(proof), message ? hex(message) : undefined)).toEqual({ valid: true })
  })
  it('binds proof to the message, point ordering and compressed Y parity', () => {
    const [g, a, b, c, proof, message] = DLEQ_VECTORS[0]
    const points = [point(g), point(a), point(b), point(c)] as const
    const damaged = hex(proof)
    damaged[40] = damaged[40]! ^ 1
    expect(Engine.verifyDLEQ(...points, damaged, hex(message)).valid).toBe(false)
    expect(Engine.verifyDLEQ(...points, hex(proof)).valid).toBe(false)
    expect(Engine.verifyDLEQ(points[0], points[1], points[3], points[2], hex(proof), hex(message)).valid).toBe(false)
    expect(Engine.verifyDLEQ(points[0], points[1], points[2], { x: points[3].x, y: P - points[3].y }, hex(proof), hex(message)).valid).toBe(false)
  })
  it('rejects proof overflow, infinity, off-curve and noncanonical points', () => {
    const [g, a, b, c, proof, message] = DLEQ_VECTORS[0]
    const points = [point(g), point(a), point(b), point(c)] as const
    for (const [offset, reason] of [[0, 'e >= n'], [32, 's >= n']] as const) {
      const invalid = hex(proof)
      invalid.set(be(N), offset)
      expect(Engine.verifyDLEQ(...points, invalid, hex(message)).reason).toBe(reason)
    }
    expect(Engine.verifyDLEQ(...points, new Uint8Array(63)).valid).toBe(false)
    expect(Engine.verifyDLEQ(...points, hex(proof), new Uint8Array(1)).valid).toBe(false)
    for (const invalid of [null, { x: 0n, y: 0n }, { x: GX + P, y: GY }, { x: GX, y: -GY }]) {
      for (let index = 0; index < 4; index++) {
        const inputs: [Point, Point, Point, Point] = [...points]
        inputs[index] = invalid
        expect(Engine.verifyDLEQ(...inputs, hex(proof)).valid).toBe(false)
      }
    }
    expect(Engine.verifyDLEQ(G, G, G, G, new Uint8Array(64)).reason).toBe('R1 is infinity')
    const oneProof = new Uint8Array(64)
    oneProof.set(be(1n)); oneProof.set(be(1n), 32)
    expect(Engine.verifyDLEQ(G, pointDouble(G), G, G, oneProof).reason).toBe('R2 is infinity')
  })
})

describe('BIP-341 Taproot tweak verification', () => {
  // Published wallet-test-vectors.json cases with odd and even control-block parity.
  it.each([
    ['187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27', '147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3', '5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21', 1],
    ['93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820', 'e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e', 'c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b', 0],
  ] as const)('checks published output and parity for %s', (internal, output, root, parity) => {
    expect(Engine.verifyTaprootTweak(hex(internal), hex(output), hex(root))).toEqual({ valid: true, parity })
    expect(Engine.verifyTaprootTweak(hex(internal), hex(output)).valid).toBe(false)
  })
  it('checks a published key-only tweak', () => {
    expect(Engine.verifyTaprootTweak(hex('d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d'),
      hex('53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343')).valid).toBe(true)
  })
  it('rejects lengths, field overflow, invalid internal key and output mismatch', () => {
    expect(Engine.verifyTaprootTweak(KEY.subarray(1), KEY).valid).toBe(false)
    expect(Engine.verifyTaprootTweak(KEY, KEY.subarray(1)).valid).toBe(false)
    expect(Engine.verifyTaprootTweak(KEY, KEY, new Uint8Array(0)).reason).toContain('Merkle root')
    expect(Engine.verifyTaprootTweak(be(0n), KEY).reason).toBe('Invalid internal key X coordinate')
    expect(Engine.verifyTaprootTweak(KEY, be(P)).reason).toBe('Output key X coordinate >= p')
    expect(Engine.verifyTaprootTweak(KEY, KEY).reason).toBe('Taproot output key mismatch')
  })
  it('rejects overflowing tweak and infinity; accepts zero tweak', () => {
    const hash = vi.spyOn(crypto, 'taggedHash').mockReturnValue(be(N))
    expect(Engine.verifyTaprootTweak(KEY, KEY)).toEqual({ valid: false, parity: -1, reason: 'Taproot tweak >= n' })
    hash.mockReturnValue(be(N - 3n))
    expect(Engine.verifyTaprootTweak(KEY, KEY).reason).toBe('Tweaked point is infinity')
    hash.mockReturnValue(be(0n))
    expect(Engine.verifyTaprootTweak(KEY, KEY)).toEqual({ valid: true, parity: 0 })
  })
})
