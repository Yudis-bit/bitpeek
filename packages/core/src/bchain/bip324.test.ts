import { createCipheriv, createECDH, hkdfSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  SECP256K1_P as P, SECP256K1_N as N, SECP256K1_GX, SECP256K1_GY, isCurvePoint, scalarMul,
} from './secp256k1'
import {
  legendre, sqrt_fp, decodeSwiftEC, decodeSwiftECBytes, inverseSwiftEC, encodeSwiftEC,
  deriveBip324SharedSecret, deriveBip324SessionKeys, bip324ChaCha20Block, bip324AeadEncrypt,
  bip324AeadDecrypt, Bip324PacketCipher, auditBip324Frame, BIP324_REKEY_INTERVAL,
} from './bip324'

const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'))
const hex = (data: Uint8Array) => Buffer.from(data).toString('hex')
const be = (value: bigint) => bytes(value.toString(16).padStart(64, '0'))
const G = { x: SECP256K1_GX, y: SECP256K1_GY }
const magic = bytes('f9beb4d9')
function csv(name: string): Record<string, string>[] {
  const [header, ...rows] = readFileSync(new URL(`./fixtures/${name}.csv`, import.meta.url), 'utf8').trim().split(/\r?\n/)
  const fields = header.split(',')
  return rows.map(row => Object.fromEntries(row.split(',').map((value, i) => [fields[i], value])))
}
const decodeVectors = csv('ellswift_decode_test_vectors')
const inverseVectors = csv('xswiftec_inv_test_vectors')
const packetVectors = csv('packet_encoding_test_vectors')
const keys = { lengthKey: be(1n), payloadKey: be(2n) }

describe('BIP-324 SwiftEC published vectors', () => {
  it.each(decodeVectors.map((vector, index) => ({ vector, index })))('decodes official vector $index', ({ vector }) => {
    const encoding = bytes(vector.ellswift), point = decodeSwiftECBytes(encoding)
    expect(point.x).toBe(BigInt(`0x${vector.x}`))
    expect(isCurvePoint(point)).toBe(true)
    expect(point.y & 1n).toBe((BigInt(`0x${vector.ellswift.slice(64)}`) % P) & 1n)
  })
  it.each(inverseVectors.map((vector, index) => ({ vector, index })))('checks all eight official inverse branches for vector $index', ({ vector }) => {
    const u = BigInt(`0x${vector.u}`), x = BigInt(`0x${vector.x}`)
    for (let branch = 0; branch < 8; branch++) {
      const t = inverseSwiftEC(x, u, branch), expected = vector[`case${branch}_t`]
      expect(t).toBe(expected === '' ? null : BigInt(`0x${expected}`))
      if (t !== null) expect(decodeSwiftEC(u, t).x).toBe(x)
    }
  })
  it.each(Array.from({ length: 16 }, (_, i) => BigInt(i + 1)))('round-trips both Y parities for scalar %s', scalar => {
    const point = scalarMul(scalar, G)!
    for (const target of [point, { x: point.x, y: P - point.y }]) {
      const encoding = encodeSwiftEC(target, be(scalar))
      expect(encoding).toHaveLength(64)
      expect(decodeSwiftECBytes(encoding)).toEqual(target)
    }
  })
  it.each([[0n, 0n], [0n, 23n], [42n, 0n], [5n, sqrt_fp(-132n)!]] as const)('handles exceptional u=%s, t=%s', (u, t) => {
    expect(isCurvePoint(decodeSwiftEC(u, t))).toBe(true)
  })
  it.each([0n, 1n, 2n, 3n, 4n, P - 1n, P, P + 1n])('agrees on Legendre and square-root classification of %s', value => {
    const root = sqrt_fp(value), symbol = legendre(value)
    expect(root === null).toBe(symbol === -1)
    if (root !== null) expect(root * root % P).toBe(value % P)
  })
  it.each([0, 32, 63, 65, 128])('rejects a %s-byte wire encoding', length => {
    expect(() => decodeSwiftECBytes(new Uint8Array(length))).toThrow('64 bytes')
  })
  it.each([-1n, P, P + 1n])('rejects non-canonical field API argument %s while wire input reduces mod p', value => {
    expect(() => decodeSwiftEC(value, 1n)).toThrow('canonical')
    expect(() => decodeSwiftEC(1n, value)).toThrow('canonical')
  })
  it('reduces p and uint256-max wire values and preserves reduced t parity', () => {
    const encoding = new Uint8Array(64).fill(255)
    expect(decodeSwiftECBytes(encoding)).toEqual(decodeSwiftEC(((1n << 256n) - 1n) % P, ((1n << 256n) - 1n) % P))
    expect(decodeSwiftECBytes(new Uint8Array([...be(P), ...be(P)]))).toEqual(decodeSwiftEC(0n, 0n))
  })
  it('requires finite canonical points and 32-byte encoder entropy', () => {
    expect(() => encodeSwiftEC({ x: 0n, y: 0n }, be(1n))).toThrow('finite')
    expect(() => encodeSwiftEC(G, new Uint8Array(31))).toThrow('32 bytes')
    expect(() => inverseSwiftEC(G.x, 0n, 0)).toThrow('nonzero')
    expect(() => inverseSwiftEC(G.x, 1n, 8)).toThrow('branch')
  })
  it('is deterministic with fixed aux, preserves inputs and varies with aux', () => {
    const aux = be(7n), copy = aux.slice(), point = { ...G }
    expect(encodeSwiftEC(point, aux)).toEqual(encodeSwiftEC(G, be(7n)))
    expect(encodeSwiftEC(G, be(8n))).not.toEqual(encodeSwiftEC(G, aux))
    expect(aux).toEqual(copy); expect(point).toEqual(G)
  })
  it('passes distribution regression checks across fresh deterministic entropy samples (not a uniformity proof)', () => {
    const samples = Array.from({ length: 128 }, (_, i) => encodeSwiftEC(G, be(BigInt(i + 1))))
    expect(new Set(samples.map(hex)).size).toBe(128)
    const buckets = new Uint32Array(16)
    for (const sample of samples) for (const byte of sample) buckets[byte >> 4]++
    expect(Array.from(buckets).every(count => count > 350 && count < 700)).toBe(true)
    for (let position = 0; position < 64; position++) expect(new Set(samples.map(sample => sample[position])).size).toBeGreaterThan(65)
  })
})

describe('BIP-324 ECDH, HKDF, packet framing and ratchet vectors', () => {
  it.each(packetVectors.map((vector, index) => ({ vector, index })))('matches official complete packet lifecycle vector $index', ({ vector }) => {
    const secret = deriveBip324SharedSecret(bytes(vector.in_priv_ours), bytes(vector.in_ellswift_ours), bytes(vector.in_ellswift_theirs), vector.in_initiating === '1')
    expect(hex(secret)).toBe(vector.mid_shared_secret)
    const session = deriveBip324SessionKeys(secret, magic)
    expect(hex(session.initiatorLengthKey)).toBe(vector.mid_initiator_l)
    expect(hex(session.initiatorPayloadKey)).toBe(vector.mid_initiator_p)
    expect(hex(session.responderLengthKey)).toBe(vector.mid_responder_l)
    expect(hex(session.responderPayloadKey)).toBe(vector.mid_responder_p)
    expect(hex(session.sessionId)).toBe(vector.out_session_id)
    const initiating = vector.in_initiating === '1'
    expect(hex(initiating ? session.initiatorGarbageTerminator : session.responderGarbageTerminator)).toBe(vector.mid_send_garbage_terminator)
    expect(hex(initiating ? session.responderGarbageTerminator : session.initiatorGarbageTerminator)).toBe(vector.mid_recv_garbage_terminator)
    const directional = initiating ? { lengthKey: session.initiatorLengthKey, payloadKey: session.initiatorPayloadKey }
      : { lengthKey: session.responderLengthKey, payloadKey: session.responderPayloadKey }
    const unit = bytes(vector.in_contents), contents = new Uint8Array(unit.length * Number(vector.in_multiply))
    for (let offset = 0; offset < contents.length; offset += unit.length) contents.set(unit, offset)
    const index = Number(vector.in_idx), aad = bytes(vector.in_aad), flags = vector.in_ignore === '1' ? 128 : 0
    const packet = new Bip324PacketCipher(directional, index).encode(contents, aad, flags)
    if (vector.out_ciphertext) expect(hex(packet)).toBe(vector.out_ciphertext)
    if (vector.out_ciphertext_endswith) expect(hex(packet.subarray(-128))).toBe(vector.out_ciphertext_endswith)
    const decoded = new Bip324PacketCipher(directional, index).decode(packet, aad)
    expect(hex(decoded.contents)).toBe(hex(contents)); expect(decoded.ignore).toBe(flags === 128)
  }, 60000)
  it('agrees with Node HKDF for every session label and binds network magic', () => {
    const secret = be(42n), session = deriveBip324SessionKeys(secret, magic)
    const salt = Buffer.concat([Buffer.from('bitcoin_v2_shared_secret'), magic])
    const expected = (label: string) => hex(new Uint8Array(hkdfSync('sha256', secret, salt, label, 32)))
    expect(hex(session.initiatorLengthKey)).toBe(expected('initiator_L'))
    expect(hex(session.initiatorPayloadKey)).toBe(expected('initiator_P'))
    expect(hex(session.responderLengthKey)).toBe(expected('responder_L'))
    expect(hex(session.responderPayloadKey)).toBe(expected('responder_P'))
    expect(hex(session.sessionId)).toBe(expected('session_id'))
    expect(hex(session.initiatorGarbageTerminator) + hex(session.responderGarbageTerminator)).toBe(expected('garbage_terminators'))
    expect(deriveBip324SessionKeys(secret, bytes('fabfb5da')).sessionId).not.toEqual(session.sessionId)
  })
  it('agrees between ECDH roles and with native X-only ECDH', () => {
    const a = encodeSwiftEC(scalarMul(3n, G)!, be(1n)), b = encodeSwiftEC(scalarMul(7n, G)!, be(2n))
    expect(deriveBip324SharedSecret(be(3n), a, b, true)).toEqual(deriveBip324SharedSecret(be(7n), b, a, false))
    const native = createECDH('secp256k1'); native.setPrivateKey(be(3n))
    const peer = createECDH('secp256k1'); peer.setPrivateKey(be(7n))
    const sharedX = native.computeSecret(peer.getPublicKey(undefined, 'compressed'))
    expect(hex(be(scalarMul(3n, decodeSwiftECBytes(b))!.x))).toBe(sharedX.toString('hex'))
    const anotherA = encodeSwiftEC(scalarMul(3n, G)!, be(99n))
    expect(deriveBip324SharedSecret(be(3n), anotherA, b, true)).not.toEqual(deriveBip324SharedSecret(be(3n), a, b, true))
  })
  it.each([0n, N, N + 1n])('rejects ECDH secret scalar %s', value => {
    const encoding = encodeSwiftEC(G, be(1n))
    expect(() => deriveBip324SharedSecret(be(value), encoding, encoding, true)).toThrow('0 < d < n')
  })
  it('rejects a local ECDH encoding that does not belong to the private key', () => {
    const encoding = encodeSwiftEC(G, be(1n))
    expect(() => deriveBip324SharedSecret(be(2n), encoding, encoding, true)).toThrow('does not match')
  })
  it('matches the RFC 8439 ChaCha20 block vector', () => {
    expect(hex(bip324ChaCha20Block(bytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
      bytes('000000090000004a00000000'), 1))).toBe('10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e')
  })
  it.each([0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 255])('matches native RFC AEAD for %s-byte plaintext and varied AAD', length => {
    const plaintext = new Uint8Array(length).fill(length & 255), aad = new Uint8Array(length % 33).fill(42), nonce = new Uint8Array(12)
    const native = createCipheriv('chacha20-poly1305', keys.payloadKey, nonce, { authTagLength: 16 })
    native.setAAD(aad, { plaintextLength: plaintext.length })
    const expected = Buffer.concat([native.update(plaintext), native.final(), native.getAuthTag()])
    const ciphertext = bip324AeadEncrypt(keys.payloadKey, nonce, aad, plaintext)
    expect(hex(ciphertext)).toBe(expected.toString('hex'))
    expect(bip324AeadDecrypt(keys.payloadKey, nonce, aad, ciphertext)).toEqual(plaintext)
    const altered = ciphertext.slice(); altered[altered.length - 1] ^= 1
    expect(bip324AeadDecrypt(keys.payloadKey, nonce, aad, altered)).toBeNull()
  })
  it('encrypts all metadata, advances both ciphers and rekeys at 224 packets', () => {
    const sender = new Bip324PacketCipher(keys), receiver = new Bip324PacketCipher(keys)
    for (let index = 0; index < 450; index++) {
      const contents = new Uint8Array([index & 255]), flags = index % 2 ? 128 : 0
      const packet = sender.encode(contents, new Uint8Array(0), flags)
      expect(new Bip324PacketCipher(keys, index).encode(contents, new Uint8Array(0), flags)).toEqual(packet)
      expect(receiver.decode(packet)).toEqual({ contents, flags, ignore: flags === 128, packetIndex: index })
    }
    expect(sender.packetIndex).toBe(450); expect(BIP324_REKEY_INTERVAL).toBe(224)
  })
  it.each([0, 1, 2, 3, 4, 12, 19])('detects tampering at wire byte %s and exposes no plaintext', position => {
    const packet = new Bip324PacketCipher(keys).encode(new Uint8Array([16, 1, 2]))
    packet[position] ^= 1
    const audit = auditBip324Frame(packet, { keys })
    expect(audit.valid).toBe(false); expect(audit.authenticationVerified).toBe(false)
    expect(audit).not.toHaveProperty('contentsHex')
  })
  it.each([0, 3, 19, 21, 25])('rejects truncated/trailing %s-byte frame', length => {
    const packet = new Bip324PacketCipher(keys).encode(new Uint8Array([16, 1]))
    const malformed = new Uint8Array(length); malformed.set(packet.subarray(0, length))
    expect(auditBip324Frame(malformed, { keys }).valid).toBe(false)
  })
  it('authenticates garbage AAD and rejects the wrong state or directional key', () => {
    const aad = bytes('010203'), packet = new Bip324PacketCipher(keys, 224).encode(bytes('100102'), aad)
    expect(auditBip324Frame(packet, { keys, packetIndex: 224, aad }).authenticationVerified).toBe(true)
    expect(auditBip324Frame(packet, { keys, packetIndex: 224 }).valid).toBe(false)
    expect(auditBip324Frame(packet, { keys, packetIndex: 223, aad }).valid).toBe(false)
    expect(auditBip324Frame(packet, { keys: { ...keys, payloadKey: be(9n) }, packetIndex: 224, aad }).valid).toBe(false)
  })
  it('permanently closes a receiver after authentication failure', () => {
    const packet = new Bip324PacketCipher(keys).encode(bytes('10')), receiver = new Bip324PacketCipher(keys)
    const corrupted = packet.slice(); corrupted[corrupted.length - 1] ^= 1
    expect(() => receiver.decode(corrupted)).toThrow('authentication')
    expect(() => receiver.decode(packet)).toThrow('closed')
    expect(() => receiver.encode(bytes('10'))).toThrow('closed')
  })
  it('requires keys for authentication and detects actual v1 plaintext headers', () => {
    const packet = new Bip324PacketCipher(keys).encode(bytes('10'))
    expect(auditBip324Frame(packet)).toMatchObject({ valid: null, authenticationVerified: false, findings: [{ code: 'keys-required' }] })
    for (const network of ['f9beb4d9', '0b110907', 'fabfb5da', '0a03cf40']) {
      const plaintext = bytes(network + '76657273696f6e0000000000' + '00'.repeat(8))
      expect(auditBip324Frame(plaintext).findings[0].code).toBe('plaintext-p2p-leak')
    }
  })
  it('accepts ignored reserved flag bits, decoys and negotiation contents', () => {
    const packet = new Bip324PacketCipher(keys).encode(new Uint8Array(0), new Uint8Array(0), 129)
    expect(auditBip324Frame(packet, { keys, inspectApplicationPayload: true })).toMatchObject({ valid: true, ignore: true, flags: 129,
      findings: [{ code: 'reserved-flags', severity: 'info' }] })
    expect(auditBip324Frame(new Bip324PacketCipher(keys).encode(new Uint8Array(0)), { keys }).valid).toBe(true)
  })
  it.each(['', '00', '0000616263' + '00'.repeat(8), '0070696e670001' + '00'.repeat(6)])('detects malformed application command %s after authenticating', payload => {
    const packet = new Bip324PacketCipher(keys).encode(bytes(payload))
    const audit = auditBip324Frame(packet, { keys, inspectApplicationPayload: true })
    expect(audit.valid).toBe(false); expect(audit.authenticationVerified).toBe(true)
  })
  it.each(['10', '0070696e67' + '00'.repeat(8)])('accepts short and long message-type encoding %s', payload => {
    expect(auditBip324Frame(new Bip324PacketCipher(keys).encode(bytes(payload)), { keys, inspectApplicationPayload: true }).valid).toBe(true)
  })
  it('validates key/nonce sizes, packet counters, flags and uint24 length', () => {
    expect(() => new Bip324PacketCipher({ ...keys, lengthKey: new Uint8Array(31) })).toThrow('32 bytes')
    expect(() => new Bip324PacketCipher(keys, -1)).toThrow('packetIndex')
    expect(() => new Bip324PacketCipher(keys, 1_000_001)).toThrow('packetIndex')
    expect(() => new Bip324PacketCipher(keys).encode(bytes('10'), new Uint8Array(0), 256)).toThrow('flags')
    expect(() => new Bip324PacketCipher(keys).encode(new Uint8Array(0x1000000))).toThrow('uint24')
    expect(() => bip324ChaCha20Block(keys.payloadKey, new Uint8Array(11), 0)).toThrow('12 bytes')
    expect(() => bip324ChaCha20Block(keys.payloadKey, new Uint8Array(12), 0x100000000)).toThrow('uint32')
  })
})
