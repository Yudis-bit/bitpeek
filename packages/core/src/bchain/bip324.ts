/** BIP-324 / RFC 8439 reference implementation for conformance inspection.
 * BigInt arithmetic, encoding rejection sampling and key handling are not constant-time.
 * Sources: bitcoin/bips bip-0324 and Bitcoin Core's MIT-licensed test reference.
 */
import { unsignedBigEndian } from '../bytes'
import { sha256, taggedHash } from '../crypto'
import {
  SECP256K1_P, SECP256K1_N, SECP256K1_GX, SECP256K1_GY, isCurvePoint, compressedPoint, scalarMul, type Point,
} from './secp256k1'

export { SECP256K1_P } from './secp256k1'
export const SECP256K1_B = 7n
export const BIP324_REKEY_INTERVAL = 224
export const BIP324_MAX_CONTENT_LENGTH = 0xffffff
export const BIP324_PACKET_OVERHEAD = 20
export const BIP324_MAX_AUDIT_PACKET_INDEX = 1_000_000

function mod(a: bigint): bigint { return ((a % SECP256K1_P) + SECP256K1_P) % SECP256K1_P }
function pow(a: bigint, exponent: bigint): bigint {
  let value = mod(a), result = 1n
  while (exponent > 0n) {
    if (exponent & 1n) result = mod(result * value)
    value = mod(value * value)
    exponent >>= 1n
  }
  return result
}
function inv(a: bigint): bigint {
  if (mod(a) === 0n) throw new RangeError('Field inverse does not exist')
  return pow(a, SECP256K1_P - 2n)
}
export function legendre(a: bigint): -1 | 0 | 1 {
  const symbol = pow(a, (SECP256K1_P - 1n) / 2n)
  return symbol === 0n ? 0 : symbol === 1n ? 1 : -1
}
export function sqrt_fp(a: bigint): bigint | null {
  const root = pow(a, (SECP256K1_P + 1n) / 4n)
  return mod(root * root) === mod(a) ? root : null
}
const ROOT_MINUS_THREE = sqrt_fp(-3n)!
const HALF = (SECP256K1_P + 1n) / 2n
function validX(x: bigint): boolean { return sqrt_fp(mod(x * x * x + SECP256K1_B)) !== null }
function field(a: bigint, name: string): void {
  if (typeof a !== 'bigint' || a < 0n || a >= SECP256K1_P) throw new RangeError(`${name} must be a canonical field element`)
}

/** Total BIP-324 XSwiftEC mapping, with libsecp256k1's t-parity lift.
 * Canonical field API; decodeSwiftECBytes reduces all 64-byte wire encodings mod p.
 */
export function decodeSwiftEC(u: bigint, t: bigint): NonNullable<Point> {
  field(u, 'u'); field(t, 't')
  const odd = t & 1n
  if (u === 0n) u = 1n
  if (t === 0n) t = 1n
  if (mod(u * u * u + t * t + SECP256K1_B) === 0n) t = mod(2n * t)
  const X = mod((u * u * u + SECP256K1_B - t * t) * inv(2n * t))
  const Y = mod((X + t) * inv(ROOT_MINUS_THREE * u))
  for (const x of [mod(u + 4n * Y * Y), mod((-X * inv(Y) - u) * HALF), mod((X * inv(Y) - u) * HALF)]) {
    const root = sqrt_fp(x * x * x + SECP256K1_B)
    if (root !== null) return { x, y: (root & 1n) === odd ? root : mod(-root) }
  }
  throw new Error('XSwiftEC mapping invariant failed')
}

export function decodeSwiftECBytes(encoding: Uint8Array): NonNullable<Point> {
  if (encoding.length !== 64) throw new RangeError('SwiftEC encoding must contain exactly 64 bytes')
  return decodeSwiftEC(unsignedBigEndian(encoding.subarray(0, 32)) % SECP256K1_P,
    unsignedBigEndian(encoding.subarray(32)) % SECP256K1_P)
}

/** The eight branches of BIP-324 XSwiftECInv; null denotes an unavailable branch. */
export function inverseSwiftEC(x: bigint, u: bigint, branch: number): bigint | null {
  field(x, 'x'); field(u, 'u')
  if (u === 0n || !validX(x)) throw new RangeError('Inverse SwiftEC requires nonzero u and a curve X coordinate')
  if (!Number.isInteger(branch) || branch < 0 || branch > 7) throw new RangeError('SwiftEC branch must be in [0, 7]')
  let v: bigint, s: bigint
  if ((branch & 2) === 0) {
    if (validX(mod(-x - u))) return null
    v = x
    const denominator = mod(u * u + u * v + v * v)
    if (denominator === 0n) return null
    s = mod(-(u * u * u + SECP256K1_B) * inv(denominator))
  } else {
    s = mod(x - u)
    if (s === 0n) return null
    const r = sqrt_fp(-s * (4n * (u * u * u + SECP256K1_B) + 3n * s * u * u))
    if (r === null || ((branch & 1) !== 0 && r === 0n)) return null
    v = mod((-u + r * inv(s)) * HALF)
  }
  const w = sqrt_fp(s)
  if (w === null) return null
  switch (branch & 5) {
    case 0: return mod(-w * (u * (1n - ROOT_MINUS_THREE) * HALF + v))
    case 1: return mod(w * (u * (1n + ROOT_MINUS_THREE) * HALF + v))
    case 4: return mod(w * (u * (1n - ROOT_MINUS_THREE) * HALF + v))
    default: return mod(-w * (u * (1n + ROOT_MINUS_THREE) * HALF + v))
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
  let offset = 0
  for (const part of parts) { result.set(part, offset); offset += part.length }
  return result
}
function be32(a: bigint): Uint8Array {
  const bytes = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) { bytes[i] = Number(a & 255n); a >>= 8n }
  return bytes
}
function le(a: bigint, size: number): Uint8Array {
  const bytes = new Uint8Array(size)
  for (let i = 0; i < size; i++) { bytes[i] = Number(a & 255n); a >>= 8n }
  return bytes
}
function fromLE(bytes: Uint8Array): bigint {
  let result = 0n
  for (let i = bytes.length - 1; i >= 0; i--) result = (result << 8n) | BigInt(bytes[i])
  return result
}
function exact(bytes: Uint8Array, size: number, name: string): void {
  if (!(bytes instanceof Uint8Array) || bytes.length !== size) throw new RangeError(`${name} must contain exactly ${size} bytes`)
}
function hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (key.length > 64) key = sha256(key)
  const inner = new Uint8Array(64).fill(0x36), outer = new Uint8Array(64).fill(0x5c)
  for (let i = 0; i < key.length; i++) { inner[i] ^= key[i]; outer[i] ^= key[i] }
  return sha256(concat(outer, sha256(concat(inner, data))))
}

/** Randomized reference encoder; fresh 32-byte aux entropy is required for each encoding.
 * Deterministic aux is useful for tests, but cannot establish pseudorandomness by itself.
 */
export function encodeSwiftEC(point: NonNullable<Point>, auxRand: Uint8Array): Uint8Array {
  if (!isCurvePoint(point)) throw new RangeError('SwiftEC encoding requires a finite secp256k1 point')
  exact(auxRand, 32, 'auxRand')
  const seed = taggedHash('Bitpeek/SwiftEC/encode', auxRand, compressedPoint(point))
  for (let attempt = 0; attempt < 4096; attempt++) {
    const counter = le(BigInt(attempt), 4)
    const uBytes = hmac(seed, concat(counter, new Uint8Array([0])))
    const u = unsignedBigEndian(uBytes)
    if (u === 0n || u >= SECP256K1_P) continue
    const branch = hmac(seed, concat(counter, new Uint8Array([1])))[0] & 7
    let t = inverseSwiftEC(point.x, u, branch)
    if (t === null || t === 0n) continue
    if ((t & 1n) !== (point.y & 1n)) t = SECP256K1_P - t
    return concat(uBytes, be32(t))
  }
  throw new RangeError('SwiftEC encoding rejection-sampling limit reached')
}

/** Encoding-bound, role-ordered BIP-324 ECDH transcript hash. */
export function deriveBip324SharedSecret(privateKey: Uint8Array, ours: Uint8Array, theirs: Uint8Array, initiating: boolean): Uint8Array {
  exact(privateKey, 32, 'privateKey'); exact(ours, 64, 'ours'); exact(theirs, 64, 'theirs')
  const d = unsignedBigEndian(privateKey)
  if (d === 0n || d >= SECP256K1_N) throw new RangeError('Private key must satisfy 0 < d < n')
  // Check the supplied local encoding belongs to this private key (x-only).
  const local = scalarMul(d, { x: SECP256K1_GX, y: SECP256K1_GY })!
  if (decodeSwiftECBytes(ours).x !== local.x) throw new RangeError('Local SwiftEC encoding does not match private key')
  const shared = scalarMul(d, decodeSwiftECBytes(theirs))!
  return taggedHash('bip324_ellswift_xonly_ecdh', initiating ? ours : theirs, initiating ? theirs : ours, be32(shared.x))
}

export interface Bip324SessionKeys {
  initiatorLengthKey: Uint8Array
  initiatorPayloadKey: Uint8Array
  responderLengthKey: Uint8Array
  responderPayloadKey: Uint8Array
  sessionId: Uint8Array
  initiatorGarbageTerminator: Uint8Array
  responderGarbageTerminator: Uint8Array
}
export function deriveBip324SessionKeys(sharedSecret: Uint8Array, networkMagic: Uint8Array): Bip324SessionKeys {
  exact(sharedSecret, 32, 'sharedSecret'); exact(networkMagic, 4, 'networkMagic')
  const prk = hmac(concat(new TextEncoder().encode('bitcoin_v2_shared_secret'), networkMagic), sharedSecret)
  const expand = (label: string) => hmac(prk, concat(new TextEncoder().encode(label), new Uint8Array([1])))
  const terminators = expand('garbage_terminators')
  return { initiatorLengthKey: expand('initiator_L'), initiatorPayloadKey: expand('initiator_P'),
    responderLengthKey: expand('responder_L'), responderPayloadKey: expand('responder_P'), sessionId: expand('session_id'),
    initiatorGarbageTerminator: terminators.slice(0, 16), responderGarbageTerminator: terminators.slice(16) }
}

/** RFC 8439 block function (32-bit counter and 96-bit nonce). */
export function bip324ChaCha20Block(key: Uint8Array, nonce: Uint8Array, counter: number): Uint8Array {
  exact(key, 32, 'key'); exact(nonce, 12, 'nonce')
  if (!Number.isInteger(counter) || counter < 0 || counter > 0xffffffff) throw new RangeError('ChaCha20 counter must be uint32')
  const initial = new Uint32Array(16)
  initial.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574])
  const k = new DataView(key.buffer, key.byteOffset, key.byteLength), n = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength)
  for (let i = 0; i < 8; i++) initial[4 + i] = k.getUint32(i * 4, true)
  initial[12] = counter
  for (let i = 0; i < 3; i++) initial[13 + i] = n.getUint32(i * 4, true)
  const state = initial.slice()
  const rotate = (v: number, bits: number) => (v << bits) | (v >>> (32 - bits))
  const quarter = (a: number, b: number, c: number, d: number) => {
    state[a] += state[b]; state[d] = rotate(state[d] ^ state[a], 16)
    state[c] += state[d]; state[b] = rotate(state[b] ^ state[c], 12)
    state[a] += state[b]; state[d] = rotate(state[d] ^ state[a], 8)
    state[c] += state[d]; state[b] = rotate(state[b] ^ state[c], 7)
  }
  for (let i = 0; i < 10; i++) {
    quarter(0, 4, 8, 12); quarter(1, 5, 9, 13); quarter(2, 6, 10, 14); quarter(3, 7, 11, 15)
    quarter(0, 5, 10, 15); quarter(1, 6, 11, 12); quarter(2, 7, 8, 13); quarter(3, 4, 9, 14)
  }
  const out = new Uint8Array(64), view = new DataView(out.buffer)
  for (let i = 0; i < 16; i++) view.setUint32(i * 4, (state[i] + initial[i]) >>> 0, true)
  return out
}
function stream(key: Uint8Array, nonce: Uint8Array, offset: number, length: number): Uint8Array {
  const result = new Uint8Array(length)
  for (let written = 0; written < length;) {
    const block = bip324ChaCha20Block(key, nonce, Math.floor(offset / 64)), start = offset % 64
    const count = Math.min(64 - start, length - written)
    result.set(block.subarray(start, start + count), written)
    written += count; offset += count
  }
  return result
}
function xor(a: Uint8Array, b: Uint8Array): Uint8Array { return a.map((byte, i) => byte ^ b[i]) }
function poly1305(key: Uint8Array, data: Uint8Array): Uint8Array {
  const r = fromLE(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn
  const s = fromLE(key.subarray(16)), prime = (1n << 130n) - 5n
  let accumulator = 0n
  for (let offset = 0; offset < data.length; offset += 16) {
    const block = data.subarray(offset, offset + 16)
    accumulator = ((accumulator + fromLE(block) + (1n << BigInt(8 * block.length))) * r) % prime
  }
  return le((accumulator + s) & ((1n << 128n) - 1n), 16)
}
function mac(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const pad = (length: number) => new Uint8Array((16 - length % 16) % 16)
  return poly1305(bip324ChaCha20Block(key, nonce, 0).subarray(0, 32),
    concat(aad, pad(aad.length), ciphertext, pad(ciphertext.length), le(BigInt(aad.length), 8), le(BigInt(ciphertext.length), 8)))
}
export function bip324AeadEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const ciphertext = xor(plaintext, stream(key, nonce, 64, plaintext.length))
  return concat(ciphertext, mac(key, nonce, aad, ciphertext))
}
export function bip324AeadDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertextAndTag: Uint8Array): Uint8Array | null {
  exact(key, 32, 'key'); exact(nonce, 12, 'nonce')
  if (ciphertextAndTag.length < 16) return null
  const ciphertext = ciphertextAndTag.subarray(0, -16), expected = mac(key, nonce, aad, ciphertext)
  let difference = 0
  for (let i = 0; i < 16; i++) difference |= expected[i] ^ ciphertextAndTag[ciphertext.length + i]
  return difference === 0 ? xor(ciphertext, stream(key, nonce, 64, ciphertext.length)) : null
}

export interface Bip324DirectionKeys { lengthKey: Uint8Array; payloadKey: Uint8Array }
export interface Bip324DecodedPacket { contents: Uint8Array; flags: number; ignore: boolean; packetIndex: number }
/** Stateful reference framer for one direction. Use separate instances for sending/receiving.
 * An authentication or framing failure permanently closes the instance.
 */
export class Bip324PacketCipher {
  private lengthKey: Uint8Array
  private payloadKey: Uint8Array
  private index = 0
  private failed = false
  public get packetIndex(): number { return this.index }
  public constructor(keys: Bip324DirectionKeys, packetIndex = 0) {
    exact(keys.lengthKey, 32, 'lengthKey'); exact(keys.payloadKey, 32, 'payloadKey')
    if (!Number.isSafeInteger(packetIndex) || packetIndex < 0 || packetIndex > BIP324_MAX_AUDIT_PACKET_INDEX) {
      throw new RangeError(`packetIndex must be in [0, ${BIP324_MAX_AUDIT_PACKET_INDEX}]`)
    }
    this.lengthKey = keys.lengthKey.slice(); this.payloadKey = keys.payloadKey.slice()
    for (let epoch = 0; epoch < Math.floor(packetIndex / BIP324_REKEY_INTERVAL); epoch++) this.rekey(epoch)
    this.index = packetIndex
  }
  private nonce(counter: number): Uint8Array {
    return concat(le(BigInt(counter), 4), le(BigInt(Math.floor(this.index / BIP324_REKEY_INTERVAL)), 8))
  }
  private rekey(epoch: number): void {
    const suffix = le(BigInt(epoch), 8)
    const nextLength = stream(this.lengthKey, concat(new Uint8Array(4), suffix), 3 * BIP324_REKEY_INTERVAL, 32)
    const nextPayload = bip324AeadEncrypt(this.payloadKey, concat(new Uint8Array(4).fill(255), suffix), new Uint8Array(0), new Uint8Array(32)).slice(0, 32)
    this.lengthKey.fill(0); this.payloadKey.fill(0)
    this.lengthKey = nextLength; this.payloadKey = nextPayload
  }
  private advance(): void {
    if ((this.index + 1) % BIP324_REKEY_INTERVAL === 0) this.rekey(Math.floor(this.index / BIP324_REKEY_INTERVAL))
    this.index++
  }
  private ensureOpen(): void {
    if (this.failed) throw new RangeError('BIP-324 cipher is closed after a framing/authentication failure')
    if (this.index >= Number.MAX_SAFE_INTEGER) throw new RangeError('BIP-324 packet counter exhausted')
  }
  private cryptLength(bytes: Uint8Array): Uint8Array {
    return xor(bytes, stream(this.lengthKey, this.nonce(0), 3 * (this.index % BIP324_REKEY_INTERVAL), 3))
  }
  public encode(contents: Uint8Array, aad: Uint8Array = new Uint8Array(0), flags = 0): Uint8Array {
    this.ensureOpen()
    if (contents.length > BIP324_MAX_CONTENT_LENGTH) throw new RangeError('BIP-324 content length exceeds uint24')
    if (!Number.isInteger(flags) || flags < 0 || flags > 255) throw new RangeError('flags must be a byte')
    const length = this.cryptLength(le(BigInt(contents.length), 3))
    const encrypted = bip324AeadEncrypt(this.payloadKey, this.nonce(this.index % BIP324_REKEY_INTERVAL), aad, concat(new Uint8Array([flags]), contents))
    this.advance()
    return concat(length, encrypted)
  }
  public decode(packet: Uint8Array, aad: Uint8Array = new Uint8Array(0)): Bip324DecodedPacket {
    this.ensureOpen()
    try {
      if (packet.length < BIP324_PACKET_OVERHEAD) throw new RangeError('Truncated BIP-324 packet')
      const length = Number(fromLE(this.cryptLength(packet.subarray(0, 3))))
      if (packet.length !== length + BIP324_PACKET_OVERHEAD) throw new RangeError('Encrypted length mismatch: tampering, truncation or wrong cipher state')
      const plaintext = bip324AeadDecrypt(this.payloadKey, this.nonce(this.index % BIP324_REKEY_INTERVAL), aad, packet.subarray(3))
      if (plaintext === null) throw new RangeError('Poly1305 authentication failed: corrupted packet, AAD or wrong cipher state')
      const result = { contents: plaintext.slice(1), flags: plaintext[0], ignore: (plaintext[0] & 0x80) !== 0, packetIndex: this.index }
      this.advance()
      return result
    } catch (error) {
      this.failed = true; this.lengthKey.fill(0); this.payloadKey.fill(0)
      throw error
    }
  }
}

export interface Bip324FrameAuditOptions {
  /** Initial directional keys; packetIndex advances their BIP-324 ratchets. */
  keys?: Bip324DirectionKeys
  packetIndex?: number
  aad?: Uint8Array
  inspectApplicationPayload?: boolean
}
export interface Bip324FrameFinding { code: string; severity: 'fatal' | 'warning' | 'info'; message: string }
export interface Bip324FrameAuditResult {
  valid: boolean | null
  authenticationVerified: boolean
  wireLength: number
  contentLength?: number
  contentsHex?: string
  flags?: number
  ignore?: boolean
  packetIndex?: number
  findings: Bip324FrameFinding[]
  verificationScope: 'bip324-authenticated-frame' | 'bip324-wire-inspection'
}
function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('') }
function plaintextV1(bytes: Uint8Array): boolean {
  if (bytes.length < 16 || !['f9beb4d9', '0b110907', 'fabfb5da', '0a03cf40'].includes(hex(bytes.subarray(0, 4)))) return false
  let padding = false, letters = 0
  for (const byte of bytes.subarray(4, 16)) {
    if (byte === 0) padding = true
    else if (padding || byte < 0x20 || byte > 0x7e) return false
    else letters++
  }
  return letters > 0
}
export function auditBip324Frame(packet: Uint8Array, options: Bip324FrameAuditOptions = {}): Bip324FrameAuditResult {
  const result: Bip324FrameAuditResult = { valid: null, authenticationVerified: false, wireLength: packet.length,
    findings: [], verificationScope: options.keys ? 'bip324-authenticated-frame' : 'bip324-wire-inspection' }
  const fatal = (code: string, message: string) => { result.valid = false; result.findings.push({ code, severity: 'fatal', message }) }
  if (plaintextV1(packet)) { fatal('plaintext-p2p-leak', 'Recognizable plaintext Bitcoin v1 network header'); return result }
  if (packet.length < BIP324_PACKET_OVERHEAD) { fatal('truncated-frame', 'BIP-324 frames require at least 20 bytes'); return result }
  if (!options.keys) {
    result.findings.push({ code: 'keys-required', severity: 'info', message: 'Encrypted length and Poly1305 tag require directional keys and packet state; authenticity is unverified' })
    return result
  }
  const cipher = new Bip324PacketCipher(options.keys, options.packetIndex)
  let decoded: Bip324DecodedPacket
  try { decoded = cipher.decode(packet, options.aad) }
  catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    fatal(message.includes('length mismatch') ? 'frame-length-mismatch' : 'authentication-failed', message)
    return result
  }
  result.valid = true; result.authenticationVerified = true
  result.contentLength = decoded.contents.length; result.contentsHex = hex(decoded.contents)
  result.flags = decoded.flags; result.ignore = decoded.ignore; result.packetIndex = decoded.packetIndex
  if ((decoded.flags & 0x7f) !== 0) result.findings.push({ code: 'reserved-flags', severity: 'info', message: 'BIP-324 receivers ignore the low seven header bits' })
  if (options.inspectApplicationPayload && !decoded.ignore) {
    const payload = decoded.contents
    if (payload.length === 0) fatal('missing-message-type', 'Application contents require a message type (empty version-negotiation contents are valid outside this scope)')
    else if (payload[0] === 0) {
      if (payload.length < 13) fatal('truncated-message-type', 'Long message type requires a 12-byte command after the zero prefix')
      else {
        let padding = false, characters = 0, valid = true
        for (const byte of payload.subarray(1, 13)) {
          if (byte === 0) padding = true
          else if (padding || byte < 0x20 || byte > 0x7e) valid = false
          else characters++
        }
        if (!valid || characters === 0) fatal('non-canonical-command', 'Message command must be printable ASCII with trailing zero padding')
      }
    }
  }
  return result
}
