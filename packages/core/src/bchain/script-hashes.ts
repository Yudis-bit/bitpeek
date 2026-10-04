// Portable legacy Script hashes; core must also run in browsers without node:crypto.
function rotateLeft(word: number, bits: number): number {
  return ((word << bits) | (word >>> (32 - bits))) >>> 0
}

function padded(bytes: Uint8Array, littleEndian: boolean): Uint8Array {
  const result = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64)
  result.set(bytes)
  result[bytes.length] = 0x80
  new DataView(result.buffer).setBigUint64(result.length - 8, BigInt(bytes.length) * 8n, littleEndian)
  return result
}

export function sha1(bytes: Uint8Array): Uint8Array {
  const data = padded(bytes, false)
  const view = new DataView(data.buffer)
  const state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
  const words = new Uint32Array(80)
  for (let offset = 0; offset < data.length; offset += 64) {
    for (let i = 0; i < 16; i++) words[i] = view.getUint32(offset + i * 4, false)
    for (let i = 16; i < 80; i++) words[i] = rotateLeft(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1)
    let [a, b, c, d, e] = state
    for (let i = 0; i < 80; i++) {
      const f = i < 20 ? (b & c) | (~b & d) : i < 40 ? b ^ c ^ d : i < 60 ? (b & c) | (b & d) | (c & d) : b ^ c ^ d
      const k = i < 20 ? 0x5a827999 : i < 40 ? 0x6ed9eba1 : i < 60 ? 0x8f1bbcdc : 0xca62c1d6
      const next = (rotateLeft(a, 5) + f + e + k + words[i]) >>> 0
      ;[a, b, c, d, e] = [next, a, rotateLeft(b, 30), c, d]
    }
    for (const [i, value] of [a, b, c, d, e].entries()) state[i] = (state[i] + value) >>> 0
  }
  const result = new Uint8Array(20)
  const output = new DataView(result.buffer)
  state.forEach((word, i) => output.setUint32(i * 4, word, false))
  return result
}

const LEFT_WORDS = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
const RIGHT_WORDS = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
const LEFT_SHIFTS = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
const RIGHT_SHIFTS = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]

function ripemdRound(round: number, x: number, y: number, z: number): number {
  switch (round) {
    case 0: return x ^ y ^ z
    case 1: return (x & y) | (~x & z)
    case 2: return (x | ~y) ^ z
    case 3: return (x & z) | (y & ~z)
    default: return x ^ (y | ~z)
  }
}

export function ripemd160(bytes: Uint8Array): Uint8Array {
  const data = padded(bytes, true)
  const view = new DataView(data.buffer)
  const state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
  const words = new Uint32Array(16)
  const leftConstants = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]
  const rightConstants = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0]
  for (let offset = 0; offset < data.length; offset += 64) {
    for (let i = 0; i < 16; i++) words[i] = view.getUint32(offset + i * 4, true)
    let [a, b, c, d, e] = state
    let [aa, bb, cc, dd, ee] = state
    for (let i = 0; i < 80; i++) {
      const round = Math.floor(i / 16)
      const left = (rotateLeft((a + ripemdRound(round, b, c, d) + words[LEFT_WORDS[i]] + leftConstants[round]) >>> 0, LEFT_SHIFTS[i]) + e) >>> 0
      ;[a, b, c, d, e] = [e, left, b, rotateLeft(c, 10), d]
      const right = (rotateLeft((aa + ripemdRound(4 - round, bb, cc, dd) + words[RIGHT_WORDS[i]] + rightConstants[round]) >>> 0, RIGHT_SHIFTS[i]) + ee) >>> 0
      ;[aa, bb, cc, dd, ee] = [ee, right, bb, rotateLeft(cc, 10), dd]
    }
    const next = (state[1] + c + dd) >>> 0
    state[1] = (state[2] + d + ee) >>> 0
    state[2] = (state[3] + e + aa) >>> 0
    state[3] = (state[4] + a + bb) >>> 0
    state[4] = (state[0] + b + cc) >>> 0
    state[0] = next
  }
  const result = new Uint8Array(20)
  const output = new DataView(result.buffer)
  state.forEach((word, i) => output.setUint32(i * 4, word, true))
  return result
}
