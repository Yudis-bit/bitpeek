import { BitpeekError } from './errors'

const CRC32_TABLE = new Uint32Array(256)
for (let i = 0; i < 256; i++) {
  let c = i
  for (let k = 0; k < 8; k++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1)
  }
  CRC32_TABLE[i] = c >>> 0
}

export class Crc32 {
  private crc = 0xffffffff

  update(chunk: Uint8Array): this {
    let c = this.crc
    for (let i = 0; i < chunk.length; i++) {
      c = (c >>> 8) ^ (CRC32_TABLE[(c ^ (chunk[i] ?? 0)) & 0xff] ?? 0)
    }
    this.crc = c >>> 0
    return this
  }

  digest(): number {
    return (this.crc ^ 0xffffffff) >>> 0
  }

  digestHex(): string {
    return this.digest().toString(16).toUpperCase().padStart(8, '0')
  }
}

export function crc32(bytes: Uint8Array): number {
  return new Crc32().update(bytes).digest()
}

export class Crc16Ccitt {
  private crc = 0xffff

  update(chunk: Uint8Array): this {
    let c = this.crc
    for (let i = 0; i < chunk.length; i++) {
      c ^= (chunk[i] ?? 0) << 8
      for (let bit = 0; bit < 8; bit++) {
        c = (c & 0x8000) !== 0 ? ((c << 1) ^ 0x1021) & 0xffff : (c << 1) & 0xffff
      }
    }
    this.crc = c
    return this
  }

  digest(): number {
    return this.crc & 0xffff
  }

  digestHex(): string {
    return this.digest().toString(16).toUpperCase().padStart(4, '0')
  }
}

export function crc16(bytes: Uint8Array): number {
  return new Crc16Ccitt().update(bytes).digest()
}

// SHA-256 standard implementation (FIPS 180-4)
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

export class Sha256 {
  private h0 = 0x6a09e667
  private h1 = 0xbb67ae85
  private h2 = 0x3c6ef372
  private h3 = 0xa54ff53a
  private h4 = 0x510e527f
  private h5 = 0x9b05688c
  private h6 = 0x1f83d9ab
  private h7 = 0x5be0cd19

  private block = new Uint8Array(64)
  private blockLen = 0
  private totalBytes = 0
  private w = new Uint32Array(64)
  private finalized = false

  update(chunk: Uint8Array): this {
    if (this.finalized) {
      throw new BitpeekError('INVALID_INPUT', 'Cannot update finalized SHA-256 instance.')
    }
    this.totalBytes += chunk.length
    let offset = 0
    let len = chunk.length

    while (len > 0) {
      if (this.blockLen === 0 && len >= 64) {
        this.processBlock(chunk.subarray(offset, offset + 64))
        offset += 64
        len -= 64
      } else {
        const toCopy = Math.min(64 - this.blockLen, len)
        this.block.set(chunk.subarray(offset, offset + toCopy), this.blockLen)
        this.blockLen += toCopy
        offset += toCopy
        len -= toCopy

        if (this.blockLen === 64) {
          this.processBlock(this.block)
          this.blockLen = 0
        }
      }
    }
    return this
  }

  private processBlock(b: Uint8Array): void {
    const w = this.w
    for (let i = 0; i < 16; i++) {
      w[i] =
        ((b[i * 4] ?? 0) << 24) |
        ((b[i * 4 + 1] ?? 0) << 16) |
        ((b[i * 4 + 2] ?? 0) << 8) |
        (b[i * 4 + 3] ?? 0)
    }
    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15] ?? 0
      const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3)
      const w2 = w[i - 2] ?? 0
      const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10)
      w[i] = (((w[i - 16] ?? 0) + s0 + (w[i - 7] ?? 0) + s1) >>> 0)
    }

    let a = this.h0
    let b0 = this.h1
    let c = this.h2
    let d = this.h3
    let e = this.h4
    let f = this.h5
    let g = this.h6
    let h = this.h7

    for (let i = 0; i < 64; i++) {
      const s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))
      const ch = (e & f) ^ (~e & g)
      const temp1 = (h + s1 + ch + (K256[i] ?? 0) + (w[i] ?? 0)) >>> 0
      const s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))
      const maj = (a & b0) ^ (a & c) ^ (b0 & c)
      const temp2 = (s0 + maj) >>> 0

      h = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b0
      b0 = a
      a = (temp1 + temp2) >>> 0
    }

    this.h0 = (this.h0 + a) >>> 0
    this.h1 = (this.h1 + b0) >>> 0
    this.h2 = (this.h2 + c) >>> 0
    this.h3 = (this.h3 + d) >>> 0
    this.h4 = (this.h4 + e) >>> 0
    this.h5 = (this.h5 + f) >>> 0
    this.h6 = (this.h6 + g) >>> 0
    this.h7 = (this.h7 + h) >>> 0
  }

  digest(): Uint8Array {
    if (!this.finalized) {
      // Append bit '1'
      this.block[this.blockLen++] = 0x80
      if (this.blockLen > 56) {
        this.block.fill(0, this.blockLen, 64)
        this.processBlock(this.block)
        this.blockLen = 0
      }
      this.block.fill(0, this.blockLen, 56)

      // Total bits as 64-bit big endian integer
      const totalBits = BigInt(this.totalBytes) * 8n
      const view = new DataView(this.block.buffer, this.block.byteOffset, 64)
      view.setBigUint64(56, totalBits, false)

      this.processBlock(this.block)
      this.finalized = true
    }

    const out = new Uint8Array(32)
    const view = new DataView(out.buffer, out.byteOffset, 32)
    view.setUint32(0, this.h0, false)
    view.setUint32(4, this.h1, false)
    view.setUint32(8, this.h2, false)
    view.setUint32(12, this.h3, false)
    view.setUint32(16, this.h4, false)
    view.setUint32(20, this.h5, false)
    view.setUint32(24, this.h6, false)
    view.setUint32(28, this.h7, false)
    return out
  }

  digestHex(): string {
    const raw = this.digest()
    let hex = ''
    for (let i = 0; i < raw.length; i++) {
      hex += (raw[i] ?? 0).toString(16).padStart(2, '0')
    }
    return hex
  }
}

export function sha256Hex(bytes: Uint8Array): string {
  return new Sha256().update(bytes).digestHex()
}

export async function sha256Stream(
  chunks: AsyncIterable<Uint8Array>,
  signal?: AbortSignal,
  onProgress?: (bytesProcessed: number) => void,
): Promise<string> {
  const hasher = new Sha256()
  let processed = 0
  for await (const chunk of chunks) {
    if (signal?.aborted) {
      throw new BitpeekError('CANCELLED', 'Hash stream was aborted.')
    }
    hasher.update(chunk)
    processed += chunk.length
    if (onProgress) onProgress(processed)
  }
  return hasher.digestHex()
}
