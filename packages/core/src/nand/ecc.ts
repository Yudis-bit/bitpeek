/**
 * Bitpeek Ultra - Reference NAND ECC Codec (Hamming SECDED)
 *
 * Implements Section 13 (NAND-04, AC044, AC045):
 * - Standard 256-byte SmartMedia / Linux MTD NAND Hamming ECC codec
 * - Separate encode, check, decode operations
 * - Bit correction ledger tracking byte offset, bit index, original/corrected bits
 * - Differentiates clean, corrected, uncorrectable, and erased states
 */

export interface EccCorrectionRecord {
  codewordIndex: number
  byteOffset: number
  bitIndex: number
  originalBit: number
  correctedBit: number
  syndrome: number
}

export type EccCheckStatus =
  | 'clean'
  | 'corrected'
  | 'uncorrectable'
  | 'erased'
  | 'parity_error'

export interface EccDecodeResult {
  status: EccCheckStatus
  correctedData: Uint8Array
  corrections: EccCorrectionRecord[]
  syndromeBytes: Uint8Array
}

// Parity table for 8-bit bytes (even parity: count of 1s % 2)
const PARITY_TABLE = new Uint8Array(256)
for (let i = 0; i < 256; i++) {
  let count = 0
  for (let b = 0; b < 8; b++) {
    if ((i & (1 << b)) !== 0) count++
  }
  PARITY_TABLE[i] = count & 1
}

// Precomputed column parity tables
// cp[byte] -> 6 bits: [p4, p4', p2, p2', p1, p1']
const CP_TABLE = new Uint8Array(256)
for (let b = 0; b < 256; b++) {
  const bit0 = (b >> 0) & 1
  const bit1 = (b >> 1) & 1
  const bit2 = (b >> 2) & 1
  const bit3 = (b >> 3) & 1
  const bit4 = (b >> 4) & 1
  const bit5 = (b >> 5) & 1
  const bit6 = (b >> 6) & 1
  const bit7 = (b >> 7) & 1

  // P1: odd bits (1, 3, 5, 7)
  const p1 = bit1 ^ bit3 ^ bit5 ^ bit7
  const p1Inv = bit0 ^ bit2 ^ bit4 ^ bit6

  // P2: bits (2, 3, 6, 7)
  const p2 = bit2 ^ bit3 ^ bit6 ^ bit7
  const p2Inv = bit0 ^ bit1 ^ bit4 ^ bit5

  // P4: bits (4, 5, 6, 7)
  const p4 = bit4 ^ bit5 ^ bit6 ^ bit7
  const p4Inv = bit0 ^ bit1 ^ bit2 ^ bit3

  CP_TABLE[b] =
    (p4 << 5) | (p4Inv << 4) | (p2 << 3) | (p2Inv << 2) | (p1 << 1) | p1Inv
}

/**
 * Calculates 3 parity bytes for a 256-byte data block.
 */
export function encodeHamming256(data: Uint8Array, offset = 0): Uint8Array {
  if (data.length < offset + 256) {
    throw new Error(`Data too short for 256-byte ECC encode: ${data.length - offset} bytes available`)
  }

  let lineP = 0 // Line parity bits (p8..p1024)
  let linePInv = 0 // Complement line parity bits
  let colP = 0 // Accumulated column parity

  for (let i = 0; i < 256; i++) {
    const val = data[offset + i]!
    const parity = PARITY_TABLE[val]!

    if (parity === 1) {
      lineP ^= i
      linePInv ^= ~i & 0xff
    }

    colP ^= CP_TABLE[val]!
  }

  // Construct 3 parity bytes according to standard SmartMedia/NAND ECC format:
  // Byte 0: [p64, p64', p32, p32', p16, p16', p8, p8']
  // Byte 1: [p1024, p1024', p512, p512', p256, p256', p128, p128']
  // Byte 2: [p4, p4', p2, p2', p1, p1', 1, 1]

  const p8 = (lineP >> 0) & 1
  const p8Inv = (linePInv >> 0) & 1
  const p16 = (lineP >> 1) & 1
  const p16Inv = (linePInv >> 1) & 1
  const p32 = (lineP >> 2) & 1
  const p32Inv = (linePInv >> 2) & 1
  const p64 = (lineP >> 3) & 1
  const p64Inv = (linePInv >> 3) & 1

  const p128 = (lineP >> 4) & 1
  const p128Inv = (linePInv >> 4) & 1
  const p256 = (lineP >> 5) & 1
  const p256Inv = (linePInv >> 5) & 1
  const p512 = (lineP >> 6) & 1
  const p512Inv = (linePInv >> 6) & 1
  const p1024 = (lineP >> 7) & 1
  const p1024Inv = (linePInv >> 7) & 1

  const byte0 =
    ~((p64 << 7) | (p64Inv << 6) | (p32 << 5) | (p32Inv << 4) | (p16 << 3) | (p16Inv << 2) | (p8 << 1) | p8Inv) & 0xff

  const byte1 =
    ~((p1024 << 7) | (p1024Inv << 6) | (p512 << 5) | (p512Inv << 4) | (p256 << 3) | (p256Inv << 2) | (p128 << 1) | p128Inv) & 0xff

  const byte2 = ~(colP << 2) & 0xfc | 0x03

  return new Uint8Array([byte0, byte1, byte2])
}

/**
 * Checks and corrects a 256-byte data block against 3 parity bytes.
 */
export function decodeHamming256(
  data: Uint8Array,
  readParity: Uint8Array,
  dataOffset = 0,
  parityOffset = 0,
  codewordIndex = 0,
): EccDecodeResult {
  // Check for erased state (all 0xFF in data and parity)
  let isErased = true
  for (let i = 0; i < 256; i++) {
    if (data[dataOffset + i] !== 0xff) {
      isErased = false
      break
    }
  }
  if (isErased && readParity[parityOffset] === 0xff && readParity[parityOffset + 1] === 0xff && readParity[parityOffset + 2] === 0xff) {
    return {
      status: 'erased',
      correctedData: data.slice(dataOffset, dataOffset + 256),
      corrections: [],
      syndromeBytes: new Uint8Array([0, 0, 0]),
    }
  }

  // Calculate actual parity over data
  const calcParity = encodeHamming256(data, dataOffset)

  // Compute XOR syndrome bytes
  const syn0 = (calcParity[0]! ^ readParity[parityOffset]!) & 0xff
  const syn1 = (calcParity[1]! ^ readParity[parityOffset + 1]!) & 0xff
  const syn2 = (calcParity[2]! ^ readParity[parityOffset + 2]!) & 0xfc
  const syndromeBytes = new Uint8Array([syn0, syn1, syn2])

  // If syndrome is 0, no error
  if (syn0 === 0 && syn1 === 0 && syn2 === 0) {
    return {
      status: 'clean',
      correctedData: data.slice(dataOffset, dataOffset + 256),
      corrections: [],
      syndromeBytes,
    }
  }

  // Count number of 1-bits in the syndrome
  const totalBits = countOnes(syn0) + countOnes(syn1) + countOnes(syn2)

  // A single bit error in data produces exactly 11 bit flips across line & column pairs
  // (8 pairs for line parity + 3 pairs for column parity)
  // Each pair must have one bit 1 and one bit 0: (P ^ P_inv) === 1
  const pairsOk =
    checkPair(syn0, 0) &&
    checkPair(syn0, 2) &&
    checkPair(syn0, 4) &&
    checkPair(syn0, 6) &&
    checkPair(syn1, 0) &&
    checkPair(syn1, 2) &&
    checkPair(syn1, 4) &&
    checkPair(syn1, 6) &&
    checkPair(syn2, 2) &&
    checkPair(syn2, 4) &&
    checkPair(syn2, 6)

  if (totalBits === 11 && pairsOk) {
    // Single bit error in data
    // Extract line byte address (0..255)
    const byteAddr =
      (((syn0 >> 1) & 1) << 0) |
      (((syn0 >> 3) & 1) << 1) |
      (((syn0 >> 5) & 1) << 2) |
      (((syn0 >> 7) & 1) << 3) |
      (((syn1 >> 1) & 1) << 4) |
      (((syn1 >> 3) & 1) << 5) |
      (((syn1 >> 5) & 1) << 6) |
      (((syn1 >> 7) & 1) << 7)

    // Extract bit index in byte (0..7)
    const bitAddr =
      (((syn2 >> 3) & 1) << 0) |
      (((syn2 >> 5) & 1) << 1) |
      (((syn2 >> 7) & 1) << 2)

    // Clone data and correct the bit
    const correctedData = data.slice(dataOffset, dataOffset + 256)
    const origByte = correctedData[byteAddr]!
    const origBit = (origByte >> bitAddr) & 1
    const correctedBit = origBit ^ 1
    correctedData[byteAddr] = origByte ^ (1 << bitAddr)

    const correction: EccCorrectionRecord = {
      codewordIndex,
      byteOffset: byteAddr,
      bitIndex: bitAddr,
      originalBit: origBit,
      correctedBit,
      syndrome: (syn1 << 16) | (syn0 << 8) | syn2,
    }

    return {
      status: 'corrected',
      correctedData,
      corrections: [correction],
      syndromeBytes,
    }
  }

  // If exactly 1 bit is set in syndrome, it was a bit flip in the parity itself
  if (totalBits === 1) {
    return {
      status: 'parity_error',
      correctedData: data.slice(dataOffset, dataOffset + 256),
      corrections: [],
      syndromeBytes,
    }
  }

  // Otherwise, multi-bit uncorrectable error
  return {
    status: 'uncorrectable',
    correctedData: data.slice(dataOffset, dataOffset + 256),
    corrections: [],
    syndromeBytes,
  }
}

function countOnes(val: number): number {
  let c = 0
  for (let i = 0; i < 8; i++) {
    if ((val & (1 << i)) !== 0) c++
  }
  return c
}

function checkPair(byteVal: number, lsb: number): boolean {
  const b0 = (byteVal >> lsb) & 1
  const b1 = (byteVal >> (lsb + 1)) & 1
  return (b0 ^ b1) === 1
}
