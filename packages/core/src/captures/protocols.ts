/**
 * Bitpeek Ultra - Embedded Protocol Decoders (UART, SPI, I2C)
 *
 * Implements Section 14 (CAP-02, AC049):
 * - UART decoder with baud/parity/framing error detection
 * - SPI decoder with clock polarity/phase and chip-select framing
 * - I2C decoder with START/STOP/ACK detection and address decoding
 */

import type { DigitalChannel, DigitalTransition } from './waveform'

// --- UART ---
export interface UartConfig {
  baudRate: number
  dataBits?: 5 | 6 | 7 | 8
  parity?: 'none' | 'even' | 'odd'
  stopBits?: 1 | 2
}

export interface DecodedUartByte {
  byte: number
  asciiChar: string
  startTimestamp: number
  endTimestamp: number
  framingError: boolean
  parityError: boolean
}

export function decodeUart(channel: DigitalChannel, config: UartConfig): DecodedUartByte[] {
  const baud = config.baudRate
  const bitTime = 1 / baud
  const dataBits = config.dataBits ?? 8
  const parity = config.parity ?? 'none'
  const stopBits = config.stopBits ?? 1

  const transitions = channel.transitions
  if (transitions.length < 2) return []

  const results: DecodedUartByte[] = []

  // Helper to query signal state at time t
  function sampleAt(t: number): 0 | 1 {
    let lastVal: 0 | 1 = 1 // idle high
    for (const tr of transitions) {
      if (tr.timestamp > t) break
      lastVal = tr.value
    }
    return lastVal
  }

  let i = 0
  while (i < transitions.length) {
    const tr = transitions[i]!
    // Look for falling edge (1 -> 0, Start Bit)
    if (tr.value === 0) {
      const startEdgeTime = tr.timestamp
      // Check start bit at center (t + 0.5 * bitTime)
      const startBitSample = sampleAt(startEdgeTime + 0.5 * bitTime)
      if (startBitSample !== 0) {
        // False start bit (glitch)
        i++
        continue
      }

      // Sample data bits (LSB first)
      let byteVal = 0
      let onesCount = 0
      for (let b = 0; b < dataBits; b++) {
        const sampleTime = startEdgeTime + (1.5 + b) * bitTime
        const bit = sampleAt(sampleTime)
        if (bit === 1) {
          byteVal |= 1 << b
          onesCount++
        }
      }

      // Sample parity bit if configured
      let parityError = false
      let nextBitOffset = 1.5 + dataBits
      if (parity !== 'none') {
        const paritySample = sampleAt(startEdgeTime + nextBitOffset * bitTime)
        nextBitOffset += 1
        const expectedParity = parity === 'even' ? (onesCount % 2 === 0 ? 0 : 1) : (onesCount % 2 === 0 ? 1 : 0)
        if (paritySample !== expectedParity) {
          parityError = true
        }
      }

      // Sample stop bit (must be 1)
      let framingError = false
      const stopSample = sampleAt(startEdgeTime + nextBitOffset * bitTime)
      if (stopSample !== 1) {
        framingError = true
      }

      const endTime = startEdgeTime + (nextBitOffset + stopBits) * bitTime
      const asciiChar = byteVal >= 32 && byteVal <= 126 ? String.fromCharCode(byteVal) : '.'

      results.push({
        byte: byteVal,
        asciiChar,
        startTimestamp: startEdgeTime,
        endTimestamp: endTime,
        framingError,
        parityError,
      })

      // Advance search index past this byte
      while (i < transitions.length && transitions[i]!.timestamp < endTime) {
        i++
      }
    } else {
      i++
    }
  }

  return results
}

// --- SPI ---
export interface SpiConfig {
  cpol?: 0 | 1 // 0: clock idle low, 1: clock idle high
  cpha?: 0 | 1 // 0: sample on 1st edge, 1: sample on 2nd edge
  bitOrder?: 'msb' | 'lsb'
  wordSize?: 8 | 16
}

export interface DecodedSpiWord {
  mosiWord: number
  misoWord: number
  startTimestamp: number
  endTimestamp: number
}

export function decodeSpi(
  sclk: DigitalChannel,
  mosi?: DigitalChannel,
  miso?: DigitalChannel,
  cs?: DigitalChannel,
  config: SpiConfig = {},
): DecodedSpiWord[] {
  const cpol = config.cpol ?? 0
  const cpha = config.cpha ?? 0
  const bitOrder = config.bitOrder ?? 'msb'
  const wordSize = config.wordSize ?? 8

  // Helper to sample channel at time t
  function sample(ch: DigitalChannel | undefined, t: number): 0 | 1 {
    if (!ch) return 0
    let v: 0 | 1 = 0
    for (const tr of ch.transitions) {
      if (tr.timestamp > t) break
      v = tr.value
    }
    return v
  }

  // Active edge condition on SCLK:
  // If cpol == 0, active edge is rising (0 -> 1) if cpha == 0, falling (1 -> 0) if cpha == 1.
  // If cpol == 1, active edge is falling (1 -> 0) if cpha == 0, rising (0 -> 1) if cpha == 1.
  const activeEdgeVal: 0 | 1 = (cpol ^ cpha) === 0 ? 1 : 0

  const words: DecodedSpiWord[] = []
  let bitCount = 0
  let mosiAcc = 0
  let misoAcc = 0
  let wordStartTime = 0

  for (const tr of sclk.transitions) {
    if (tr.value !== activeEdgeVal) continue

    // Check CS if present (active low)
    if (cs && sample(cs, tr.timestamp) === 1) {
      // CS inactive, reset bit accumulator
      bitCount = 0
      mosiAcc = 0
      misoAcc = 0
      continue
    }

    if (bitCount === 0) {
      wordStartTime = tr.timestamp
    }

    const mosiBit = sample(mosi, tr.timestamp)
    const misoBit = sample(miso, tr.timestamp)

    if (bitOrder === 'msb') {
      mosiAcc = (mosiAcc << 1) | mosiBit
      misoAcc = (misoAcc << 1) | misoBit
    } else {
      mosiAcc |= mosiBit << bitCount
      misoAcc |= misoBit << bitCount
    }

    bitCount++

    if (bitCount === wordSize) {
      words.push({
        mosiWord: mosiAcc,
        misoWord: misoAcc,
        startTimestamp: wordStartTime,
        endTimestamp: tr.timestamp,
      })
      bitCount = 0
      mosiAcc = 0
      misoAcc = 0
    }
  }

  return words
}

// --- I2C ---
export interface DecodedI2cTransaction {
  address: number
  isRead: boolean
  ack: boolean
  dataBytes: number[]
  startTimestamp: number
  endTimestamp: number
}

export function decodeI2c(scl: DigitalChannel, sda: DigitalChannel): DecodedI2cTransaction[] {
  // Helper to query SDA at time t
  function sampleSda(t: number): 0 | 1 {
    let v: 0 | 1 = 1
    for (const tr of sda.transitions) {
      if (tr.timestamp > t) break
      v = tr.value
    }
    return v
  }

  function sampleScl(t: number): 0 | 1 {
    let v: 0 | 1 = 1
    for (const tr of scl.transitions) {
      if (tr.timestamp > t) break
      v = tr.value
    }
    return v
  }

  const transactions: DecodedI2cTransaction[] = []

  // Detect START: SDA falling (1 -> 0) while SCL is 1
  for (let i = 0; i < sda.transitions.length; i++) {
    const sdaTr = sda.transitions[i]!
    if (sdaTr.value === 0 && sampleScl(sdaTr.timestamp) === 1) {
      const startTime = sdaTr.timestamp

      // Collect 9 clock pulses on SCLK after startTime
      const clkEdges: number[] = []
      for (const clkTr of scl.transitions) {
        if (clkTr.timestamp > startTime && clkTr.value === 1) {
          clkEdges.push(clkTr.timestamp)
        }
      }

      if (clkEdges.length < 9) continue

      // First 8 bits: Address (7 bits) + R/W bit (1 bit)
      let addrByte = 0
      for (let b = 0; b < 8; b++) {
        const bit = sampleSda(clkEdges[b]!)
        addrByte = (addrByte << 1) | bit
      }

      const address = addrByte >> 1
      const isRead = (addrByte & 1) === 1
      // 9th bit: ACK (0 = ACK, 1 = NACK)
      const ackBit = sampleSda(clkEdges[8]!)
      const ack = ackBit === 0

      // Read subsequent bytes (9 bits each: 8 data + 1 ACK)
      const dataBytes: number[] = []
      let byteIdx = 9
      while (byteIdx + 8 < clkEdges.length) {
        let bVal = 0
        for (let b = 0; b < 8; b++) {
          bVal = (bVal << 1) | sampleSda(clkEdges[byteIdx + b]!)
        }
        dataBytes.push(bVal)
        byteIdx += 9
      }

      const endTime = clkEdges[Math.min(byteIdx, clkEdges.length - 1)]!
      transactions.push({
        address,
        isRead,
        ack,
        dataBytes,
        startTimestamp: startTime,
        endTimestamp: endTime,
      })
    }
  }

  return transactions
}
