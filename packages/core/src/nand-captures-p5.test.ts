import { describe, it, expect } from 'vitest'
import {
  NandGeometryManager,
  SYNTHETIC_LAB_NAND_PROFILE,
  ONFI_2K_64_PROFILE,
  encodeHamming256,
  decodeHamming256,
  MultiReadAnalyzer,
  SyntheticFtlReconstructor,
} from './nand'
import {
  parseCsvWaveform,
  parseVcdWaveform,
  decodeUart,
  decodeSpi,
  decodeI2c,
  CmsisSvdParser,
  type DigitalChannel,
} from './captures'
import { crc16 } from './crypto'

describe('Phase P5 - Raw NAND, ECC, and Hardware Captures', () => {
  describe('NAND Geometry & Address Mapping (NAND-01, AC041)', () => {
    it('maps offsets to physical coordinates and back reversibly across block and OOB boundaries', () => {
      const mgr = new NandGeometryManager(SYNTHETIC_LAB_NAND_PROFILE)
      // Page size: 512 + 16 = 528 bytes. Block size: 528 * 32 = 16,896 bytes.
      expect(mgr.getRawPageSize()).toBe(528)
      expect(mgr.getRawBlockSize()).toBe(16896)

      // Test data offset inside Block 0, Page 0, Column 100
      const p1 = mgr.offsetToPhysical(100)
      expect(p1).toEqual({ chip: 0, lun: 0, block: 0, page: 0, column: 100, isOob: false })
      expect(mgr.physicalToOffset(p1)).toBe(100)

      // Test OOB offset inside Block 0, Page 0 (column 512..527)
      const pOob = mgr.offsetToPhysical(515)
      expect(pOob).toEqual({ chip: 0, lun: 0, block: 0, page: 0, column: 515, isOob: true })
      expect(mgr.physicalToOffset(pOob)).toBe(515)

      // Test boundary: Block 1, Page 0, Column 0 -> 16896
      const pBlock1 = mgr.offsetToPhysical(16896)
      expect(pBlock1).toEqual({ chip: 0, lun: 0, block: 1, page: 0, column: 0, isOob: false })
      expect(mgr.physicalToOffset(pBlock1)).toBe(16896)

      // Test ONFI profile page span
      const onfiMgr = new NandGeometryManager(ONFI_2K_64_PROFILE)
      const span = onfiMgr.getPageSpan(0, 0, 5, 10)
      expect(span.dataLength).toBe(2048)
      expect(span.oobLength).toBe(64)
      expect(span.rawLength).toBe(2112)
    })

    it('detects factory bad block markers in dump buffers (NAND-02, AC042)', () => {
      const mgr = new NandGeometryManager(SYNTHETIC_LAB_NAND_PROFILE)
      const dump = new Uint8Array(16896 * 3) // 3 blocks
      dump.fill(0xff) // clean erased blocks

      expect(mgr.isBlockBad(dump, 0)).toBe(false)
      expect(mgr.isBlockBad(dump, 1)).toBe(false)

      // Mark block 1 as bad by setting marker byte (offset 512 + 5 = 517) in page 0 of block 1
      const blk1Page0Offset = 16896 + (512 + 5)
      dump[blk1Page0Offset] = 0x00 // bad block indicator

      expect(mgr.isBlockBad(dump, 1)).toBe(true)
      expect(mgr.isBlockBad(dump, 0)).toBe(false)
    })
  })

  describe('Hamming SECDED Reference ECC Codec (NAND-04, AC044, AC045)', () => {
    it('encodes data, checks clean codewords, and correctly identifies erased pages', () => {
      const data = new Uint8Array(256)
      for (let i = 0; i < 256; i++) data[i] = (i * 37) & 0xff

      const parity = encodeHamming256(data)
      expect(parity.length).toBe(3)

      const decClean = decodeHamming256(data, parity)
      expect(decClean.status).toBe('clean')
      expect(decClean.corrections.length).toBe(0)

      // Erased page check (all 0xFF)
      const erasedData = new Uint8Array(256).fill(0xff)
      const erasedParity = new Uint8Array([0xff, 0xff, 0xff])
      const decErased = decodeHamming256(erasedData, erasedParity)
      expect(decErased.status).toBe('erased')
    })

    it('corrects single-bit errors across byte and bit positions and records correction ledger (AC044, AC045)', () => {
      const originalData = new Uint8Array(256)
      for (let i = 0; i < 256; i++) originalData[i] = (i * 13 + 7) & 0xff

      const parity = encodeHamming256(originalData)

      // Test multiple single-bit corruptions at various byte offsets and bit indices
      const testCases = [
        { byteIdx: 0, bitIdx: 0 },
        { byteIdx: 42, bitIdx: 5 },
        { byteIdx: 127, bitIdx: 3 },
        { byteIdx: 255, bitIdx: 7 },
      ]

      for (const tc of testCases) {
        const corruptedData = new Uint8Array(originalData)
        corruptedData[tc.byteIdx] ^= 1 << tc.bitIdx // Inject 1-bit flip

        const result = decodeHamming256(corruptedData, parity, 0, 0, 1)
        expect(result.status).toBe('corrected')
        expect(result.corrections.length).toBe(1)

        const ledger = result.corrections[0]!
        expect(ledger.byteOffset).toBe(tc.byteIdx)
        expect(ledger.bitIndex).toBe(tc.bitIdx)
        expect(ledger.correctedBit).toBe((originalData[tc.byteIdx]! >> tc.bitIdx) & 1)

        // Verify corrected buffer matches original exactly
        expect(result.correctedData).toEqual(originalData)
      }
    })

    it('detects uncorrectable double-bit errors without falsely declaring success (AC045)', () => {
      const data = new Uint8Array(256)
      data.fill(0x5a)
      const parity = encodeHamming256(data)

      // Inject 2-bit flip in byte 10
      const corrupted = new Uint8Array(data)
      corrupted[10] ^= 0x03 // flip bit 0 and bit 1

      const result = decodeHamming256(corrupted, parity)
      expect(result.status).toBe('uncorrectable')
      expect(result.corrections.length).toBe(0)
    })
  })

  describe('Multi-Read Variability & Majority Voting (NAND-03, AC046)', () => {
    it('analyzes bit variability across reads and performs majority reconstruction', () => {
      const groundTruth = new Uint8Array([0xaa, 0x55, 0x0f, 0xf0])
      // Read 1: clean
      const r1 = new Uint8Array(groundTruth)
      // Read 2: bit flip at byte 1, bit 0 (0x55 ^ 1 = 0x54)
      const r2 = new Uint8Array(groundTruth)
      r2[1] = 0x54
      // Read 3: bit flip at byte 3, bit 7 (0xf0 ^ 0x80 = 0x70)
      const r3 = new Uint8Array(groundTruth)
      r3[3] = 0x70

      const variability = MultiReadAnalyzer.analyzeVariability([r1, r2, r3])
      expect(variability.totalBytes).toBe(4)
      expect(variability.variableByteCount).toBe(2)
      expect(variability.variableBitCount).toBe(2)

      // Majority vote (2 out of 3 agree on true bits)
      const vote = MultiReadAnalyzer.reconstructMajority([r1, r2, r3], ['read-1', 'read-2', 'read-3'])
      expect(vote.reconstructed).toEqual(groundTruth)
      expect(vote.conflictByteOffsets.length).toBe(0)
      expect(vote.unanimousBitRatio).toBe((32 - 2) / 32)
      expect(vote.provenance.contributingReadCount).toBe(3)
    })
  })

  describe('Synthetic FTL Reconstruction (NAND-05, AC047)', () => {
    it('reconstructs logical block address stream resolving sequence updates, stale pages, and missing holes', () => {
      const geom = new NandGeometryManager(SYNTHETIC_LAB_NAND_PROFILE)
      const rawPageSize = geom.getRawPageSize() // 528
      const pageSize = 512

      // Create physical dump with 4 pages:
      // Page 0: LBA 0, seq 1, valid, content: 'Page0-v1'
      // Page 1: LBA 1, seq 1, valid, content: 'Page1-v1'
      // Page 2: LBA 0, seq 2, valid (update!), content: 'Page0-v2' (should overwrite Page 0)
      // Page 3: LBA 3, seq 1, valid, content: 'Page3-v1' (note: LBA 2 is missing/hole!)
      const dump = new Uint8Array(rawPageSize * 4)

      const writePage = (pageIdx: number, lba: number, seq: number, flags: number, text: string) => {
        const offset = pageIdx * rawPageSize
        const textBytes = new TextEncoder().encode(text)
        dump.set(textBytes, offset)

        // Write OOB synthetic header at offset + 512
        const oobOffset = offset + 512
        dump[oobOffset] = 0x46 // 'F'
        dump[oobOffset + 1] = 0x54 // 'T'
        const view = new DataView(dump.buffer, oobOffset)
        view.setUint32(2, lba, true)
        view.setUint32(6, seq, true)
        dump[oobOffset + 10] = flags
        const crc = crc16(dump.subarray(oobOffset, oobOffset + 11))
        view.setUint16(11, crc, true)
      }

      writePage(0, 0, 1, 0x01, 'Page0-v1')
      writePage(1, 1, 1, 0x01, 'Page1-v1')
      writePage(2, 0, 2, 0x01, 'Page0-v2') // higher sequence
      writePage(3, 3, 1, 0x01, 'Page3-v1') // LBA 2 is intentionally missing!

      const ftl = new SyntheticFtlReconstructor(geom)
      const res = ftl.reconstruct(dump)

      expect(res.totalPhysicalPagesScanned).toBe(4)
      expect(res.validPagesFound).toBe(4)
      expect(res.uniqueLbas).toBe(3) // LBA 0, 1, 3
      expect(res.maxLba).toBe(3)
      expect(res.missingLbas).toEqual([2]) // LBA 2 detected as hole
      expect(res.staleCandidates.length).toBe(1) // Page 0 v1 marked stale

      // Check reconstructed logical content
      const lba0Content = new TextDecoder().decode(res.logicalImage.subarray(0, 8))
      expect(lba0Content).toBe('Page0-v2') // took latest sequence!

      const lba1Content = new TextDecoder().decode(res.logicalImage.subarray(pageSize, pageSize + 8))
      expect(lba1Content).toBe('Page1-v1')

      const lba3Content = new TextDecoder().decode(res.logicalImage.subarray(pageSize * 3, pageSize * 3 + 8))
      expect(lba3Content).toBe('Page3-v1')
    })
  })

  describe('Hardware Waveform & Protocol Decoders (CAP-01, CAP-02, AC049)', () => {
    it('parses CSV waveform captures', () => {
      const csv = `
Time,CLK,MOSI,MISO,CS
0.000000,0,0,1,1
0.000001,1,1,0,0
0.000002,0,1,0,0
`
      const cap = parseCsvWaveform(csv)
      expect(cap.channels.has('CLK')).toBe(true)
      expect(cap.channels.has('MOSI')).toBe(true)
      expect(cap.channels.get('CLK')!.transitions.length).toBe(3)
    })

    it('parses VCD digital trace format', () => {
      const vcd = `
$date Today $end
$version 1.0 $end
$timescale 1us $end
$scope module top $end
$var wire 1 ! clk $end
$var wire 1 " data $end
$upscope $end
$enddefinitions $end
#0
0!
0"
#10
1!
#20
0!
1"
`
      const cap = parseVcdWaveform(vcd)
      expect(cap.channels.has('clk')).toBe(true)
      expect(cap.channels.has('data')).toBe(true)
      expect(cap.channels.get('clk')!.transitions.length).toBe(3)
    })

    it('decodes UART bytes with framing and parity checking', () => {
      // Craft UART transmission for byte 0x41 ('A' = 0b01000001) at 1000 baud (1ms per bit)
      // Idle high: 1
      // Start bit: 0 (t = 10ms..11ms)
      // Bit 0: 1 (11..12ms)
      // Bit 1..5: 0 (12..17ms)
      // Bit 6: 1 (17..18ms)
      // Bit 7: 0 (18..19ms)
      // Stop bit: 1 (19..20ms)
      const ch: DigitalChannel = {
        name: 'TX',
        id: 'tx',
        transitions: [
          { timestamp: 0.0, value: 1 },
          { timestamp: 0.010, value: 0 }, // Start bit
          { timestamp: 0.011, value: 1 }, // Bit 0
          { timestamp: 0.012, value: 0 }, // Bit 1
          { timestamp: 0.017, value: 1 }, // Bit 6
          { timestamp: 0.018, value: 0 }, // Bit 7
          { timestamp: 0.019, value: 1 }, // Stop bit
          { timestamp: 0.025, value: 1 }, // Idle
        ],
      }

      const decoded = decodeUart(ch, { baudRate: 1000 })
      expect(decoded.length).toBe(1)
      expect(decoded[0]!.byte).toBe(0x41)
      expect(decoded[0]!.asciiChar).toBe('A')
      expect(decoded[0]!.framingError).toBe(false)
      expect(decoded[0]!.parityError).toBe(false)
    })
  })

  describe('CMSIS-SVD Register Parser & Read-Only Viewing (CAP-03, AC050)', () => {
    it('parses SVD XML peripheral and register bitfields and safely inspects snapshot buffers', () => {
      const svdXml = `
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>STM32_TEST</name>
  <description>Test ARM Cortex MCU</description>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <description>General-purpose I/O</description>
      <baseAddress>0x40020000</baseAddress>
      <registers>
        <register>
          <name>MODER</name>
          <description>GPIO port mode register</description>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
          <access>read-write</access>
          <fields>
            <field>
              <name>MODE0</name>
              <description>Port x configuration bits (y = 0)</description>
              <bitOffset>0</bitOffset>
              <bitWidth>2</bitWidth>
            </field>
            <field>
              <name>MODE1</name>
              <description>Port x configuration bits (y = 1)</description>
              <bitOffset>2</bitOffset>
              <bitWidth>2</bitWidth>
            </field>
          </fields>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
`
      const dev = CmsisSvdParser.parse(svdXml)
      expect(dev.name).toBe('STM32_TEST')
      expect(dev.peripherals.length).toBe(1)

      const gpioA = dev.peripherals[0]!
      expect(gpioA.name).toBe('GPIOA')
      expect(gpioA.baseAddress).toBe(0x40020000)

      const moder = gpioA.registers[0]!
      expect(moder.name).toBe('MODER')
      expect(moder.fields.length).toBe(2)

      // Test safe read-only inspection against memory snapshot:
      // Create a virtual memory snapshot containing GPIOA at offset 0
      const snapshot = new Uint8Array(64)
      // Let's set MODER = 0b00001001 (MODE0 = 1 (output), MODE1 = 2 (alternate))
      snapshot[0] = 0x09
      snapshot[1] = 0x00
      snapshot[2] = 0x00
      snapshot[3] = 0x00

      // Map baseAddress = 0 for snapshot test
      const testPeriph = { ...gpioA, baseAddress: 0 }
      const regVal = CmsisSvdParser.readRegisterValue(snapshot, testPeriph, moder)
      expect(regVal).toBe(0x09)

      const mode0 = CmsisSvdParser.extractFieldValue(regVal, moder.fields[0]!)
      const mode1 = CmsisSvdParser.extractFieldValue(regVal, moder.fields[1]!)
      expect(mode0).toBe(1)
      expect(mode1).toBe(2)
    })
  })
})
