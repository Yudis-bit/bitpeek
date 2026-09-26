import { describe, expect, it } from 'vitest'
import { parsePng } from './png'
import { parseElf } from './elf'
import { parseCustomStructure, type CustomStructureSchema } from './schema'
import { crc32 } from '../crypto'

describe('Structure Inspector (ELF, PNG, Custom Schema)', () => {
  describe('PNG Parser (R09.3)', () => {
    function createMinimalPng(width = 100, height = 200): Uint8Array {
      const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
      // IHDR: 13 bytes
      const ihdrData = new Uint8Array(13)
      const view = new DataView(ihdrData.buffer)
      view.setUint32(0, width, false)
      view.setUint32(4, height, false)
      ihdrData[8] = 8 // 8-bit
      ihdrData[9] = 6 // RGBA
      ihdrData[10] = 0
      ihdrData[11] = 0
      ihdrData[12] = 0

      const ihdrType = new TextEncoder().encode('IHDR')
      const ihdrCrcPayload = new Uint8Array(4 + 13)
      ihdrCrcPayload.set(ihdrType, 0)
      ihdrCrcPayload.set(ihdrData, 4)
      const ihdrCrc = crc32(ihdrCrcPayload)

      // IEND
      const iendType = new TextEncoder().encode('IEND')
      const iendCrc = crc32(iendType)

      // Total = 8 (sig) + 12 + 13 (ihdr) + 12 + 0 (iend) = 45 bytes
      const png = new Uint8Array(45)
      png.set(sig, 0)

      // IHDR chunk at offset 8
      const pngView = new DataView(png.buffer)
      pngView.setUint32(8, 13, false)
      png.set(ihdrType, 12)
      png.set(ihdrData, 16)
      pngView.setUint32(29, ihdrCrc, false)

      // IEND chunk at offset 33
      pngView.setUint32(33, 0, false)
      png.set(iendType, 37)
      pngView.setUint32(41, iendCrc, false)

      return png
    }

    it('parses valid minimal PNG and maps IHDR width/height fields to exact byte ranges', () => {
      const png = createMinimalPng(1920, 1080)
      const result = parsePng(png)

      expect(result.status).toBe('valid')
      expect(result.warnings).toHaveLength(0)

      const ihdrChunk = result.fields.find((f) => f.id === 'png.chunk[1]')
      expect(ihdrChunk).toBeDefined()

      const widthField = ihdrChunk?.children?.find((f) => f.id === 'png.ihdr.width')
      expect(widthField).toBeDefined()
      expect(widthField?.range).toEqual({ start: 16, end: 20 })
      expect(widthField?.interpretedValue).toBe(1920)
      expect(widthField?.endian).toBe('big')

      const heightField = ihdrChunk?.children?.find((f) => f.id === 'png.ihdr.height')
      expect(heightField).toBeDefined()
      expect(heightField?.range).toEqual({ start: 20, end: 24 })
      expect(heightField?.interpretedValue).toBe(1080)
      expect(heightField?.endian).toBe('big')
    })

    it('reports CRC mismatch when single byte in IHDR is modified', () => {
      const png = createMinimalPng(100, 200)
      // Corrupt 1 byte in IHDR width at offset 19
      png[19] = (png[19] ?? 0) ^ 0x01

      const result = parsePng(png)
      expect(result.status).toBe('partial')
      expect(result.warnings.some((w) => w.includes('CRC mismatch'))).toBe(true)

      const ihdrChunk = result.fields.find((f) => f.id === 'png.chunk[1]')
      const crcField = ihdrChunk?.children?.find((f) => f.id === 'png.chunk[1].crc')
      expect(crcField?.status).toBe('inconsistent')
      expect(crcField?.reason).toContain('CRC mismatch')
    })

    it('returns structured truncation when file is truncated inside chunk header', () => {
      const png = createMinimalPng(100, 200).slice(0, 12) // cut off inside IHDR header
      const result = parsePng(png)
      expect(result.status).toBe('partial')
      expect(result.fields.some((f) => f.status === 'truncated')).toBe(true)
    })
  })

  describe('ELF Parser (R09.2)', () => {
    function createElf64Le(): Uint8Array {
      const buf = new Uint8Array(64)
      const view = new DataView(buf.buffer)
      // e_ident
      buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46 // magic
      buf[4] = 2 // 64-bit
      buf[5] = 1 // Little-endian
      buf[6] = 1 // EV_CURRENT
      buf[7] = 0 // System V

      view.setUint16(16, 2, true) // ET_EXEC
      view.setUint16(18, 62, true) // EM_X86_64
      view.setUint32(20, 1, true) // EV_CURRENT
      view.setBigUint64(24, 0x401000n, true) // e_entry
      view.setBigUint64(32, 64n, true) // e_phoff
      view.setBigUint64(40, 0n, true) // e_shoff
      view.setUint32(48, 0, true) // e_flags
      view.setUint16(52, 64, true) // e_ehsize
      view.setUint16(54, 56, true) // e_phentsize
      view.setUint16(56, 1, true) // e_phnum
      view.setUint16(58, 64, true) // e_shentsize
      view.setUint16(60, 0, true) // e_shnum
      view.setUint16(62, 0, true) // e_shstrndx
      return buf
    }

    function createElf32Be(): Uint8Array {
      const buf = new Uint8Array(52)
      const view = new DataView(buf.buffer)
      // e_ident
      buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46
      buf[4] = 1 // 32-bit
      buf[5] = 2 // Big-endian
      buf[6] = 1
      buf[7] = 0

      view.setUint16(16, 3, false) // ET_DYN
      view.setUint16(18, 40, false) // EM_ARM
      view.setUint32(20, 1, false)
      view.setUint32(24, 0x1000, false) // e_entry
      view.setUint32(28, 52, false) // e_phoff
      view.setUint32(32, 0, false) // e_shoff
      view.setUint32(36, 0, false) // e_flags
      view.setUint16(40, 52, false) // e_ehsize
      view.setUint16(42, 32, false) // e_phentsize
      view.setUint16(44, 0, false) // e_phnum
      view.setUint16(46, 40, false) // e_shentsize
      view.setUint16(48, 0, false) // e_shnum
      view.setUint16(50, 0, false) // e_shstrndx
      return buf
    }

    it('parses ELF64 Little-Endian header with correct entry point and machine', () => {
      const elf = createElf64Le()
      const result = parseElf(elf)
      expect(result.status).toBe('valid')

      const ehdr = result.fields.find((f) => f.id === 'elf.header')
      expect(ehdr).toBeDefined()

      const entry = ehdr?.children?.find((f) => f.id === 'elf.header.entry')
      expect(entry?.interpretedValue).toBe('0x401000')
      expect(entry?.endian).toBe('little')

      const machine = ehdr?.children?.find((f) => f.id === 'elf.header.machine')
      expect(machine?.interpretedValue).toContain('AMD x86-64')
    })

    it('parses ELF32 Big-Endian header with correct architecture and endianness', () => {
      const elf = createElf32Be()
      const result = parseElf(elf)
      expect(result.status).toBe('valid')

      const ehdr = result.fields.find((f) => f.id === 'elf.header')
      const machine = ehdr?.children?.find((f) => f.id === 'elf.header.machine')
      expect(machine?.interpretedValue).toContain('ARM')
      expect(machine?.endian).toBe('big')
    })

    it('stops with structured truncation error when ELF header is truncated', () => {
      const truncated = createElf64Le().slice(0, 30)
      const result = parseElf(truncated)
      expect(result.status).toBe('partial')
      expect(result.fields.some((f) => f.status === 'truncated')).toBe(true)
    })
  })

  describe('Custom Declarative Structure Schema (R09.4)', () => {
    const protocolSchema: CustomStructureSchema = {
      schemaVersion: 1,
      name: 'Synthetic Packet Header',
      defaultEndian: 'big',
      fields: [
        { id: 'magic', label: 'Magic', offset: 0, type: 'u16' },
        {
          id: 'flags_version',
          label: 'Version & Flags',
          offset: 2,
          type: 'bitfield',
          containerType: 'u8',
          lsb: 4,
          width: 4,
        },
        {
          id: 'flags_urgent',
          label: 'Urgent Flag',
          offset: 2,
          type: 'bitfield',
          containerType: 'u8',
          lsb: 0,
          width: 1,
        },
        { id: 'length', label: 'Payload Length', offset: 3, type: 'u16' },
      ],
    }

    it('maps packet fields and decodes bitfield correctly', () => {
      // magic: 0xCAFE, version=3 (0011 << 4 = 0x30), urgent=1 (0x01) -> byte[2] = 0x31, length: 1024 (0x0400)
      const packet = Uint8Array.from([0xca, 0xfe, 0x31, 0x04, 0x00])
      const result = parseCustomStructure(packet, protocolSchema)

      expect(result.status).toBe('valid')

      const magicField = result.fields.find((f) => f.id === 'magic')
      expect(magicField?.interpretedValue).toBe(0xcafe)

      const versionField = result.fields.find((f) => f.id === 'flags_version')
      expect(versionField?.interpretedValue).toContain('0x3 (3)')

      const urgentField = result.fields.find((f) => f.id === 'flags_urgent')
      expect(urgentField?.interpretedValue).toContain('0x1 (1)')

      const lengthField = result.fields.find((f) => f.id === 'length')
      expect(lengthField?.interpretedValue).toBe(1024)
    })
  })
})
