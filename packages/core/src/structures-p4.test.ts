import { describe, it, expect } from 'vitest'
import {
  parsePe,
  parseWasm,
  parseZip,
  parseGpt,
  parseUbi,
  parseSquashfs,
  autoDetectAndParseStructure,
  parseCustomStructureV2,
  type CustomStructureSchemaV2,
} from './structures'
import { FormatDiscoveryEngine, type SampleInput } from './discovery'

describe('Phase P4 - Format Parsers & Structural Reasoning', () => {
  describe('PE/COFF Parser', () => {
    it('parses PE32 header, sections, and performs RVA mapping', () => {
      // Create minimal PE header
      const pe = new Uint8Array(1024)
      // DOS Header: "MZ" at 0, e_lfanew at 0x3c -> 0x80
      pe[0] = 0x4d // 'M'
      pe[1] = 0x5a // 'Z'
      const view = new DataView(pe.buffer)
      view.setUint32(0x3c, 0x80, true) // e_lfanew = 128

      // PE Signature: "PE\0\0" at 0x80
      pe[0x80] = 0x50 // 'P'
      pe[0x81] = 0x45 // 'E'
      pe[0x82] = 0x00
      pe[0x83] = 0x00

      // COFF File Header at 0x84
      view.setUint16(0x84, 0x014c, true) // Machine = i386 (PE32)
      view.setUint16(0x86, 1, true) // NumberOfSections = 1
      view.setUint16(0x94, 224, true) // SizeOfOptionalHeader = 224
      view.setUint16(0x96, 0x0102, true) // Characteristics (Executable)

      // Optional Header at 0x98 (PE32 magic = 0x10b)
      view.setUint16(0x98, 0x010b, true)
      view.setUint32(0x98 + 16, 0x1000, true) // AddressOfEntryPoint = 0x1000
      view.setUint32(0x98 + 28, 0x00400000, true) // ImageBase = 0x400000
      view.setUint32(0x98 + 32, 0x1000, true) // SectionAlignment = 0x1000
      view.setUint32(0x98 + 36, 0x200, true) // FileAlignment = 0x200

      // Section Table at 0x98 + 224 = 0x178
      const secOffset = 0x178
      const secName = new TextEncoder().encode('.text\0\0\0')
      pe.set(secName, secOffset)
      view.setUint32(secOffset + 8, 0x500, true) // VirtualSize = 0x500
      view.setUint32(secOffset + 12, 0x1000, true) // VirtualAddress = 0x1000
      view.setUint32(secOffset + 16, 0x200, true) // SizeOfRawData = 0x200 (512 bytes)
      view.setUint32(secOffset + 20, 0x200, true) // PointerToRawData = 0x200

      const parsed = parsePe(pe)
      expect(parsed).not.toBeNull()
      expect(parsed!.format).toBe('pe')
      expect(parsed!.confidence).toBe(1.0)

      // Test RVA translation on result
      const rvaToFile = (parsed as any).rvaToFileOffset
      expect(rvaToFile).toBeDefined()
      // RVA 0x1050 should map to File Offset 0x250 (file-backed)
      const mapped = rvaToFile(0x1050)
      expect(mapped.status).toBe('file-backed')
      expect(mapped.fileOffset).toBe(0x250)

      // RVA 0x1300 is past SizeOfRawData (0x200) but within VirtualSize (0x500) -> zero-fill
      const zeroFill = rvaToFile(0x1300)
      expect(zeroFill.status).toBe('zero-fill')

      // RVA 0x9000 is unmapped
      const unmapped = rvaToFile(0x9000)
      expect(unmapped.status).toBe('unmapped')
    })
  })

  describe('WebAssembly Parser', () => {
    it('parses wasm magic, version, and sections', () => {
      // \0asm + version 1 + Type section (id=1, size=4, payload)
      const wasm = new Uint8Array([
        0x00, 0x61, 0x73, 0x6d, // \0asm
        0x01, 0x00, 0x00, 0x00, // version 1
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section (id 1, size 4)
      ])

      const res = parseWasm(wasm)
      expect(res).not.toBeNull()
      expect(res!.format).toBe('wasm')
      expect(res!.fields.length).toBeGreaterThanOrEqual(3)
      expect(res!.fields[0]!.interpretedValue).toBe('\\0asm')
      expect(res!.fields[1]!.interpretedValue).toBe(1)
      expect(res!.fields[2]!.label).toContain('Type')
    })
  })

  describe('ZIP Parser', () => {
    it('parses ZIP local header and central directory', () => {
      // Craft minimal ZIP with 1 file: "test.txt", content: "hi"
      const zip = new Uint8Array(256)
      const view = new DataView(zip.buffer)

      // Local file header at 0
      view.setUint32(0, 0x04034b50, true) // PK\x03\x04
      view.setUint16(4, 20, true) // version
      view.setUint16(6, 0, true) // flags
      view.setUint16(8, 0, true) // compression = 0 (stored)
      view.setUint16(10, 0, true) // time
      view.setUint16(12, 0, true) // date
      view.setUint32(14, 0x12345678, true) // crc
      view.setUint32(18, 2, true) // comp size
      view.setUint32(22, 2, true) // uncomp size
      view.setUint16(26, 8, true) // filename len = 8
      view.setUint16(28, 0, true) // extra len
      zip.set(new TextEncoder().encode('test.txt'), 30)
      zip.set(new TextEncoder().encode('hi'), 38)
      // payload ends at 40

      // Central directory header at 40
      const cdOffset = 40
      view.setUint32(cdOffset, 0x02014b50, true) // PK\x01\x02
      view.setUint16(cdOffset + 4, 20, true)
      view.setUint16(cdOffset + 6, 20, true)
      view.setUint16(cdOffset + 8, 0, true)
      view.setUint16(cdOffset + 10, 0, true)
      view.setUint32(cdOffset + 16, 0x12345678, true)
      view.setUint32(cdOffset + 20, 2, true)
      view.setUint32(cdOffset + 24, 2, true)
      view.setUint16(cdOffset + 28, 8, true)
      view.setUint16(cdOffset + 30, 0, true)
      view.setUint16(cdOffset + 32, 0, true)
      view.setUint32(cdOffset + 42, 0, true) // relative offset of local header
      zip.set(new TextEncoder().encode('test.txt'), cdOffset + 46)
      const cdSize = 46 + 8

      // EOCD at cdOffset + cdSize
      const eocdOffset = cdOffset + cdSize
      view.setUint32(eocdOffset, 0x06054b50, true) // PK\x05\x06
      view.setUint16(eocdOffset + 4, 0, true)
      view.setUint16(eocdOffset + 6, 0, true)
      view.setUint16(eocdOffset + 8, 1, true) // entries on disk
      view.setUint16(eocdOffset + 10, 1, true) // total entries
      view.setUint32(eocdOffset + 12, cdSize, true) // size of CD
      view.setUint32(eocdOffset + 16, cdOffset, true) // offset of CD
      view.setUint16(eocdOffset + 20, 0, true) // comment len

      const parsed = parseZip(zip.subarray(0, eocdOffset + 22))
      expect(parsed).not.toBeNull()
      expect(parsed!.format).toBe('zip')
      expect(parsed!.fields.some((f) => f.label.includes('EOCD'))).toBe(true)
      expect(parsed!.fields.some((f) => f.label.includes('Central Directory'))).toBe(true)
    })
  })

  describe('GPT and UBI Parsers', () => {
    it('parses GPT header at LBA 1 (offset 512)', () => {
      const buf = new Uint8Array(1024)
      const view = new DataView(buf.buffer)
      // Protective MBR signature at 510
      view.setUint16(510, 0xaa55, true)

      // GPT signature at 512: "EFI PART" (0x5452415020494645n)
      const sig = new TextEncoder().encode('EFI PART')
      buf.set(sig, 512)
      view.setUint32(520, 0x00010000, true) // revision 1.0
      view.setUint32(524, 92, true) // header size = 92
      view.setBigUint64(536, 1n, true) // myLBA = 1
      view.setBigUint64(544, 2047n, true) // alternateLBA = 2047
      view.setBigUint64(552, 34n, true) // firstUsableLBA = 34
      view.setBigUint64(560, 2014n, true) // lastUsableLBA = 2014
      view.setBigUint64(568, 2n, true) // partitionEntryLBA = 2
      view.setUint32(576, 128, true) // numEntries = 128
      view.setUint32(580, 128, true) // entrySize = 128

      const res = parseGpt(buf)
      expect(res).not.toBeNull()
      expect(res!.format).toBe('gpt')
      expect(res!.fields.some((f) => f.label === 'Header Size' && f.interpretedValue === 92)).toBe(true)
    })

    it('parses UBI Erase Counter (EC) header', () => {
      const ubi = new Uint8Array(128)
      const view = new DataView(ubi.buffer)
      // Magic: "UBI#" = 0x55, 0x42, 0x49, 0x23
      ubi[0] = 0x55
      ubi[1] = 0x42
      ubi[2] = 0x49
      ubi[3] = 0x23
      ubi[4] = 1 // version 1
      view.setBigUint64(8, 42n, false) // ec = 42 (big endian)
      view.setUint32(16, 2048, false) // vid_hdr_offset = 2048
      view.setUint32(20, 4096, false) // data_offset = 4096
      view.setUint32(24, 1, false) // image_seq = 1

      const res = parseUbi(ubi)
      expect(res).not.toBeNull()
      expect(res!.format).toBe('ubi')
      expect(res!.fields.some((f) => f.label === 'Erase Counter' && (f.interpretedValue === 42n || (typeof f.interpretedValue === 'bigint' && f.interpretedValue === 42n)))).toBe(true)
    })
  })

  describe('SquashFS Parser', () => {
    it('parses SquashFS 4.0 superblock', () => {
      const sq = new Uint8Array(128)
      const view = new DataView(sq.buffer)
      // Magic: 0x73717368 (LE: 0x68, 0x73, 0x71, 0x73)
      view.setUint32(0, 0x73717368, true)
      view.setUint32(4, 10, true) // inodes = 10
      view.setUint32(8, 1600000000, true) // mkfs_time
      view.setUint32(12, 131072, true) // block_size = 128KiB
      view.setUint32(16, 5, true) // fragments = 5
      view.setUint16(20, 1, true) // compression = 1 (GZIP)
      view.setUint16(22, 17, true) // block_log = 17
      view.setUint16(28, 4, true) // major version = 4
      view.setUint16(30, 0, true) // minor version = 0
      view.setBigUint64(40, 65536n, true) // bytes_used = 65536

      const res = parseSquashfs(sq)
      expect(res).not.toBeNull()
      expect(res!.format).toBe('squashfs')
      expect(res!.fields.some((f) => f.label === 'Inodes Count' && f.interpretedValue === 10)).toBe(true)
      expect(res!.fields.some((f) => f.label === 'Compression' && f.interpretedValue === 'GZIP')).toBe(true)
    })
  })

  describe('Custom Schema v2 Interpreter', () => {
    it('executes bounded AST expressions, conditional logic, and dynamic arrays', () => {
      // Craft binary payload:
      // [0..3]: Magic 0xDEADBEEF
      // [4]: Tag (1 for TypeA, 2 for TypeB)
      // [5]: Item count = 3
      // [6..8]: 3 bytes of data: 10, 20, 30
      const payload = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x03, 10, 20, 30])

      const schema: CustomStructureSchemaV2 = {
        schemaVersion: 2,
        name: 'test_packet',
        defaultEndian: 'big',
        fields: [
          {
            id: 'magic',
            label: 'Magic Number',
            type: 'u32',
            offset: 0,
            assertions: [
              {
                condition: {
                  type: 'binary',
                  op: 'eq',
                  left: { type: 'ref', path: '_val' },
                  right: { type: 'literal', value: 0xdeadbeef },
                },
                message: 'Invalid magic signature',
                severity: 'error',
              },
            ],
          },
          {
            id: 'tag',
            label: 'Packet Tag',
            type: 'u8',
            offset: 4,
          },
          {
            id: 'count',
            label: 'Item Count',
            type: 'u8',
            offset: 5,
          },
          {
            id: 'items',
            label: 'Data Items',
            type: 'array',
            offset: 6,
            count: { type: 'ref', path: 'count' },
            itemType: {
              id: 'val',
              label: 'Value',
              type: 'u8',
            },
          },
        ],
      }

      const res = autoDetectAndParseStructure(payload, schema)
      expect(res).not.toBeNull()
      expect(res!.format).toBe('custom-v2:test_packet')
      expect(res!.fields.length).toBe(4)

      const magicField = res!.fields.find((f) => f.id === 'magic')
      expect(magicField?.status).toBe('valid')
      expect(magicField?.interpretedValue).toBe(0xdeadbeef)

      const itemsField = res!.fields.find((f) => f.id === 'items')
      expect(itemsField?.children?.length).toBe(3)
      expect(itemsField?.children?.[0]?.interpretedValue).toBe(10)
      expect(itemsField?.children?.[1]?.interpretedValue).toBe(20)
      expect(itemsField?.children?.[2]?.interpretedValue).toBe(30)
    })

    it('rejects infinite loops and enforces fuel limits without arbitrary code execution', () => {
      const payload = new Uint8Array(100)
      const schema: CustomStructureSchemaV2 = {
        schemaVersion: 2,
        name: 'exhaust_test',
        maxFuel: 5, // low fuel limit
        fields: [
          { id: 'f1', label: 'F1', type: 'u8', offset: 0 },
          { id: 'f2', label: 'F2', type: 'u8', offset: 1 },
          { id: 'f3', label: 'F3', type: 'u8', offset: 2 },
          { id: 'f4', label: 'F4', type: 'u8', offset: 3 },
          { id: 'f5', label: 'F5', type: 'u8', offset: 4 },
          { id: 'f6', label: 'F6', type: 'u8', offset: 5 },
        ],
      }

      expect(() => parseCustomStructureV2(payload, schema)).toThrow(/fuel exhausted/)
    })
  })

  describe('Discovery Hypothesis Engine (DISC-01, DISC-02, AC076, AC077)', () => {
    it('distinguishes total file length from record count using held-out samples and flags contradictions', () => {
      // Craft training samples:
      // Format: 4-byte Magic "TEST", 2-byte count/length (offset 4, LE), N records of 4 bytes each.
      // In training samples:
      // Sample 1: 2 records -> 4 (magic) + 2 (header) + 8 (records) = 14 bytes total. If field = 2, it matches count! If field = 14, it matches length!
      // To test discrimination:
      // Let field at offset 4 be RECORD COUNT:
      // S1: 2 records -> payload 8 bytes, total 14 bytes. field at offset 4 = 2.
      // S2: 3 records -> payload 12 bytes, total 18 bytes. field at offset 4 = 3.
      const makeSample = (id: string, count: number, recordSize: number): SampleInput => {
        const total = 6 + count * recordSize
        const buf = new Uint8Array(total)
        // magic "TEST"
        buf.set(new TextEncoder().encode('TEST'), 0)
        // offset 4: count (u16 LE)
        new DataView(buf.buffer).setUint16(4, count, true)
        // fill records
        for (let i = 6; i < total; i++) {
          buf[i] = 0xaa
        }
        return { id, data: buf }
      }

      const train1 = makeSample('train-1', 2, 4) // count = 2, total = 14
      const train2 = makeSample('train-2', 4, 4) // count = 4, total = 22

      // Held-out samples:
      // Holdout 1: 5 records -> count = 5, total = 26
      const holdout1 = makeSample('holdout-1', 5, 4)
      // Contradictory sample: malformed sample where count says 10 but buffer only has 14 bytes
      const contradictSample: SampleInput = {
        id: 'contradict-1',
        data: new Uint8Array([0x54, 0x45, 0x53, 0x54, 0x0a, 0x00, 0x11, 0x22]),
      }

      const engine = new FormatDiscoveryEngine()
      const result = engine.analyze([train1, train2], [holdout1, contradictSample])

      expect(result.trainingSampleIds).toEqual(['train-1', 'train-2'])
      expect(result.holdoutSampleIds).toEqual(['holdout-1', 'contradict-1'])

      // Magic hypothesis should be supported under tests
      const magicHyp = result.hypotheses.find((h) => h.candidateKind === 'magic' && h.width === 4)
      expect(magicHyp).toBeDefined()
      expect(magicHyp?.status).toBe('supported-under-tests')

      // Record count hypothesis with stride 4 should be found
      const recCountHyp = result.hypotheses.find(
        (h) => h.candidateKind === 'record_count' && h.hypothesisId.includes('stride4'),
      )
      expect(recCountHyp).toBeDefined()
      expect(recCountHyp?.trainingScore).toBe(1.0)
      // holdout1 matches, contradictSample contradicts it:
      expect(recCountHyp?.contradictingSamples).toContain('contradict-1')
      expect(recCountHyp?.status).toBe('inconclusive') // partially supported, partially contradicted

      // Length hypothesis should NOT match training since field at offset 4 has values 2 and 4, not 14 and 22
      const lenHyp = result.hypotheses.find((h) => h.candidateKind === 'file_length')
      expect(lenHyp).toBeUndefined()
    })
  })
})
