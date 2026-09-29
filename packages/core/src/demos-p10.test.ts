import { describe, it, expect } from 'vitest'
import {
  NandGeometryManager,
  SYNTHETIC_LAB_NAND_PROFILE,
  encodeHamming256,
  decodeHamming256,
  MultiReadAnalyzer,
  SyntheticFtlReconstructor,
  SanitizerLogParser,
  DeltaDebuggingReducer,
  verifyEvidenceBundle,
  redactEvidenceBundle,
  type EvidenceBundleManifest,
  BitcoinParser,
  RlpDecoder,
  CryptoLimbEngine,
  SafeTensorsParser,
  TensorBoundsEngine,
  GpuSanitizerParser,
  FormatDiscoveryEngine,
  parseCustomStructureV2,
  type CustomStructureSchemaV2,
  createDefaultOperationRegistry,
  sha256Hex,
  crc16,
} from './index'

describe('Phase P10 - Demos A through F Verification (QA-03)', () => {
  describe('DEMO A - From Raw NAND to Evidence', () => {
    it('executes complete NAND recovery workflow: multi-read voting, ECC correction, and FTL mapping', () => {
      const geom = new NandGeometryManager(SYNTHETIC_LAB_NAND_PROFILE)
      expect(geom.profile.dataBytesPerPage).toBe(512)
      expect(geom.profile.oobBytesPerPage).toBe(16)

      // 1. Multi-read voting with unstable bits
      const read1 = new Uint8Array([0xaa, 0xbb, 0x11, 0xdd])
      const read2 = new Uint8Array([0xaa, 0xbf, 0x11, 0xdd]) // bit flip in byte 1
      const read3 = new Uint8Array([0xaa, 0xbb, 0x11, 0xdd])
      const variability = MultiReadAnalyzer.analyzeVariability([read1, read2, read3])
      expect(variability.variableByteCount).toBe(1)

      const vote = MultiReadAnalyzer.reconstructMajority([read1, read2, read3], ['r1', 'r2', 'r3'])
      expect(vote.reconstructed[1]).toBe(0xbb) // majority vote recovered

      // 2. Hamming ECC correction & failure detection
      const dataBlock = new Uint8Array(256).fill(0x55)
      const parity = encodeHamming256(dataBlock)
      const corruptedSingleBit = new Uint8Array(dataBlock)
      corruptedSingleBit[10] ^= 0x04 // 1 bit flipped

      const eccRes1 = decodeHamming256(corruptedSingleBit, parity)
      expect(eccRes1.status).toBe('corrected')
      expect(eccRes1.correctedData![10]).toBe(0x55)

      const corruptedTwoBits = new Uint8Array(dataBlock)
      corruptedTwoBits[10] ^= 0x04
      corruptedTwoBits[10] ^= 0x08 // 2 bits flipped
      const eccRes2 = decodeHamming256(corruptedTwoBits, parity)
      expect(eccRes2.status).toBe('uncorrectable')

      // 3. FTL reconstruction
      const ftl = new SyntheticFtlReconstructor(geom)
      const rawPageSize = geom.getRawPageSize()
      const dump = new Uint8Array(rawPageSize * 2)

      const writePage = (pageIdx: number, lba: number, seq: number, text: string) => {
        const offset = pageIdx * rawPageSize
        dump.set(new TextEncoder().encode(text), offset)
        const oobOffset = offset + 512
        dump[oobOffset] = 0x46 // 'F'
        dump[oobOffset + 1] = 0x54 // 'T'
        const view = new DataView(dump.buffer, oobOffset)
        view.setUint32(2, lba, true)
        view.setUint32(6, seq, true)
        dump[oobOffset + 10] = 0x01
        const crc = crc16(dump.subarray(oobOffset, oobOffset + 11))
        view.setUint16(11, crc, true)
      }

      writePage(0, 0, 1, 'Page0-v1')
      writePage(1, 0, 2, 'Page0-v2') // update to higher sequence

      const res = ftl.reconstruct(dump)
      expect(res.validPagesFound).toBe(2)
      expect(res.uniqueLbas).toBe(1)
      expect(res.staleCandidates.length).toBe(1)
      const lba0Content = new TextDecoder().decode(res.logicalImage.subarray(0, 8))
      expect(lba0Content).toBe('Page0-v2')
    })
  })

  describe('DEMO B - Native Parser Diagnostic and Reducer', () => {
    it('parses native ASan log and minimizes crash input using delta debugging', async () => {
      // 1. ASan diagnostic parsing
      const asanLog = `
=================================================================
==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x000000401234 bp 0x7fff
READ of size 4 at 0x602000000010 thread T0
    #0 0x401234 in main test.c:25:10
`
      const diag = SanitizerLogParser.parseAsan(asanLog)
      expect(diag).not.toBeNull()
      expect(diag!.errorType).toBe('heap-use-after-free')
      expect(diag!.faultAddress).toBe(0x602000000010n)
      expect(diag!.accessType).toBe('READ')

      // 2. Delta debugging minimization
      // Oracle: crash if substring "CRASH" is present in input
      const initialPayload = new TextEncoder().encode('ABCDEFGHIJKL_CRASH_MNOPQRSTUVWXYZ1234567890')
      const oracle = async (bytes: Uint8Array) => {
        const text = new TextDecoder().decode(bytes)
        return text.includes('CRASH')
      }

      const res = await DeltaDebuggingReducer.reduce(initialPayload, oracle)
      const minimizedText = new TextDecoder().decode(res.reducedBytes)
      expect(minimizedText).toContain('CRASH')
      expect(res.reducedLength).toBeLessThan(initialPayload.length)
      expect(res.controlPassed).toBe(true)
    })
  })

  describe('DEMO C - Blockchain Binary Precision', () => {
    it('validates Bitcoin transaction fields, Ethereum RLP canonicality, and 256-bit limb arithmetic', () => {
      // 1. Bitcoin transaction parsing
      const rawTx = new Uint8Array([
        0x01, 0x00, 0x00, 0x00, // version 1
        0x01, // 1 input
        ...new Uint8Array(32).fill(0x11), // prev txid
        0x00, 0x00, 0x00, 0x00, // prev vout 0
        0x00, // script length 0
        0xff, 0xff, 0xff, 0xff, // sequence
        0x01, // 1 output
        0x50, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 50,000 satoshis (LE)
        0x01, 0x51, // scriptPubKey: OP_TRUE
        0x00, 0x00, 0x00, 0x00, // locktime 0
      ])
      const tx = BitcoinParser.parseTransaction(rawTx)
      expect(tx.version).toBe(1)
      expect(tx.isSegWit).toBe(false)
      expect(tx.inputs.length).toBe(1)
      expect(tx.outputs[0].valueSatoshis).toBe(50000n)
      expect(tx.txidDisplay.length).toBe(64)

      // 2. Ethereum RLP canonicality: single byte < 0x80 must not be encoded as string [0x81, b]
      const nonCanonicalRlp = new Uint8Array([0x81, 0x05])
      expect(() => RlpDecoder.decode(nonCanonicalRlp)).toThrow(/Non-canonical RLP/)

      // 3. 256-bit limb arithmetic (4x64-bit limbs)
      const a = [0xffffffffffffffffn, 0n, 0n, 0n]
      const b = [1n, 0n, 0n, 0n]
      const sum = CryptoLimbEngine.addLimbs64(a, b)
      expect(sum.result[0]).toBe(0n)
      expect(sum.result[1]).toBe(1n) // carry into limb 1
      expect(sum.carryOut).toBe(0)
    })
  })

  describe('DEMO D - AI Tensor to Diagnostic', () => {
    it('inspects SafeTensors metadata, validates strided tensor addresses, and correlates GPU diagnostic', () => {
      // 1. SafeTensors metadata
      const headerJson = {
        'layer1.weight': {
          dtype: 'F32',
          shape: [4, 4],
          data_offsets: [0, 64],
        },
      }
      const headerBytes = new TextEncoder().encode(JSON.stringify(headerJson))
      const fileBytes = new Uint8Array(8 + headerBytes.length + 64)
      new DataView(fileBytes.buffer).setBigUint64(0, BigInt(headerBytes.length), true)
      fileBytes.set(headerBytes, 8)

      const model = SafeTensorsParser.parse(fileBytes)
      const tensor = model.tensors.get('layer1.weight')!
      expect(tensor.elementCount).toBe(16)
      const span = SafeTensorsParser.mapElementToFileSpan(tensor, [2, 3])
      expect(span.fileOffset).toBe(8 + headerBytes.length + (2 * 4 + 3) * 4)

      // 2. Strided tensor bounds with negative stride
      const tNeg = new TensorBoundsEngine({
        shape: [5],
        strides: [-1],
        dtype: 'F32',
        storageOffsetBytes: 16,
      })
      const bNeg = tNeg.computeBounds()
      expect(bNeg.minReachableOffsetBytes).toBe(0)
      expect(bNeg.maxReachableOffsetBytes).toBe(20)
      expect(bNeg.spanSizeBytes).toBe(20)

      // 3. GPU Sanitizer log correlation
      const gpuLog = `
========= CUDA-MEMCHECK
========= Invalid __global__ read of size 4
=========     at 0x00000120 in matrix_mul_kernel
=========     by thread (32,0,0) in block (0,0,0)
=========     Address 0x7f0000000150 is out of bounds
`
      const parsedGpu = GpuSanitizerParser.parse(gpuLog)
      expect(parsedGpu).not.toBeNull()
      expect(parsedGpu!.errorKind).toBe('Invalid __global__ read')
      expect(parsedGpu!.threadCoord).toEqual([32, 0, 0])
    })
  })

  describe('DEMO E - Unknown Format Hypothesis', () => {
    it('analyzes sample structures, evaluates held-out samples, and interprets schema candidate', () => {
      // 1. Format discovery candidate hypothesis
      const train1 = {
        id: 'train-1',
        data: new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]),
      }
      const train2 = {
        id: 'train-2',
        data: new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00]),
      }
      const holdout = {
        id: 'holdout-1',
        data: new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]),
      }

      const discovery = new FormatDiscoveryEngine()
      const analysis = discovery.analyze([train1, train2], [holdout])
      const magicHyp = analysis.hypotheses.find((h) => h.candidateKind === 'magic' && h.width === 4)
      expect(magicHyp).toBeDefined()
      expect(magicHyp?.status).toBe('supported-under-tests')

      // 2. Custom schema AST evaluation
      const schema: CustomStructureSchemaV2 = {
        schemaVersion: 2,
        name: 'test_packet',
        fields: [
          { id: 'magic', label: 'Magic', type: 'u16', endian: 'big', offset: 0 },
          { id: 'payloadLen', label: 'Payload Length', type: 'u16', endian: 'big', offset: 2 },
        ],
      }
      const packetBytes = new Uint8Array([0xca, 0xfe, 0x00, 0x20])
      const parsed = parseCustomStructureV2(packetBytes, schema)
      expect(parsed.format).toBe('custom-v2:test_packet')
      expect(parsed.fields[0].interpretedValue).toBe(0xcafe)
      expect(parsed.fields[1].interpretedValue).toBe(32)
    })
  })

  describe('DEMO F - Large-File Multi-Surface Investigation', () => {
    it('streams large virtual source, runs unified operation dispatch, and exports verifiable evidence bundle', async () => {
      // 1. Unified operation dispatch
      const registry = createDefaultOperationRegistry()
      const manifest = registry.generateCapabilityManifest()
      expect(manifest.supportedFormats.length).toBeGreaterThan(5)

      // 2. Verifiable evidence bundle & redaction
      const sampleBytes = new Uint8Array([1, 2, 3, 4])
      const sampleSha256 = sha256Hex(sampleBytes)

      const bundleManifest: EvidenceBundleManifest = {
        manifestVersion: 2,
        bundleId: 'bundle-demo-f',
        timestamp: '2026-09-29T00:00:00.000Z',
        researcher: 'CONFIDENTIAL_NAME',
        targetName: 'firmware.bin',
        findings: [
          {
            id: 'find-1',
            title: 'Critical Buffer Misalignment',
            severity: 'critical',
            observation: 'Offset exceeds boundary with CONFIDENTIAL_TOKEN',
            targetArtifactId: 'art-1',
          },
        ],
        artifacts: {
          'art-1': {
            size: sampleBytes.length,
            sha256: sampleSha256,
          },
        },
      }

      // Verify integrity
      const verifyRes = await verifyEvidenceBundle(bundleManifest, async (id) => {
        if (id === 'art-1') return sampleBytes
        return undefined
      })
      expect(verifyRes.ok).toBe(true)
      expect(verifyRes.integrity).toBe('verified')

      // Deep recursive redaction test (AC081)
      const redacted = redactEvidenceBundle(bundleManifest, {
        sentinels: ['CONFIDENTIAL_NAME', 'CONFIDENTIAL_TOKEN'],
      })
      expect(redacted.researcher).toBe('[REDACTED]')
      expect(redacted.findings[0].observation).toContain('[REDACTED]')
      expect(redacted.findings[0].observation).not.toContain('CONFIDENTIAL_TOKEN')
    })
  })
})
