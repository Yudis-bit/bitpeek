import {
  OperationDescriptor,
  OperationExecutionContext,
  BitpeekCapabilityManifest,
} from './types'
import { BitpeekDoctor } from './doctor'
import { sha256Hex } from '../crypto'
import { calculateEntropy, parseHexPattern, findBytePatternPaged } from '../analysis'
import { extractPrintableStrings } from '../strings'
import { diffBytes } from '../diff'
import { parseElf, parsePng } from '../structures/index'
import { parsePe } from '../structures/pe'
import { parseWasm } from '../structures/wasm'
import { parseZip } from '../structures/zip'
import { parseGpt } from '../structures/gpt'
import { parseUbi } from '../structures/ubi'
import { parseSquashfs } from '../structures/squashfs'
import {
  NandGeometryManager,
  SYNTHETIC_LAB_NAND_PROFILE,
  ONFI_2K_64_PROFILE,
} from '../nand/geometry'
import { SafeTensorsParser } from '../ai/safetensors'
import { BitcoinParser } from '../bchain/bitcoin'

export class OperationRegistry {
  private operations = new Map<string, OperationDescriptor>()

  public register<TInput = any, TOutput = any>(descriptor: OperationDescriptor<TInput, TOutput>): void {
    this.operations.set(descriptor.id, descriptor)
  }

  public get(id: string): OperationDescriptor | undefined {
    return this.operations.get(id)
  }

  public has(id: string): boolean {
    return this.operations.has(id)
  }

  public list(): OperationDescriptor[] {
    return Array.from(this.operations.values())
  }

  public async execute<TInput = any, TOutput = any>(
    id: string,
    input: TInput,
    context?: OperationExecutionContext,
  ): Promise<TOutput> {
    const op = this.operations.get(id)
    if (!op) {
      throw new Error(`Unknown operation: ${id}`)
    }
    return op.execute(input, context)
  }

  public generateCapabilityManifest(): BitpeekCapabilityManifest {
    return {
      engine: 'Bitpeek Ultra Core',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      protocol: 'MCP stdio 2026-07-28 / CLI v1',
      supportedFormats: ['elf', 'png', 'pe', 'wasm', 'zip', 'gpt', 'ubi', 'squashfs'],
      supportedOperations: this.list().map((op) => ({
        id: op.id,
        title: op.title,
        version: op.version,
        deterministic: op.deterministic,
        readOnly: op.readOnly,
        environment: op.environment,
      })),
      limits: {
        maxReadBytes: 65536,
        maxSearchMatches: 1000,
        maxStrings: 1000,
        maxFileSizeDesktop: '512 MiB',
      },
      diagnostics: {
        nodeVersion: typeof process !== 'undefined' ? process.version : 'unknown',
        platform: typeof process !== 'undefined' ? process.platform : 'unknown',
        arch: typeof process !== 'undefined' ? process.arch : 'unknown',
      },
    }
  }
}

export function createDefaultOperationRegistry(): OperationRegistry {
  const registry = new OperationRegistry()

  // 1. Doctor check
  registry.register({
    id: 'doctor.check',
    version: '1.0.0',
    title: 'Diagnostic System Health Check',
    description: 'Inspect runtime, engines, parsers, and external environment readiness.',
    environment: 'any',
    deterministic: false,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 16 * 1024 * 1024, maxExecutionMs: 5000 },
    async execute() {
      return BitpeekDoctor.runDiagnostics()
    },
  })

  // 2. core.read
  registry.register({
    id: 'core.read',
    version: '1.0.0',
    title: 'Bounded Byte Read',
    description: 'Read bytes bounded by length and offset.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 1024 * 1024, maxExecutionMs: 1000 },
    async execute(input: { offset: number; length: number }, context?: OperationExecutionContext) {
      if (!context?.source) throw new Error('ByteSource context required for core.read')
      const maxLen = Math.min(input.length, 65536)
      const bytes = await context.source.read(input.offset, maxLen)
      return {
        offset: input.offset,
        length: bytes.length,
        bytes,
        sha256: sha256Hex(bytes),
      }
    },
  })

  // 3. core.inspect
  registry.register({
    id: 'core.inspect',
    version: '1.0.0',
    title: 'Inspect Scalar Interpretations & Entropy',
    description: 'Inspect scalar interpretations, hex dumps, and local Shannon entropy.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 1024 * 1024, maxExecutionMs: 1000 },
    async execute(input: { offset: number; length: number }, context?: OperationExecutionContext) {
      if (!context?.source) throw new Error('ByteSource context required for core.inspect')
      const len = Math.min(input.length, 65536)
      const bytes = await context.source.read(input.offset, len)
      return {
        offset: input.offset,
        length: bytes.length,
        entropy: calculateEntropy(bytes),
        sha256: sha256Hex(bytes),
        byteCount: bytes.length,
      }
    },
  })

  // 4. core.find
  registry.register({
    id: 'core.find',
    version: '1.0.0',
    title: 'Paged Pattern Search',
    description: 'Search for hexadecimal byte pattern with wildcards.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 4 * 1024 * 1024, maxExecutionMs: 10000 },
    async execute(input: { pattern: string; limit?: number; cursor?: number }, context?: OperationExecutionContext) {
      if (!context?.source) throw new Error('ByteSource context required for core.find')
      const parsed = parseHexPattern(input.pattern)
      if (!parsed.ok) throw new Error(`Invalid hex pattern: ${parsed.error}`)
      const limit = Math.min(input.limit ?? 1000, 1000)
      const cursor = input.cursor ?? 0
      const bytes = await context.source.read(0, Math.min(context.source.size, 10 * 1024 * 1024))
      return findBytePatternPaged(bytes, parsed.pattern, limit, cursor)
    },
  })

  // 5. core.strings
  registry.register({
    id: 'core.strings',
    version: '1.0.0',
    title: 'Extract Printable Strings',
    description: 'Extract ASCII and UTF-16LE printable strings with byte offsets.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 4 * 1024 * 1024, maxExecutionMs: 5000 },
    async execute(input: { minLength?: number; limit?: number }, context?: OperationExecutionContext) {
      if (!context?.source) throw new Error('ByteSource context required for core.strings')
      const bytes = await context.source.read(0, Math.min(context.source.size, 1024 * 1024))
      const strings = extractPrintableStrings(bytes, input.minLength ?? 4, input.limit ?? 1000)
      return { strings: strings.items, totalReturned: strings.items.length }
    },
  })

  // 6. core.diff
  registry.register({
    id: 'core.diff',
    version: '1.0.0',
    title: 'Bounded Byte Difference',
    description: 'Compare reference and current byte sources.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 8 * 1024 * 1024, maxExecutionMs: 10000 },
    async execute(input: { refBytes: Uint8Array; curBytes: Uint8Array }) {
      return diffBytes(input.refBytes, input.curBytes)
    },
  })

  // 7. core.structure
  registry.register({
    id: 'core.structure',
    version: '1.0.0',
    title: 'Multi-Format Structure Parser',
    description: 'Parse PE, ELF, PNG, Wasm, ZIP, GPT, UBI, SquashFS file headers.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 16 * 1024 * 1024, maxExecutionMs: 5000 },
    async execute(input: { format?: string }, context?: OperationExecutionContext) {
      if (!context?.source) throw new Error('ByteSource context required for core.structure')
      const head = await context.source.read(0, Math.min(context.source.size, 65536))
      const fmt = input.format?.toLowerCase() ?? 'auto'

      if (fmt === 'pe' || (fmt === 'auto' && head.length > 2 && head[0] === 0x4d && head[1] === 0x5a)) {
        const res = parsePe(head)
        if (!res) throw new Error('Failed to parse PE header')
        return res
      }
      if (fmt === 'elf' || (fmt === 'auto' && head.length > 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46)) {
        return parseElf(head)
      }
      if (fmt === 'png' || (fmt === 'auto' && head.length > 8 && head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47)) {
        return parsePng(head)
      }
      if (fmt === 'wasm' || (fmt === 'auto' && head.length > 4 && head[0] === 0x00 && head[1] === 0x61 && head[2] === 0x73 && head[3] === 0x6d)) {
        const res = parseWasm(head)
        if (!res) throw new Error('Failed to parse Wasm header')
        return res
      }
      if (fmt === 'zip' || (fmt === 'auto' && head.length > 4 && head[0] === 0x50 && head[1] === 0x4b)) {
        const res = parseZip(head)
        if (!res) throw new Error('Failed to parse ZIP header')
        return res
      }
      if (fmt === 'ubi' || (fmt === 'auto' && head.length > 4 && head[0] === 0x55 && head[1] === 0x42 && head[2] === 0x49 && head[3] === 0x23)) {
        const res = parseUbi(head)
        if (!res) throw new Error('Failed to parse UBI header')
        return res
      }
      if (fmt === 'squashfs' || (fmt === 'auto' && head.length > 4 && head[0] === 0x68 && head[1] === 0x73 && head[2] === 0x71 && head[3] === 0x73)) {
        const res = parseSquashfs(head)
        if (!res) throw new Error('Failed to parse SquashFS header')
        return res
      }
      if (fmt === 'gpt') {
        const res = parseGpt(head)
        if (!res) throw new Error('Failed to parse GPT header')
        return res
      }
      throw new Error(`Unsupported or unrecognized structure format: ${input.format}`)
    },
  })

  // 8. nand.geometry
  registry.register({
    id: 'nand.geometry',
    version: '1.0.0',
    title: 'NAND Geometry & Address Translation',
    description: 'Translate physical NAND chip/lun/block/page/column coordinates.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 2 * 1024 * 1024, maxExecutionMs: 1000 },
    async execute(input: { profile: 'synthetic-lab-512' | 'onfi-2k'; block: number; page: number; column?: number }) {
      const geom = new NandGeometryManager(
        input.profile === 'synthetic-lab-512'
          ? SYNTHETIC_LAB_NAND_PROFILE
          : ONFI_2K_64_PROFILE,
      )
      const column = input.column ?? 0
      const isOob = column >= geom.profile.dataBytesPerPage
      const offset = geom.physicalToOffset({
        chip: 0,
        lun: 0,
        block: input.block,
        page: input.page,
        column,
        isOob,
      })
      return {
        profile: geom.profile.name,
        physicalByteOffset: offset,
        isSpare: isOob,
      }
    },
  })

  // 9. safetensors.inspect
  registry.register({
    id: 'safetensors.inspect',
    version: '1.0.0',
    title: 'SafeTensors Inspection & Mapping',
    description: 'Inspect SafeTensors header and resolve element coordinates to byte offsets.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 8 * 1024 * 1024, maxExecutionMs: 2000 },
    async execute(input: { coordinates?: { tensor: string; indices: number[] } }, context?: OperationExecutionContext) {
      if (!context?.source) throw new Error('ByteSource context required for safetensors.inspect')
      const bytes = await context.source.read(0, Math.min(context.source.size, 10 * 1024 * 1024))
      const model = SafeTensorsParser.parse(bytes)
      const tensorSummaries: Record<string, any> = {}
      for (const [name, meta] of model.tensors.entries()) {
        tensorSummaries[name] = {
          dtype: meta.dtype,
          shape: meta.shape,
          elementCount: meta.elementCount,
          byteLength: meta.byteLength,
        }
      }
      let mappedCoord: any = null
      if (input.coordinates) {
        const t = model.tensors.get(input.coordinates.tensor)
        if (t) {
          mappedCoord = SafeTensorsParser.mapElementToFileSpan(t, input.coordinates.indices)
        }
      }
      return {
        headerLength: model.headerLength,
        metadata: model.metadata,
        tensorCount: model.tensors.size,
        tensors: tensorSummaries,
        mappedCoordinate: mappedCoord,
      }
    },
  })

  // 10. bitcoin.parse
  registry.register({
    id: 'bitcoin.parse',
    version: '1.0.0',
    title: 'Bitcoin Transaction Parser',
    description: 'Parse raw Bitcoin transaction bytes and compute double-SHA256 TXID.',
    environment: 'any',
    deterministic: true,
    readOnly: true,
    resourceProfile: { maxMemoryBytes: 2 * 1024 * 1024, maxExecutionMs: 1000 },
    async execute(input: { rawHex?: string }, context?: OperationExecutionContext) {
      let rawBytes: Uint8Array
      if (input.rawHex) {
        rawBytes = Uint8Array.from(
          input.rawHex.replace(/\s+/g, '').match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) ?? [],
        )
      } else if (context?.source) {
        rawBytes = await context.source.read(0, Math.min(context.source.size, 1024 * 1024))
      } else {
        throw new Error('Either rawHex or ByteSource context required')
      }

      const tx = BitcoinParser.parseTransaction(rawBytes)
      return {
        version: tx.version,
        isSegWit: tx.isSegWit,
        txidDisplay: tx.txidDisplay,
        txidWire: tx.txidWire,
        inputCount: tx.inputs.length,
        outputCount: tx.outputs.length,
        totalOutputSatoshis: tx.outputs.reduce((acc, out) => acc + out.valueSatoshis, 0n).toString(),
      }
    },
  })

  return registry
}
