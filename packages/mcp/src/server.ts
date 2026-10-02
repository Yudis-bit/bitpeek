import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'
import { writeFile } from 'node:fs/promises'
import { McpSecurityManager } from './security.js'
import { callAuditTool, MCP_AUDIT_TOOLS, MCP_TIMING_MAX_BYTES, MCP_TIMING_MAX_INSTRUCTIONS } from './audit-tools.js'
import {
  FileByteSource,
  parseHexPattern,
  findBytePatternPaged,
  extractPrintableStrings,
  sha256Hex,
  crc32,
  diffBytes,
  validateOffsetPatch,
  verifyPatch,
  validateRecipe,
  runRecipe,
  replayRecipeV2,
  formatHex,
  readFloat16,
  readFloat32,
  readFloat64,
  formatFloat,
  calculateEntropy,
  BitpeekError,
  parseStructureByFormat,
  ReferenceDisassembler,
  BitpeekDoctor,
  SECP256K1_AUDIT_MAX_BYTES,
} from '../../core/src/index.js'

export function createBitpeekMcpServer(security = new McpSecurityManager()) {
  const server = new Server(
    {
      name: 'bitpeek',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    },
  )

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        ...MCP_AUDIT_TOOLS,
        {
          name: 'bitpeek_capabilities',
          description: 'Get Bitpeek engine capabilities, supported formats (ELF, PE, WASM, PNG, ZIP, GPT, UBI, SquashFS, SafeTensors, Bitcoin, Ethereum, Custom Schema), schemas, and resource limits.',
          inputSchema: { type: 'object', properties: {} },
        },
        {
          name: 'bitpeek_open',
          description: 'Open and register a local file within allowed input roots, returning an opaque session handle.',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: { type: 'string', description: 'Relative or absolute path to the local binary file.' },
            },
            required: ['filePath'],
          },
        },
        {
          name: 'bitpeek_read',
          description: 'Read a bounded byte range from an open session handle.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle returned from bitpeek_open.' },
              offset: { type: 'number', description: 'Starting byte offset (non-negative safe integer).' },
              length: { type: 'number', description: 'Number of bytes to read (max 65536).' },
            },
            required: ['handle', 'offset', 'length'],
          },
        },
        {
          name: 'bitpeek_inspect',
          description: 'Inspect scalar interpretations (u8-u64, i8-i64, f16-f64), checksums, and entropy on a byte range.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle.' },
              offset: { type: 'number', description: 'Starting byte offset.' },
              length: { type: 'number', description: 'Length of bytes to inspect.' },
              type: { type: 'string', description: 'Scalar type (u8, u16, u32, u64, i8, i16, i32, i64, f16, f32, f64).' },
              endian: { type: 'string', enum: ['little', 'big'], description: 'Endianness (default: big).' },
            },
            required: ['handle', 'offset', 'length'],
          },
        },
        {
          name: 'bitpeek_find',
          description: 'Search for hexadecimal byte patterns (with wildcard support) with pagination.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle.' },
              pattern: { type: 'string', description: 'Hex pattern string, e.g. "DE ?? BE EF".' },
              limit: { type: 'number', description: 'Maximum matches to return (default 1000).' },
              cursor: { type: 'number', description: 'Cursor to resume pagination.' },
            },
            required: ['handle', 'pattern'],
          },
        },
        {
          name: 'bitpeek_strings',
          description: 'Extract printable ASCII and UTF-16 strings with byte offsets.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle.' },
              minLength: { type: 'number', description: 'Minimum string length (default 4).' },
              limit: { type: 'number', description: 'Maximum strings to return.' },
            },
            required: ['handle'],
          },
        },
        {
          name: 'bitpeek_structure',
          description: 'Parse file structure (ELF, PE, WASM, PNG, ZIP, GPT, UBI, SquashFS, SafeTensors, Bitcoin, Ethereum, or Custom Schema) with exact byte-to-field mappings and status validation.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle.' },
              format: {
                type: 'string',
                enum: [
                  'auto',
                  'elf',
                  'pe',
                  'wasm',
                  'png',
                  'zip',
                  'gpt',
                  'ubi',
                  'squashfs',
                  'safetensors',
                  'bitcoin',
                  'ethereum',
                  'custom-schema',
                ],
                description: 'Format parser to use (default: auto).',
              },
              customSchemaJson: { type: 'string', description: 'Optional JSON string for custom-schema v1 or v2.' },
            },
            required: ['handle'],
          },
        },
        {
          name: 'bitpeek_diff',
          description: 'Compare bytes between current session and a reference file.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle for current file.' },
              referencePath: { type: 'string', description: 'Path to reference file to compare against.' },
            },
            required: ['handle', 'referencePath'],
          },
        },
        {
          name: 'bitpeek_verify_patch',
          description: 'Verify a bitpeek-offset-patch (version 1 or version 2) against an open session.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle.' },
              patchJson: { type: 'string', description: 'JSON string of bitpeek-offset-patch.' },
            },
            required: ['handle', 'patchJson'],
          },
        },
        {
          name: 'bitpeek_run_recipe',
          description: 'Run a deterministic recipe (recipe-v1 or recipe-v2) against open sessions.',
          inputSchema: {
            type: 'object',
            properties: {
              recipeJson: { type: 'string', description: 'JSON string of recipe-v1 or recipe-v2.' },
              inputs: { type: 'object', description: 'Mapping of inputId to session handle.' },
              dryRun: { type: 'boolean', description: 'Dry run execution (default true).' },
            },
            required: ['recipeJson', 'inputs'],
          },
        },
        {
          name: 'bitpeek_export',
          description: 'Write byte buffer to allowed output directory.',
          inputSchema: {
            type: 'object',
            properties: {
              outputPath: { type: 'string', description: 'Target file path in allowed output directory.' },
              hexData: { type: 'string', description: 'Hex-encoded bytes to write.' },
              force: { type: 'boolean', description: 'Overwrite existing file.' },
            },
            required: ['outputPath', 'hexData'],
          },
        },
        {
          name: 'bitpeek_close',
          description: 'Close an open session and release resources.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle to close.' },
            },
            required: ['handle'],
          },
        },
        {
          name: 'bitpeek_disassemble',
          description: 'Disassemble machine code instructions (x86_64 or aarch64) over a byte range in an open session.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle.' },
              offset: { type: 'number', description: 'Starting byte offset (default: 0).' },
              length: { type: 'number', description: 'Number of bytes to disassemble (max 65536, default: 256).' },
              arch: { type: 'string', enum: ['x86_64', 'aarch64'], description: 'Target architecture (default: x86_64).' },
              baseAddress: { type: 'string', description: 'Optional base address as hex or decimal string (e.g. "0x401000").' },
              maxInstructions: { type: 'number', description: 'Maximum instructions to return (default: 1000).' },
            },
            required: ['handle'],
          },
        },
        {
          name: 'bitpeek_doctor',
          description: 'Run Bitpeek subsystem health checks and runtime diagnostics.',
          inputSchema: { type: 'object', properties: {} },
        },
        {
          name: 'bitpeek_entropy',
          description: 'Calculate Shannon entropy (0.0 to 8.0 bits/byte) and chunked entropy distribution over a byte range.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle.' },
              offset: { type: 'number', description: 'Starting byte offset (default: 0).' },
              length: { type: 'number', description: 'Number of bytes to analyze (defaults to remaining size).' },
              blockSize: { type: 'number', description: 'Block size for chunked entropy profile (default: 256).' },
            },
            required: ['handle'],
          },
        },
      ],
    }
  })

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: args } = request.params
    try {
      if (name === 'bitpeek_secp256k1_audit' || name === 'bitpeek_constant_time_audit') {
        return await callAuditTool(name, args ?? {}, security, extra?.signal)
      }
      switch (name) {
        case 'bitpeek_capabilities': {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    engine: 'Bitpeek Ultra Core v1.0.0',
                    version: '1.0.0',
                    protocol: 'MCP stdio 2026-07-28',
                    supportedFormats: [
                      'elf',
                      'pe',
                      'wasm',
                      'png',
                      'zip',
                      'gpt',
                      'ubi',
                      'squashfs',
                      'safetensors',
                      'bitcoin',
                      'ethereum',
                      'custom-schema',
                    ],
                    supportedChecksums: [
                      'crc16-ccitt',
                      'crc32-ieee',
                      'sha256',
                      'sha512',
                      'sum8',
                      'xor8',
                      'entropy-shannon',
                    ],
                    supportedEncodings: [
                      'hex',
                      'binary',
                      'decimal',
                      'base64',
                      'ascii',
                      'utf8',
                      'utf16le',
                      'utf16be',
                    ],
                    limits: {
                      maxReadBytes: 65536,
                      maxSearchMatches: 1000,
                      maxStrings: 1000,
                      maxFileSizeDesktop: '512 MiB',
                      maxSecp256k1AuditBytes: SECP256K1_AUDIT_MAX_BYTES,
                      maxConstantTimeAuditBytes: MCP_TIMING_MAX_BYTES,
                      maxConstantTimeAuditInstructions: MCP_TIMING_MAX_INSTRUCTIONS,
                    },
                    schemas: {
                      patchV1: 'schemas/offset-patch-v1.json',
                      patchV2: 'schemas/offset-patch-v2.json',
                      recipeV1: 'schemas/recipe-v1.json',
                      recipeV2: 'schemas/recipe-v2.json',
                      evidenceReportV1: 'schemas/evidence-report-v1.json',
                      structure: 'schemas/structure-schema-v1.json',
                    },
                    auditTools: MCP_AUDIT_TOOLS.map(tool => ({ name: tool.name, description: tool.description })),
                    auditRecipes: ['secp256k1.audit'],
                    workspaceFeatures: [
                      'multiple-documents',
                      'local-projects',
                      'session-recovery',
                      'annotations',
                      'aligned-diff',
                      'structure-comparison',
                      'entropy-map',
                      'recipe-preview',
                      'evidence-export',
                    ],
                  },
                  null,
                  2,
                ),
              },
            ],
          }
        }

        case 'bitpeek_open': {
          const filePath = String(args?.['filePath'] ?? '')
          const realPath = await security.validateInputPath(filePath)
          const source = await FileByteSource.open(realPath)
          const size = source.size
          await source.close()
          const handle = security.createSession(realPath, size)
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ handle, filePath: realPath, size }),
              },
            ],
          }
        }

        case 'bitpeek_read': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const offset = Number(args?.['offset'] ?? 0)
          const length = Math.min(65536, Number(args?.['length'] ?? 4096))
          const source = await FileByteSource.open(session.canonicalPath)
          const bytes = await source.read(offset, length)
          await source.close()
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  handle,
                  offset,
                  length: bytes.length,
                  hex: formatHex(bytes),
                  sha256: sha256Hex(bytes),
                }),
              },
            ],
          }
        }

        case 'bitpeek_inspect': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const offset = Number(args?.['offset'] ?? 0)
          const length = Number(args?.['length'] ?? 4)
          const type = (args?.['type'] as string | undefined) ?? 'u32'
          const endian = (args?.['endian'] as 'little' | 'big' | undefined) ?? 'big'
          const le = endian === 'little'

          const source = await FileByteSource.open(session.canonicalPath)
          const bytes = await source.read(offset, length)
          await source.close()

          let value: unknown
          const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
          if (type === 'u8' && bytes.length >= 1) value = bytes[0]
          else if (type === 'i8' && bytes.length >= 1) value = view.getInt8(0)
          else if (type === 'u16' && bytes.length >= 2) value = view.getUint16(0, le)
          else if (type === 'i16' && bytes.length >= 2) value = view.getInt16(0, le)
          else if (type === 'u32' && bytes.length >= 4) value = view.getUint32(0, le)
          else if (type === 'i32' && bytes.length >= 4) value = view.getInt32(0, le)
          else if (type === 'u64' && bytes.length >= 8) value = view.getBigUint64(0, le).toString(10)
          else if (type === 'i64' && bytes.length >= 8) value = view.getBigInt64(0, le).toString(10)
          else if (type === 'f16' && bytes.length >= 2) value = formatFloat(readFloat16(bytes.subarray(0, 2), endian))
          else if (type === 'f32' && bytes.length >= 4) value = formatFloat(readFloat32(bytes.subarray(0, 4), endian))
          else if (type === 'f64' && bytes.length >= 8) value = formatFloat(readFloat64(bytes.subarray(0, 8), endian))

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  offset,
                  length: bytes.length,
                  hex: formatHex(bytes),
                  type,
                  endian,
                  value,
                  entropy: calculateEntropy(bytes),
                  crc32: crc32(bytes).toString(16).toUpperCase().padStart(8, '0'),
                  sha256: sha256Hex(bytes),
                }),
              },
            ],
          }
        }

        case 'bitpeek_find': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const pattern = String(args?.['pattern'] ?? '')
          const limit = Number(args?.['limit'] ?? 1000)
          const cursor = Number(args?.['cursor'] ?? 0)

          const source = await FileByteSource.open(session.canonicalPath)
          const fullBytes = await source.read(0, session.size)
          await source.close()

          const pat = parseHexPattern(pattern)
          if (!pat.ok) throw new BitpeekError('INVALID_INPUT', pat.error)
          const matches = findBytePatternPaged(fullBytes, pat.pattern, limit, cursor)

          return {
            content: [{ type: 'text', text: JSON.stringify(matches) }],
          }
        }

        case 'bitpeek_strings': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const minLength = Number(args?.['minLength'] ?? 4)
          const limit = Number(args?.['limit'] ?? 1000)

          const source = await FileByteSource.open(session.canonicalPath)
          const fullBytes = await source.read(0, session.size)
          await source.close()

          const result = extractPrintableStrings(fullBytes, minLength, limit)
          return {
            content: [{ type: 'text', text: JSON.stringify(result) }],
          }
        }

        case 'bitpeek_structure': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const format = String(args?.['format'] ?? 'auto')
          let customSchema: any = undefined
          if (args?.['customSchemaJson']) {
            try {
              customSchema = JSON.parse(String(args['customSchemaJson']))
            } catch (err: unknown) {
              throw new BitpeekError('INVALID_INPUT', `Invalid customSchemaJson: ${String(err)}`)
            }
          }

          const source = await FileByteSource.open(session.canonicalPath)
          const fullBytes = await source.read(0, session.size)
          await source.close()

          const result = parseStructureByFormat(fullBytes, format, customSchema)
          if (!result) {
            throw new BitpeekError(
              'INVALID_INPUT',
              `Could not detect or parse structure for format "${format}". Ensure the file contains valid headers.`,
            )
          }
          const safeJson = (data: unknown) =>
            JSON.stringify(data, (_, v) => (typeof v === 'bigint' ? v.toString() : v))
          return {
            content: [{ type: 'text', text: safeJson(result) }],
          }
        }

        case 'bitpeek_diff': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const refPath = await security.validateInputPath(String(args?.['referencePath'] ?? ''))

          const curSource = await FileByteSource.open(session.canonicalPath)
          const refSource = await FileByteSource.open(refPath)
          const curBytes = await curSource.read(0, session.size)
          const refBytes = await refSource.read(0, refSource.size)
          await curSource.close()
          await refSource.close()

          const diff = diffBytes(curBytes, refBytes)
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  currentSize: curBytes.length,
                  referenceSize: refBytes.length,
                  modified: diff.modified,
                  currentOnly: diff.currentOnly,
                  referenceOnly: diff.referenceOnly,
                  ranges: diff.ranges,
                }),
              },
            ],
          }
        }

        case 'bitpeek_verify_patch': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const rawPatch = JSON.parse(String(args?.['patchJson'] ?? '{}'))
          const valRes = validateOffsetPatch(rawPatch)
          if (!valRes.ok) throw new BitpeekError('INVALID_INPUT', valRes.error)

          const source = await FileByteSource.open(session.canonicalPath)
          const refBytes = await source.read(0, session.size)
          await source.close()

          const verRes = verifyPatch(refBytes, valRes.patch)
          return {
            content: [{ type: 'text', text: JSON.stringify(verRes) }],
          }
        }

        case 'bitpeek_run_recipe': {
          const rawRecipe = JSON.parse(String(args?.['recipeJson'] ?? '{}'))
          const handles = (args?.['inputs'] as Record<string, string>) ?? {}
          const inputBuffers: Record<string, Uint8Array> = {}
          for (const [id, handle] of Object.entries(handles)) {
            const sess = security.getSession(handle)
            const src = await FileByteSource.open(sess.canonicalPath)
            inputBuffers[id] = await src.read(0, sess.size)
            await src.close()
          }

          if (rawRecipe.version === 2) {
            const result = replayRecipeV2(rawRecipe, inputBuffers)
            return {
              content: [{ type: 'text', text: JSON.stringify(result) }],
            }
          }

          const valRes = validateRecipe(rawRecipe)
          if (!valRes.ok) throw new BitpeekError('INVALID_INPUT', valRes.error)

          const result = runRecipe(valRes.recipe, inputBuffers, { dryRun: Boolean(args?.['dryRun'] ?? true) })
          return {
            content: [{ type: 'text', text: JSON.stringify(result) }],
          }
        }

        case 'bitpeek_export': {
          const outPath = await security.validateOutputPath(String(args?.['outputPath'] ?? ''))
          const hex = String(args?.['hexData'] ?? '').replace(/\s+/g, '')
          const bytes = new Uint8Array(hex.length / 2)
          for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
          }
          await writeFile(outPath, bytes)
          return {
            content: [{ type: 'text', text: JSON.stringify({ ok: true, path: outPath, bytesWritten: bytes.length }) }],
          }
        }

        case 'bitpeek_close': {
          const handle = String(args?.['handle'] ?? '')
          const closed = security.closeSession(handle)
          return {
            content: [{ type: 'text', text: JSON.stringify({ ok: closed, handle }) }],
          }
        }

        case 'bitpeek_disassemble': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const offset = Number(args?.['offset'] ?? 0)
          const length = Math.min(65536, Number(args?.['length'] ?? 256))
          const arch = (args?.['arch'] as 'x86_64' | 'aarch64') ?? 'x86_64'
          const baseAddrStr = String(args?.['baseAddress'] ?? '0')
          const baseAddress = baseAddrStr.startsWith('0x') || baseAddrStr.startsWith('0X')
            ? BigInt(baseAddrStr)
            : BigInt(baseAddrStr || '0')
          const maxInstructions = Math.min(10000, Number(args?.['maxInstructions'] ?? 1000))

          const source = await FileByteSource.open(session.canonicalPath)
          const bytes = await source.read(offset, length)
          await source.close()

          const insts = ReferenceDisassembler.disassemble(bytes, { arch, baseAddress, maxInstructions })
          const serialized = insts.map((i) => ({
            address: '0x' + i.address.toString(16),
            length: i.length,
            mnemonic: i.mnemonic,
            operands: i.operands,
            arch: i.arch,
            isValid: i.isValid,
            hex: formatHex(i.bytes),
          }))
          return {
            content: [{ type: 'text', text: JSON.stringify(serialized) }],
          }
        }

        case 'bitpeek_doctor': {
          const report = await BitpeekDoctor.runDiagnostics()
          return {
            content: [{ type: 'text', text: JSON.stringify(report) }],
          }
        }

        case 'bitpeek_entropy': {
          const handle = String(args?.['handle'] ?? '')
          const session = security.getSession(handle)
          const offset = Number(args?.['offset'] ?? 0)
          const length = Number(args?.['length'] ?? (session.size - offset))
          const blockSize = Math.max(1, Number(args?.['blockSize'] ?? 256))

          const source = await FileByteSource.open(session.canonicalPath)
          const bytes = await source.read(offset, length)
          await source.close()

          const overallEntropy = calculateEntropy(bytes)
          const blocks: (number | null)[] = []
          for (let i = 0; i < bytes.length; i += blockSize) {
            const chunk = bytes.subarray(i, Math.min(i + blockSize, bytes.length))
            const ent = calculateEntropy(chunk)
            blocks.push(ent !== null ? Number(ent.toFixed(4)) : null)
          }
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  offset,
                  length: bytes.length,
                  overallEntropy: overallEntropy !== null ? Number(overallEntropy.toFixed(4)) : null,
                  blockSize,
                  blockCount: blocks.length,
                  blocks,
                }),
              },
            ],
          }
        }

        default:
          throw new BitpeekError('INVALID_INPUT', `Unknown tool: ${name}`)
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)
      return {
        isError: true,
        content: [{ type: 'text', text: `Error: ${message}` }],
      }
    }
  })

  return server
}

export async function runMcpServer(customSecurity?: McpSecurityManager) {
  let security = customSecurity
  if (!security) {
    const allowedRoots: string[] = []
    for (let i = 2; i < process.argv.length; i++) {
      if (process.argv[i] === '--allowed-roots' && process.argv[i + 1]) {
        allowedRoots.push(...process.argv[i + 1]!.split(',').map((s: string) => s.trim()).filter(Boolean))
        i++
      }
    }
    if (process.env['BITPEEK_ALLOWED_ROOTS']) {
      allowedRoots.push(...process.env['BITPEEK_ALLOWED_ROOTS'].split(',').map((s: string) => s.trim()).filter(Boolean))
    }
    if (allowedRoots.length > 0) {
      security = new McpSecurityManager({
        allowedInputRoots: allowedRoots,
        allowedOutputRoots: allowedRoots,
      })
    }
  }
  const server = createBitpeekMcpServer(security)
  const transport = new StdioServerTransport()
  await server.connect(transport)
  process.stderr.write('Bitpeek MCP server running on stdio.\n')
}
