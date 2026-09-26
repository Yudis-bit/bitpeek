import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js'
import { writeFile } from 'node:fs/promises'
import { McpSecurityManager } from './security.js'
import {
  FileByteSource,
  parseHexPattern,
  findBytePatternPaged,
  extractPrintableStrings,
  sha256Hex,
  crc32,
  parseElf,
  parsePng,
  diffBytes,
  validateOffsetPatch,
  verifyPatch,
  validateRecipe,
  runRecipe,
  formatHex,
  readFloat16,
  readFloat32,
  readFloat64,
  formatFloat,
  calculateEntropy,
  BitpeekError,
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
        {
          name: 'bitpeek_capabilities',
          description: 'Get Bitpeek engine capabilities, supported formats, schemas, and resource limits.',
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
          description: 'Parse file structure (ELF or PNG) with exact byte-to-field mappings and status validation.',
          inputSchema: {
            type: 'object',
            properties: {
              handle: { type: 'string', description: 'Session handle.' },
              format: { type: 'string', enum: ['elf', 'png', 'auto'], description: 'Format parser to use.' },
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
          description: 'Verify a bitpeek-offset-patch against an open session.',
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
          description: 'Run a deterministic recipe against open sessions.',
          inputSchema: {
            type: 'object',
            properties: {
              recipeJson: { type: 'string', description: 'JSON string of recipe-v1.' },
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
      ],
    }
  })

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params
    try {
      switch (name) {
        case 'bitpeek_capabilities': {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    engine: 'Bitpeek Core v1.0.0',
                    protocol: 'MCP stdio 2026-07-28',
                    supportedFormats: ['elf', 'png', 'custom-schema'],
                    limits: {
                      maxReadBytes: 65536,
                      maxSearchMatches: 1000,
                      maxStrings: 1000,
                      maxFileSizeDesktop: '512 MiB',
                    },
                    schemas: {
                      patch: 'schemas/offset-patch-v1.json',
                      recipe: 'schemas/recipe-v1.json',
                      structure: 'schemas/structure-schema-v1.json',
                    },
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

          const source = await FileByteSource.open(session.canonicalPath)
          const fullBytes = await source.read(0, session.size)
          await source.close()

          let result
          if (format === 'elf') result = parseElf(fullBytes)
          else if (format === 'png') result = parsePng(fullBytes)
          else {
            if (fullBytes.length >= 8 && fullBytes[0] === 0x89 && fullBytes[1] === 0x50) result = parsePng(fullBytes)
            else if (fullBytes.length >= 4 && fullBytes[0] === 0x7f && fullBytes[1] === 0x45) result = parseElf(fullBytes)
            else throw new BitpeekError('INVALID_INPUT', 'Could not auto-detect format. Specify format="elf" or "png".')
          }
          return {
            content: [{ type: 'text', text: JSON.stringify(result) }],
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
          const valRes = validateRecipe(rawRecipe)
          if (!valRes.ok) throw new BitpeekError('INVALID_INPUT', valRes.error)

          const handles = (args?.['inputs'] as Record<string, string>) ?? {}
          const inputBuffers: Record<string, Uint8Array> = {}
          for (const [id, handle] of Object.entries(handles)) {
            const sess = security.getSession(handle)
            const src = await FileByteSource.open(sess.canonicalPath)
            inputBuffers[id] = await src.read(0, sess.size)
            await src.close()
          }

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

export async function runMcpServer() {
  const server = createBitpeekMcpServer()
  const transport = new StdioServerTransport()
  await server.connect(transport)
  process.stderr.write('Bitpeek MCP server running on stdio.\n')
}
