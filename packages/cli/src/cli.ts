import { readFile, writeFile, rename, unlink, stat } from 'node:fs/promises'
import { resolve } from 'node:path'
import {
  FileByteSource,
  parseHexPattern,
  findBytePatternPaged,
  extractPrintableStrings,
  sha256Hex,
  crc32,
  crc16,
  parseElf,
  parsePng,
  parseCustomStructure,
  diffBytes,
  validateOffsetPatch,
  verifyPatch,
  applyVerifiedPatch,
  validateRecipe,
  runRecipe,
  readFloat16,
  readFloat32,
  readFloat64,
  formatFloat,
  formatHex,
  BitpeekError,
  BitpeekDoctor,
} from '../../core/src/index'

export const EXIT_SUCCESS = 0
export const EXIT_INTERNAL_OR_IO = 1
export const EXIT_USAGE = 2
export const EXIT_INVALID_INPUT_OR_RANGE = 3
export const EXIT_INTEGRITY_OR_PRECONDITION_FAILED = 4
export const EXIT_RESOURCE_LIMIT = 5
export const EXIT_INTERRUPTED = 130

export const VERSION = '1.0.0'

export interface CliOptions {
  json?: boolean
  offset?: number
  length?: number
  type?: string
  endian?: 'little' | 'big'
  hex?: string
  text?: string
  limit?: number
  cursor?: number
  min_length?: number
  algorithm?: string
  format?: string
  schema?: string
  source?: string
  output?: string
  force?: boolean
  check?: boolean
  inputs?: Record<string, string>
  dry_run?: boolean
}

export function parseCliArgs(args: string[]): { command: string; subcommands: string[]; files: string[]; options: CliOptions } {
  const options: CliOptions = { inputs: {} }
  const files: string[] = []
  const subcommands: string[] = []
  let command = ''

  let i = 0
  while (i < args.length) {
    const arg = args[i]!
    if (arg === '--help' || arg === '-h') {
      command = 'help'
      i++
      continue
    }
    if (arg === '--version' || arg === '-v') {
      command = 'version'
      i++
      continue
    }

    if (arg === '--json') {
      options.json = true
      i++
    } else if (arg === '--force' || arg === '-f') {
      options.force = true
      i++
    } else if (arg === '--check') {
      options.check = true
      i++
    } else if (arg === '--dry-run') {
      options.dry_run = true
      i++
    } else if (arg === '--offset') {
      const val = args[++i]
      if (!val) throw new Error('Missing value for --offset')
      options.offset = /^0x/i.test(val) ? parseInt(val, 16) : parseInt(val, 10)
      i++
    } else if (arg === '--length') {
      const val = args[++i]
      if (!val) throw new Error('Missing value for --length')
      options.length = /^0x/i.test(val) ? parseInt(val, 16) : parseInt(val, 10)
      i++
    } else if (arg === '--type') {
      options.type = args[++i]
      i++
    } else if (arg === '--endian') {
      const val = (args[++i] ?? '').toLowerCase()
      options.endian = val === 'le' || val === 'little' ? 'little' : 'big'
      i++
    } else if (arg === '--hex') {
      options.hex = args[++i]
      i++
    } else if (arg === '--text') {
      options.text = args[++i]
      i++
    } else if (arg === '--limit') {
      options.limit = parseInt(args[++i] ?? '1000', 10)
      i++
    } else if (arg === '--cursor') {
      options.cursor = parseInt(args[++i] ?? '0', 10)
      i++
    } else if (arg === '--min-length') {
      options.min_length = parseInt(args[++i] ?? '4', 10)
      i++
    } else if (arg === '--algorithm') {
      options.algorithm = args[++i]
      i++
    } else if (arg === '--format') {
      options.format = args[++i]
      i++
    } else if (arg === '--schema') {
      options.schema = args[++i]
      i++
    } else if (arg === '--source') {
      options.source = args[++i]
      i++
    } else if (arg === '--output' || arg === '-o') {
      options.output = args[++i]
      i++
    } else if (arg === '--input') {
      const pair = args[++i] ?? ''
      const eq = pair.indexOf('=')
      if (eq > 0) {
        const id = pair.slice(0, eq)
        const path = pair.slice(eq + 1)
        options.inputs![id] = path
      }
      i++
    } else if (arg.startsWith('--')) {
      throw new Error(`Unknown option: ${arg}`)
    } else {
      if (!command) {
        command = arg
      } else if (['patch', 'recipe'].includes(command) && subcommands.length === 0) {
        subcommands.push(arg)
      } else {
        files.push(arg)
      }
      i++
    }
  }

  return { command, subcommands, files, options }
}

async function writeOutputAtomic(filePath: string, bytes: Uint8Array, force = false): Promise<void> {
  const fullPath = resolve(filePath)
  if (!force) {
    try {
      await stat(fullPath)
      throw new Error(`Output file already exists: ${filePath}. Use --force to overwrite.`)
    } catch (err: unknown) {
      if ((err as { code?: string }).code !== 'ENOENT') throw err
    }
  }

  const tmpPath = `${fullPath}.tmp.${process.pid}.${Date.now()}`
  try {
    await writeFile(tmpPath, bytes)
    await rename(tmpPath, fullPath)
  } catch (err) {
    try {
      await unlink(tmpPath)
    } catch {
      // ignore
    }
    throw err
  }
}

export async function runCli(argv: string[]): Promise<number> {
  let parsed: ReturnType<typeof parseCliArgs>
  try {
    parsed = parseCliArgs(argv)
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    process.stderr.write(`Error: ${msg}\nTry 'bitpeek --help' for usage.\n`)
    return EXIT_USAGE
  }

  const { command, subcommands, files, options } = parsed

  if (command === 'version') {
    process.stdout.write(`bitpeek ${VERSION}\n`)
    return EXIT_SUCCESS
  }

  if (command === 'help' || !command) {
    const help = `bitpeek v${VERSION} — A local-first binary workbench for inspecting bytes, checking structure, and reproducing changes.

Usage:
  bitpeek inspect <file> [--offset <n>] [--length <n>] [--type <t>] [--endian <le|be>] [--json]
  bitpeek find <file> (--hex <pattern> | --text <str>) [--limit <n>] [--cursor <n>] [--json]
  bitpeek strings <file> [--min-length <n>] [--limit <n>] [--json]
  bitpeek hash <file> [--algorithm <sha256|crc32|crc16>] [--json]
  bitpeek structure <file> [--format <elf|png|custom-schema>] [--schema <file.json>] [--json]
  bitpeek diff <reference> <current> [--json] [--check]
  bitpeek patch verify <patch.json> --source <reference> [--json]
  bitpeek patch apply <patch.json> --source <reference> --output <result> [--force]
  bitpeek recipe run <recipe.json> [--input <id=file>...] [--dry-run] [--output <id=out>] [--json]
  bitpeek doctor [--json]
  bitpeek --version
  bitpeek --help
`
    process.stdout.write(help)
    return EXIT_SUCCESS
  }

  try {
    switch (command) {
      case 'doctor': {
        const report = await BitpeekDoctor.runDiagnostics()
        if (options.json) {
          process.stdout.write(JSON.stringify(report, null, 2) + '\n')
        } else {
          process.stdout.write(`Bitpeek System Doctor Report [${report.overallStatus.toUpperCase()}]\n`)
          process.stdout.write(`Platform: ${report.platform} (${report.arch}), Node: ${report.nodeVersion}\n\n`)
          for (const c of report.checks) {
            const sym = c.status === 'pass' ? '✓' : c.status === 'warn' ? '⚠' : '✗'
            process.stdout.write(`[${sym}] ${c.category.toUpperCase()}: ${c.name} - ${c.details}\n`)
          }
        }
        return report.overallStatus === 'failing' ? EXIT_INTERNAL_OR_IO : EXIT_SUCCESS
      }

      case 'inspect': {
        const file = files[0]
        if (!file) {
          process.stderr.write('Error: Missing file argument for inspect.\n')
          return EXIT_USAGE
        }
        const source = await FileByteSource.open(file)
        const offset = options.offset ?? 0
        const length = options.length ?? Math.min(16, Math.max(0, source.size - offset))
        const endian = options.endian ?? 'big'
        const le = endian === 'little'

        if (offset < 0 || offset + length > source.size) {
          process.stderr.write(`Error: Requested range [${offset}, ${offset + length}) exceeds file size ${source.size}.\n`)
          await source.close()
          return EXIT_INVALID_INPUT_OR_RANGE
        }

        const bytes = await source.read(offset, length)
        await source.close()

        let interpretedValue: unknown = undefined
        const type = options.type
        if (type) {
          const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
          if (type === 'u8') interpretedValue = bytes[0]
          else if (type === 'i8') interpretedValue = view.getInt8(0)
          else if (type === 'u16' && bytes.length >= 2) interpretedValue = view.getUint16(0, le)
          else if (type === 'i16' && bytes.length >= 2) interpretedValue = view.getInt16(0, le)
          else if (type === 'u32' && bytes.length >= 4) interpretedValue = view.getUint32(0, le)
          else if (type === 'i32' && bytes.length >= 4) interpretedValue = view.getInt32(0, le)
          else if (type === 'u64' && bytes.length >= 8) interpretedValue = view.getBigUint64(0, le).toString(10)
          else if (type === 'i64' && bytes.length >= 8) interpretedValue = view.getBigInt64(0, le).toString(10)
          else if (type === 'f16' && bytes.length >= 2) interpretedValue = formatFloat(readFloat16(bytes.subarray(0, 2), endian))
          else if (type === 'f32' && bytes.length >= 4) interpretedValue = formatFloat(readFloat32(bytes.subarray(0, 4), endian))
          else if (type === 'f64' && bytes.length >= 8) interpretedValue = formatFloat(readFloat64(bytes.subarray(0, 8), endian))
        }

        const out = {
          file,
          fileSize: source.size,
          offset,
          length,
          hex: formatHex(bytes),
          endian,
          ...(type ? { type, value: interpretedValue } : {}),
        }

        if (options.json) {
          process.stdout.write(JSON.stringify(out, null, 2) + '\n')
        } else {
          process.stdout.write(`File: ${file} (${source.size} bytes)\n`)
          process.stdout.write(`Range: 0x${offset.toString(16).toUpperCase()}..0x${(offset + length).toString(16).toUpperCase()} (${length} bytes)\n`)
          process.stdout.write(`Hex: ${out.hex}\n`)
          if (type) process.stdout.write(`${type} (${endian}-endian): ${interpretedValue}\n`)
        }
        return EXIT_SUCCESS
      }

      case 'find': {
        const file = files[0]
        if (!file) {
          process.stderr.write('Error: Missing file argument for find.\n')
          return EXIT_USAGE
        }
        if (!options.hex && !options.text) {
          process.stderr.write('Error: Either --hex or --text pattern must be provided.\n')
          return EXIT_USAGE
        }

        const source = await FileByteSource.open(file)
        const fullBytes = await source.read(0, source.size)
        await source.close()

        const patternRes = parseHexPattern(options.hex ?? '')
        if (!patternRes.ok) {
          process.stderr.write(`Error: Invalid hex pattern: ${patternRes.error}\n`)
          return EXIT_INVALID_INPUT_OR_RANGE
        }

        const limit = options.limit ?? 1000
        const cursor = options.cursor ?? 0
        const matches = findBytePatternPaged(fullBytes, patternRes.pattern, limit, cursor)

        const out = {
          file,
          pattern: options.hex,
          matches: matches.offsets,
          count: matches.offsets.length,
          truncated: matches.truncated,
          scannedBytes: matches.scannedBytes,
          nextCursor: matches.nextCursor,
        }

        if (options.json) {
          process.stdout.write(JSON.stringify(out, null, 2) + '\n')
        } else {
          process.stdout.write(`Found ${matches.offsets.length} match(es) in ${file}:\n`)
          for (const off of matches.offsets) {
            process.stdout.write(`  0x${off.toString(16).toUpperCase().padStart(8, '0')} (${off})\n`)
          }
          if (matches.truncated) {
            process.stdout.write(`(Results truncated at limit ${limit}; resume with --cursor ${matches.nextCursor})\n`)
          }
        }
        return EXIT_SUCCESS
      }

      case 'strings': {
        const file = files[0]
        if (!file) {
          process.stderr.write('Error: Missing file argument for strings.\n')
          return EXIT_USAGE
        }
        const source = await FileByteSource.open(file)
        const fullBytes = await source.read(0, source.size)
        await source.close()

        const minLen = options.min_length ?? 4
        const limit = options.limit ?? 1000
        const result = extractPrintableStrings(fullBytes, minLen, limit)

        if (options.json) {
          process.stdout.write(JSON.stringify(result, null, 2) + '\n')
        } else {
          for (const item of result.items) {
            process.stdout.write(
              `0x${item.offset.toString(16).toUpperCase().padStart(8, '0')}\t${item.encoding}\t${item.byteLength}\t${item.value}\n`,
            )
          }
          if (result.truncated) {
            process.stdout.write(`(Output truncated at limit ${limit})\n`)
          }
        }
        return EXIT_SUCCESS
      }

      case 'hash': {
        const file = files[0]
        if (!file) {
          process.stderr.write('Error: Missing file argument for hash.\n')
          return EXIT_USAGE
        }
        const source = await FileByteSource.open(file)
        const fullBytes = await source.read(0, source.size)
        await source.close()

        const algo = (options.algorithm ?? 'sha256').toLowerCase()
        let digest = ''
        if (algo === 'sha256') digest = sha256Hex(fullBytes)
        else if (algo === 'crc32') digest = crc32(fullBytes).toString(16).toUpperCase().padStart(8, '0')
        else if (algo === 'crc16') digest = crc16(fullBytes).toString(16).toUpperCase().padStart(4, '0')
        else {
          process.stderr.write(`Error: Unsupported hash algorithm: ${options.algorithm}\n`)
          return EXIT_INVALID_INPUT_OR_RANGE
        }

        const out = { file, size: fullBytes.length, algorithm: algo, hash: digest }
        if (options.json) {
          process.stdout.write(JSON.stringify(out, null, 2) + '\n')
        } else {
          process.stdout.write(`${digest}  ${file}\n`)
        }
        return EXIT_SUCCESS
      }

      case 'structure': {
        const file = files[0]
        if (!file) {
          process.stderr.write('Error: Missing file argument for structure.\n')
          return EXIT_USAGE
        }
        const source = await FileByteSource.open(file)
        const fullBytes = await source.read(0, source.size)
        await source.close()

        const fmt = (options.format ?? 'auto').toLowerCase()
        let result
        if (fmt === 'elf') result = parseElf(fullBytes)
        else if (fmt === 'png') result = parsePng(fullBytes)
        else if (options.schema) {
          const rawSchema = JSON.parse(await readFile(options.schema, 'utf8'))
          result = parseCustomStructure(fullBytes, rawSchema)
        } else {
          // Auto
          if (fullBytes.length >= 8 && fullBytes[0] === 0x89 && fullBytes[1] === 0x50) {
            result = parsePng(fullBytes)
          } else if (fullBytes.length >= 4 && fullBytes[0] === 0x7f && fullBytes[1] === 0x45) {
            result = parseElf(fullBytes)
          } else {
            process.stderr.write('Error: Could not auto-detect format. Specify --format <elf|png> or --schema <file.json>.\n')
            return EXIT_INVALID_INPUT_OR_RANGE
          }
        }

        if (options.json) {
          process.stdout.write(JSON.stringify(result, null, 2) + '\n')
        } else {
          process.stdout.write(`Structure: ${result.format.toUpperCase()} (${result.status})\n`)
          for (const field of result.fields) {
            process.stdout.write(`- [0x${field.range.start.toString(16).toUpperCase()}..0x${field.range.end.toString(16).toUpperCase()}] ${field.label}: ${field.interpretedValue}\n`)
            if (field.children) {
              for (const child of field.children) {
                process.stdout.write(`    • [0x${child.range.start.toString(16).toUpperCase()}..0x${child.range.end.toString(16).toUpperCase()}] ${child.label}: ${child.interpretedValue}\n`)
              }
            }
          }
          if (result.warnings.length > 0) {
            process.stderr.write(`Warnings:\n${result.warnings.map((w) => `  - ${w}`).join('\n')}\n`)
          }
        }
        return EXIT_SUCCESS
      }

      case 'diff': {
        const refFile = files[0]
        const curFile = files[1]
        if (!refFile || !curFile) {
          process.stderr.write('Error: diff requires <reference> and <current> files.\n')
          return EXIT_USAGE
        }
        const refSource = await FileByteSource.open(refFile)
        const curSource = await FileByteSource.open(curFile)
        const refBytes = await refSource.read(0, refSource.size)
        const curBytes = await curSource.read(0, curSource.size)
        await refSource.close()
        await curSource.close()

        const diff = diffBytes(curBytes, refBytes)

        const out = {
          reference: { file: refFile, size: refBytes.length, sha256: sha256Hex(refBytes) },
          current: { file: curFile, size: curBytes.length, sha256: sha256Hex(curBytes) },
          modified: diff.modified,
          currentOnly: diff.currentOnly,
          referenceOnly: diff.referenceOnly,
          totalDifferences: diff.modified + diff.currentOnly + diff.referenceOnly,
          rangesCount: diff.ranges.length,
          ranges: diff.ranges,
        }

        if (options.json) {
          process.stdout.write(JSON.stringify(out, null, 2) + '\n')
        } else {
          process.stdout.write(`Diff: ${refFile} <-> ${curFile}\n`)
          process.stdout.write(`Modified bytes: ${diff.modified}\n`)
          process.stdout.write(`Current only: ${diff.currentOnly}\n`)
          process.stdout.write(`Reference only: ${diff.referenceOnly}\n`)
          process.stdout.write(`Difference ranges: ${diff.ranges.length}\n`)
        }

        if (options.check && (diff.modified > 0 || diff.currentOnly > 0 || diff.referenceOnly > 0)) {
          return 1 // exit 1 if differences found when --check requested for CI
        }
        return EXIT_SUCCESS
      }

      case 'patch': {
        const sub = subcommands[0]
        if (sub === 'verify') {
          const patchFile = files[0]
          if (!patchFile || !options.source) {
            process.stderr.write('Error: patch verify requires <patch.json> and --source <file>.\n')
            return EXIT_USAGE
          }
          const raw = JSON.parse(await readFile(patchFile, 'utf8'))
          const valRes = validateOffsetPatch(raw)
          if (!valRes.ok) {
            process.stderr.write(`Error: Invalid patch format: ${valRes.error}\n`)
            return EXIT_INVALID_INPUT_OR_RANGE
          }
          const source = await FileByteSource.open(options.source)
          const refBytes = await source.read(0, source.size)
          await source.close()

          const verRes = verifyPatch(refBytes, valRes.patch)
          if (!verRes.ok) {
            process.stderr.write(`Integrity failure: ${verRes.error}\n`)
            return EXIT_INTEGRITY_OR_PRECONDITION_FAILED
          }

          if (options.json) {
            process.stdout.write(JSON.stringify({ ok: true, patch: patchFile, source: options.source, integrity: verRes.integrity }, null, 2) + '\n')
          } else {
            process.stdout.write(`Patch "${patchFile}" is VALID against source "${options.source}" (${verRes.integrity}).\n`)
          }
          return EXIT_SUCCESS
        }

        if (sub === 'apply') {
          const patchFile = files[0]
          if (!patchFile || !options.source || !options.output) {
            process.stderr.write('Error: patch apply requires <patch.json>, --source <file>, and --output <target>.\n')
            return EXIT_USAGE
          }
          const raw = JSON.parse(await readFile(patchFile, 'utf8'))
          const valRes = validateOffsetPatch(raw)
          if (!valRes.ok) {
            process.stderr.write(`Error: Invalid patch format: ${valRes.error}\n`)
            return EXIT_INVALID_INPUT_OR_RANGE
          }
          const source = await FileByteSource.open(options.source)
          const refBytes = await source.read(0, source.size)
          await source.close()

          const appRes = applyVerifiedPatch(refBytes, valRes.patch)
          if (!appRes.ok) {
            process.stderr.write(`Integrity failure: ${appRes.error}\n`)
            return EXIT_INTEGRITY_OR_PRECONDITION_FAILED
          }

          await writeOutputAtomic(options.output, appRes.target, options.force)

          if (options.json) {
            process.stdout.write(JSON.stringify({ ok: true, output: options.output, size: appRes.target.length, sha256: sha256Hex(appRes.target) }, null, 2) + '\n')
          } else {
            process.stdout.write(`Successfully applied patch to "${options.output}" (${appRes.target.length} bytes).\n`)
          }
          return EXIT_SUCCESS
        }

        process.stderr.write(`Error: Unknown patch subcommand: "${sub}". Use verify or apply.\n`)
        return EXIT_USAGE
      }

      case 'recipe': {
        const sub = subcommands[0]
        if (sub === 'run') {
          const recipeFile = files[0]
          if (!recipeFile) {
            process.stderr.write('Error: recipe run requires <recipe.json>.\n')
            return EXIT_USAGE
          }
          const raw = JSON.parse(await readFile(recipeFile, 'utf8'))
          const valRes = validateRecipe(raw)
          if (!valRes.ok) {
            process.stderr.write(`Error: Invalid recipe: ${valRes.error}\n`)
            return EXIT_INVALID_INPUT_OR_RANGE
          }

          const inputBuffers: Record<string, Uint8Array> = {}
          for (const [id, path] of Object.entries(options.inputs ?? {})) {
            inputBuffers[id] = new Uint8Array(await readFile(path))
          }

          const result = runRecipe(valRes.recipe, inputBuffers, { dryRun: options.dry_run })
          if (!result.ok) {
            process.stderr.write(`Recipe execution failed: ${result.error}\n`)
            if (options.json) {
              process.stdout.write(JSON.stringify(result, null, 2) + '\n')
            }
            return EXIT_INTEGRITY_OR_PRECONDITION_FAILED
          }

          if (options.output && result.finalBytes && !options.dry_run) {
            await writeOutputAtomic(options.output, result.finalBytes, options.force)
          }

          if (options.json) {
            process.stdout.write(JSON.stringify(result, null, 2) + '\n')
          } else {
            process.stdout.write(`Recipe "${result.recipeId}" executed successfully (${result.stepResults.length} steps).\n`)
          }
          return EXIT_SUCCESS
        }

        process.stderr.write(`Error: Unknown recipe subcommand: "${sub}". Use run.\n`)
        return EXIT_USAGE
      }

      default:
        process.stderr.write(`Error: Unknown command "${command}". Try 'bitpeek --help'.\n`)
        return EXIT_USAGE
    }
  } catch (err: unknown) {
    if (err instanceof BitpeekError) {
      if (err.code === 'INVALID_INPUT' || err.code === 'INVALID_RANGE' || err.code === 'TRUNCATED_INPUT') {
        process.stderr.write(`Error: [${err.code}] ${err.message}\n`)
        return EXIT_INVALID_INPUT_OR_RANGE
      }
      if (err.code === 'PRECONDITION_FAILED' || err.code === 'HASH_MISMATCH') {
        process.stderr.write(`Error: [${err.code}] ${err.message}\n`)
        return EXIT_INTEGRITY_OR_PRECONDITION_FAILED
      }
      if (err.code === 'LIMIT_EXCEEDED') {
        process.stderr.write(`Error: [${err.code}] ${err.message}\n`)
        return EXIT_RESOURCE_LIMIT
      }
    }
    const message = err instanceof Error ? err.message : String(err)
    process.stderr.write(`Error: ${message}\n`)
    return EXIT_INTERNAL_OR_IO
  }
}
