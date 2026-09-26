import { describe, expect, it } from 'vitest'
import { writeFile, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { runCli, EXIT_SUCCESS, EXIT_USAGE, EXIT_INVALID_INPUT_OR_RANGE } from './cli'

describe('Bitpeek CLI (Section 12)', () => {
  const tempSample = join(tmpdir(), `bitpeek-cli-test-${Date.now()}.bin`)

  it('runs --help with exit code 0', async () => {
    const code = await runCli(['--help'])
    expect(code).toBe(EXIT_SUCCESS)
  })

  it('runs --version with exit code 0', async () => {
    const code = await runCli(['--version'])
    expect(code).toBe(EXIT_SUCCESS)
  })

  it('returns usage exit code 2 when argument is missing', async () => {
    const code = await runCli(['inspect'])
    expect(code).toBe(EXIT_USAGE)
  })

  it('inspects a binary file and returns exit code 0', async () => {
    const bytes = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04])
    await writeFile(tempSample, bytes)
    try {
      const code = await runCli(['inspect', tempSample, '--offset', '0', '--length', '4', '--type', 'u32', '--json'])
      expect(code).toBe(EXIT_SUCCESS)
    } finally {
      await unlink(tempSample).catch(() => {})
    }
  })

  it('returns invalid range exit code 3 when offset exceeds file size', async () => {
    const bytes = Uint8Array.from([1, 2, 3])
    await writeFile(tempSample, bytes)
    try {
      const code = await runCli(['inspect', tempSample, '--offset', '100', '--json'])
      expect(code).toBe(EXIT_INVALID_INPUT_OR_RANGE)
    } finally {
      await unlink(tempSample).catch(() => {})
    }
  })
})
