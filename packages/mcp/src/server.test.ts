import { describe, expect, it } from 'vitest'
import { writeFile, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { createBitpeekMcpServer } from './server'
import { McpSecurityManager } from './security'

describe('Bitpeek MCP Server (Section 13)', () => {
  const tempDir = tmpdir()
  const security = new McpSecurityManager({
    allowedInputRoots: [tempDir],
    allowedOutputRoots: [tempDir],
  })
  const server = createBitpeekMcpServer(security)

  const tempFile = join(tempDir, `bitpeek-mcp-test-${Date.now()}.bin`)

  interface ServerInternal {
    _requestHandlers: Map<
      string,
      (req: { method: string; params: Record<string, unknown> }) => Promise<{
        tools: Array<{ name: string }>
        content: Array<{ text: string }>
        isError?: boolean
      }>
    >
  }

  it('lists all 17 official Bitpeek tools', async () => {
    const handler = (server as unknown as ServerInternal)._requestHandlers.get('tools/list')
    expect(handler).toBeDefined()
    const res = await handler!({ method: 'tools/list', params: {} })
    const toolNames = res.tools.map((t: { name: string }) => t.name)
    expect(toolNames).toContain('bitpeek_capabilities')
    expect(toolNames).toContain('bitpeek_open')
    expect(toolNames).toContain('bitpeek_read')
    expect(toolNames).toContain('bitpeek_inspect')
    expect(toolNames).toContain('bitpeek_find')
    expect(toolNames).toContain('bitpeek_strings')
    expect(toolNames).toContain('bitpeek_structure')
    expect(toolNames).toContain('bitpeek_diff')
    expect(toolNames).toContain('bitpeek_verify_patch')
    expect(toolNames).toContain('bitpeek_run_recipe')
    expect(toolNames).toContain('bitpeek_export')
    expect(toolNames).toContain('bitpeek_close')
    expect(toolNames).toContain('bitpeek_disassemble')
    expect(toolNames).toContain('bitpeek_doctor')
    expect(toolNames).toContain('bitpeek_entropy')
    expect(toolNames).toContain('bitpeek_secp256k1_audit')
    expect(toolNames).toContain('bitpeek_constant_time_audit')
    expect(res.tools).toHaveLength(17)
  })

  it('calls bitpeek_capabilities and returns engine details with Ultra formats', async () => {
    const handler = (server as unknown as ServerInternal)._requestHandlers.get('tools/call')
    const res = await handler!({
      method: 'tools/call',
      params: {
        name: 'bitpeek_capabilities',
        arguments: {},
      },
    })
    expect(res.isError).toBeUndefined()
    const payload = JSON.parse(res.content[0]?.text ?? '{}')
    expect(payload.engine).toContain('Bitpeek Ultra Core')
    expect(payload.supportedFormats).toContain('elf')
    expect(payload.supportedFormats).toContain('pe')
    expect(payload.supportedFormats).toContain('wasm')
    expect(payload.supportedFormats).toContain('png')
    expect(payload.supportedFormats).toContain('zip')
    expect(payload.supportedFormats).toContain('gpt')
    expect(payload.supportedFormats).toContain('ubi')
    expect(payload.supportedFormats).toContain('squashfs')
    expect(payload.supportedFormats).toContain('safetensors')
    expect(payload.supportedFormats).toContain('bitcoin')
    expect(payload.supportedFormats).toContain('ethereum')
    expect(payload.supportedFormats).toContain('custom-schema')
  })

  it('opens a file, reads bytes, and inspects scalars securely', async () => {
    const bytes = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04])
    await writeFile(tempFile, bytes)

    try {
      const callHandler = (server as unknown as ServerInternal)._requestHandlers.get('tools/call')!

      // 1. bitpeek_open
      const openRes = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_open',
          arguments: { filePath: tempFile },
        },
      })
      expect(openRes.isError).toBeUndefined()
      const openPayload = JSON.parse(openRes.content[0]?.text ?? '{}')
      expect(openPayload.handle).toMatch(/^sess_/)
      expect(openPayload.size).toBe(8)
      const handle = openPayload.handle

      // 2. bitpeek_read
      const readRes = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_read',
          arguments: { handle, offset: 0, length: 4 },
        },
      })
      const readPayload = JSON.parse(readRes.content[0]?.text ?? '{}')
      expect(readPayload.hex).toBe('DE AD BE EF')

      // 3. bitpeek_inspect
      const inspectRes = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_inspect',
          arguments: { handle, offset: 0, length: 4, type: 'u32', endian: 'big' },
        },
      })
      const inspectPayload = JSON.parse(inspectRes.content[0]?.text ?? '{}')
      expect(inspectPayload.value).toBe(3735928559)

      // 4. bitpeek_close
      const closeRes = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_close',
          arguments: { handle },
        },
      })
      const closePayload = JSON.parse(closeRes.content[0]?.text ?? '{}')
      expect(closePayload.ok).toBe(true)
    } finally {
      await unlink(tempFile).catch(() => {})
    }
  })

  it('runs bitpeek_doctor diagnostics through MCP tool', async () => {
    const callHandler = (server as unknown as ServerInternal)._requestHandlers.get('tools/call')!
    const res = await callHandler({
      method: 'tools/call',
      params: {
        name: 'bitpeek_doctor',
        arguments: {},
      },
    })
    expect(res.isError).toBeUndefined()
    const report = JSON.parse(res.content[0]?.text ?? '{}')
    expect(report.platform).toBeDefined()
    expect(report.overallStatus).toBeDefined()
    expect(Array.isArray(report.checks)).toBe(true)
    expect(report.checks.length).toBeGreaterThanOrEqual(5)
  })

  it('disassembles machine code and calculates entropy on an open session', async () => {
    // x86_64: 90 (NOP), C3 (RET)
    const codeBytes = Uint8Array.from([0x90, 0xc3, 0x00, 0x00, 0xff, 0xff])
    await writeFile(tempFile, codeBytes)
    try {
      const callHandler = (server as unknown as ServerInternal)._requestHandlers.get('tools/call')!

      // Open
      const openRes = await callHandler({
        method: 'tools/call',
        params: { name: 'bitpeek_open', arguments: { filePath: tempFile } },
      })
      const handle = JSON.parse(openRes.content[0]?.text ?? '{}').handle

      // Disassemble
      const disasmRes = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_disassemble',
          arguments: { handle, offset: 0, length: 2, arch: 'x86_64' },
        },
      })
      expect(disasmRes.isError).toBeUndefined()
      const insts = JSON.parse(disasmRes.content[0]?.text ?? '[]')
      expect(insts.length).toBeGreaterThanOrEqual(2)
      expect(insts[0].mnemonic).toBe('nop')
      expect(insts[1].mnemonic).toBe('ret')

      // Entropy
      const entRes = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_entropy',
          arguments: { handle, offset: 0, length: 6, blockSize: 2 },
        },
      })
      expect(entRes.isError).toBeUndefined()
      const entPayload = JSON.parse(entRes.content[0]?.text ?? '{}')
      expect(entPayload.overallEntropy).toBeGreaterThan(0)
      expect(entPayload.blockCount).toBe(3)

      // Close
      await callHandler({
        method: 'tools/call',
        params: { name: 'bitpeek_close', arguments: { handle } },
      })
    } finally {
      await unlink(tempFile).catch(() => {})
    }
  })

  it('parses WebAssembly structure using bitpeek_structure', async () => {
    // Standard WASM binary header: \0asm\1\0\0\0
    const wasmBytes = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
    await writeFile(tempFile, wasmBytes)
    try {
      const callHandler = (server as unknown as ServerInternal)._requestHandlers.get('tools/call')!
      const openRes = await callHandler({
        method: 'tools/call',
        params: { name: 'bitpeek_open', arguments: { filePath: tempFile } },
      })
      const handle = JSON.parse(openRes.content[0]?.text ?? '{}').handle

      const structRes = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_structure',
          arguments: { handle, format: 'auto' },
        },
      })
      expect(structRes.isError).toBeUndefined()
      const struct = JSON.parse(structRes.content[0]?.text ?? '{}')
      expect(struct.format).toBe('wasm')
      expect(struct.fields.length).toBeGreaterThanOrEqual(1)

      await callHandler({
        method: 'tools/call',
        params: { name: 'bitpeek_close', arguments: { handle } },
      })
    } finally {
      await unlink(tempFile).catch(() => {})
    }
  })

  it('verifies a Patch v2 using bitpeek_verify_patch', async () => {
    const srcBytes = Uint8Array.from([0x01, 0x02, 0x03, 0x04])
    await writeFile(tempFile, srcBytes)
    try {
      const callHandler = (server as unknown as ServerInternal)._requestHandlers.get('tools/call')!
      const openRes = await callHandler({
        method: 'tools/call',
        params: { name: 'bitpeek_open', arguments: { filePath: tempFile } },
      })
      const handle = JSON.parse(openRes.content[0]?.text ?? '{}').handle

      const patchV2Json = JSON.stringify({
        format: 'bitpeek-offset-patch',
        version: 2,
        sourceLength: 4,
        targetLength: 4,
        sourceSha256: '9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a',
        targetSha256: '1c2d69135de3ff945156bd8daa9c67c360565b037956aa9b0fa01c3ae04bcbef',
        operations: [{ offset: 1, bytes: '99 88', precondition: '02 03' }],
      })

      const verRes = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_verify_patch',
          arguments: { handle, patchJson: patchV2Json },
        },
      })
      expect(verRes.isError).toBeUndefined()
      const verPayload = JSON.parse(verRes.content[0]?.text ?? '{}')
      expect(verPayload.ok).toBe(true)

      await callHandler({
        method: 'tools/call',
        params: { name: 'bitpeek_close', arguments: { handle } },
      })
    } finally {
      await unlink(tempFile).catch(() => {})
    }
  })

  it('rejects access to file outside allowed input roots', async () => {
    const restrictedServer = createBitpeekMcpServer(new McpSecurityManager({
      allowedInputRoots: [join(tempDir, 'bitpeek-allowed-inputs')],
    }))
    await writeFile(tempFile, Uint8Array.from([0x01]))
    try {
      const callHandler = (restrictedServer as unknown as ServerInternal)._requestHandlers.get('tools/call')!
      const res = await callHandler({
        method: 'tools/call',
        params: {
          name: 'bitpeek_open',
          arguments: { filePath: tempFile },
        },
      })
      expect(res.isError).toBe(true)
      expect(res.content[0]?.text).toContain('Access denied')
    } finally {
      await unlink(tempFile)
    }
  })
})
