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

  it('lists all 12 official Bitpeek tools', async () => {
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
    expect(res.tools).toHaveLength(12)
  })

  it('calls bitpeek_capabilities and returns engine details', async () => {
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
    expect(payload.engine).toContain('Bitpeek')
    expect(payload.supportedFormats).toContain('elf')
    expect(payload.supportedFormats).toContain('png')
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

  it('rejects access to file outside allowed input roots', async () => {
    const callHandler = (server as unknown as ServerInternal)._requestHandlers.get('tools/call')!
    const res = await callHandler({
      method: 'tools/call',
      params: {
        name: 'bitpeek_open',
        arguments: { filePath: 'C:\\Windows\\System32\\drivers\\etc\\hosts' },
      },
    })
    expect(res.isError).toBe(true)
    expect(res.content[0]?.text).toContain('Access denied')
  })
})
