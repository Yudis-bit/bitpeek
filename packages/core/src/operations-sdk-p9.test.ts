import { describe, it, expect } from 'vitest'
import {
  createDefaultOperationRegistry,
  OperationRegistry,
  BitpeekDoctor,
  PluginManager,
  Adler32Plugin,
  TarHeaderPlugin,
  MemoryByteSource,
} from './index'

describe('Phase P9 - Unified Operation Dispatch & Plugin SDK', () => {
  describe('Operation Registry & Capabilities (CORE-06, AC084)', () => {
    it('initializes default registry with all core operations', () => {
      const registry = createDefaultOperationRegistry()
      const ops = registry.list()
      expect(ops.length).toBeGreaterThanOrEqual(10)

      expect(registry.has('doctor.check')).toBe(true)
      expect(registry.has('core.read')).toBe(true)
      expect(registry.has('core.inspect')).toBe(true)
      expect(registry.has('core.find')).toBe(true)
      expect(registry.has('core.strings')).toBe(true)
      expect(registry.has('core.diff')).toBe(true)
      expect(registry.has('core.structure')).toBe(true)
      expect(registry.has('nand.geometry')).toBe(true)
      expect(registry.has('safetensors.inspect')).toBe(true)
      expect(registry.has('bitcoin.parse')).toBe(true)
    })

    it('generates accurate BitpeekCapabilityManifest reflecting supported formats and operations', () => {
      const registry = createDefaultOperationRegistry()
      const manifest = registry.generateCapabilityManifest()

      expect(manifest.engine).toBe('Bitpeek Ultra Core')
      expect(manifest.version).toBe('1.0.0')
      expect(manifest.supportedFormats).toContain('pe')
      expect(manifest.supportedFormats).toContain('elf')
      expect(manifest.supportedFormats).toContain('png')
      expect(manifest.supportedFormats).toContain('wasm')
      expect(manifest.supportedFormats).toContain('zip')
      expect(manifest.supportedFormats).toContain('gpt')
      expect(manifest.supportedFormats).toContain('ubi')
      expect(manifest.supportedFormats).toContain('squashfs')

      const opIds = manifest.supportedOperations.map((o) => o.id)
      expect(opIds).toContain('core.read')
      expect(opIds).toContain('nand.geometry')
      expect(opIds).toContain('safetensors.inspect')
      expect(opIds).toContain('bitcoin.parse')
    })

    it('rejects execution of unregistered operation', async () => {
      const registry = createDefaultOperationRegistry()
      await expect(registry.execute('nonexistent.operation', {})).rejects.toThrow('Unknown operation: nonexistent.operation')
    })
  })

  describe('Doctor Health Diagnostics (CLI-02)', () => {
    it('runs BitpeekDoctor diagnostics and reports healthy or degraded status', async () => {
      const report = await BitpeekDoctor.runDiagnostics()
      expect(report.platform).toBeDefined()
      expect(report.arch).toBeDefined()
      expect(report.checks.length).toBeGreaterThanOrEqual(5)
      expect(['healthy', 'degraded']).toContain(report.overallStatus)

      const cryptoCheck = report.checks.find((c) => c.name.includes('Cryptographic'))
      expect(cryptoCheck?.status).toBe('pass')

      const formatCheck = report.checks.find((c) => c.name.includes('Structural'))
      expect(formatCheck?.status).toBe('pass')
    })
  })

  describe('Plugin SDK & Lifecycle (SDK-01, SDK-02, AC084)', () => {
    it('validates plugin manifests and rejects invalid entries', () => {
      const registry = new OperationRegistry()
      const manager = new PluginManager(registry)

      const invalidPlugin: any = {
        manifest: { name: 'Invalid No ID' },
      }
      const val = manager.validatePlugin(invalidPlugin)
      expect(val.valid).toBe(false)
      expect(val.errors.length).toBeGreaterThan(0)
    })

    it('registers and executes Adler-32 plugin operation (SDK-02)', async () => {
      const registry = new OperationRegistry()
      const manager = new PluginManager(registry)

      await manager.registerPlugin(Adler32Plugin)
      expect(registry.has('plugin.adler32')).toBe(true)

      const testData = new TextEncoder().encode('Wikipedia')
      // Standard Adler-32 of "Wikipedia" is 0x11E60398
      const res: any = await registry.execute('plugin.adler32', { bytes: testData })
      expect(res.checksumHex).toBe('11e60398')

      // Unregister
      const unregistered = await manager.unregisterPlugin(Adler32Plugin.manifest.id)
      expect(unregistered).toBe(true)
    })

    it('registers and parses TAR header via TarHeaderPlugin (SDK-02)', async () => {
      const registry = new OperationRegistry()
      const manager = new PluginManager(registry)

      await manager.registerPlugin(TarHeaderPlugin)
      expect(registry.has('plugin.format.tar')).toBe(true)

      // Create a 512-byte dummy tar header:
      // name: "test.txt", mode: "0000644\0", size: "00000000100\0" (64 bytes in octal), magic: "ustar\0"
      const header = new Uint8Array(512)
      new TextEncoder().encodeInto('test.txt\0', header.subarray(0, 10))
      new TextEncoder().encodeInto('0000644\0', header.subarray(100, 108))
      new TextEncoder().encodeInto('00000000100\0', header.subarray(124, 136))
      new TextEncoder().encodeInto('ustar\0', header.subarray(257, 263))

      const res: any = await registry.execute('plugin.format.tar', { headerBytes: header })
      expect(res.name).toBe('test.txt')
      expect(res.size).toBe(64)
      expect(res.isUstar).toBe(true)
    })
  })

  describe('Cross-Surface Semantic Parity (AC086)', () => {
    it('executes core.inspect and core.read with identical results to direct byte operations', async () => {
      const registry = createDefaultOperationRegistry()
      const sample = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x42, 0xaa])
      const source = new MemoryByteSource(sample)

      const readRes: any = await registry.execute('core.read', { offset: 1, length: 3 }, { source })
      expect(readRes.offset).toBe(1)
      expect(readRes.length).toBe(3)
      expect(Array.from(readRes.bytes)).toEqual([0xad, 0xbe, 0xef])

      const inspectRes: any = await registry.execute('core.inspect', { offset: 0, length: 6 }, { source })
      expect(inspectRes.byteCount).toBe(6)
      expect(inspectRes.entropy).toBeGreaterThan(0)
    })

    it('nand.geometry produces identical physical byte offset calculations', async () => {
      const registry = createDefaultOperationRegistry()
      const res: any = await registry.execute('nand.geometry', {
        profile: 'synthetic-lab-512',
        block: 2,
        page: 5,
        column: 10,
      })
      // block size = 32 * 528 = 16896
      // page 5 = 5 * 528 = 2640
      // 2 * 16896 + 2640 + 10 = 33792 + 2640 + 10 = 36442
      expect(res.physicalByteOffset).toBe(36442)
      expect(res.isSpare).toBe(false)
    })
  })
})
