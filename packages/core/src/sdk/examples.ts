import { PluginInstance, PluginContext } from './types'

/**
 * Example Plugin: Adler32 Checksum Plugin (SDK-02)
 * Demonstrates registering a custom deterministic mathematical operation.
 */
export const Adler32Plugin: PluginInstance = {
  manifest: {
    id: 'plugin-adler32',
    name: 'Adler-32 Checksum Calculator',
    version: '1.0.0',
    description: 'Computes Adler-32 rolling checksum on byte buffers.',
    author: 'Bitpeek Contrib',
    trustLevel: 'trusted',
    permissions: ['read'],
  },
  initialize(context: PluginContext) {
    context.registry.register({
      id: 'plugin.adler32',
      version: '1.0.0',
      title: 'Adler-32 Checksum',
      description: 'Compute 32-bit Adler-32 checksum',
      environment: 'any',
      deterministic: true,
      readOnly: true,
      resourceProfile: { maxMemoryBytes: 1024 * 1024, maxExecutionMs: 1000 },
      async execute(input: { bytes: Uint8Array }) {
        let a = 1
        let b = 0
        const MOD_ADLER = 65521
        for (let i = 0; i < input.bytes.length; i++) {
          a = (a + input.bytes[i]) % MOD_ADLER
          b = (b + a) % MOD_ADLER
        }
        const checksum = (b << 16) | a
        return {
          checksumHex: (checksum >>> 0).toString(16).padStart(8, '0'),
          checksumNum: checksum >>> 0,
        }
      },
    })
  },
  teardown() {},
}

/**
 * Example Plugin: TarHeaderPlugin (SDK-02)
 * Demonstrates registering a custom structural format parser.
 */
export const TarHeaderPlugin: PluginInstance = {
  manifest: {
    id: 'plugin-tar-header',
    name: 'POSIX UStar TAR Header Parser',
    version: '1.0.0',
    description: 'Parses standard 512-byte POSIX UStar tar headers.',
    author: 'Bitpeek Contrib',
    trustLevel: 'trusted',
    permissions: ['read'],
  },
  initialize(context: PluginContext) {
    context.registry.register({
      id: 'plugin.format.tar',
      version: '1.0.0',
      title: 'TAR Header Parser',
      description: 'Parse POSIX tar header fields',
      environment: 'any',
      deterministic: true,
      readOnly: true,
      resourceProfile: { maxMemoryBytes: 1024 * 1024, maxExecutionMs: 1000 },
      async execute(input: { headerBytes: Uint8Array }) {
        if (input.headerBytes.length < 512) {
          throw new Error('TAR header requires at least 512 bytes')
        }
        const decoder = new TextDecoder('ascii')
        const name = decoder.decode(input.headerBytes.subarray(0, 100)).replace(/\0+$/, '')
        const mode = decoder.decode(input.headerBytes.subarray(100, 108)).replace(/\0+$/, '').trim()
        const sizeStr = decoder.decode(input.headerBytes.subarray(124, 136)).replace(/\0+$/, '').trim()
        const magic = decoder.decode(input.headerBytes.subarray(257, 263)).replace(/\0+$/, '')
        const isUstar = magic.startsWith('ustar')
        const size = parseInt(sizeStr, 8) || 0
        return {
          name,
          mode,
          size,
          magic,
          isUstar,
        }
      },
    })
  },
  teardown() {},
}
