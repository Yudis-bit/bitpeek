import { OperationRegistry } from '../operations/registry'

export type PluginTrustLevel = 'untrusted' | 'trusted' | 'system'

export interface PluginManifest {
  id: string
  name: string
  version: string
  description: string
  author?: string
  trustLevel: PluginTrustLevel
  permissions: ('read' | 'write' | 'network' | 'native')[]
  entrypoint?: string
}

export interface PluginContext {
  registry: OperationRegistry
  quota: {
    maxMemoryBytes: number
    maxExecutionMs: number
  }
  log(message: string): void
}

export interface PluginInstance {
  manifest: PluginManifest
  initialize(context: PluginContext): Promise<void> | void
  teardown?(): Promise<void> | void
}
