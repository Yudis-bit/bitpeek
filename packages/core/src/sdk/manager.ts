import { PluginInstance, PluginManifest, PluginContext } from './types'
import { OperationRegistry } from '../operations/registry'

export class PluginManager {
  private plugins = new Map<string, PluginInstance>()
  private registry: OperationRegistry

  constructor(registry: OperationRegistry) {
    this.registry = registry
  }

  public validatePlugin(plugin: PluginInstance): { valid: boolean; errors: string[] } {
    const errors: string[] = []
    if (!plugin.manifest) {
      errors.push('Plugin manifest is required')
      return { valid: false, errors }
    }
    if (!plugin.manifest.id || typeof plugin.manifest.id !== 'string') {
      errors.push('Plugin manifest must contain a valid id')
    }
    if (!plugin.manifest.version || typeof plugin.manifest.version !== 'string') {
      errors.push('Plugin manifest must contain a valid semver version')
    }
    if (typeof plugin.initialize !== 'function') {
      errors.push('Plugin must implement initialize(context) function')
    }
    return { valid: errors.length === 0, errors }
  }

  public async registerPlugin(plugin: PluginInstance): Promise<void> {
    const validation = this.validatePlugin(plugin)
    if (!validation.valid) {
      throw new Error(`Plugin validation failed: ${validation.errors.join(', ')}`)
    }

    if (this.plugins.has(plugin.manifest.id)) {
      throw new Error(`Plugin with ID "${plugin.manifest.id}" is already registered`)
    }

    const context: PluginContext = {
      registry: this.registry,
      quota: {
        maxMemoryBytes: 32 * 1024 * 1024,
        maxExecutionMs: 5000,
      },
      log: (_msg: string) => {},
    }

    await plugin.initialize(context)
    this.plugins.set(plugin.manifest.id, plugin)
  }

  public async unregisterPlugin(pluginId: string): Promise<boolean> {
    const plugin = this.plugins.get(pluginId)
    if (!plugin) return false

    if (plugin.teardown) {
      await plugin.teardown()
    }
    this.plugins.delete(pluginId)
    return true
  }

  public getPlugin(pluginId: string): PluginInstance | undefined {
    return this.plugins.get(pluginId)
  }

  public listPlugins(): PluginManifest[] {
    return Array.from(this.plugins.values()).map((p) => p.manifest)
  }
}
