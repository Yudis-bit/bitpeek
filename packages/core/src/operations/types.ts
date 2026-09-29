import { ByteSource } from '../byte-source'

export type OperationEnvironment = 'any' | 'node-only' | 'browser-only'

export interface ResourceProfile {
  maxMemoryBytes?: number
  maxExecutionMs?: number
}

export interface OperationDescriptor<TInput = any, TOutput = any> {
  id: string
  version: string
  title: string
  description: string
  environment: OperationEnvironment
  deterministic: boolean
  readOnly: boolean
  resourceProfile: ResourceProfile
  inputSchema?: Record<string, unknown>
  outputSchema?: Record<string, unknown>
  execute(input: TInput, context?: OperationExecutionContext): Promise<TOutput>
}

export interface OperationExecutionContext {
  signal?: AbortSignal
  source?: ByteSource
  sessionHandle?: string
  workingDirectory?: string
}

export interface BitpeekCapabilityManifest {
  engine: string
  version: string
  timestamp: string
  protocol: string
  supportedFormats: string[]
  supportedOperations: {
    id: string
    title: string
    version: string
    deterministic: boolean
    readOnly: boolean
    environment: OperationEnvironment
  }[]
  limits: {
    maxReadBytes: number
    maxSearchMatches: number
    maxStrings: number
    maxFileSizeDesktop: string
  }
  diagnostics: {
    nodeVersion: string
    platform: string
    arch: string
  }
}
