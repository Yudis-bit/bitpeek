import { BitpeekError } from './errors'
import type { Diagnostic } from './types'

export interface ResourceBudgetLimits {
  maxBytesAllocated: number
  maxNodes: number
  maxReads: number
  maxOutputBytes: number
  deadlineMs?: number
}

export const DEFAULT_RESOURCE_BUDGET_LIMITS: ResourceBudgetLimits = {
  maxBytesAllocated: 64 * 1024 * 1024, // 64 MiB managed buffer target
  maxNodes: 50_000,
  maxReads: 100_000,
  maxOutputBytes: 16 * 1024 * 1024,
}

export class ResourceBudget {
  readonly limits: ResourceBudgetLimits
  private bytesAllocated = 0
  private nodesCount = 0
  private readsCount = 0
  private outputBytesCount = 0
  private startTime: number

  constructor(limits: Partial<ResourceBudgetLimits> = {}) {
    this.limits = { ...DEFAULT_RESOURCE_BUDGET_LIMITS, ...limits }
    this.startTime = Date.now()
  }

  reserveBytes(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0) {
      throw new BitpeekError('INVALID_RANGE', `Byte reservation must be non-negative: ${bytes}`)
    }
    if (this.bytesAllocated + bytes > this.limits.maxBytesAllocated) {
      throw new BitpeekError(
        'RESOURCE_LIMIT',
        `Exceeded memory quota: cannot allocate ${bytes} bytes (current: ${this.bytesAllocated}, limit: ${this.limits.maxBytesAllocated}).`,
      )
    }
    this.bytesAllocated += bytes
  }

  releaseBytes(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0) return
    this.bytesAllocated = Math.max(0, this.bytesAllocated - bytes)
  }

  chargeNodes(count = 1): void {
    this.nodesCount += count
    if (this.nodesCount > this.limits.maxNodes) {
      throw new BitpeekError(
        'RESOURCE_LIMIT',
        `Exceeded node budget limit of ${this.limits.maxNodes} items.`,
      )
    }
  }

  chargeReads(count = 1): void {
    this.readsCount += count
    if (this.readsCount > this.limits.maxReads) {
      throw new BitpeekError(
        'RESOURCE_LIMIT',
        `Exceeded I/O read count budget limit of ${this.limits.maxReads} operations.`,
      )
    }
  }

  chargeOutputBytes(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0) return
    this.outputBytesCount += bytes
    if (this.outputBytesCount > this.limits.maxOutputBytes) {
      throw new BitpeekError(
        'RESOURCE_LIMIT',
        `Exceeded output byte budget limit of ${this.limits.maxOutputBytes} bytes.`,
      )
    }
  }

  checkDeadline(): void {
    if (this.limits.deadlineMs !== undefined) {
      const elapsed = Date.now() - this.startTime
      if (elapsed > this.limits.deadlineMs) {
        throw new BitpeekError(
          'RESOURCE_LIMIT',
          `Operation exceeded maximum execution deadline of ${this.limits.deadlineMs} ms.`,
        )
      }
    }
  }

  childBudget(childLimits: Partial<ResourceBudgetLimits> = {}): ResourceBudget {
    return new ResourceBudget({
      maxBytesAllocated: Math.min(
        this.limits.maxBytesAllocated - this.bytesAllocated,
        childLimits.maxBytesAllocated ?? this.limits.maxBytesAllocated,
      ),
      maxNodes: Math.min(
        this.limits.maxNodes - this.nodesCount,
        childLimits.maxNodes ?? this.limits.maxNodes,
      ),
      maxReads: Math.min(
        this.limits.maxReads - this.readsCount,
        childLimits.maxReads ?? this.limits.maxReads,
      ),
      maxOutputBytes: Math.min(
        this.limits.maxOutputBytes - this.outputBytesCount,
        childLimits.maxOutputBytes ?? this.limits.maxOutputBytes,
      ),
      deadlineMs: childLimits.deadlineMs ?? this.limits.deadlineMs,
    })
  }

  get stats() {
    return {
      bytesAllocated: this.bytesAllocated,
      nodesCount: this.nodesCount,
      readsCount: this.readsCount,
      outputBytesCount: this.outputBytesCount,
      elapsedMs: Date.now() - this.startTime,
    }
  }
}

export interface OperationProgress {
  phase: string
  completed: number
  total?: number
  message?: string
}

export interface OperationContext {
  signal?: AbortSignal
  resources: ResourceBudget
  progress?: (event: OperationProgress) => void
  diagnostics: Diagnostic[]
}

export function createOperationContext(
  signal?: AbortSignal,
  limits?: Partial<ResourceBudgetLimits>,
): OperationContext {
  return {
    signal,
    resources: new ResourceBudget(limits),
    diagnostics: [],
  }
}
