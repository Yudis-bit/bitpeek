/**
 * Bitpeek Ultra - GPU Compute Sanitizer Log Parser & Tensor Correlator
 *
 * Implements Section 16 (AI-06, AC073):
 * - Normalizes NVIDIA Compute Sanitizer / cuda-memcheck diagnostic logs
 * - Extracts fault device addresses, kernel names, thread/block coordinates
 * - Correlates observed illegal accesses to declared tensor allocations
 */

export interface GpuDiagnostic {
  tool: 'compute-sanitizer' | 'cuda-memcheck'
  errorKind: string
  deviceAddress: bigint
  accessType?: 'READ' | 'WRITE'
  accessSizeBytes?: number
  threadCoord?: [number, number, number]
  blockCoord?: [number, number, number]
  kernelName?: string
  sourceLocation?: string
  correlatedTensor?: {
    tensorName: string
    declaredBaseAddress: bigint
    declaredSizeBytes: bigint
    offsetInTensorBytes: bigint
    isOutOfBounds: boolean
    overflowBytes?: bigint
  }
}

export interface DeclaredGpuTensor {
  name: string
  deviceAddress: bigint
  sizeBytes: bigint
}

export class GpuSanitizerParser {
  /**
   * Parses NVIDIA Compute Sanitizer output and correlates with declared tensors.
   */
  public static parse(
    logText: string,
    declaredTensors: DeclaredGpuTensor[] = [],
  ): GpuDiagnostic | null {
    const lines = logText.split(/\r?\n/)

    let errorKind = ''
    let deviceAddress = 0n
    let accessType: 'READ' | 'WRITE' | undefined
    let accessSizeBytes: number | undefined
    let threadCoord: [number, number, number] | undefined
    let blockCoord: [number, number, number] | undefined
    let kernelName: string | undefined
    let sourceLocation: string | undefined

    for (const line of lines) {
      const trimmed = line.trim()

      // Error line: ========= Invalid __global__ read of size 4 [bytes]
      const errMatch = trimmed.match(/Invalid __global__ (read|write) of size ([0-9]+)(?: bytes)?/i)
      if (errMatch) {
        accessType = errMatch[1]!.toUpperCase() as 'READ' | 'WRITE'
        accessSizeBytes = parseInt(errMatch[2]!, 10)
        errorKind = `Invalid __global__ ${errMatch[1]!.toLowerCase()}`
      }

      // Address line: =========     at 0x0000007f90001004 in ...
      const addrMatch = trimmed.match(/at (0x[0-9a-fA-F]+)(?: in (.*))?/)
      if (addrMatch) {
        deviceAddress = BigInt(addrMatch[1]!)
        if (addrMatch[2]) {
          kernelName = addrMatch[2].trim()
        }
      }

      // Thread/Block coordinates: =========     by thread (0,0,0) in block (1,0,0)
      const coordMatch = trimmed.match(/by thread \(([0-9]+),([0-9]+),([0-9]+)\) in block \(([0-9]+),([0-9]+),([0-9]+)\)/)
      if (coordMatch) {
        threadCoord = [parseInt(coordMatch[1]!, 10), parseInt(coordMatch[2]!, 10), parseInt(coordMatch[3]!, 10)]
        blockCoord = [parseInt(coordMatch[4]!, 10), parseInt(coordMatch[5]!, 10), parseInt(coordMatch[6]!, 10)]
      }

      // Source location line: =========     Saved host backtrace / path/to/kernel.cu:42
      const srcMatch = trimmed.match(/([a-zA-Z0-9_./\\-]+\.(?:cu|c|cpp|h)):([0-9]+)/)
      if (srcMatch && !sourceLocation) {
        sourceLocation = `${srcMatch[1]}:${srcMatch[2]}`
      }
    }

    if (!errorKind && deviceAddress === 0n) {
      return null
    }

    // Correlate with declared tensors
    let correlatedTensor: GpuDiagnostic['correlatedTensor']
    for (const t of declaredTensors) {
      const start = t.deviceAddress
      const end = t.deviceAddress + t.sizeBytes

      // Check if address is inside or just past this tensor
      if (deviceAddress >= start && deviceAddress < end + 1024n * 1024n) {
        const offsetInTensor = deviceAddress - start
        const isOutOfBounds = deviceAddress >= end
        const overflowBytes = isOutOfBounds ? deviceAddress - end : undefined

        correlatedTensor = {
          tensorName: t.name,
          declaredBaseAddress: start,
          declaredSizeBytes: t.sizeBytes,
          offsetInTensorBytes: offsetInTensor,
          isOutOfBounds,
          overflowBytes,
        }
        break
      }
    }

    return {
      tool: 'compute-sanitizer',
      errorKind: errorKind || 'Illegal Memory Access',
      deviceAddress,
      accessType,
      accessSizeBytes,
      threadCoord,
      blockCoord,
      kernelName,
      sourceLocation,
      correlatedTensor,
    }
  }
}
