/**
 * Bitpeek Ultra - ASan & UBSan Diagnostic Log Parser
 *
 * Implements Section 11 (TRACE-03, AC054, AC055, AC056):
 * - Normalizes real AddressSanitizer (ASan) & UBSan diagnostic logs
 * - Extracts fault addresses, access sizes, crash stacks, allocation & free stacks
 */

export interface SanitizerStackFrame {
  frameNumber: number
  pc: bigint
  functionName: string
  sourceFile?: string
  lineNumber?: number
}

export interface SanitizerDiagnostic {
  sanitizer: 'asan' | 'ubsan'
  errorType: string
  faultAddress?: bigint
  accessType?: 'READ' | 'WRITE'
  accessSize?: number
  crashStack: SanitizerStackFrame[]
  freeStack?: SanitizerStackFrame[]
  allocStack?: SanitizerStackFrame[]
  rawSummary?: string
}

export class SanitizerLogParser {
  /**
   * Parses an AddressSanitizer (ASan) log text.
   */
  public static parseAsan(logText: string): SanitizerDiagnostic | null {
    const lines = logText.split(/\r?\n/)
    let errorType = ''
    let faultAddress: bigint | undefined
    let accessType: 'READ' | 'WRITE' | undefined
    let accessSize: number | undefined
    let rawSummary: string | undefined

    const crashStack: SanitizerStackFrame[] = []
    const freeStack: SanitizerStackFrame[] = []
    const allocStack: SanitizerStackFrame[] = []

    type StackTarget = 'crash' | 'free' | 'alloc' | 'none'
    let currentTarget: StackTarget = 'none'

    for (const line of lines) {
      const trimmed = line.trim()

      // Header: ==123==ERROR: AddressSanitizer: <bug-type> on address 0x...
      const errMatch = trimmed.match(/ERROR:\s+AddressSanitizer:\s+([a-zA-Z0-9\-_]+)\s+on\s+address\s+(0x[0-9a-fA-F]+)/)
      if (errMatch) {
        errorType = errMatch[1]!
        faultAddress = BigInt(errMatch[2]!)
        rawSummary = trimmed
        currentTarget = 'crash'
        continue
      }

      // Access: READ of size 4 at 0x...
      const accessMatch = trimmed.match(/(READ|WRITE)\s+of\s+size\s+([0-9]+)/)
      if (accessMatch) {
        accessType = accessMatch[1] as 'READ' | 'WRITE'
        accessSize = parseInt(accessMatch[2]!, 10)
        continue
      }

      if (trimmed.includes('freed by thread') || trimmed.includes('freed here:')) {
        currentTarget = 'free'
        continue
      }

      if (trimmed.includes('previously allocated by thread') || trimmed.includes('allocated here:')) {
        currentTarget = 'alloc'
        continue
      }

      // Stack frame: #0 0x401234 in main /path/to/test.c:42
      const frameMatch = trimmed.match(/^#([0-9]+)\s+(0x[0-9a-fA-F]+)\s+in\s+([^\s]+)(?:\s+(.+?):([0-9]+))?/)
      if (frameMatch) {
        const frameNumber = parseInt(frameMatch[1]!, 10)
        const pc = BigInt(frameMatch[2]!)
        const functionName = frameMatch[3]!
        const sourceFile = frameMatch[4]
        const lineNumber = frameMatch[5] ? parseInt(frameMatch[5], 10) : undefined

        const frame: SanitizerStackFrame = {
          frameNumber,
          pc,
          functionName,
          sourceFile,
          lineNumber,
        }

        if (currentTarget === 'crash') {
          crashStack.push(frame)
        } else if (currentTarget === 'free') {
          freeStack.push(frame)
        } else if (currentTarget === 'alloc') {
          allocStack.push(frame)
        }
      }
    }

    if (!errorType && crashStack.length === 0) {
      return null
    }

    return {
      sanitizer: 'asan',
      errorType: errorType || 'unknown-asan-error',
      faultAddress,
      accessType,
      accessSize,
      crashStack,
      freeStack: freeStack.length > 0 ? freeStack : undefined,
      allocStack: allocStack.length > 0 ? allocStack : undefined,
      rawSummary,
    }
  }

  /**
   * Parses an UndefinedBehaviorSanitizer (UBSan) log text.
   */
  public static parseUbsan(logText: string): SanitizerDiagnostic | null {
    const lines = logText.split(/\r?\n/)

    for (const line of lines) {
      const match = line.match(/^(.+?):([0-9]+):(?:[0-9]+:)?\s+runtime error:\s+(.+)$/)
      if (match) {
        const sourceFile = match[1]!
        const lineNumber = parseInt(match[2]!, 10)
        const desc = match[3]!

        let errorType = 'undefined-behavior'
        if (desc.includes('overflow')) errorType = 'integer-overflow'
        else if (desc.includes('out of bounds')) errorType = 'index-out-of-bounds'
        else if (desc.includes('null pointer')) errorType = 'null-pointer-dereference'
        else if (desc.includes('shift')) errorType = 'invalid-shift'

        return {
          sanitizer: 'ubsan',
          errorType,
          crashStack: [
            {
              frameNumber: 0,
              pc: 0n,
              functionName: 'unknown',
              sourceFile,
              lineNumber,
            },
          ],
          rawSummary: desc,
        }
      }
    }

    return null
  }
}
