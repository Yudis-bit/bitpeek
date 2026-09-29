/**
 * Bitpeek Ultra - EVM Trace Record Adapter
 *
 * Implements Section 15 (BCHAIN-03, AC064):
 * - Structured EVM trace events (PC, opcode, gas, stack, memory)
 * - Exact 256-bit stack words as BigInt
 */

export interface EvmTraceStep {
  stepIndex: number
  pc: number
  op: string
  gas: bigint
  gasCost: bigint
  depth: number
  stack: bigint[]
  memory?: Uint8Array
  returnData?: Uint8Array
}

export class EvmTraceParser {
  /**
   * Parses standard JSON or object-based EVM trace dumps (e.g. from Geth / Hardhat / Foundry).
   */
  public static parseTrace(rawSteps: any[]): EvmTraceStep[] {
    return rawSteps.map((step, idx) => {
      const pc = typeof step.pc === 'number' ? step.pc : parseInt(step.pc, 10) || 0
      const op = step.op || step.opcode || 'UNKNOWN'
      const gas = BigInt(step.gas ?? 0)
      const gasCost = BigInt(step.gasCost ?? step.cost ?? 0)
      const depth = step.depth ?? 1

      // Normalize stack items to BigInt 256-bit
      const stack: bigint[] = []
      if (Array.isArray(step.stack)) {
        for (const item of step.stack) {
          if (typeof item === 'bigint') {
            stack.push(item)
          } else if (typeof item === 'string') {
            const clean = item.startsWith('0x') ? item.substring(2) : item
            stack.push(clean.length > 0 ? BigInt('0x' + clean) : 0n)
          } else if (typeof item === 'number') {
            stack.push(BigInt(item))
          }
        }
      }

      return {
        stepIndex: idx,
        pc,
        op,
        gas,
        gasCost,
        depth,
        stack,
      }
    })
  }
}
