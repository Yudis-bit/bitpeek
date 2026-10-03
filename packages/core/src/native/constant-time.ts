import { ReferenceDisassembler } from './disassembler'
import type { DecodedInstruction, DisassemblyOptions } from './disassembler'

export type DisassembledInstruction = DecodedInstruction

export type HazardSeverity = 'CRITICAL' | 'HIGH' | 'WARN'

export interface AuditHazard {
  offset: number
  mnemonic: string
  operands?: string
  severity: HazardSeverity
  category: 'BRANCH' | 'VARIABLE_LATENCY' | 'CACHE_TIMING' | 'UNDECODED'
  reason: string
}

export interface ConstantTimeAuditOptions {
  checkMemoryLookups?: boolean
}

export interface ConstantTimeAuditResult {
  hasConditionalBranches: boolean
  branchCount: number
  hasCacheTimingHazards: boolean
  hasVariableLatencyHazards: boolean
  suspiciousInstructions: Array<{ offset: number; mnemonic: string; reason: string }>
  hazards: AuditHazard[]
  isCleanConstantTime: boolean
}

const X86_BRANCHES = new Set([
  'jo', 'jno', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'je', 'jz', 'jne', 'jnz',
  'jbe', 'jna', 'ja', 'jnbe', 'js', 'jns', 'jp', 'jpe', 'jnp', 'jpo', 'jl', 'jnge',
  'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jcxz', 'jecxz', 'jrcxz',
  'loop', 'loope', 'loopz', 'loopne', 'loopnz',
])
const ARM_BRANCHES = new Set([
  'cbz', 'cbnz', 'tbz', 'tbnz', 'b.eq', 'b.ne', 'b.cs', 'b.hs', 'b.cc', 'b.lo',
  'b.mi', 'b.pl', 'b.vs', 'b.vc', 'b.hi', 'b.ls', 'b.ge', 'b.lt', 'b.gt', 'b.le',
  'bc.eq', 'bc.ne', 'bc.cs', 'bc.cc', 'bc.mi', 'bc.pl', 'bc.vs', 'bc.vc',
  'bc.hi', 'bc.ls', 'bc.ge', 'bc.lt', 'bc.gt', 'bc.le',
])

function hasIndexedMemory(operands: string, arch: DecodedInstruction['arch']): boolean {
  for (const match of operands.toLowerCase().matchAll(/\[([^\]]+)\]/g)) {
    const memory = match[1]!
    if (arch === 'x86_64') {
      const registers = memory.match(/\b(?:r(?:1[0-5]|[0-9])[dwb]?|[re]?(?:ax|bx|cx|dx|si|di|bp|sp)|rip|eip)\b/g) ?? []
      if (registers.length > 1 || (registers.length > 0 && memory.includes('*'))) return true
    } else if (/\[\s*(?:x\d+|sp)\s*,\s*[xw]\d+\b/.test(match[0])) {
      return true
    }
  }
  return false
}

/** Conservative mnemonic inspection of a caller-selected secret-handling region.
 * A clean result means no listed hazards were found; it is not a timing proof.
 */
export class ConstantTimeAuditor {
  public static auditX86_64(instructions: DisassembledInstruction[], options: ConstantTimeAuditOptions = {}): ConstantTimeAuditResult {
    return this.audit(instructions, 'x86_64', X86_BRANCHES, new Set(['div', 'idiv', 'divb', 'divw', 'divl', 'divq', 'idivb', 'idivw', 'idivl', 'idivq']), options)
  }

  public static auditARM64(instructions: DisassembledInstruction[], options: ConstantTimeAuditOptions = {}): ConstantTimeAuditResult {
    return this.audit(instructions, 'aarch64', ARM_BRANCHES, new Set(['udiv', 'sdiv']), options)
  }

  public static auditBytes(code: Uint8Array, options: DisassemblyOptions & ConstantTimeAuditOptions): ConstantTimeAuditResult {
    const instructions = ReferenceDisassembler.disassemble(code, options)
    const result = options.arch === 'x86_64' ? this.auditX86_64(instructions, options) : this.auditARM64(instructions, options)
    const decodedBytes = instructions.reduce((sum, instruction) => sum + instruction.length, 0)
    if (decodedBytes < code.length) {
      result.suspiciousInstructions.push({ offset: decodedBytes, mnemonic: '<unexamined>', reason: 'Instruction budget left bytes unexamined' })
      result.hazards.push({ offset: decodedBytes, mnemonic: '<unexamined>', severity: 'WARN', category: 'UNDECODED', reason: 'Instruction budget left bytes unexamined' })
      result.isCleanConstantTime = false
    }
    return result
  }

  private static audit(
    instructions: DisassembledInstruction[],
    arch: DecodedInstruction['arch'],
    branches: ReadonlySet<string>,
    divisions: ReadonlySet<string>,
    options: ConstantTimeAuditOptions,
  ): ConstantTimeAuditResult {
    const suspiciousInstructions: ConstantTimeAuditResult['suspiciousInstructions'] = []
    const hazards: AuditHazard[] = []
    let branchCount = 0
    let offset = 0
    for (const instruction of instructions) {
      if (!Number.isSafeInteger(instruction.length) || instruction.length <= 0) {
        throw new RangeError('Instruction length must be a positive safe integer')
      }
      const mnemonic = instruction.mnemonic.trim().toLowerCase()
      const issue = (reason: string, category: AuditHazard['category'] = 'UNDECODED', severity: HazardSeverity = 'WARN') => {
        suspiciousInstructions.push({ offset, mnemonic: instruction.mnemonic, reason })
        hazards.push({ offset, mnemonic: instruction.mnemonic, operands: instruction.operands, reason, category, severity })
      }
      if (instruction.arch !== arch) issue('Instruction architecture does not match the audit architecture')
      if (instruction.bytes.length !== instruction.length) issue('Instruction length does not match its byte span')
      if (!instruction.isValid || ['db', '.byte', '.inst'].includes(mnemonic)) {
        issue('Undecoded or truncated instruction prevents complete static inspection')
      } else {
        if (branches.has(mnemonic)) {
          branchCount++
          issue('Conditional branch may depend on secret data; review branch dependencies', 'BRANCH', 'CRITICAL')
        }
        if (divisions.has(mnemonic)) issue('Division latency may depend on operands and processor; review timing guarantees', 'VARIABLE_LATENCY', 'HIGH')
        if (options.checkMemoryLookups !== false && !/^lea[qwl]?$/.test(mnemonic) && hasIndexedMemory(instruction.operands, arch)) {
          issue('Memory operand uses register indexing; potential cache-timing / table-lookup leak', 'CACHE_TIMING', 'HIGH')
        }
        const operands = instruction.operands.toLowerCase().split(',').map(operand => operand.trim())
        if (arch === 'x86_64') {
          if (/^bs[fr][qwl]?$/.test(mnemonic)) issue('Bit scan latency may depend on operands and processor', 'VARIABLE_LATENCY')
          const shiftCount = instruction.operands.includes('%') ? operands[0] : operands[1]
          if (/^(?:shl|sal|shr|sar|rol|ror)[bwlq]?$/.test(mnemonic)
            && /^%?(?:cl|[re]?(?:ax|bx|cx|dx|si|di|bp|sp)|r\d+[dwb]?)$/.test(shiftCount ?? '')) {
            issue('Register-controlled shift or rotate requires processor-specific timing review', 'VARIABLE_LATENCY')
          }
          if (/^rep(?:e|z|ne|nz)?\s+(?:movs|stos)[bwdql]?$/.test(`${mnemonic} ${instruction.operands}`.trim())) {
            issue('Repeated string operation timing depends on count and memory access', 'VARIABLE_LATENCY', 'HIGH')
          }
        } else if (/^(?:lslv|lsrv|asrv|rorv|clz|cls|rbit)$/.test(mnemonic)
          || (/^(?:lsl|lsr|asr|ror)$/.test(mnemonic) && /^[xw]\d+$/.test(operands[2] ?? ''))) {
          issue('Variable bit operation requires processor-specific timing review', 'VARIABLE_LATENCY')
        }
      }
      offset += instruction.length
      if (!Number.isSafeInteger(offset)) throw new RangeError('Instruction byte offset exceeds the safe integer range')
    }
    return {
      hasConditionalBranches: branchCount > 0,
      branchCount,
      hasCacheTimingHazards: hazards.some(hazard => hazard.category === 'CACHE_TIMING'),
      hasVariableLatencyHazards: hazards.some(hazard => hazard.category === 'VARIABLE_LATENCY'),
      suspiciousInstructions,
      hazards,
      isCleanConstantTime: instructions.length > 0 && suspiciousInstructions.length === 0,
    }
  }
}
