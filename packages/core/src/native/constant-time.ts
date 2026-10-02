import { ReferenceDisassembler } from './disassembler'
import type { DecodedInstruction, DisassemblyOptions } from './disassembler'

export type DisassembledInstruction = DecodedInstruction

export interface ConstantTimeAuditResult {
  hasConditionalBranches: boolean
  branchCount: number
  suspiciousInstructions: Array<{ offset: number; mnemonic: string; reason: string }>
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

/** Conservative mnemonic inspection of a caller-selected secret-handling region.
 * A clean result means no listed hazards were found; it is not a timing proof.
 */
export class ConstantTimeAuditor {
  public static auditX86_64(instructions: DisassembledInstruction[]): ConstantTimeAuditResult {
    return this.audit(instructions, 'x86_64', X86_BRANCHES, new Set(['div', 'idiv', 'divb', 'divw', 'divl', 'divq', 'idivb', 'idivw', 'idivl', 'idivq']))
  }

  public static auditARM64(instructions: DisassembledInstruction[]): ConstantTimeAuditResult {
    return this.audit(instructions, 'aarch64', ARM_BRANCHES, new Set(['udiv', 'sdiv']))
  }

  public static auditBytes(code: Uint8Array, options: DisassemblyOptions): ConstantTimeAuditResult {
    const instructions = ReferenceDisassembler.disassemble(code, options)
    const result = options.arch === 'x86_64' ? this.auditX86_64(instructions) : this.auditARM64(instructions)
    const decodedBytes = instructions.reduce((sum, instruction) => sum + instruction.length, 0)
    if (decodedBytes < code.length) {
      result.suspiciousInstructions.push({ offset: decodedBytes, mnemonic: '<unexamined>', reason: 'Instruction budget left bytes unexamined' })
      result.isCleanConstantTime = false
    }
    return result
  }

  private static audit(
    instructions: DisassembledInstruction[],
    arch: DecodedInstruction['arch'],
    branches: ReadonlySet<string>,
    divisions: ReadonlySet<string>,
  ): ConstantTimeAuditResult {
    const suspiciousInstructions: ConstantTimeAuditResult['suspiciousInstructions'] = []
    let branchCount = 0
    let offset = 0
    for (const instruction of instructions) {
      if (!Number.isSafeInteger(instruction.length) || instruction.length <= 0) {
        throw new RangeError('Instruction length must be a positive safe integer')
      }
      const mnemonic = instruction.mnemonic.trim().toLowerCase()
      const issue = (reason: string) => suspiciousInstructions.push({ offset, mnemonic: instruction.mnemonic, reason })
      if (instruction.arch !== arch) issue('Instruction architecture does not match the audit architecture')
      if (instruction.bytes.length !== instruction.length) issue('Instruction length does not match its byte span')
      if (!instruction.isValid || ['db', '.byte', '.inst'].includes(mnemonic)) {
        issue('Undecoded or truncated instruction prevents complete static inspection')
      } else {
        if (branches.has(mnemonic)) {
          branchCount++
          issue('Conditional branch may depend on secret data; review branch dependencies')
        }
        if (divisions.has(mnemonic)) issue('Division latency may depend on operands and processor; review timing guarantees')
      }
      offset += instruction.length
      if (!Number.isSafeInteger(offset)) throw new RangeError('Instruction byte offset exceeds the safe integer range')
    }
    return {
      hasConditionalBranches: branchCount > 0,
      branchCount,
      suspiciousInstructions,
      isCleanConstantTime: instructions.length > 0 && suspiciousInstructions.length === 0,
    }
  }
}
