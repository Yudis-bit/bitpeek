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

export interface TaintSource {
  type: 'REGISTER' | 'STACK_OFFSET'
  identifier: string
}

export interface TaintTraceStep {
  offset: number
  mnemonic: string
  operands?: string
  taintedInputs: string[]
  taintedOutputs: string[]
  violation?: {
    type: 'BRANCH_DEPENDENCY' | 'INDEXED_MEMORY_LEAK' | 'VARIABLE_LATENCY'
    severity: HazardSeverity
    reason: string
  }
}

export interface TaintAuditOptions {
  /** Addresses stay bigint; trace and hazard offsets are relative byte offsets. */
  baseAddress?: bigint | number
  stopOnFirstViolation?: boolean
  /** Track stored values and eight-byte STACK_OFFSET input slots. Defaults to true. */
  trackMemoryTaints?: boolean
}

export interface TaintAuditResult {
  /** Verification of the supplied instruction sequence and declared sources only. */
  isProvablyConstantTime: boolean
  hasViolations: boolean
  activeTaints: string[]
  trace: TaintTraceStep[]
  /** UNDECODED findings mean the sequence could not be completely verified. */
  violations: AuditHazard[]
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

  /** Forward non-interference verification for a caller-selected instruction sequence.
   * Unmodelled instructions fail closed. This does not explore alternate control-flow
   * paths, callees, or processor-specific timing outside the modelled hazards.
   */
  public static verifyNonInterference(
    instructions: DisassembledInstruction[],
    secrets: TaintSource[],
    arch: DecodedInstruction['arch'],
    options: TaintAuditOptions = {},
  ): TaintAuditResult {
    return new ForwardTaintTracker(arch, secrets, options).verify(instructions)
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

const X86_TAINT_ROOTS = new Map<string, string>()
for (const aliases of [
  ['rax', 'eax', 'ax', 'al', 'ah'], ['rbx', 'ebx', 'bx', 'bl', 'bh'],
  ['rcx', 'ecx', 'cx', 'cl', 'ch'], ['rdx', 'edx', 'dx', 'dl', 'dh'],
  ['rsi', 'esi', 'si', 'sil'], ['rdi', 'edi', 'di', 'dil'],
  ['rbp', 'ebp', 'bp', 'bpl'], ['rsp', 'esp', 'sp', 'spl'],
  ['rflags', 'eflags', 'flags', 'cf', 'zf', 'sf', 'of', 'pf', 'af'],
  ['rip', 'eip'],
]) {
  for (const alias of aliases) X86_TAINT_ROOTS.set(alias, aliases[0]!)
}
for (let index = 8; index <= 15; index++) {
  for (const suffix of ['', 'd', 'w', 'b']) X86_TAINT_ROOTS.set(`r${index}${suffix}`, `r${index}`)
}

function taintRegister(name: string, arch: DecodedInstruction['arch']): string | undefined {
  const register = name.trim().toLowerCase().replace(/^[%*]+/, '')
  if (arch === 'x86_64') {
    const vector = register.match(/^(?:xmm|ymm|zmm)([12]?\d|3[01])$/)
    return X86_TAINT_ROOTS.get(register) ?? (vector ? `xmm${vector[1]}` : undefined)
  }
  if (/^[xw](?:[12]?\d|30)$/.test(register)) return `x${register.slice(1)}`
  if (register === 'sp' || register === 'wsp') return 'sp'
  if (register === 'fp') return 'x29'
  if (register === 'lr') return 'x30'
  if (register === 'nzcv') return 'nzcv'
  return undefined // xzr/wzr always read as zero and discard writes.
}

function taintOperands(text: string, arch: DecodedInstruction['arch']): string[] {
  const operands: string[] = []
  let depth = 0
  let start = 0
  for (let index = 0; index < text.length; index++) {
    if (text[index] === '[' || text[index] === '(') depth++
    if (text[index] === ']' || text[index] === ')') depth--
    if (text[index] === ',' && depth === 0) {
      operands.push(text.slice(start, index).trim().toLowerCase())
      start = index + 1
    }
  }
  if (text.slice(start).trim()) operands.push(text.slice(start).trim().toLowerCase())
  if (arch === 'x86_64' && text.includes('%')) operands.reverse()
  return operands
}

function taintImmediate(text: string): bigint | undefined {
  const value = text.trim().replace(/^[$#]/, '')
  if (!/^[+-]?(?:0x[\da-f]+|\d+)$/i.test(value)) return undefined
  const sign = value[0] === '-' ? -1n : 1n
  return sign * BigInt(value.replace(/^[+-]/, ''))
}

function isTaintMemory(operand: string): boolean {
  return operand.includes('[') || operand.includes('(')
}

function taintRegisterWidth(operand: string, arch: DecodedInstruction['arch']): number | undefined {
  const register = operand.trim().toLowerCase().replace(/^%/, '')
  if (!taintRegister(register, arch)) return undefined
  if (arch === 'aarch64') return register.startsWith('w') ? 4 : 8
  if (register.startsWith('zmm')) return 64
  if (register.startsWith('ymm')) return 32
  if (register.startsWith('xmm')) return 16
  if (/^(?:[abcd][lh]|[sd]il|[bs]pl|r\d+b)$/.test(register)) return 1
  if (/^(?:[abcd]x|[sd]i|[bs]p|r\d+w)$/.test(register)) return 2
  if (/^(?:e\w+|r\d+d)$/.test(register)) return 4
  return 8
}

interface TaintStackLocation {
  base: string
  offset: bigint
}

interface TaintMemoryRange extends TaintStackLocation {
  size: number
}

/** Whole-register taints deliberately retain untouched bytes on partial writes. */
class ForwardTaintTracker {
  private readonly registers = new Set<string>()
  private readonly vectorWidths = new Map<string, number>()
  private readonly stackOrigins = new Map<string, TaintStackLocation>()
  private memory: TaintMemoryRange[] = []
  private unknownMemoryTainted = false
  private readonly flags: string
  private readonly baseAddress: bigint

  constructor(
    private readonly arch: DecodedInstruction['arch'],
    secrets: TaintSource[],
    private readonly options: TaintAuditOptions,
  ) {
    if (arch !== 'x86_64' && arch !== 'aarch64') throw new RangeError('Unsupported taint audit architecture')
    const address = options.baseAddress ?? 0n
    if ((typeof address !== 'number' && typeof address !== 'bigint')
      || (typeof address === 'number' && (!Number.isSafeInteger(address) || address < 0))) {
      throw new RangeError('baseAddress must be an unsigned safe integer or bigint')
    }
    this.baseAddress = BigInt(address)
    if (this.baseAddress < 0n || this.baseAddress > 0xffffffffffffffffn) throw new RangeError('baseAddress exceeds the unsigned 64-bit address range')
    this.flags = arch === 'x86_64' ? 'rflags' : 'nzcv'
    for (const base of arch === 'x86_64' ? ['rsp', 'rbp'] : ['sp']) {
      this.stackOrigins.set(base, { base, offset: 0n })
    }
    for (const source of secrets) {
      if (typeof source.identifier !== 'string') throw new RangeError('Taint source identifier must be a string')
      if (source.type === 'REGISTER') {
        const register = taintRegister(source.identifier, arch)
        if (!register) throw new RangeError(`Unknown ${arch} secret register: ${source.identifier}`)
        this.registers.add(register)
        if (register.startsWith('xmm')) {
          this.vectorWidths.set(register, Math.max(this.vectorWidths.get(register) ?? 0, taintRegisterWidth(source.identifier, arch)!))
        }
      } else if (source.type === 'STACK_OFFSET') {
        const location = this.stackLocation(`[${source.identifier.toLowerCase()}]`)
        if (!location) throw new RangeError(`Invalid ${arch} secret stack offset: ${source.identifier}`)
        this.storeMemory(location, 8, true)
      } else {
        throw new RangeError('Unsupported taint source type')
      }
    }
  }

  private operandRegisters(operand: string): string[] {
    return [...new Set((operand.match(/\b[a-z][a-z\d]*\b/g) ?? [])
      .map(register => taintRegister(register, this.arch)).filter((register): register is string => register !== undefined))]
  }

  private stackLocation(operand: string): TaintStackLocation | undefined {
    const bracketed = operand.match(/\[([^\]]+)\]/)?.[1]
    const att = operand.match(/^\s*([+-]?(?:0x[\da-f]+|\d+))?\(%([a-z\d]+)\)$/)
    const expression = (bracketed ?? (att ? `${att[2]}+${att[1] ?? '0'}` : undefined))
      ?.replace(/[\s#%]/g, '').replace(',', '+')
    if (!expression) return undefined
    const match = expression.match(/^([a-z][a-z\d]*)(?:([+-])((?:0x[\da-f]+|\d+)))?$/)
    if (!match) return undefined
    const register = taintRegister(match[1]!, this.arch)
    const origin = register ? this.stackOrigins.get(register) : undefined
    if (!origin) return undefined
    const displacement = match[3] ? BigInt(match[3]) * (match[2] === '-' ? -1n : 1n) : 0n
    return { base: origin.base, offset: origin.offset + displacement }
  }

  private memoryName(location: TaintStackLocation): string {
    return `${location.base}${location.offset < 0n ? '' : '+'}${location.offset}`
  }

  private memoryIsTainted(operand: string, size: number): boolean {
    if (this.unknownMemoryTainted) return true
    const location = this.stackLocation(operand)
    // Unresolved public pointers may alias a tracked secret slot.
    if (!location) return this.memory.length > 0
    return this.memory.some(range => range.base !== location.base // Entry stack/frame bases can alias.
      || (range.offset < location.offset + BigInt(size)
        && location.offset < range.offset + BigInt(range.size)))
  }

  private storeMemory(location: TaintStackLocation, size: number, tainted: boolean): void {
    const end = location.offset + BigInt(size)
    const remaining: TaintMemoryRange[] = []
    for (const range of this.memory) {
      const rangeEnd = range.offset + BigInt(range.size)
      if (range.base !== location.base || rangeEnd <= location.offset || range.offset >= end) {
        remaining.push(range)
      } else {
        if (range.offset < location.offset) remaining.push({ ...range, size: Number(location.offset - range.offset) })
        if (rangeEnd > end) remaining.push({ ...range, offset: end, size: Number(rangeEnd - end) })
      }
    }
    if (tainted) remaining.push({ ...location, size })
    this.memory = remaining
  }

  private memoryWidth(operand: string, registerOperand: string, mnemonic: string): number {
    const width = operand.match(/\b(byte|word|dword|qword|xmmword|ymmword|zmmword)\s+(?:ptr\s+)?\[/)?.[1]
    if (width) return { byte: 1, word: 2, dword: 4, qword: 8, xmmword: 16, ymmword: 32, zmmword: 64 }[width]!
    if (this.arch === 'aarch64') {
      if (/^(?:ldr|str|ldur|stur)(?:s?b)$/.test(mnemonic)) return 1
      if (/^(?:ldr|str|ldur|stur)(?:s?h)$/.test(mnemonic)) return 2
      if (/^(?:ldr|ldur)sw$/.test(mnemonic)) return 4
    }
    // Without a width qualifier or register, a clean store may only clear the
    // first byte with certainty. Do not erase neighbouring secret bytes.
    return taintRegisterWidth(registerOperand, this.arch) ?? 1
  }

  private writeRegister(operand: string, tainted: boolean, outputs: Set<string>): void {
    const register = taintRegister(operand, this.arch)
    if (!register) return
    const width = taintRegisterWidth(operand, this.arch)!
    if (tainted) {
      this.registers.add(register)
      if (register.startsWith('xmm')) this.vectorWidths.set(register, Math.max(this.vectorWidths.get(register) ?? 0, width))
    }
    // GPR writes of 32 bits zero-extend; 8/16-bit writes cannot clear the root.
    else if (width >= (register.startsWith('xmm') ? this.vectorWidths.get(register) ?? 0 : 4)) {
      this.registers.delete(register)
      this.vectorWidths.delete(register)
    }
    outputs.add(register)
    this.stackOrigins.delete(register)
  }

  private operation(instruction: DisassembledInstruction): string {
    let mnemonic = instruction.mnemonic.trim().toLowerCase()
    // The reference decoder preserves the group-1 opcode as alu64. Interpret
    // its ModRM extension locally, keeping legacy decoder/auditor output intact.
    if (this.arch === 'x86_64' && mnemonic === 'alu64'
      && instruction.bytes[0] === 0x48 && instruction.bytes[1] === 0x83 && instruction.bytes.length >= 4) {
      mnemonic = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'][(instruction.bytes[2]! >> 3) & 7]!
    }
    if (this.arch === 'x86_64') {
      const suffixed = mnemonic.match(/^(mov|movzx|movsx|lea|xchg|add|sub|adc|sbb|or|and|xor|cmp|test|div|idiv|shl|sal|shr|sar|rol|ror|shld|shrd|inc|dec|neg|not|push|pop)[bwlq]$/)
      if (suffixed) mnemonic = suffixed[1]!
    }
    return mnemonic
  }

  verify(instructions: DisassembledInstruction[]): TaintAuditResult {
    const trace: TaintTraceStep[] = []
    const violations: AuditHazard[] = []
    let offset = 0
    for (const instruction of instructions) {
      if (!Number.isSafeInteger(instruction.length) || instruction.length <= 0) throw new RangeError('Instruction length must be a positive safe integer')
      const nextOffset = offset + instruction.length
      if (!Number.isSafeInteger(nextOffset)) throw new RangeError('Instruction byte offset exceeds the safe integer range')
      if (this.baseAddress + BigInt(nextOffset - 1) > 0xffffffffffffffffn) throw new RangeError('Code range exceeds the unsigned 64-bit address range')
      const mnemonic = this.operation(instruction)
      const operands = taintOperands(instruction.operands, this.arch)
      const inputs = new Set<string>()
      const outputs = new Set<string>()
      const step: TaintTraceStep = { offset, mnemonic: instruction.mnemonic, operands: instruction.operands, taintedInputs: [], taintedOutputs: [] }
      const firstViolation = violations.length
      const issue = (category: AuditHazard['category'], severity: HazardSeverity, reason: string, type?: NonNullable<TaintTraceStep['violation']>['type']) => {
        violations.push({ offset, mnemonic: instruction.mnemonic, operands: instruction.operands, category, severity, reason })
        if (type && !step.violation) step.violation = { type, severity, reason }
      }
      const incomplete = (reason: string) => issue('UNDECODED', 'WARN', reason)
      const readFlags = () => {
        if (!this.registers.has(this.flags)) return false
        inputs.add(this.flags)
        return true
      }
      const writeFlags = (tainted: boolean, preserve = false) => {
        if (tainted) this.registers.add(this.flags)
        else if (!preserve) this.registers.delete(this.flags)
        outputs.add(this.flags)
      }
      const read = (operand: string, size = 8): boolean => {
        let tainted = false
        for (const register of this.operandRegisters(operand)) {
          if (this.registers.has(register)) { inputs.add(register); tainted = true }
        }
        if (isTaintMemory(operand) && this.memoryIsTainted(operand, Math.max(size, this.memoryWidth(operand, '', mnemonic)))) {
          const location = this.stackLocation(operand)
          inputs.add(location ? this.memoryName(location) : 'memory:*')
          tainted = true
        }
        return tainted
      }
      const write = (operand: string, tainted: boolean, size = 8) => {
        if (!isTaintMemory(operand)) { this.writeRegister(operand, tainted, outputs); return }
        if (this.options.trackMemoryTaints === false) {
          if (tainted) incomplete('Secret store cannot be verified with memory taint tracking disabled')
          return
        }
        const location = this.stackLocation(operand)
        if (location) {
          this.storeMemory(location, size, tainted)
          if (tainted) outputs.add(this.memoryName(location))
        } else if (tainted) {
          this.unknownMemoryTainted = true
          outputs.add('memory:*')
        }
      }

      if (instruction.arch !== this.arch || instruction.bytes.length !== instruction.length
        || !instruction.isValid || ['db', '.byte', '.inst'].includes(mnemonic)) {
        incomplete('Undecoded, inconsistent, or architecture-mismatched instruction prevents non-interference verification')
      } else {
        // LEA computes an address without accessing memory.
        if (mnemonic !== 'lea') {
          for (const operand of operands.filter(isTaintMemory)) {
            const registers = this.operandRegisters(operand).filter(register => this.registers.has(register))
            for (const register of registers) inputs.add(register)
            if (registers.length > 0) issue('CACHE_TIMING', 'CRITICAL',
              'Memory address calculation uses secret-tainted register; causes cache-timing side-channel.', 'INDEXED_MEMORY_LEAK')
          }
        }

        const directArmBranch = this.arch === 'aarch64' && /^(?:cbz|cbnz|tbz|tbnz)$/.test(mnemonic)
        const branch = (this.arch === 'x86_64' ? X86_BRANCHES : ARM_BRANCHES).has(mnemonic)
        if (branch) {
          if (operands.length < (directArmBranch ? mnemonic.startsWith('tb') ? 3 : 2 : 1)) incomplete('Branch instruction is missing operands')
          if (directArmBranch) {
            if (read(operands[0] ?? '')) issue('BRANCH', 'CRITICAL',
              'Direct register test branch depends on secret-tainted register.', 'BRANCH_DEPENDENCY')
          } else {
            const flagsTainted = readFlags()
            const counterTainted = this.arch === 'x86_64' && /^(?:j[er]?cxz|loop\w*)$/.test(mnemonic) ? read('rcx') : false
            if (flagsTainted || counterTainted) issue('BRANCH', 'CRITICAL', flagsTainted
              ? 'Conditional branch depends on secret-tainted flags; violates constant-time non-interference.'
              : 'Direct register test branch depends on secret-tainted register.', 'BRANCH_DEPENDENCY')
          }
        } else if (/^(?:jmp|call|br|blr|ret)$/.test(mnemonic)) {
          const target = operands[0] ?? (mnemonic === 'ret' ? this.arch === 'aarch64' ? 'x30' : '[rsp]' : '')
          if (read(target)) issue('BRANCH', 'CRITICAL', 'Indirect control-flow target depends on secret-tainted data.', 'BRANCH_DEPENDENCY')
          if (mnemonic === 'call' || mnemonic === 'blr') incomplete('Callee effects are outside the selected instruction sequence')
        } else if (['nop', 'b', 'b.al', 'b.nv'].includes(mnemonic)) {
          // No data-flow effects within the supplied sequence.
        } else if (/^(?:mov|movzx|movsx|movsxd|movz|movn|ldr|ldrb|ldrh|ldrsb|ldrsh|ldrsw|ldur|ldurb|ldurh|ldursb|ldursh|ldursw)$/.test(mnemonic)) {
          if (operands.length < 2) incomplete('Transfer instruction is missing operands')
          else {
            const [destination, source] = operands as [string, string]
            const size = this.memoryWidth(isTaintMemory(source) ? source : destination, isTaintMemory(source) ? destination : source, mnemonic)
            const origin = this.stackOrigins.get(taintRegister(source, this.arch) ?? '')
            const tainted = read(source, size)
            write(destination, tainted, size)
            const destinationRegister = taintRegister(destination, this.arch)
            if (origin && destinationRegister && taintRegisterWidth(destination, this.arch) === 8) this.stackOrigins.set(destinationRegister, { ...origin })
            if (operands.some(operand => operand.includes('!')) || (mnemonic.startsWith('ld') && operands.length > 2)) incomplete('Load writeback addressing is outside the supported transfer model')
          }
        } else if (/^(?:str|strb|strh|stur|sturb|sturh)$/.test(mnemonic)) {
          if (operands.length < 2) incomplete('Store instruction is missing operands')
          else {
            write(operands[1]!, read(operands[0]!), this.memoryWidth(operands[1]!, operands[0]!, mnemonic))
            if (operands[1]!.includes('!') || operands.length > 2) incomplete('Store writeback addressing is outside the supported transfer model')
          }
        } else if (mnemonic === 'xchg') {
          if (operands.length !== 2) incomplete('Exchange instruction requires two operands')
          else {
            const left = read(operands[0]!)
            const right = read(operands[1]!)
            const leftOrigin = this.stackOrigins.get(taintRegister(operands[0]!, this.arch) ?? '')
            const rightOrigin = this.stackOrigins.get(taintRegister(operands[1]!, this.arch) ?? '')
            write(operands[0]!, right, this.memoryWidth(operands[0]!, operands[1]!, mnemonic))
            write(operands[1]!, left, this.memoryWidth(operands[1]!, operands[0]!, mnemonic))
            if (rightOrigin && taintRegisterWidth(operands[0]!, this.arch) === 8) this.stackOrigins.set(taintRegister(operands[0]!, this.arch)!, rightOrigin)
            if (leftOrigin && taintRegisterWidth(operands[1]!, this.arch) === 8) this.stackOrigins.set(taintRegister(operands[1]!, this.arch)!, leftOrigin)
          }
        } else if (/^(?:cmp|cmn|test|tst)$/.test(mnemonic)) {
          if (operands.length < 2) incomplete('Comparison instruction is missing operands')
          else {
            const tainted = operands.map(operand => read(operand)).some(Boolean)
            writeFlags(tainted)
          }
        } else if (/^(?:cmov\w+|set\w+|csel|csinc|csinv|csneg|cset|csetm|cinc|cinv|cneg)$/.test(mnemonic)) {
          if (operands.length === 0) incomplete('Conditional selection is missing a destination')
          else {
            const flagTainted = readFlags()
            const values = (mnemonic.startsWith('cmov') ? operands : operands.slice(1)).map(operand => read(operand))
            write(operands[0]!, flagTainted || values.some(Boolean), mnemonic.startsWith('set') ? 1 : this.memoryWidth(operands[0]!, operands[1] ?? '', mnemonic))
          }
        } else if (/^(?:div|idiv|udiv|sdiv)$/.test(mnemonic)) {
          if (operands.length === 0 || (this.arch === 'aarch64' && operands.length < 3)) incomplete('Division instruction is missing operands')
          else {
            const values = (this.arch === 'x86_64' ? [...operands, 'rax', 'rdx'] : operands.slice(1)).map(operand => read(operand))
            const tainted = values.some(Boolean)
            if (tainted) issue('VARIABLE_LATENCY', 'HIGH', 'Division uses secret-tainted operands; latency may depend on secret data.', 'VARIABLE_LATENCY')
            if (this.arch === 'x86_64') {
              write('rax', tainted); write('rdx', tainted); writeFlags(tainted, true)
            } else write(operands[0]!, tainted)
          }
        } else if (/^(?:shl|sal|shr|sar|rol|ror|shld|shrd|lsl|lsr|asr|lslv|lsrv|asrv|rorv)$/.test(mnemonic)) {
          if (operands.length < (this.arch === 'aarch64' || /^(?:shld|shrd)$/.test(mnemonic) ? 3 : 2)) incomplete('Shift instruction is missing operands')
          else {
            const count = operands[this.arch === 'x86_64' ? /^(?:shld|shrd)$/.test(mnemonic) ? 2 : 1 : 2] ?? ''
            const countTainted = read(count)
            const values = (this.arch === 'x86_64' ? operands : operands.slice(1)).map(operand => read(operand))
            if (countTainted) issue('VARIABLE_LATENCY', 'HIGH', 'Shift count uses a secret-tainted register; latency may depend on secret data.', 'VARIABLE_LATENCY')
            const tainted = values.some(Boolean)
            write(operands[0]!, tainted)
            if (this.arch === 'x86_64') writeFlags(tainted, true) // A zero count preserves flags.
          }
        } else if (/^(?:add|adds|sub|subs|adc|adcs|sbb|sbc|sbcs|or|orr|and|ands|xor|eor|pxor|vpxor|lea|inc|dec|neg|negs|not|mvn|mul|imul|madd|msub|bic|bics|orn|eon)$/.test(mnemonic)) {
          const unary = /^(?:inc|dec|neg|negs|not|mvn)$/.test(mnemonic)
          if (operands.length < (unary ? 1 : 2)) incomplete('Arithmetic instruction is missing operands')
          else {
            const destination = operands[0]!
            const size = this.memoryWidth(destination, operands.find(operand => !!taintRegister(operand, this.arch)) ?? '', mnemonic)
            const valueOperands = this.arch === 'x86_64' && mnemonic !== 'lea' && !mnemonic.startsWith('v') ? operands : operands.slice(1)
            const values = valueOperands.map(operand => mnemonic === 'lea'
              ? this.operandRegisters(operand).map(register => read(register)).some(Boolean) : read(operand, size))
            const carryTainted = /^(?:adc|adcs|sbb|sbc|sbcs)$/.test(mnemonic) ? readFlags() : false
            const sameRegister = (left: string, right: string) => !!taintRegister(left, this.arch)
              && left.replace(/^%/, '') === right.replace(/^%/, '')
            const zero = this.arch === 'x86_64'
              ? (/^(?:xor|sub|pxor)$/.test(mnemonic) && operands.length === 2 && sameRegister(operands[0]!, operands[1]!))
                || (mnemonic === 'vpxor' && operands.length === 3 && sameRegister(operands[1]!, operands[2]!))
              : /^(?:eor|sub|subs)$/.test(mnemonic) && operands.length === 3 && sameRegister(operands[1]!, operands[2]!)
            const tainted = !zero && (values.some(Boolean) || carryTainted)
            const origin = mnemonic === 'lea' ? this.stackLocation(operands[1]!)
              : this.stackOrigins.get(taintRegister(this.arch === 'x86_64' ? destination : operands[1] ?? '', this.arch) ?? '')
            write(destination, tainted, size)
            const register = taintRegister(destination, this.arch)
            const immediate = taintImmediate(operands[this.arch === 'x86_64' ? 1 : 2] ?? '')
            if (origin && register && taintRegisterWidth(destination, this.arch) === 8) {
              if (mnemonic === 'lea') this.stackOrigins.set(register, origin)
              else if (immediate !== undefined && /^(?:add|sub)$/.test(mnemonic)) {
                this.stackOrigins.set(register, { base: origin.base, offset: origin.offset + (mnemonic === 'sub' ? -immediate : immediate) })
              }
            }
            // Flag-neutral arithmetic never erases existing flag taints. Its
            // taint summary is conservative, including address arithmetic.
            const flagNeutral = /^(?:lea|not|mvn|pxor|vpxor)$/.test(mnemonic)
              || (this.arch === 'aarch64' && !/^(?:adds|subs|adcs|sbcs|ands|bics|negs)$/.test(mnemonic))
            if (!flagNeutral || tainted) writeFlags(tainted, flagNeutral || /^(?:inc|dec|mul|imul)$/.test(mnemonic))
          }
        } else if (this.arch === 'x86_64' && /^(?:push|pop)$/.test(mnemonic)) {
          const origin = this.stackOrigins.get('rsp')
          if (operands.length !== 1 || !origin) incomplete('Stack operation requires a known stack origin and one operand')
          else {
            const size = taintRegisterWidth(operands[0]!, this.arch) === 2 ? 2 : 8
            if (this.registers.has('rsp')) {
              inputs.add('rsp')
              issue('CACHE_TIMING', 'CRITICAL', 'Memory address calculation uses secret-tainted register; causes cache-timing side-channel.', 'INDEXED_MEMORY_LEAK')
            }
            if (mnemonic === 'push') {
              const location = { base: origin.base, offset: origin.offset - BigInt(size) }
              const tainted = read(operands[0]!)
              if (this.options.trackMemoryTaints === false && tainted) incomplete('Secret store cannot be verified with memory taint tracking disabled')
              else this.storeMemory(location, size, tainted)
              this.stackOrigins.set('rsp', location)
              if (tainted) outputs.add(this.memoryName(location))
            } else {
              write(operands[0]!, read('[rsp]', size))
              this.stackOrigins.set('rsp', { ...origin, offset: origin.offset + BigInt(size) })
              if (taintRegister(operands[0]!, this.arch) === 'rsp') incomplete('Pop into the stack pointer requires an unmodelled stack origin')
            }
          }
        } else {
          for (const operand of operands) read(operand)
          incomplete(`Instruction ${instruction.mnemonic.trim()} is outside the supported non-interference model`)
        }
      }
      step.taintedInputs = [...inputs]
      step.taintedOutputs = [...outputs].filter(name => this.registers.has(name)
        || name === 'memory:*' || this.memory.some(range => this.memoryName(range) === name))
      trace.push(step)
      offset = nextOffset
      if (this.options.stopOnFirstViolation && violations.length > firstViolation) break
    }
    return {
      isProvablyConstantTime: instructions.length > 0 && violations.length === 0,
      hasViolations: violations.length > 0,
      activeTaints: [...new Set([...this.registers, ...this.memory.map(range => this.memoryName(range)),
        ...(this.unknownMemoryTainted ? ['memory:*'] : [])])],
      trace,
      violations,
    }
  }
}
