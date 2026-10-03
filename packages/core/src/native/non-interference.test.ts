import { describe, expect, it } from 'vitest'
import { ConstantTimeAuditor, ReferenceDisassembler } from '../index'
import type { DisassembledInstruction, TaintAuditOptions, TaintAuditResult, TaintSource, TaintTraceStep } from '../index'

type Arch = DisassembledInstruction['arch']

function sequence(assembly: Array<[string, string]>, arch: Arch = 'x86_64'): DisassembledInstruction[] {
  return assembly.map(([mnemonic, operands], index) => ({
    address: BigInt(index * 4), bytes: new Uint8Array(4), length: 4, mnemonic, operands, arch, isValid: true,
  }))
}

function verify(assembly: Array<[string, string]>, registers: string[], arch: Arch = 'x86_64', options: TaintAuditOptions = {}): TaintAuditResult {
  const sources: TaintSource[] = registers.map(identifier => ({ type: 'REGISTER', identifier }))
  return ConstantTimeAuditor.verifyNonInterference(sequence(assembly, arch), sources, arch, options)
}

describe('forward symbolic taint and non-interference verification', () => {
  it('exports the engine and its contracts through the core API', () => {
    const step: TaintTraceStep = { offset: 0, mnemonic: 'nop', taintedInputs: [], taintedOutputs: [] }
    expect(verify([['nop', '']], []).trace[0]).toMatchObject(step)
  })

  it('propagates secret arithmetic without reporting a timing violation', () => {
    const result = verify([['add', 'rax, rdx'], ['xor', 'r8, rax'], ['sub', 'r9, r8']], ['rdx'])
    expect(result).toMatchObject({ isProvablyConstantTime: true, hasViolations: false, violations: [] })
    expect(result.activeTaints).toEqual(expect.arrayContaining(['rdx', 'rax', 'r8', 'r9', 'rflags']))
    expect(result.trace).toEqual([
      expect.objectContaining({ offset: 0, taintedInputs: ['rdx'], taintedOutputs: ['rax', 'rflags'] }),
      expect.objectContaining({ offset: 4, taintedInputs: ['rax'], taintedOutputs: ['r8', 'rflags'] }),
      expect.objectContaining({ offset: 8, taintedInputs: ['r8'], taintedOutputs: ['r9', 'rflags'] }),
    ])
  })

  it.each(['xor', 'sub', 'pxor'])('clears taint after self-zeroing with %s', mnemonic => {
    const register = mnemonic === 'pxor' ? 'xmm0' : 'rax'
    const result = verify([[mnemonic, `${register}, ${register}`]], [register])
    expect(result.activeTaints).not.toContain(register)
    expect(result.trace[0].taintedOutputs).toEqual([])
    expect(result.isProvablyConstantTime).toBe(true)
  })

  it.each(['0', '0x0', '42', '$0'])('removes taint when a full register is overwritten with %s', immediate => {
    expect(verify([['mov', `rax, ${immediate}`]], ['rax']).activeTaints).toEqual([])
  })

  it('normalizes operand case, source case, whitespace and AT&T operand order', () => {
    const result = verify([[' MOVQ ', ' %RDI, %RAX '], ['CMPQ', '$0, %RAX'], [' JE ', '.Ltarget']], [' RDI '])
    expect(result.trace[0]).toMatchObject({ mnemonic: ' MOVQ ', taintedInputs: ['rdi'], taintedOutputs: ['rax'] })
    expect(result.trace[2].violation?.type).toBe('BRANCH_DEPENDENCY')
  })

  const x86Aliases = [
    ['rax', 'eax', 'ax', 'al', 'ah'], ['rbx', 'ebx', 'bx', 'bl', 'bh'],
    ['rcx', 'ecx', 'cx', 'cl', 'ch'], ['rdx', 'edx', 'dx', 'dl', 'dh'],
    ['rsi', 'esi', 'si', 'sil'], ['rdi', 'edi', 'di', 'dil'],
    ['rbp', 'ebp', 'bp', 'bpl'], ['rsp', 'esp', 'sp', 'spl'],
    ...Array.from({ length: 8 }, (_, index) => [`r${index + 8}`, `r${index + 8}d`, `r${index + 8}w`, `r${index + 8}b`]),
  ].flatMap(aliases => aliases.map(alias => [aliases[0], alias]))

  it.each(x86Aliases)('normalizes secret alias %s / %s', (root, alias) => {
    const result = verify([['mov', `r10, ${alias}`]], [alias])
    expect(result.activeTaints).toEqual(expect.arrayContaining([root, 'r10']))
    expect(result.trace[0].taintedInputs).toEqual([root])
  })

  it('clears the canonical root on a 32-bit zero-extending write', () => {
    expect(verify([['xor', 'eax, eax']], ['rax']).activeTaints).not.toContain('rax')
    expect(verify([['mov', 'r9d, 0']], ['r9']).activeTaints).not.toContain('r9')
  })

  it.each(['mov al, 0', 'xor ax, ax', 'sub ah, ah'])('retains untouched secret bytes on partial write %s', assembly => {
    const space = assembly.indexOf(' ')
    const result = verify([[assembly.slice(0, space), assembly.slice(space + 1)], ['cmp', 'rax, 0'], ['je', '.Ltarget']], ['rax'])
    expect(result.activeTaints).toContain('rax')
    expect(result.trace[2].violation?.type).toBe('BRANCH_DEPENDENCY')
  })

  it('does not confuse distinct aliases with a self-zeroing idiom', () => {
    expect(verify([['xor', 'al, ah']], ['rax']).activeTaints).toContain('rax')
  })

  it('tracks SIMD aliases and retains secret upper lanes after a narrow zeroization', () => {
    const result = verify([['pxor', 'xmm0, xmm0'], ['movq', 'rax, xmm0']], [' YMM0 '])
    expect(result.activeTaints).toEqual(expect.arrayContaining(['xmm0', 'rax']))
    expect(result.trace[1].taintedInputs).toEqual(['xmm0'])
    expect(verify([['vpxor', 'ymm0, ymm0, ymm0']], ['ymm0']).activeTaints).toEqual([])
  })

  it.each(['mov', 'movzx', 'movsx'])('transfers and overwrites taint with %s', mnemonic => {
    const result = verify([[mnemonic, 'rax, rdi'], [mnemonic, 'rax, rbx']], ['rdi'])
    expect(result.trace[0].taintedOutputs).toEqual(['rax'])
    expect(result.trace[1].taintedOutputs).toEqual([])
    expect(result.activeTaints).not.toContain('rax')
  })

  it('swaps register taints instead of merging them for xchg', () => {
    const result = verify([['xchg', 'rax, rbx']], ['rax'])
    expect(result.activeTaints).toEqual(['rbx'])
    expect(result.trace[0]).toMatchObject({ taintedInputs: ['rax'], taintedOutputs: ['rbx'] })
  })

  it('detects the required secret-dependent compare and branch', () => {
    const result = verify([['mov', 'rax, rdi'], ['cmp', 'rax, 0'], ['je', '.Lbranch']], ['rdi'])
    expect(result).toMatchObject({ isProvablyConstantTime: false, hasViolations: true })
    expect(result.trace[1].taintedOutputs).toEqual(['rflags'])
    expect(result.trace[2]).toMatchObject({ taintedInputs: ['rflags'], violation: { type: 'BRANCH_DEPENDENCY', severity: 'CRITICAL' } })
    expect(result.violations).toEqual([expect.objectContaining({ offset: 8, mnemonic: 'je', category: 'BRANCH', severity: 'CRITICAL',
      reason: 'Conditional branch depends on secret-tainted flags; violates constant-time non-interference.' })])
  })

  it.each(['cmp', 'test'])('overwrites stale secret flags with a clean %s', mnemonic => {
    const result = verify([['cmp', 'rdi, 0'], [mnemonic, 'rbx, rbx'], ['jne', '.Lpublic']], ['rdi'])
    expect(result.activeTaints).not.toContain('rflags')
    expect(result.violations).toEqual([])
  })

  it('retains secret flags across mov and consumes carry taint in adc/sbb', () => {
    const result = verify([['cmp', 'rdi, 0'], ['mov', 'rax, 0'], ['adc', 'rax, rbx'], ['sbb', 'r8, r9']], ['rdi'])
    expect(result.trace[1].taintedOutputs).toEqual([])
    expect(result.trace[2].taintedInputs).toEqual(['rflags'])
    expect(result.activeTaints).toEqual(expect.arrayContaining(['rax', 'r8', 'rflags']))
  })

  it('retains carry dependencies through inc and possible zero-count shifts', () => {
    const result = verify([['cmp', 'rdi, 0'], ['inc', 'rbx'], ['shl', 'rbx, cl'], ['jb', '.Ltarget']], ['rdi'])
    expect(result.trace[3].violation?.type).toBe('BRANCH_DEPENDENCY')
  })

  it.each(['jrcxz', 'jecxz', 'jcxz', 'loop', 'loope', 'loopne'])('checks implicit counter dependencies for %s', mnemonic => {
    expect(verify([[mnemonic, '.Ltarget']], ['ecx']).violations[0]).toMatchObject({ category: 'BRANCH', severity: 'CRITICAL' })
  })

  it.each(['jmp', 'call'])('detects secret indirect control-flow targets for %s', mnemonic => {
    expect(verify([[mnemonic, 'rax']], ['rax']).trace[0].violation?.type).toBe('BRANCH_DEPENDENCY')
  })

  it('propagates conditional-move/selection flag dependencies into later sinks', () => {
    const result = verify([['cmp', 'rdi, 0'], ['cmovz', 'rax, rbx'], ['mov', 'rdx, [rax]']], ['rdi'])
    expect(result.trace[1].taintedInputs).toEqual(['rflags'])
    expect(result.trace[1].taintedOutputs).toEqual(['rax'])
    expect(result.trace[2].violation?.type).toBe('INDEXED_MEMORY_LEAK')
  })

  it('detects the required indexed cache-timing violation', () => {
    const result = verify([['mov', 'rax, rdi'], ['mov', 'rdx, [rbx + rax*8]']], ['rdi'])
    expect(result.violations).toEqual([expect.objectContaining({ offset: 4, severity: 'CRITICAL', category: 'CACHE_TIMING',
      reason: 'Memory address calculation uses secret-tainted register; causes cache-timing side-channel.' })])
    expect(result.trace[1]).toMatchObject({ taintedInputs: ['rax'], violation: { type: 'INDEXED_MEMORY_LEAK' } })
  })

  it.each(['rax, [rdi]', '[rdi], rax', 'rax, [rsp + rdi*8]', 'rax, [rbp - rdi]'])('detects a tainted base or index in %s', operands => {
    expect(verify([['mov', operands]], ['rdi']).violations[0]).toMatchObject({ category: 'CACHE_TIMING', severity: 'CRITICAL' })
  })

  it.each(['rax, [rsp + 8]', 'rax, [rbp - 16]', 'rax, [rbx + rcx*8]'])('accepts public address calculations %s', operands => {
    expect(verify([['mov', operands]], ['rdi']).isProvablyConstantTime).toBe(true)
  })

  it('does not exempt a tainted stack base', () => {
    expect(verify([['mov', 'rax, [rsp + 8]']], ['rsp']).violations[0].category).toBe('CACHE_TIMING')
  })

  it('propagates LEA without reporting a memory access until dereference', () => {
    const result = verify([['lea', 'rax, [rbx + rdi*8]'], ['mov', 'rdx, [rax]']], ['rdi'])
    expect(result.trace[0].violation).toBeUndefined()
    expect(result.trace[0].taintedOutputs).toContain('rax')
    expect(result.violations[0]).toMatchObject({ offset: 4, category: 'CACHE_TIMING' })
  })

  it.each(['div', 'idiv'])('detects explicit and implicit secret %s operands', mnemonic => {
    for (const register of ['rcx', 'rax', 'rdx']) {
      expect(verify([[mnemonic, 'rcx']], [register]).violations[0]).toMatchObject({ category: 'VARIABLE_LATENCY', severity: 'HIGH' })
    }
    expect(verify([[mnemonic, 'rcx']], ['rdi']).isProvablyConstantTime).toBe(true)
  })

  it('reports multiple invariant violations for one instruction', () => {
    const result = verify([['div', '[rdi]']], ['rdi'])
    expect(result.violations.map(hazard => hazard.category)).toEqual(['CACHE_TIMING', 'VARIABLE_LATENCY'])
    expect(result.trace[0].violation?.type).toBe('INDEXED_MEMORY_LEAK')
  })

  it.each(['shl', 'shr', 'sar', 'rol', 'ror'])('checks secret shift count for %s', mnemonic => {
    expect(verify([[mnemonic, 'rax, cl']], ['ecx']).violations[0]).toMatchObject({ severity: 'HIGH', category: 'VARIABLE_LATENCY' })
    expect(verify([[mnemonic, 'rax, 3']], ['rax']).hasViolations).toBe(false)
  })

  it('recognizes real reference-decoded mov/alu64/branch without changing legacy output', () => {
    const bytes = Uint8Array.from(Buffer.from('4889f84883f8007400', 'hex'))
    const instructions = ReferenceDisassembler.disassemble(bytes, { arch: 'x86_64', baseAddress: 2n ** 63n })
    expect(instructions.map(instruction => instruction.mnemonic)).toEqual(['mov', 'alu64', 'je'])
    const result = ConstantTimeAuditor.verifyNonInterference(instructions, [{ type: 'REGISTER', identifier: 'rdi' }], 'x86_64', { baseAddress: 2n ** 63n })
    expect(result.trace[1].taintedOutputs).toEqual(['rflags'])
    expect(result.violations[0]).toMatchObject({ offset: 7, category: 'BRANCH' })
  })
})

describe('stack value taints and spills', () => {
  it('loads declared secret stack offsets through canonical expressions', () => {
    const result = ConstantTimeAuditor.verifyNonInterference(sequence([['mov', 'rax, [rsp + 0x8]'], ['cmp', 'rax, 0'], ['jne', '.Ltarget']]),
      [{ type: 'STACK_OFFSET', identifier: 'rsp+8' }], 'x86_64')
    expect(result.trace[0]).toMatchObject({ taintedInputs: ['rsp+8'], taintedOutputs: ['rax'] })
    expect(result.violations[0].category).toBe('BRANCH')
  })

  it('tracks a spill and reload as data rather than an address hazard', () => {
    const result = verify([['mov', '[rsp + 8], rdi'], ['mov', 'rax, [rsp + 8]'], ['cmp', 'rax, 0'], ['je', '.Ltarget']], ['rdi'])
    expect(result.trace[0].taintedOutputs).toEqual(['rsp+8'])
    expect(result.trace[1].taintedInputs).toEqual(['rsp+8'])
    expect(result.violations).toEqual([expect.objectContaining({ offset: 12, category: 'BRANCH' })])
  })

  it('clears a fully overwritten stack slot', () => {
    const result = verify([['mov', '[rsp + 8], rdi'], ['mov', '[rsp + 8], rbx'], ['mov', 'rax, [rsp + 8]']], ['rdi'])
    expect(result.activeTaints).toEqual(['rdi'])
    expect(result.trace[2].taintedInputs).toEqual([])
  })

  it('tracks overlapping stack reads and retains bytes after a partial overwrite', () => {
    const result = verify([['mov', '[rsp + 8], rdi'], ['mov', 'byte ptr [rsp + 8], bl'], ['mov', 'eax, [rsp + 12]'], ['cmp', 'eax, 0'], ['je', '.Ltarget']], ['rdi'])
    expect(result.trace[2].taintedInputs).toContain('rsp+12')
    expect(result.violations[0].category).toBe('BRANCH')
  })

  it('does not clear neighbouring bytes with SETcc or a store of unspecified width', () => {
    for (const overwrite of [['setne', 'byte ptr [rsp + 8]'], ['mov', '[rsp + 8], 0']] as Array<[string, string]>) {
      const result = verify([['mov', '[rsp + 8], rdi'], overwrite, ['mov', 'eax, [rsp + 12]'], ['test', 'eax, eax'], ['je', '.Ltarget']], ['rdi'])
      expect(result.violations[0].category).toBe('BRANCH')
    }
  })

  it('does not assume the entry stack and frame pointers cannot alias', () => {
    const result = ConstantTimeAuditor.verifyNonInterference(sequence([['mov', 'rax, [rbp + 8]'], ['test', 'rax, rax'], ['je', '.Ltarget']]),
      [{ type: 'STACK_OFFSET', identifier: 'rsp+8' }], 'x86_64')
    expect(result.violations[0].category).toBe('BRANCH')
  })

  it('preserves stack slot identities through stack adjustment and frame-pointer copies', () => {
    const result = verify([['mov', '[rsp + 8], rdi'], ['mov', 'rbp, rsp'], ['sub', 'rsp, 16'], ['mov', 'rax, [rsp + 24]'], ['mov', 'rdx, [rbp + 8]']], ['rdi'])
    expect(result.trace[3].taintedInputs).toEqual(['rsp+8'])
    expect(result.trace[4].taintedInputs).toEqual(['rsp+8'])
    expect(result.activeTaints).toEqual(expect.arrayContaining(['rax', 'rdx']))
  })

  it('tracks push/pop spill dependencies', () => {
    const result = verify([['push', 'rdi'], ['pop', 'rax'], ['test', 'rax, rax'], ['jne', '.Ltarget']], ['rdi'])
    expect(result.trace[1].taintedInputs).toEqual(['rsp-8'])
    expect(result.violations[0].category).toBe('BRANCH')
  })

  it('conservatively retains stores through unresolved public pointer aliases', () => {
    const result = verify([['mov', '[rbx], rdi'], ['mov', 'rax, [rsi]'], ['test', 'rax, rax'], ['je', '.Ltarget']], ['rdi'])
    expect(result.trace[1].taintedInputs).toContain('memory:*')
    expect(result.violations[0].category).toBe('BRANCH')
  })

  it('fails closed if secret stores cannot be tracked', () => {
    const result = verify([['mov', '[rsp + 8], rdi']], ['rdi'], 'x86_64', { trackMemoryTaints: false })
    expect(result).toMatchObject({ isProvablyConstantTime: false, hasViolations: true })
    expect(result.violations[0]).toMatchObject({ category: 'UNDECODED', reason: expect.stringContaining('memory taint tracking disabled') })
  })
})

describe('AArch64 taint propagation and sinks', () => {
  it.each(Array.from({ length: 31 }, (_, index) => index))('normalizes w%s to its x register root', index => {
    expect(verify([['mov', `x5, w${index}`]], [`w${index}`], 'aarch64').activeTaints).toEqual(expect.arrayContaining([`x${index}`, 'x5']))
  })

  it('normalizes wsp and clears through a w-register zero-extending write', () => {
    expect(verify([['mov', 'x0, wsp']], ['wsp'], 'aarch64').activeTaints).toEqual(['sp', 'x0'])
    expect(verify([['mov', 'w0, #0']], ['x0'], 'aarch64').activeTaints).toEqual([])
  })

  it.each(['cbz', 'cbnz', 'tbz', 'tbnz'])('detects a direct register test branch for %s', mnemonic => {
    const operands = mnemonic.startsWith('tb') ? 'w0, #3, .Ltarget' : 'x0, .Ltarget'
    const result = verify([[mnemonic, operands]], ['x0'], 'aarch64')
    expect(result.violations[0]).toMatchObject({ category: 'BRANCH', severity: 'CRITICAL', reason: 'Direct register test branch depends on secret-tainted register.' })
    expect(result.trace[0].violation?.type).toBe('BRANCH_DEPENDENCY')
  })

  it('clears eor self-zeroing without clearing a prior NZCV dependency', () => {
    const result = verify([['cmp', 'x0, #0'], ['eor', 'x0, x0, x0'], ['cbz', 'x0, .Lpublic'], ['b.eq', '.Lsecret']], ['x0'], 'aarch64')
    expect(result.activeTaints).not.toContain('x0')
    expect(result.trace[1].taintedOutputs).toEqual([])
    expect(result.trace[2].violation).toBeUndefined()
    expect(result.trace[3].violation?.type).toBe('BRANCH_DEPENDENCY')
  })

  it('checks three-operand arithmetic/flag effects without reading old destination taint', () => {
    const result = verify([['adds', 'x2, x0, x1'], ['subs', 'x3, x2, #1'], ['b.ne', '.Ltarget']], ['w0'], 'aarch64')
    expect(result.activeTaints).toEqual(expect.arrayContaining(['x0', 'x2', 'x3', 'nzcv']))
    expect(result.trace[2].violation?.type).toBe('BRANCH_DEPENDENCY')
    expect(verify([['sub', 'x0, x1, x1']], ['x0'], 'aarch64').activeTaints).not.toContain('x0')
  })

  it('checks ARM indexed memory and propagates loaded address dependencies', () => {
    const result = verify([['ldr', 'x3, [sp, w0, uxtw #3]']], ['x0'], 'aarch64')
    expect(result.trace[0]).toMatchObject({ taintedInputs: ['x0'], taintedOutputs: ['x3'], violation: { type: 'INDEXED_MEMORY_LEAK' } })
  })

  it('accepts clean SP-relative loads and the hardwired zero register', () => {
    const result = verify([['ldr', 'x3, [sp, #16]'], ['mov', 'x0, xzr']], ['x0'], 'aarch64')
    expect(result).toMatchObject({ isProvablyConstantTime: true, activeTaints: [] })
  })

  it('tracks ARM stack stores and loads including comma-containing addresses', () => {
    const result = verify([['str', 'x0, [sp, #16]'], ['ldr', 'x2, [sp, #16]'], ['cbnz', 'x2, .Ltarget']], ['x0'], 'aarch64')
    expect(result.trace[1].taintedInputs).toEqual(['sp+16'])
    expect(result.violations[0].category).toBe('BRANCH')
  })

  it.each(['udiv', 'sdiv'])('checks actual source operands for %s', mnemonic => {
    expect(verify([[mnemonic, 'x0, x1, x2']], ['x1'], 'aarch64').violations[0]).toMatchObject({ category: 'VARIABLE_LATENCY', severity: 'HIGH' })
    expect(verify([[mnemonic, 'x0, x1, x2']], ['x0'], 'aarch64').hasViolations).toBe(false)
  })

  it.each(['lslv', 'lsrv', 'asrv', 'rorv'])('checks a secret ARM shift count for %s', mnemonic => {
    expect(verify([[mnemonic, 'x0, x1, x2']], ['w2'], 'aarch64').violations[0]).toMatchObject({ category: 'VARIABLE_LATENCY', severity: 'HIGH' })
    expect(verify([[mnemonic, 'x0, x1, x2']], ['x1'], 'aarch64').hasViolations).toBe(false)
  })

  it('propagates conditional selection into later branch dependencies', () => {
    const result = verify([['cmp', 'x0, #0'], ['csel', 'x1, x2, x3, eq'], ['cbz', 'x1, .Ltarget']], ['x0'], 'aarch64')
    expect(result.trace[1].taintedInputs).toEqual(['nzcv'])
    expect(result.trace[2].violation?.type).toBe('BRANCH_DEPENDENCY')
  })
})

describe('verification completeness and options', () => {
  it('stops after the first violating instruction when requested', () => {
    const result = verify([['cmp', 'rdi, 0'], ['je', '.Ltarget'], ['mov', 'rax, [rdi]']], ['rdi'], 'x86_64', { stopOnFirstViolation: true })
    expect(result.trace).toHaveLength(2)
    expect(result.violations).toHaveLength(1)
    expect(result.activeTaints).not.toContain('rax')
  })

  it('continues and reports all violating instructions by default', () => {
    expect(verify([['cmp', 'rdi, 0'], ['je', '.Ltarget'], ['mov', 'rax, [rdi]']], ['rdi']).violations).toHaveLength(2)
  })

  it('never proves empty or partially decoded instruction streams', () => {
    expect(verify([], ['rax'])).toMatchObject({ isProvablyConstantTime: false, hasViolations: false })
    const invalid = sequence([['db', '0x00']])
    invalid[0].isValid = false
    const result = ConstantTimeAuditor.verifyNonInterference(invalid, [], 'x86_64')
    expect(result).toMatchObject({ isProvablyConstantTime: false, hasViolations: true })
    expect(result.violations[0].category).toBe('UNDECODED')
  })

  it('fails closed for unsupported instructions and malformed transfers', () => {
    for (const instruction of [['opaque', 'rax, rdi'], ['mov', 'rax']] as Array<[string, string]>) {
      expect(verify([instruction], ['rdi']).violations[0].category).toBe('UNDECODED')
    }
  })

  it('fails closed for mismatched architectures and byte spans', () => {
    const instructions = sequence([['nop', '']])
    expect(ConstantTimeAuditor.verifyNonInterference(instructions, [], 'aarch64').isProvablyConstantTime).toBe(false)
    instructions[0].bytes = new Uint8Array(3)
    expect(ConstantTimeAuditor.verifyNonInterference(instructions, [], 'x86_64').isProvablyConstantTime).toBe(false)
  })

  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])('rejects invalid instruction length %s', length => {
    const instructions = sequence([['nop', '']])
    instructions[0].length = length
    expect(() => ConstantTimeAuditor.verifyNonInterference(instructions, [], 'x86_64')).toThrow(RangeError)
  })

  it('keeps offsets relative and preserves high bigint base addresses', () => {
    for (const baseAddress of [0x1000, 2n ** 63n]) {
      const result = verify([['mov', 'rax, rdi'], ['cmp', 'rax, 0'], ['jne', '.Ltarget']], ['rdi'], 'x86_64', { baseAddress })
      expect(result.violations[0].offset).toBe(8)
      expect(() => JSON.stringify(result)).not.toThrow()
    }
  })

  it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1, -1n, 2n ** 64n])('rejects an invalid base address %s', baseAddress => {
    expect(() => verify([['nop', '']], [], 'x86_64', { baseAddress })).toThrow(RangeError)
  })

  it.each(['unknown', 'x0', '', 'r16'])('rejects unknown x86 secret register %s', register => {
    expect(() => verify([['nop', '']], [register])).toThrow(RangeError)
  })

  it.each(['rax', 'x31', 'xzr'])('rejects invalid AArch64 secret register %s', register => {
    expect(() => verify([['nop', '']], [register], 'aarch64')).toThrow(RangeError)
  })

  it('rejects malformed stack sources and address-space overflow', () => {
    expect(() => ConstantTimeAuditor.verifyNonInterference(sequence([['nop', '']]), [{ type: 'STACK_OFFSET', identifier: 'rdi+8' }], 'x86_64')).toThrow(RangeError)
    expect(() => verify([['nop', '']], [], 'x86_64', { baseAddress: 0xffffffffffffffffn })).toThrow(RangeError)
  })

  it('does not mutate input instructions or leak taint state between calls', () => {
    const instructions = sequence([['mov', 'rax, rdi']])
    const before = structuredClone(instructions)
    ConstantTimeAuditor.verifyNonInterference(instructions, [{ type: 'REGISTER', identifier: 'rdi' }], 'x86_64')
    expect(instructions).toEqual(before)
    expect(ConstantTimeAuditor.verifyNonInterference(instructions, [], 'x86_64').activeTaints).toEqual([])
  })
})
