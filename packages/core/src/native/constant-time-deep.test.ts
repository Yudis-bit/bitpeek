import { describe, expect, it } from 'vitest'
import { ConstantTimeAuditor as Auditor } from './constant-time'
import type { DisassembledInstruction } from './constant-time'
import { ReferenceDisassembler } from './disassembler'

function instruction(mnemonic: string, operands: string, arch: 'x86_64' | 'aarch64' = 'x86_64'): DisassembledInstruction {
  return { mnemonic, operands, arch, address: 0n, bytes: new Uint8Array(4), length: 4, isValid: true }
}

function x86(hex: string, checkMemoryLookups = true) {
  return Auditor.auditBytes(Uint8Array.from(Buffer.from(hex, 'hex')), { arch: 'x86_64', checkMemoryLookups })
}

function arm(word: number) {
  const bytes = new Uint8Array(4)
  new DataView(bytes.buffer).setUint32(0, word, true)
  return Auditor.auditBytes(bytes, { arch: 'aarch64' })
}

describe('classified constant-time hazards', () => {
  it.each(['rax, [rbx + rcx*8]', 'rax, [rax + rbx]', 'eax, [rsi + rdx]', 'rax, [rsp + rax*4]'])(
    'flags indexed x86 memory %s', operands => {
      const result = Auditor.auditX86_64([instruction('mov', operands)])
      expect(result).toMatchObject({ hasCacheTimingHazards: true, hasVariableLatencyHazards: false, isCleanConstantTime: false })
      expect(result.hazards).toEqual([expect.objectContaining({ offset: 0, mnemonic: 'mov', operands, severity: 'HIGH', category: 'CACHE_TIMING' })])
    },
  )
  it.each(['rax, [rbp - 16]', 'rax, [rsp + 8]', 'rax, [rip + 0x100]', 'rax, [rdi]', 'rax, [0x1000]'])(
    'accepts fixed/base x86 memory %s', operands => {
      expect(Auditor.auditX86_64([instruction('mov', operands)]).hazards).toEqual([])
    },
  )
  it('excludes LEA address arithmetic and honors memory opt-out', () => {
    expect(Auditor.auditX86_64([instruction('lea', 'rax, [rbx + rcx*8]')]).isCleanConstantTime).toBe(true)
    expect(Auditor.auditX86_64([instruction('mov', 'rax, [rbx + rcx*8]')], { checkMemoryLookups: false }).hazards).toEqual([])
  })
  it.each(['x0, [x1, x2]', 'x0, [x1, x2, lsl #3]', 'w0, [sp, w2, uxtw #2]'])(
    'flags ARM register-offset memory %s', operands => {
      expect(Auditor.auditARM64([instruction('ldr', operands, 'aarch64')]).hazards[0]).toMatchObject({ category: 'CACHE_TIMING', severity: 'HIGH' })
    },
  )
  it.each(['x0, [sp, #16]', 'x0, [x1]', 'x0, [x1, xzr]'])(
    'accepts fixed ARM memory %s', operands => {
      expect(Auditor.auditARM64([instruction('ldr', operands, 'aarch64')]).hasCacheTimingHazards).toBe(false)
    },
  )
  it.each([['shl', 'rax, cl'], ['ror', 'eax, ecx'], ['shlq', '%cl, %rax'], ['bsf', 'eax, ebx'], ['bsr', 'rax, rbx'], ['rep movsb', ''], ['rep', 'stosq']])(
    'flags variable x86 instruction %s %s', (mnemonic, operands) => {
      expect(Auditor.auditX86_64([instruction(mnemonic, operands)])).toMatchObject({ hasVariableLatencyHazards: true, isCleanConstantTime: false })
    },
  )
  it.each([['shl', 'rax, 3'], ['shlq', '$3, %rax'], ['ror', 'rax, 1']])(
    'accepts constant-count shift %s %s', (mnemonic, operands) => {
      expect(Auditor.auditX86_64([instruction(mnemonic, operands)]).hasVariableLatencyHazards).toBe(false)
    },
  )
  it.each(['lslv', 'lsrv', 'asrv', 'rorv', 'clz', 'cls', 'rbit', 'lsl'])(
    'flags ARM bit operation %s', mnemonic => {
      expect(Auditor.auditARM64([instruction(mnemonic, 'x0, x1, x2', 'aarch64')]).hasVariableLatencyHazards).toBe(true)
    },
  )
  it('retains byte offsets, multiple hazard categories, and legacy findings', () => {
    const result = Auditor.auditX86_64([instruction('nop', ''), instruction('je', '0x10'), instruction('div', '[rax + rbx]')])
    expect(result.branchCount).toBe(1)
    expect(result.hazards.map(hazard => [hazard.offset, hazard.category, hazard.severity])).toEqual([
      [4, 'BRANCH', 'CRITICAL'], [8, 'VARIABLE_LATENCY', 'HIGH'], [8, 'CACHE_TIMING', 'HIGH'],
    ])
    expect(result.suspiciousInstructions).toEqual(result.hazards.map(({ offset, mnemonic, reason }) => ({ offset, mnemonic, reason })))
  })
  it('classifies undecoded code and an unexamined tail', () => {
    expect(x86('00').hazards[0]).toMatchObject({ category: 'UNDECODED', severity: 'WARN' })
    expect(Auditor.auditBytes(Uint8Array.of(0x90, 0xc3), { arch: 'x86_64', maxInstructions: 1 }).hazards[0]).toMatchObject({ offset: 1, category: 'UNDECODED' })
  })
})

describe('deep hazards from real machine code', () => {
  it.each(['488b04cb', '488904cb', '4b8b04cc', '488b0418', '488b048df0ffffff', '48f734cb', '4883bc087400000001'])(
    'decodes indexed x86 memory without losing byte spans: %s', hex => {
      const bytes = Uint8Array.from(Buffer.from(hex, 'hex'))
      const decoded = ReferenceDisassembler.disassemble(bytes, { arch: 'x86_64' })
      expect(decoded).toHaveLength(1)
      expect(decoded[0]).toMatchObject({ length: bytes.length, isValid: true })
      expect(x86(hex).hasCacheTimingHazards).toBe(true)
    },
  )
  it.each(['488b45f0', '488b442408', '488b0574000000', '488b042574000000', '488b04e3', '498b442408'])(
    'decodes fixed memory without false cache findings: %s', hex => {
      expect(x86(hex)).toMatchObject({ hasCacheTimingHazards: false, isCleanConstantTime: true })
    },
  )
  it.each(['48d3e0', 'd3e8', '48d3c8', '480fbcc1', '0fbdc1', 'f3a4', 'f348ab', '66f3a5'])(
    'decodes variable-latency x86 machine code: %s', hex => {
      expect(x86(hex)).toMatchObject({ hasVariableLatencyHazards: true, isCleanConstantTime: false })
      expect(x86(hex).hazards.every(hazard => hazard.category !== 'UNDECODED')).toBe(true)
    },
  )
  it.each(['48c1e003', '48d1e0', '66c1c001'])(
    'keeps immediate shifts clean: %s', hex => expect(x86(hex).isCleanConstantTime).toBe(true),
  )
  it.each(['488b04', '488b0574', '48c1e0', '480fbc', 'f3', '66d3'])(
    'fails closed on truncated deep instructions: %s', hex => expect(x86(hex).isCleanConstantTime).toBe(false),
  )
  it('reports exact SIB operands and offsets, including extended registers', () => {
    expect(x86('90488b04cb').hazards[0]).toMatchObject({ offset: 1, operands: 'rax, [rbx + rcx*8]' })
    expect(x86('4b8b04cc').hazards[0]?.operands).toBe('rax, [r12 + r9*8]')
    expect(x86('488b04cb', false).isCleanConstantTime).toBe(true)
  })
  it.each([0xf8626820, 0xf8627820, 0xf8226820, 0xb8625820])('decodes ARM register-offset loads/stores: %s', word => {
    expect(arm(word)).toMatchObject({ hasCacheTimingHazards: true, hasVariableLatencyHazards: false })
    expect(arm(word).hazards[0]?.operands).toContain('[x1,')
  })
  it('ignores ARM zero register offsets', () => {
    expect(arm(0xf87f6820).isCleanConstantTime).toBe(true)
  })
  it.each([0x9ac22020, 0x9ac22420, 0x1ac22820, 0x9ac22c20])('decodes ARM variable shifts: %s', word => {
    expect(arm(word).hazards[0]).toMatchObject({ category: 'VARIABLE_LATENCY', severity: 'WARN' })
  })
})
