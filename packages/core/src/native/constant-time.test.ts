import { describe, expect, it } from 'vitest'
import { ConstantTimeAuditor as Auditor } from './constant-time'
import type { DisassembledInstruction } from './constant-time'
import { ReferenceDisassembler } from './disassembler'

function instruction(mnemonic: string, arch: 'x86_64' | 'aarch64' = 'x86_64', length = 1): DisassembledInstruction {
  return { address: 2n ** 63n, bytes: new Uint8Array(length), length, mnemonic, operands: '', arch, isValid: true }
}

function arm(words: number[]): Uint8Array {
  const bytes = new Uint8Array(words.length * 4)
  const view = new DataView(bytes.buffer)
  words.forEach((word, index) => view.setUint32(index * 4, word, true))
  return bytes
}

describe('constant-time static instruction inspection', () => {
  it.each(['jz', 'jnz', 'je', 'jne', 'ja', 'jbe', 'jo', 'jnp', 'jrcxz', 'loope'])('flags x86 conditional branch %s', mnemonic => {
    const result = Auditor.auditX86_64([instruction('nop', 'x86_64', 3), instruction(mnemonic, 'x86_64', 2)])
    expect(result).toMatchObject({ hasConditionalBranches: true, branchCount: 1, isCleanConstantTime: false })
    expect(result.suspiciousInstructions[0]).toMatchObject({ offset: 3, mnemonic })
  })
  it.each(['cbz', 'cbnz', 'tbz', 'tbnz', 'b.eq', 'b.ne', 'b.gt', 'b.lo', 'bc.eq'])('flags ARM conditional branch %s', mnemonic => {
    const result = Auditor.auditARM64([instruction(mnemonic, 'aarch64', 4)])
    expect(result.branchCount).toBe(1)
    expect(result.isCleanConstantTime).toBe(false)
  })
  it.each(['div', 'idiv', 'divq', 'idivl'])('flags x86 division %s', mnemonic => {
    expect(Auditor.auditX86_64([instruction(mnemonic)])).toMatchObject({ branchCount: 0, isCleanConstantTime: false })
  })
  it.each(['udiv', 'sdiv'])('flags ARM division %s', mnemonic => {
    expect(Auditor.auditARM64([instruction(mnemonic, 'aarch64', 4)]).suspiciousInstructions[0]?.reason).toContain('Division latency')
  })
  it('accepts branchless arithmetic and conditional moves in a supplied stream', () => {
    const mnemonics = ['mov', 'add', 'sub', 'xor', 'cmovz', 'setne', 'jmp', 'ret']
    expect(Auditor.auditX86_64(mnemonics.map(name => instruction(name))).isCleanConstantTime).toBe(true)
    expect(Auditor.auditARM64(['add', 'eor', 'csel', 'b', 'b.al', 'b.nv', 'ret'].map(name => instruction(name, 'aarch64', 4))).isCleanConstantTime).toBe(true)
  })
  it('normalizes mnemonic case and whitespace without changing reported mnemonic', () => {
    expect(Auditor.auditX86_64([instruction('  JNZ ')]).suspiciousInstructions[0]?.mnemonic).toBe('  JNZ ')
  })
  it('fails closed for empty streams, unknown instructions and architecture mismatch', () => {
    expect(Auditor.auditX86_64([]).isCleanConstantTime).toBe(false)
    expect(Auditor.auditX86_64([{ ...instruction('db'), isValid: false }]).isCleanConstantTime).toBe(false)
    expect(Auditor.auditARM64([instruction('nop')]).isCleanConstantTime).toBe(false)
  })
  it('does not narrow high instruction addresses to floating point offsets', () => {
    expect(Auditor.auditX86_64([instruction('div')]).suspiciousInstructions[0]?.offset).toBe(0)
  })
  it('rejects invalid lengths without silently corrupting offsets', () => {
    for (const length of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => Auditor.auditX86_64([{ ...instruction('nop'), length }])).toThrow(RangeError)
    }
  })
  it('fails closed for inconsistent instruction byte spans', () => {
    expect(Auditor.auditX86_64([{ ...instruction('nop'), bytes: new Uint8Array(0) }]).isCleanConstantTime).toBe(false)
  })
})

describe('binary disassembly integrated with timing audit', () => {
  it('decodes short and near x86 branches with exact signed targets and offsets', () => {
    const code = Uint8Array.from([0x90, 0x74, 0xfd, 0x0f, 0x85, 0xf7, 0xff, 0xff, 0xff, 0xc3])
    const instructions = ReferenceDisassembler.disassemble(code, { arch: 'x86_64', baseAddress: 0x1000n })
    expect(instructions.map(i => [i.mnemonic, i.length, i.operands])).toEqual([
      ['nop', 1, ''], ['je', 2, '0x1000'], ['jne', 6, '0x1000'], ['ret', 1, ''],
    ])
    const result = Auditor.auditBytes(code, { arch: 'x86_64' })
    expect(result.branchCount).toBe(2)
    expect(result.suspiciousInstructions.map(i => i.offset)).toEqual([1, 3])
  })
  it.each(Array.from({ length: 16 }, (_, index) => index))('decodes both x86 Jcc forms for condition %s', condition => {
    for (const code of [Uint8Array.from([0x70 + condition, 0]), Uint8Array.from([0x0f, 0x80 + condition, 0, 0, 0, 0])]) {
      expect(Auditor.auditBytes(code, { arch: 'x86_64' }).branchCount).toBe(1)
    }
  })
  it.each([
    [0xf6, 0xf0], [0xf7, 0xf8], [0x48, 0xf7, 0xf0],
    [0x49, 0xf7, 0xf1], [0xf7, 0x75, 0x74],
    [0x48, 0xf7, 0xbc, 0x24, 0x74, 0, 0, 0],
    [0xf7, 0x34, 0x25, 0, 0, 0, 0], [0xf7, 0x35, 0, 0, 0, 0],
  ])('consumes complete x86 division instruction %j', (...encoding) => {
    const code = Uint8Array.from(encoding)
    const instructions = ReferenceDisassembler.disassemble(code, { arch: 'x86_64' })
    expect(instructions).toHaveLength(1)
    expect(instructions[0]?.length).toBe(code.length)
    expect(Auditor.auditX86_64(instructions)).toMatchObject({ branchCount: 0, isCleanConstantTime: false })
  })
  it('decodes ARM branches and divisions with exact byte positions', () => {
    const code = arm([0xd503201f, 0x54000000, 0x54000001, 0xb4000000, 0x35000000, 0x36000000, 0xb7000000, 0x9ac20820, 0x1ac20c20, 0xd65f03c0])
    const instructions = ReferenceDisassembler.disassemble(code, { arch: 'aarch64' })
    expect(instructions.map(i => i.mnemonic)).toEqual(['nop', 'b.eq', 'b.ne', 'cbz', 'cbnz', 'tbz', 'tbnz', 'udiv', 'sdiv', 'ret'])
    expect(instructions[7]?.operands).toBe('x0, x1, x2')
    const result = Auditor.auditBytes(code, { arch: 'aarch64' })
    expect(result.branchCount).toBe(6)
    expect(result.suspiciousInstructions.map(i => i.offset)).toEqual([4, 8, 12, 16, 20, 24, 28, 32])
  })
  it('sign extends ARM branch immediates', () => {
    const instructions = ReferenceDisassembler.disassemble(arm([0x54ffffe0, 0xb4ffffe0, 0x36ffffe0]), { arch: 'aarch64', baseAddress: 0x1000n })
    expect(instructions.map(i => i.operands)).toEqual(['0xffc', 'x0, 0x1000', 'w0, #31, 0x1004'])
  })
  it('keeps unconditional ARM condition codes out of the branch count', () => {
    expect(Auditor.auditBytes(arm([0x5400000e, 0x5400000f]), { arch: 'aarch64' }).branchCount).toBe(0)
  })
  it('fails closed on unknown and truncated code', () => {
    for (const code of [[0x74], [0x0f, 0x85], [0x48, 0xf7, 0x74], [0xf7, 0x35, 0], [0x00]]) {
      expect(Auditor.auditBytes(Uint8Array.from(code), { arch: 'x86_64' }).isCleanConstantTime).toBe(false)
    }
    expect(Auditor.auditBytes(new Uint8Array(3), { arch: 'aarch64' }).isCleanConstantTime).toBe(false)
    expect(Auditor.auditBytes(arm([0]), { arch: 'aarch64' }).isCleanConstantTime).toBe(false)
  })
  it('fails closed if an instruction limit leaves bytes unexamined', () => {
    const result = Auditor.auditBytes(Uint8Array.from([0x90, 0x74, 0]), { arch: 'x86_64', maxInstructions: 1 })
    expect(result.isCleanConstantTime).toBe(false)
    expect(result.suspiciousInstructions[0]).toMatchObject({ offset: 1, mnemonic: '<unexamined>' })
  })
  it('recognizes fully decoded simple clean snippets', () => {
    expect(Auditor.auditBytes(Uint8Array.from([0x90, 0xc3]), { arch: 'x86_64' }).isCleanConstantTime).toBe(true)
    expect(Auditor.auditBytes(arm([0xd503201f, 0xd65f03c0]), { arch: 'aarch64' }).isCleanConstantTime).toBe(true)
  })
  it('consumes ModRM memory displacements instead of treating their bytes as branches', () => {
    const code = Uint8Array.from([0x48, 0x89, 0x84, 0x24, 0x74, 0, 0, 0, 0x48, 0x83, 0xbc, 0x24, 0x74, 0, 0, 0, 1])
    const instructions = ReferenceDisassembler.disassemble(code, { arch: 'x86_64' })
    expect(instructions.map(i => [i.mnemonic, i.length])).toEqual([['mov', 8], ['alu64', 9]])
    expect(Auditor.auditX86_64(instructions).isCleanConstantTime).toBe(true)
    for (const truncated of [[0x48, 0x89, 0x04], [0x48, 0x89, 0x05, 0], [0x48, 0x83, 0xc0]]) {
      expect(Auditor.auditBytes(Uint8Array.from(truncated), { arch: 'x86_64' }).isCleanConstantTime).toBe(false)
    }
  })
  it('rejects unsafe or fractional instruction budgets', () => {
    for (const maxInstructions of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => Auditor.auditBytes(Uint8Array.from([0x90]), { arch: 'x86_64', maxInstructions })).toThrow(RangeError)
    }
  })
})
