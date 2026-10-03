/**
 * Bitpeek Ultra - Disassembly Adapter (x86-64 & AArch64 Reference Subset)
 *
 * Implements Section 10 (NATIVE-02, AC052):
 * - Instruction disassembly for x86-64 and AArch64
 * - Exact byte spans, address space mode, decoded length
 * - Preserves undecodable bytes and truncated edges without hallucination
 */

export interface DecodedInstruction {
  address: bigint
  bytes: Uint8Array
  length: number
  mnemonic: string
  operands: string
  arch: 'x86_64' | 'aarch64'
  isValid: boolean
}

export interface DisassemblyOptions {
  arch: 'x86_64' | 'aarch64'
  baseAddress?: bigint
  maxInstructions?: number
}

export class ReferenceDisassembler {
  /**
   * Disassembles a byte stream for a target architecture within bounds.
   */
  public static disassemble(
    code: Uint8Array,
    options: DisassemblyOptions,
  ): DecodedInstruction[] {
    const arch = options.arch
    const baseAddr = options.baseAddress ?? 0n
    const maxInst = options.maxInstructions ?? 10_000
    if (!Number.isSafeInteger(maxInst) || maxInst < 0) throw new RangeError('maxInstructions must be a non-negative safe integer')
    if (arch !== 'x86_64' && arch !== 'aarch64') throw new Error('Unsupported disassembly architecture')

    const instructions: DecodedInstruction[] = []
    let cursor = 0

    while (cursor < code.length && instructions.length < maxInst) {
      const currentAddr = baseAddr + BigInt(cursor)
      const remaining = code.subarray(cursor)

      const inst =
        arch === 'x86_64'
          ? this.decodeX86_64(remaining, currentAddr)
          : this.decodeAArch64(remaining, currentAddr)

      instructions.push(inst)
      cursor += inst.length
    }

    return instructions
  }

  private static decodeX86_64(bytes: Uint8Array, addr: bigint): DecodedInstruction {
    if (bytes.length === 0) {
      return {
        address: addr,
        bytes: new Uint8Array(0),
        length: 0,
        mnemonic: 'db',
        operands: '0x00',
        arch: 'x86_64',
        isValid: false,
      }
    }

    const b0 = bytes[0]!

    const decoded = (length: number, mnemonic: string, operands: string): DecodedInstruction => ({
      address: addr, bytes: bytes.subarray(0, length), length,
      mnemonic, operands, arch: 'x86_64', isValid: true,
    })
    const modrmEnd = (offset: number): number | null => {
      if (offset >= bytes.length) return null
      const modrm = bytes[offset]!
      const mod = modrm >> 6
      const rm = modrm & 7
      let end = offset + 1
      if (mod !== 3 && rm === 4) {
        if (end >= bytes.length) return null
        const sib = bytes[end++]!
        if (mod === 0 && (sib & 7) === 5) end += 4
      }
      if (mod === 0 && rm === 5) end += 4
      if (mod === 1) end += 1
      if (mod === 2) end += 4
      return end <= bytes.length ? end : null
    }
    const conditions = ['jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja', 'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg']
    if (b0 >= 0x70 && b0 <= 0x7f && bytes.length >= 2) {
      const rel = (bytes[1]! << 24) >> 24
      return decoded(2, conditions[b0 - 0x70]!, `0x${(addr + 2n + BigInt(rel)).toString(16)}`)
    }
    if (b0 === 0x0f && bytes[1]! >= 0x80 && bytes[1]! <= 0x8f && bytes.length >= 6) {
      const rel = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(2, true)
      return decoded(6, conditions[bytes[1]! - 0x80]!, `0x${(addr + 6n + BigInt(rel)).toString(16)}`)
    }
    if (b0 >= 0xe0 && b0 <= 0xe3 && bytes.length >= 2) {
      const rel = (bytes[1]! << 24) >> 24
      return decoded(2, ['loopne', 'loope', 'loop', 'jrcxz'][b0 - 0xe0]!, `0x${(addr + 2n + BigInt(rel)).toString(16)}`)
    }

    // Decode group-3 divisions, including REX, SIB and displacement lengths.
    let opcodeOffset = 0
    let operand16 = false
    let repeat = false
    while (opcodeOffset < 15 && [0x66, 0xf2, 0xf3].includes(bytes[opcodeOffset] ?? -1)) {
      if (bytes[opcodeOffset] === 0x66) operand16 = true
      else repeat = true
      opcodeOffset++
    }
    const rex = (bytes[opcodeOffset] ?? 0) >= 0x40 && (bytes[opcodeOffset] ?? 0) <= 0x4f ? bytes[opcodeOffset++]! : 0
    const opcode = bytes[opcodeOffset]
    const width = (rex & 8) !== 0 ? 64 : operand16 ? 16 : 32
    const register = (index: number, size = width): string => {
      if (index >= 8) return `r${index}${size === 64 ? '' : size === 32 ? 'd' : size === 16 ? 'w' : 'b'}`
      if (size === 8) return (rex ? ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil'] : ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh'])[index]!
      const names = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
      return `${size === 64 ? 'r' : size === 32 ? 'e' : ''}${names[index]}`
    }
    const memoryOperand = (offset: number, size = width): string => {
      const modrm = bytes[offset]!
      const mode = modrm >> 6
      const rm = modrm & 7
      if (mode === 3) return register(rm + ((rex & 1) << 3), size)
      const parts: string[] = []
      let cursor = offset + 1
      let displacementSize = mode === 1 ? 1 : mode === 2 ? 4 : 0
      if (rm === 4) {
        const sib = bytes[cursor++]!
        const base = sib & 7
        const index = (sib >> 3) & 7
        if (mode === 0 && base === 5) displacementSize = 4
        else parts.push(register(base + ((rex & 1) << 3), 64))
        if (index !== 4 || (rex & 2) !== 0) {
          const scale = 1 << (sib >> 6)
          const indexRegister = register(index + ((rex & 2) << 2), 64)
          parts.push(scale === 1 ? indexRegister : `${indexRegister}*${scale}`)
        }
      } else if (mode === 0 && rm === 5) {
        parts.push('rip')
        displacementSize = 4
      } else parts.push(register(rm + ((rex & 1) << 3), 64))
      const displacement = displacementSize === 1 ? (bytes[cursor]! << 24) >> 24
        : displacementSize === 4 ? new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(cursor, true) : 0
      let expression = parts.join(' + ')
      if (expression === '') expression = displacement.toString()
      else if (displacement !== 0) expression += displacement < 0 ? ` - ${-displacement}` : ` + ${displacement}`
      return `[${expression}]`
    }
    const complete = (length: number | null, mnemonic: string, operands: () => string): DecodedInstruction => {
      if (length === null || length > 15 || length > bytes.length) {
        return { ...decoded(Math.min(bytes.length, 15), 'db', ''), isValid: false }
      }
      return decoded(length, mnemonic, operands())
    }
    if (repeat && [0xa4, 0xa5, 0xaa, 0xab].includes(opcode ?? -1)) {
      const suffix = opcode === 0xa4 || opcode === 0xaa ? 'b' : width === 64 ? 'q' : width === 16 ? 'w' : 'd'
      return complete(opcodeOffset + 1, `rep ${opcode! < 0xaa ? 'movs' : 'stos'}${suffix}`, () => '')
    }
    if (opcode === 0x88 || opcode === 0x89 || opcode === 0x8a || opcode === 0x8b) {
      const size = opcode === 0x88 || opcode === 0x8a ? 8 : width
      return complete(modrmEnd(opcodeOffset + 1), 'mov', () => {
        const destination = register(((bytes[opcodeOffset + 1]! >> 3) & 7) + ((rex & 4) << 1), size)
        const memory = memoryOperand(opcodeOffset + 1, size)
        return opcode === 0x8a || opcode === 0x8b ? `${destination}, ${memory}` : `${memory}, ${destination}`
      })
    }
    if ([0xd0, 0xd1, 0xd2, 0xd3, 0xc0, 0xc1].includes(opcode ?? -1)) {
      const operandEnd = modrmEnd(opcodeOffset + 1)
      if (operandEnd === null) return complete(null, '', () => '')
      const extension = (bytes[opcodeOffset + 1]! >> 3) & 7
      const mnemonic = ['rol', 'ror', undefined, undefined, 'shl', 'shr', undefined, 'sar'][extension]
      if (mnemonic !== undefined) {
        const immediate = opcode === 0xc0 || opcode === 0xc1
        return complete(operandEnd + (immediate ? 1 : 0), mnemonic, () =>
          `${memoryOperand(opcodeOffset + 1, opcode! % 2 === 0 ? 8 : width)}, ${immediate ? bytes[operandEnd] : opcode === 0xd2 || opcode === 0xd3 ? 'cl' : '1'}`)
      }
    }
    if (opcode === 0x0f && (bytes[opcodeOffset + 1] === 0xbc || bytes[opcodeOffset + 1] === 0xbd) && !repeat) {
      return complete(modrmEnd(opcodeOffset + 2), bytes[opcodeOffset + 1] === 0xbc ? 'bsf' : 'bsr', () =>
        `${register(((bytes[opcodeOffset + 2]! >> 3) & 7) + ((rex & 4) << 1))}, ${memoryOperand(opcodeOffset + 2)}`)
    }
    if ((opcode === 0xf6 || opcode === 0xf7) && bytes.length >= opcodeOffset + 2) {
      const modrm = bytes[opcodeOffset + 1]!
      const extension = (modrm >> 3) & 7
      if (extension === 6 || extension === 7) {
        const length = modrmEnd(opcodeOffset + 1)
        if (length === null) return { ...decoded(bytes.length, 'db', ''), isValid: false }
        return complete(length, extension === 6 ? 'div' : 'idiv', () => memoryOperand(opcodeOffset + 1, opcode === 0xf6 ? 8 : width))
      }
    }

    // 1-byte opcodes
    if (b0 === 0x90) {
      return {
        address: addr,
        bytes: bytes.subarray(0, 1),
        length: 1,
        mnemonic: 'nop',
        operands: '',
        arch: 'x86_64',
        isValid: true,
      }
    }

    if (b0 === 0xc3) {
      return {
        address: addr,
        bytes: bytes.subarray(0, 1),
        length: 1,
        mnemonic: 'ret',
        operands: '',
        arch: 'x86_64',
        isValid: true,
      }
    }

    if (b0 === 0xcc) {
      return {
        address: addr,
        bytes: bytes.subarray(0, 1),
        length: 1,
        mnemonic: 'int3',
        operands: '',
        arch: 'x86_64',
        isValid: true,
      }
    }

    if (b0 >= 0x50 && b0 <= 0x57) {
      const regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
      return {
        address: addr,
        bytes: bytes.subarray(0, 1),
        length: 1,
        mnemonic: 'push',
        operands: regs[b0 - 0x50]!,
        arch: 'x86_64',
        isValid: true,
      }
    }

    if (b0 >= 0x58 && b0 <= 0x5f) {
      const regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
      return {
        address: addr,
        bytes: bytes.subarray(0, 1),
        length: 1,
        mnemonic: 'pop',
        operands: regs[b0 - 0x58]!,
        arch: 'x86_64',
        isValid: true,
      }
    }

    // 2-byte opcodes
    if (b0 === 0x0f && bytes.length >= 2) {
      const b1 = bytes[1]!
      if (b1 === 0x05) {
        return {
          address: addr,
          bytes: bytes.subarray(0, 2),
          length: 2,
          mnemonic: 'syscall',
          operands: '',
          arch: 'x86_64',
          isValid: true,
        }
      }
      if (b1 === 0x0b) {
        return {
          address: addr,
          bytes: bytes.subarray(0, 2),
          length: 2,
          mnemonic: 'ud2',
          operands: '',
          arch: 'x86_64',
          isValid: true,
        }
      }
    }

    // Relative Jumps & Calls
    if (b0 === 0xeb && bytes.length >= 2) {
      // jmp rel8
      const rel = (bytes[1]! << 24) >> 24
      const target = addr + 2n + BigInt(rel)
      return {
        address: addr,
        bytes: bytes.subarray(0, 2),
        length: 2,
        mnemonic: 'jmp',
        operands: `0x${target.toString(16)}`,
        arch: 'x86_64',
        isValid: true,
      }
    }

    if (b0 === 0xe9 && bytes.length >= 5) {
      // jmp rel32
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
      const rel = view.getInt32(1, true)
      const target = addr + 5n + BigInt(rel)
      return {
        address: addr,
        bytes: bytes.subarray(0, 5),
        length: 5,
        mnemonic: 'jmp',
        operands: `0x${target.toString(16)}`,
        arch: 'x86_64',
        isValid: true,
      }
    }

    if (b0 === 0xe8 && bytes.length >= 5) {
      // call rel32
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
      const rel = view.getInt32(1, true)
      const target = addr + 5n + BigInt(rel)
      return {
        address: addr,
        bytes: bytes.subarray(0, 5),
        length: 5,
        mnemonic: 'call',
        operands: `0x${target.toString(16)}`,
        arch: 'x86_64',
        isValid: true,
      }
    }

    // REX.W (0x48) immediate arithmetic.
    if (b0 === 0x48 && bytes.length >= 3) {
      const b1 = bytes[1]!
      const b2 = bytes[2]!
      if (b1 === 0x83) {
        // add/sub/cmp r/m64, imm8
        const operandEnd = modrmEnd(2)
        const length = operandEnd === null ? bytes.length : Math.min(operandEnd + 1, bytes.length)
        return {
          address: addr,
          bytes: bytes.subarray(0, length),
          length,
          mnemonic: 'alu64',
          operands: operandEnd === null ? `modrm(0x${b2.toString(16)})` : `${memoryOperand(2)}, ${bytes[operandEnd] ?? '<truncated>'}`,
          arch: 'x86_64',
          isValid: operandEnd !== null && bytes.length > operandEnd,
        }
      }
    }

    // Undecodable / unknown fallback byte
    return {
      address: addr,
      bytes: bytes.subarray(0, 1),
      length: 1,
      mnemonic: 'db',
      operands: `0x${b0.toString(16).padStart(2, '0')}`,
      arch: 'x86_64',
      isValid: false,
    }
  }

  private static decodeAArch64(bytes: Uint8Array, addr: bigint): DecodedInstruction {
    if (bytes.length < 4) {
      return {
        address: addr,
        bytes: bytes.subarray(0, bytes.length),
        length: bytes.length,
        mnemonic: '.byte',
        operands: Array.from(bytes).map((b) => `0x${b.toString(16)}`).join(', '),
        arch: 'aarch64',
        isValid: false,
      }
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    const insn = view.getUint32(0, true) // AArch64 is little-endian 32-bit fixed

    const decoded = (mnemonic: string, operands: string): DecodedInstruction => ({
      address: addr, bytes: bytes.subarray(0, 4), length: 4,
      mnemonic, operands, arch: 'aarch64', isValid: true,
    })
    const target = (immediate: number, bits: number) => {
      const signed = (immediate << (32 - bits)) >> (32 - bits)
      return `0x${(addr + BigInt(signed) * 4n).toString(16)}`
    }
    if (((insn & 0xff000000) >>> 0) === 0x54000000 && (insn & 0x10) === 0) {
      const condition = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'][insn & 15]!
      return decoded(`b.${condition}`, target((insn >>> 5) & 0x7ffff, 19))
    }
    if (((insn & 0x7e000000) >>> 0) === 0x34000000) {
      const register = `${(insn >>> 31) === 1 ? 'x' : 'w'}${insn & 31}`
      return decoded((insn & 0x01000000) === 0 ? 'cbz' : 'cbnz', `${register}, ${target((insn >>> 5) & 0x7ffff, 19)}`)
    }
    if (((insn & 0x7e000000) >>> 0) === 0x36000000) {
      const bit = ((insn >>> 31) << 5) | ((insn >>> 19) & 31)
      return decoded((insn & 0x01000000) === 0 ? 'tbz' : 'tbnz', `${bit >= 32 ? 'x' : 'w'}${insn & 31}, #${bit}, ${target((insn >>> 5) & 0x3fff, 14)}`)
    }
    const divisionOpcode = (insn & 0x7fe0fc00) >>> 0
    if (divisionOpcode === 0x1ac00800 || divisionOpcode === 0x1ac00c00) {
      const prefix = (insn >>> 31) === 1 ? 'x' : 'w'
      return decoded(divisionOpcode === 0x1ac00800 ? 'udiv' : 'sdiv', `${prefix}${insn & 31}, ${prefix}${(insn >>> 5) & 31}, ${prefix}${(insn >>> 16) & 31}`)
    }
    if ([0x1ac02000, 0x1ac02400, 0x1ac02800, 0x1ac02c00].includes(divisionOpcode)) {
      const prefix = (insn >>> 31) === 1 ? 'x' : 'w'
      const mnemonic = ['lslv', 'lsrv', 'asrv', 'rorv'][(divisionOpcode - 0x1ac02000) >>> 10]!
      return decoded(mnemonic, `${prefix}${insn & 31}, ${prefix}${(insn >>> 5) & 31}, ${prefix}${(insn >>> 16) & 31}`)
    }
    // Integer register-offset loads/stores; reject reserved extend/opcode combinations.
    if (((insn & 0x3f200c00) >>> 0) === 0x38200800) {
      const size = insn >>> 30
      const operation = (insn >>> 22) & 3
      const option = (insn >>> 13) & 7
      if ([2, 3, 6, 7].includes(option) && operation <= 1) {
        const register = (index: number, prefix: string) => index === 31 ? `${prefix}zr` : `${prefix}${index}`
        const base = (insn >>> 5) & 31
        const index = register((insn >>> 16) & 31, option === 2 || option === 6 ? 'w' : 'x')
        const shift = (insn & 0x1000) !== 0 ? size : 0
        const extension = option === 3 ? (shift ? `, lsl #${shift}` : '') : `, ${option === 2 ? 'uxtw' : option === 6 ? 'sxtw' : 'sxtx'}${shift ? ` #${shift}` : ''}`
        const mnemonic = `${operation === 1 ? 'ldr' : 'str'}${size === 0 ? 'b' : size === 1 ? 'h' : ''}`
        return decoded(mnemonic, `${register(insn & 31, size === 3 ? 'x' : 'w')}, [${base === 31 ? 'sp' : `x${base}`}, ${index}${extension}]`)
      }
    }

    // NOP: 0xd503201f
    if (insn === 0xd503201f) {
      return {
        address: addr,
        bytes: bytes.subarray(0, 4),
        length: 4,
        mnemonic: 'nop',
        operands: '',
        arch: 'aarch64',
        isValid: true,
      }
    }

    // RET: 0xd65f03c0 (ret x30)
    if (insn === 0xd65f03c0) {
      return {
        address: addr,
        bytes: bytes.subarray(0, 4),
        length: 4,
        mnemonic: 'ret',
        operands: '',
        arch: 'aarch64',
        isValid: true,
      }
    }

    // SVC #imm: 0xd4000001 (svc 0)
    if (((insn & 0xffe0001f) >>> 0) === 0xd4000001) {
      const imm = (insn >> 5) & 0xffff
      return {
        address: addr,
        bytes: bytes.subarray(0, 4),
        length: 4,
        mnemonic: 'svc',
        operands: `#0x${imm.toString(16)}`,
        arch: 'aarch64',
        isValid: true,
      }
    }

    // B imm26: op 000101...
    if (((insn & 0xfc000000) >>> 0) === 0x14000000) {
      let imm26 = insn & 0x03ffffff
      if ((imm26 & 0x02000000) !== 0) {
        imm26 |= ~0x03ffffff // sign extend
      }
      const target = addr + BigInt(imm26 * 4)
      return {
        address: addr,
        bytes: bytes.subarray(0, 4),
        length: 4,
        mnemonic: 'b',
        operands: `0x${target.toString(16)}`,
        arch: 'aarch64',
        isValid: true,
      }
    }

    // BL imm26: op 100101...
    if (((insn & 0xfc000000) >>> 0) === 0x94000000) {
      let imm26 = insn & 0x03ffffff
      if ((imm26 & 0x02000000) !== 0) {
        imm26 |= ~0x03ffffff // sign extend
      }
      const target = addr + BigInt(imm26 * 4)
      return {
        address: addr,
        bytes: bytes.subarray(0, 4),
        length: 4,
        mnemonic: 'bl',
        operands: `0x${target.toString(16)}`,
        arch: 'aarch64',
        isValid: true,
      }
    }

    // Default 32-bit word fallback
    return {
      address: addr,
      bytes: bytes.subarray(0, 4),
      length: 4,
      mnemonic: '.inst',
      operands: `0x${insn.toString(16).padStart(8, '0')}`,
      arch: 'aarch64',
      isValid: false,
    }
  }
}
