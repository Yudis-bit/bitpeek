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

    // REX.W (0x48) common 64-bit prefixes
    if (b0 === 0x48 && bytes.length >= 3) {
      const b1 = bytes[1]!
      const b2 = bytes[2]!
      if (b1 === 0x89) {
        // mov r/m64, r64
        return {
          address: addr,
          bytes: bytes.subarray(0, 3),
          length: 3,
          mnemonic: 'mov',
          operands: `modrm(0x${b2.toString(16)})`,
          arch: 'x86_64',
          isValid: true,
        }
      }
      if (b1 === 0x83) {
        // add/sub/cmp r/m64, imm8
        return {
          address: addr,
          bytes: bytes.subarray(0, Math.min(4, bytes.length)),
          length: Math.min(4, bytes.length),
          mnemonic: 'alu64',
          operands: `modrm(0x${b2.toString(16)})`,
          arch: 'x86_64',
          isValid: bytes.length >= 4,
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
