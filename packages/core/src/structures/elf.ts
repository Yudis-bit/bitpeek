import type { StructureField, StructureParseResult } from './types'
import { formatHex } from '../bytes'

const ELF_SPEC_URL = 'https://gabi.xinuos.com/elf/02-eheader.html'

function formatHexSlice(bytes: Uint8Array, start: number, end: number): string {
  return formatHex(bytes.slice(start, Math.min(bytes.length, end)))
}

const ELF_TYPES: Record<number, string> = {
  0: 'ET_NONE (No file type)',
  1: 'ET_REL (Relocatable object)',
  2: 'ET_EXEC (Executable file)',
  3: 'ET_DYN (Shared object / Dynamic library)',
  4: 'ET_CORE (Core file)',
}

const ELF_MACHINES: Record<number, string> = {
  0: 'EM_NONE',
  2: 'EM_SPARC',
  3: 'EM_386 (Intel 80386 / x86)',
  8: 'EM_MIPS',
  18: 'EM_SPARC32PLUS',
  20: 'EM_PPC (PowerPC)',
  21: 'EM_PPC64',
  40: 'EM_ARM',
  50: 'EM_IA_64 (Itanium)',
  62: 'EM_X86_64 (AMD x86-64)',
  183: 'EM_AARCH64 (ARM 64-bit)',
  243: 'EM_RISCV (RISC-V)',
}

const SH_TYPES: Record<number, string> = {
  0: 'SHT_NULL',
  1: 'SHT_PROGBITS',
  2: 'SHT_SYMTAB',
  3: 'SHT_STRTAB',
  4: 'SHT_RELA',
  5: 'SHT_HASH',
  6: 'SHT_DYNAMIC',
  7: 'SHT_NOTE',
  8: 'SHT_NOBITS',
  9: 'SHT_REL',
  10: 'SHT_SHLIB',
  11: 'SHT_DYNSYM',
}

const PH_TYPES: Record<number, string> = {
  0: 'PT_NULL',
  1: 'PT_LOAD',
  2: 'PT_DYNAMIC',
  3: 'PT_INTERP',
  4: 'PT_NOTE',
  5: 'PT_SHLIB',
  6: 'PT_PHDR',
  7: 'PT_TLS',
}

export function parseElf(bytes: Uint8Array): StructureParseResult {
  const fields: StructureField[] = []
  const warnings: string[] = []
  let status: 'valid' | 'partial' | 'invalid' = 'valid'

  if (bytes.length < 16) {
    fields.push({
      id: 'elf.ident',
      label: 'ELF Identification (e_ident)',
      range: { start: 0, end: bytes.length },
      rawHex: formatHexSlice(bytes, 0, bytes.length),
      interpretedValue: 'Truncated e_ident',
      type: 'bytes[16]',
      status: 'truncated',
      reason: `Expected 16-byte e_ident header, only ${bytes.length} bytes available.`,
      specLink: ELF_SPEC_URL,
    })
    return {
      format: 'elf',
      status: 'invalid',
      fields,
      warnings: ['File is smaller than the 16-byte ELF identification.'],
      totalBytesParsed: bytes.length,
    }
  }

  // Check magic 0x7F 'E' 'L' 'F'
  const magicMatches =
    bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46

  const identChildren: StructureField[] = [
    {
      id: 'elf.ident.magic',
      label: 'Magic Number',
      range: { start: 0, end: 4 },
      rawHex: formatHexSlice(bytes, 0, 4),
      interpretedValue: magicMatches ? '0x7F "ELF"' : 'Invalid ELF magic',
      type: 'bytes[4]',
      status: magicMatches ? 'valid' : 'inconsistent',
      reason: magicMatches ? undefined : 'Bytes 0..3 do not match \\x7fELF magic.',
      specLink: ELF_SPEC_URL,
    },
  ]

  if (!magicMatches) {
    fields.push({
      id: 'elf.ident',
      label: 'ELF Identification (e_ident)',
      range: { start: 0, end: 16 },
      rawHex: formatHexSlice(bytes, 0, 16),
      interpretedValue: 'Invalid ELF magic bytes',
      type: 'bytes[16]',
      status: 'inconsistent',
      children: identChildren,
      specLink: ELF_SPEC_URL,
    })
    return {
      format: 'elf',
      status: 'invalid',
      fields,
      warnings: ['Leading bytes do not match ELF magic (0x7F "ELF").'],
      totalBytesParsed: 16,
    }
  }

  const eiClass = bytes[4] ?? 0
  const is64Bit = eiClass === 2
  const classValid = eiClass === 1 || eiClass === 2
  identChildren.push({
    id: 'elf.ident.class',
    label: 'Class (EI_CLASS)',
    range: { start: 4, end: 5 },
    rawHex: formatHexSlice(bytes, 4, 5),
    interpretedValue: eiClass === 1 ? 'ELF32 (32-bit)' : eiClass === 2 ? 'ELF64 (64-bit)' : `Invalid class (${eiClass})`,
    type: 'u8',
    status: classValid ? 'valid' : 'inconsistent',
    specLink: ELF_SPEC_URL,
  })

  const eiData = bytes[5] ?? 0
  const isLittleEndian = eiData === 1
  const dataValid = eiData === 1 || eiData === 2
  identChildren.push({
    id: 'elf.ident.data',
    label: 'Data Encoding (EI_DATA)',
    range: { start: 5, end: 6 },
    rawHex: formatHexSlice(bytes, 5, 6),
    interpretedValue: eiData === 1 ? '2\'s complement, Little-Endian' : eiData === 2 ? '2\'s complement, Big-Endian' : `Invalid data encoding (${eiData})`,
    type: 'u8',
    status: dataValid ? 'valid' : 'inconsistent',
    specLink: ELF_SPEC_URL,
  })

  const eiVersion = bytes[6] ?? 0
  identChildren.push({
    id: 'elf.ident.version',
    label: 'Version (EI_VERSION)',
    range: { start: 6, end: 7 },
    rawHex: formatHexSlice(bytes, 6, 7),
    interpretedValue: eiVersion === 1 ? '1 (Current)' : `Version ${eiVersion}`,
    type: 'u8',
    status: eiVersion === 1 ? 'valid' : 'inconsistent',
    specLink: ELF_SPEC_URL,
  })

  const eiOsabi = bytes[7] ?? 0
  identChildren.push({
    id: 'elf.ident.osabi',
    label: 'OS/ABI (EI_OSABI)',
    range: { start: 7, end: 8 },
    rawHex: formatHexSlice(bytes, 7, 8),
    interpretedValue: eiOsabi === 0 ? 'System V' : eiOsabi === 3 ? 'Linux' : `ABI ${eiOsabi}`,
    type: 'u8',
    status: 'valid',
    specLink: ELF_SPEC_URL,
  })

  const eiAbiVer = bytes[8] ?? 0
  identChildren.push({
    id: 'elf.ident.abiversion',
    label: 'ABI Version (EI_ABIVERSION)',
    range: { start: 8, end: 9 },
    rawHex: formatHexSlice(bytes, 8, 9),
    interpretedValue: String(eiAbiVer),
    type: 'u8',
    status: 'valid',
    specLink: ELF_SPEC_URL,
  })

  identChildren.push({
    id: 'elf.ident.pad',
    label: 'Padding (EI_PAD)',
    range: { start: 9, end: 16 },
    rawHex: formatHexSlice(bytes, 9, 16),
    interpretedValue: 'Reserved padding',
    type: 'bytes[7]',
    status: 'valid',
    specLink: ELF_SPEC_URL,
  })

  fields.push({
    id: 'elf.ident',
    label: 'ELF Identification (e_ident)',
    range: { start: 0, end: 16 },
    rawHex: formatHexSlice(bytes, 0, 16),
    interpretedValue: `${is64Bit ? 'ELF64' : 'ELF32'}, ${isLittleEndian ? 'Little-Endian' : 'Big-Endian'}`,
    type: 'bytes[16]',
    status: classValid && dataValid ? 'valid' : 'inconsistent',
    children: identChildren,
    specLink: ELF_SPEC_URL,
  })

  if (!classValid || !dataValid) {
    return {
      format: 'elf',
      status: 'invalid',
      fields,
      warnings: ['Invalid ELF class or data endianness.'],
      totalBytesParsed: 16,
    }
  }

  const endian = isLittleEndian ? 'little' : 'big'
  const ehdrSize = is64Bit ? 64 : 52

  if (bytes.length < ehdrSize) {
    fields.push({
      id: 'elf.header.truncated',
      label: 'ELF Header (Truncated)',
      range: { start: 16, end: bytes.length },
      rawHex: formatHexSlice(bytes, 16, bytes.length),
      interpretedValue: `Expected ${ehdrSize} bytes, got ${bytes.length}`,
      type: 'ehdr',
      status: 'truncated',
      reason: `File ended before completing ${ehdrSize}-byte ELF header.`,
      specLink: ELF_SPEC_URL,
    })
    return {
      format: 'elf',
      status: 'partial',
      fields,
      warnings: [`ELF header truncated (needed ${ehdrSize} bytes, file has ${bytes.length}).`],
      totalBytesParsed: bytes.length,
    }
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const le = isLittleEndian

  let cursor = 16
  const eType = view.getUint16(cursor, le); cursor += 2
  const eMachine = view.getUint16(cursor, le); cursor += 2
  const eVersion = view.getUint32(cursor, le); cursor += 4

  let eEntry: bigint
  let ePhoff: bigint
  let eShoff: bigint

  if (is64Bit) {
    eEntry = view.getBigUint64(cursor, le); cursor += 8
    ePhoff = view.getBigUint64(cursor, le); cursor += 8
    eShoff = view.getBigUint64(cursor, le); cursor += 8
  } else {
    eEntry = BigInt(view.getUint32(cursor, le)); cursor += 4
    ePhoff = BigInt(view.getUint32(cursor, le)); cursor += 4
    eShoff = BigInt(view.getUint32(cursor, le)); cursor += 4
  }

  const eFlags = view.getUint32(cursor, le); cursor += 4
  const eEhsize = view.getUint16(cursor, le); cursor += 2
  const ePhentsize = view.getUint16(cursor, le); cursor += 2
  const ePhnum = view.getUint16(cursor, le); cursor += 2
  const eShentsize = view.getUint16(cursor, le); cursor += 2
  const eShnum = view.getUint16(cursor, le); cursor += 2
  const eShstrndx = view.getUint16(cursor, le)

  const headerChildren: StructureField[] = [
    {
      id: 'elf.header.type',
      label: 'Object File Type (e_type)',
      range: { start: 16, end: 18 },
      rawHex: formatHexSlice(bytes, 16, 18),
      interpretedValue: ELF_TYPES[eType] ?? `Unknown (0x${eType.toString(16)})`,
      type: 'u16',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.machine',
      label: 'Target Architecture (e_machine)',
      range: { start: 18, end: 20 },
      rawHex: formatHexSlice(bytes, 18, 20),
      interpretedValue: ELF_MACHINES[eMachine] ?? `Architecture ${eMachine}`,
      type: 'u16',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.version',
      label: 'Version (e_version)',
      range: { start: 20, end: 24 },
      rawHex: formatHexSlice(bytes, 20, 24),
      interpretedValue: eVersion,
      type: 'u32',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.entry',
      label: 'Entry Point (e_entry)',
      range: { start: 24, end: is64Bit ? 32 : 28 },
      rawHex: formatHexSlice(bytes, 24, is64Bit ? 32 : 28),
      interpretedValue: `0x${eEntry.toString(16)}`,
      type: is64Bit ? 'u64' : 'u32',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.phoff',
      label: 'Program Header Table Offset (e_phoff)',
      range: { start: is64Bit ? 32 : 28, end: is64Bit ? 40 : 32 },
      rawHex: formatHexSlice(bytes, is64Bit ? 32 : 28, is64Bit ? 40 : 32),
      interpretedValue: `0x${ePhoff.toString(16)} (${ePhoff.toString(10)})`,
      type: is64Bit ? 'u64' : 'u32',
      endian,
      status: Number(ePhoff) <= bytes.length ? 'valid' : 'inconsistent',
      reason: Number(ePhoff) > bytes.length ? 'Program header offset exceeds file bounds.' : undefined,
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.shoff',
      label: 'Section Header Table Offset (e_shoff)',
      range: { start: is64Bit ? 40 : 32, end: is64Bit ? 48 : 36 },
      rawHex: formatHexSlice(bytes, is64Bit ? 40 : 32, is64Bit ? 48 : 36),
      interpretedValue: `0x${eShoff.toString(16)} (${eShoff.toString(10)})`,
      type: is64Bit ? 'u64' : 'u32',
      endian,
      status: Number(eShoff) <= bytes.length ? 'valid' : 'inconsistent',
      reason: Number(eShoff) > bytes.length ? 'Section header offset exceeds file bounds.' : undefined,
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.flags',
      label: 'Processor Flags (e_flags)',
      range: { start: is64Bit ? 48 : 36, end: is64Bit ? 52 : 40 },
      rawHex: formatHexSlice(bytes, is64Bit ? 48 : 36, is64Bit ? 52 : 40),
      interpretedValue: `0x${eFlags.toString(16).padStart(8, '0')}`,
      type: 'u32',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.ehsize',
      label: 'ELF Header Size (e_ehsize)',
      range: { start: is64Bit ? 52 : 40, end: is64Bit ? 54 : 42 },
      rawHex: formatHexSlice(bytes, is64Bit ? 52 : 40, is64Bit ? 54 : 42),
      interpretedValue: `${eEhsize} bytes`,
      type: 'u16',
      endian,
      status: eEhsize === ehdrSize ? 'valid' : 'inconsistent',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.phentsize',
      label: 'Program Header Entry Size (e_phentsize)',
      range: { start: is64Bit ? 54 : 42, end: is64Bit ? 56 : 44 },
      rawHex: formatHexSlice(bytes, is64Bit ? 54 : 42, is64Bit ? 56 : 44),
      interpretedValue: `${ePhentsize} bytes`,
      type: 'u16',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.phnum',
      label: 'Program Header Count (e_phnum)',
      range: { start: is64Bit ? 56 : 44, end: is64Bit ? 58 : 46 },
      rawHex: formatHexSlice(bytes, is64Bit ? 56 : 44, is64Bit ? 58 : 46),
      interpretedValue: ePhnum,
      type: 'u16',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.shentsize',
      label: 'Section Header Entry Size (e_shentsize)',
      range: { start: is64Bit ? 58 : 46, end: is64Bit ? 60 : 48 },
      rawHex: formatHexSlice(bytes, is64Bit ? 58 : 46, is64Bit ? 60 : 48),
      interpretedValue: `${eShentsize} bytes`,
      type: 'u16',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.shnum',
      label: 'Section Header Count (e_shnum)',
      range: { start: is64Bit ? 60 : 48, end: is64Bit ? 62 : 50 },
      rawHex: formatHexSlice(bytes, is64Bit ? 60 : 48, is64Bit ? 62 : 50),
      interpretedValue: eShnum,
      type: 'u16',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
    {
      id: 'elf.header.shstrndx',
      label: 'Section String Table Index (e_shstrndx)',
      range: { start: is64Bit ? 62 : 50, end: is64Bit ? 64 : 52 },
      rawHex: formatHexSlice(bytes, is64Bit ? 62 : 50, is64Bit ? 64 : 52),
      interpretedValue: eShstrndx,
      type: 'u16',
      endian,
      status: 'valid',
      specLink: ELF_SPEC_URL,
    },
  ]

  fields.push({
    id: 'elf.header',
    label: 'ELF Header',
    range: { start: 16, end: ehdrSize },
    rawHex: formatHexSlice(bytes, 16, ehdrSize),
    interpretedValue: `${ELF_TYPES[eType] ?? 'ELF'}, ${ELF_MACHINES[eMachine] ?? 'Arch ' + eMachine}`,
    type: 'ehdr',
    status: 'valid',
    children: headerChildren,
    specLink: ELF_SPEC_URL,
  })

  // Parse Section Headers (to get shstrtab for naming)
  const shoffNum = Number(eShoff)
  let shstrtabBytes: Uint8Array | null = null

  if (eShnum > 0 && eShoff > 0n && shoffNum < bytes.length) {
    const shent = eShentsize > 0 ? eShentsize : is64Bit ? 64 : 40
    // First, locate shstrtab if valid
    if (eShstrndx < eShnum) {
      const shstrEntryOffset = shoffNum + eShstrndx * shent
      if (shstrEntryOffset + shent <= bytes.length) {
        let strOff: bigint
        let strSize: bigint
        if (is64Bit) {
          strOff = view.getBigUint64(shstrEntryOffset + 24, le)
          strSize = view.getBigUint64(shstrEntryOffset + 32, le)
        } else {
          strOff = BigInt(view.getUint32(shstrEntryOffset + 16, le))
          strSize = BigInt(view.getUint32(shstrEntryOffset + 20, le))
        }
        const sOff = Number(strOff)
        const sSize = Number(strSize)
        if (sOff + sSize <= bytes.length && sSize < 10 * 1024 * 1024) {
          shstrtabBytes = bytes.slice(sOff, sOff + sSize)
        }
      }
    }

    const sectionEntries: StructureField[] = []
    const count = Math.min(eShnum, 1_000)

    for (let i = 0; i < count; i++) {
      const entryOff = shoffNum + i * shent
      if (entryOff + shent > bytes.length) {
        status = 'partial'
        warnings.push(`Section header table truncated at entry ${i}.`)
        break
      }

      const shNameOff = view.getUint32(entryOff, le)
      const shType = view.getUint32(entryOff + 4, le)
      let shOffset: bigint
      let shSize: bigint

      if (is64Bit) {
        shOffset = view.getBigUint64(entryOff + 24, le)
        shSize = view.getBigUint64(entryOff + 32, le)
      } else {
        shOffset = BigInt(view.getUint32(entryOff + 16, le))
        shSize = BigInt(view.getUint32(entryOff + 20, le))
      }

      let sectionName = `[${i}]`
      if (shstrtabBytes && shNameOff < shstrtabBytes.length) {
        let end = shNameOff
        while (end < shstrtabBytes.length && shstrtabBytes[end] !== 0) end++
        sectionName = new TextDecoder('utf-8').decode(shstrtabBytes.subarray(shNameOff, end)) || `[${i}]`
      }

      sectionEntries.push({
        id: `elf.sh[${i}]`,
        label: `Section ${sectionName}`,
        range: { start: entryOff, end: entryOff + shent },
        rawHex: formatHexSlice(bytes, entryOff, Math.min(bytes.length, entryOff + 8)),
        interpretedValue: `${SH_TYPES[shType] ?? 'Type ' + shType}, offset 0x${shOffset.toString(16)}, size ${shSize.toString(10)} B`,
        type: 'elf_shdr',
        endian,
        status: Number(shOffset) + Number(shSize) <= bytes.length ? 'valid' : 'inconsistent',
        children: [
          {
            id: `elf.sh[${i}].name`,
            label: 'sh_name',
            range: { start: entryOff, end: entryOff + 4 },
            rawHex: formatHexSlice(bytes, entryOff, entryOff + 4),
            interpretedValue: `"${sectionName}" (string table offset ${shNameOff})`,
            type: 'u32',
            endian,
            status: 'valid',
          },
          {
            id: `elf.sh[${i}].type`,
            label: 'sh_type',
            range: { start: entryOff + 4, end: entryOff + 8 },
            rawHex: formatHexSlice(bytes, entryOff + 4, entryOff + 8),
            interpretedValue: SH_TYPES[shType] ?? `0x${shType.toString(16)}`,
            type: 'u32',
            endian,
            status: 'valid',
          },
        ],
      })
    }

    fields.push({
      id: 'elf.sh_table',
      label: 'Section Header Table',
      range: { start: shoffNum, end: Math.min(bytes.length, shoffNum + eShnum * shent) },
      rawHex: formatHexSlice(bytes, shoffNum, Math.min(bytes.length, shoffNum + 16)),
      interpretedValue: `${eShnum} section headers`,
      type: 'table',
      status: 'valid',
      children: sectionEntries,
    })
  }

  // Parse Program Headers if present
  const phoffNum = Number(ePhoff)
  if (ePhnum > 0 && ePhoff > 0n && phoffNum < bytes.length) {
    const phent = ePhentsize > 0 ? ePhentsize : is64Bit ? 56 : 32
    const programEntries: StructureField[] = []
    const count = Math.min(ePhnum, 500)

    for (let i = 0; i < count; i++) {
      const entryOff = phoffNum + i * phent
      if (entryOff + phent > bytes.length) {
        status = 'partial'
        warnings.push(`Program header table truncated at entry ${i}.`)
        break
      }

      const pType = view.getUint32(entryOff, le)
      let pOffset: bigint
      let pFilesz: bigint

      if (is64Bit) {
        pOffset = view.getBigUint64(entryOff + 8, le)
        pFilesz = view.getBigUint64(entryOff + 32, le)
      } else {
        pOffset = BigInt(view.getUint32(entryOff + 4, le))
        pFilesz = BigInt(view.getUint32(entryOff + 16, le))
      }

      programEntries.push({
        id: `elf.ph[${i}]`,
        label: `Program Header #${i} (${PH_TYPES[pType] ?? 'Type ' + pType})`,
        range: { start: entryOff, end: entryOff + phent },
        rawHex: formatHexSlice(bytes, entryOff, Math.min(bytes.length, entryOff + 8)),
        interpretedValue: `${PH_TYPES[pType] ?? 'Type ' + pType}, offset 0x${pOffset.toString(16)}, filesz ${pFilesz.toString(10)} B`,
        type: 'elf_phdr',
        endian,
        status: Number(pOffset) + Number(pFilesz) <= bytes.length ? 'valid' : 'inconsistent',
      })
    }

    fields.push({
      id: 'elf.ph_table',
      label: 'Program Header Table',
      range: { start: phoffNum, end: Math.min(bytes.length, phoffNum + ePhnum * phent) },
      rawHex: formatHexSlice(bytes, phoffNum, Math.min(bytes.length, phoffNum + 16)),
      interpretedValue: `${ePhnum} program headers`,
      type: 'table',
      status: 'valid',
      children: programEntries,
    })
  }

  return {
    format: 'elf',
    status,
    fields,
    warnings,
    totalBytesParsed: bytes.length,
  }
}
