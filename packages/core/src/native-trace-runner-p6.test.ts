import { describe, it, expect } from 'vitest'
import {
  NativeAddressSpace,
  ReferenceDisassembler,
  MemoryDumpWorkbench,
} from './native'
import {
  IndexedTraceStore,
  GdbMiParser,
  QemuConfigBuilder,
  SanitizerLogParser,
} from './trace'
import {
  DeterministicMutator,
  OracleMatcher,
  DeltaDebuggingReducer,
  DifferentialComparator,
} from './runner'

describe('Phase P6 - Native Code, Traces, and Experiment Runner', () => {
  describe('Native Address Space Mapping (NATIVE-01, AC051)', () => {
    it('translates virtual addresses to file offsets and handles zero-fill BSS ranges', () => {
      const space = new NativeAddressSpace(64, 'little')
      // Register module "libc.so" loaded at 0x7fff0000 with ASLR slide 0x10000
      space.registerModule({
        moduleId: 'libc.so',
        name: 'libc.so.6',
        preferredBase: 0x7ffe0000n,
        actualBase: 0x7fff0000n,
        aslrSlide: 0x10000n,
        ranges: [
          // .text: file-backed at file offset 0x1000, size 0x2000
          {
            start: 0x7fff1000n,
            size: 0x2000n,
            permissions: 'rx',
            kind: 'file-backed',
            fileOffset: 0x1000,
            name: '.text',
          },
          // .bss: zero-fill at 0x7fff5000, size 0x1000
          {
            start: 0x7fff5000n,
            size: 0x1000n,
            permissions: 'rw',
            kind: 'zero-fill',
            name: '.bss',
          },
        ],
      })

      // Translate address inside .text: 0x7fff1500 -> file offset 0x1500
      const resText = space.translateVirtualAddress(0x7fff1500n)
      expect(resText.status).toBe('file-backed')
      expect(resText.fileOffset).toBe(0x1500)
      expect(resText.module?.name).toBe('libc.so.6')

      // Translate address inside .bss: 0x7fff5200 -> zero-fill
      const resBss = space.translateVirtualAddress(0x7fff5200n)
      expect(resBss.status).toBe('zero-fill')
      expect(resBss.fileOffset).toBeUndefined()

      // Translate unmapped address: 0x1000 -> unmapped
      const resUnmapped = space.translateVirtualAddress(0x1000n)
      expect(resUnmapped.status).toBe('unmapped')

      // Reverse translation: file offset 0x1500 in libc.so -> 0x7fff1500
      const va = space.fileOffsetToVirtualAddress('libc.so', 0x1500)
      expect(va).toBe(0x7fff1500n)
    })
  })

  describe('Instruction Disassembly (NATIVE-02, AC052)', () => {
    it('disassembles x86-64 instructions and preserves undecodable bytes', () => {
      // Byte stream:
      // 0x90 (nop)
      // 0x50 (push rax)
      // 0x58 (pop rax)
      // 0x0f, 0x05 (syscall)
      // 0xc3 (ret)
      // 0xff (undecodable/fallback)
      const code = new Uint8Array([0x90, 0x50, 0x58, 0x0f, 0x05, 0xc3, 0xff])
      const insts = ReferenceDisassembler.disassemble(code, {
        arch: 'x86_64',
        baseAddress: 0x400000n,
      })

      expect(insts.length).toBe(6)
      expect(insts[0]!.mnemonic).toBe('nop')
      expect(insts[0]!.address).toBe(0x400000n)
      expect(insts[1]!.mnemonic).toBe('push')
      expect(insts[1]!.operands).toBe('rax')
      expect(insts[2]!.mnemonic).toBe('pop')
      expect(insts[3]!.mnemonic).toBe('syscall')
      expect(insts[4]!.mnemonic).toBe('ret')
      expect(insts[5]!.isValid).toBe(false)
      expect(insts[5]!.mnemonic).toBe('db')
    })

    it('disassembles AArch64 fixed 32-bit instructions', () => {
      // 0xd503201f (nop)
      // 0xd65f03c0 (ret)
      // 0xd4000001 (svc 0)
      const code = new Uint8Array([
        0x1f, 0x20, 0x03, 0xd5, // nop
        0xc0, 0x03, 0x5f, 0xd6, // ret
        0x01, 0x00, 0x00, 0xd4, // svc 0
      ])

      const insts = ReferenceDisassembler.disassemble(code, {
        arch: 'aarch64',
        baseAddress: 0x1000n,
      })

      expect(insts.length).toBe(3)
      expect(insts[0]!.mnemonic).toBe('nop')
      expect(insts[1]!.mnemonic).toBe('ret')
      expect(insts[2]!.mnemonic).toBe('svc')
    })
  })

  describe('Memory Dump Workbench & Pointer Scanning (NATIVE-04, AC053)', () => {
    it('scans candidate pointers pointing into allowed heap/stack target ranges', () => {
      // Create a 32-byte region buffer containing two 64-bit pointers and random data
      const buf = new Uint8Array(32)
      const view = new DataView(buf.buffer)

      // Pointer 1 at offset 0: 0x7fff1000 (valid target)
      view.setBigUint64(0, 0x7fff1000n, true)
      // Offset 8: non-pointer integer 42
      view.setBigUint64(8, 42n, true)
      // Pointer 2 at offset 16: 0x7fff2500 (valid target)
      view.setBigUint64(16, 0x7fff2500n, true)
      // Offset 24: 0x00000000
      view.setBigUint64(24, 0n, true)

      const candidates = MemoryDumpWorkbench.scanCandidatePointers(buf, 0x100000n, {
        pointerWidthBytes: 8,
        endian: 'little',
        alignmentBytes: 8,
        validTargetRanges: [{ start: 0x7fff0000n, end: 0x7fff8000n }],
      })

      expect(candidates.length).toBe(2)
      expect(candidates[0]!.sourceAddress).toBe(0x100000n)
      expect(candidates[0]!.targetAddress).toBe(0x7fff1000n)
      expect(candidates[1]!.sourceAddress).toBe(0x100010n)
      expect(candidates[1]!.targetAddress).toBe(0x7fff2500n)
    })
  })

  describe('Indexed Trace Store (TRACE-01, AC054)', () => {
    it('ingests trace events and queries by time window and kind with pagination', () => {
      const store = new IndexedTraceStore()

      store.appendEvent({
        eventId: 'ev1',
        timestampTicks: 100,
        threadId: 1,
        kind: 'instruction',
        address: 0x401000n,
      })

      store.appendEvent({
        eventId: 'ev2',
        timestampTicks: 150,
        threadId: 1,
        kind: 'memory-read',
        address: 0x7fff0010n,
        size: 4,
      })

      store.appendEvent({
        eventId: 'ev3',
        timestampTicks: 200,
        threadId: 2,
        kind: 'instruction',
        address: 0x401004n,
      })

      expect(store.getEventCount()).toBe(3)

      // Query by kind = 'instruction'
      const instQuery = store.query({ kinds: ['instruction'] })
      expect(instQuery.totalMatches).toBe(2)
      expect(instQuery.events.map((e) => e.eventId)).toEqual(['ev1', 'ev3'])

      // Query by time window [120..250]
      const timeQuery = store.query({ timeWindow: { startTicks: 120, endTicks: 250 } })
      expect(timeQuery.totalMatches).toBe(2)
      expect(timeQuery.events.map((e) => e.eventId)).toEqual(['ev2', 'ev3'])
    })
  })

  describe('GDB/MI & QEMU Config (TRACE-04, TRACE-05, AC057)', () => {
    it('parses GDB/MI output and enforces command allowlist', () => {
      const line1 = '101^done,value="42"'
      const rec1 = GdbMiParser.parseLine(line1)
      expect(rec1.token).toBe(101)
      expect(rec1.type).toBe('result')
      expect(rec1.class).toBe('done')

      const line2 = '*stopped,reason="breakpoint-hit"'
      const rec2 = GdbMiParser.parseLine(line2)
      expect(rec2.type).toBe('exec_async')
      expect(rec2.class).toBe('stopped')

      // Allowlist checks
      expect(GdbMiParser.classifyCommand('-data-read-memory 0x1000')).toBe('read_only')
      expect(GdbMiParser.classifyCommand('-exec-continue')).toBe('state_modifying')
      expect(GdbMiParser.classifyCommand('!rm -rf /')).toBe('forbidden')
    })

    it('generates safe QEMU launch arguments with isolated local GDB port', () => {
      const argv = QemuConfigBuilder.buildArgv({
        arch: 'x86_64',
        machine: 'q35',
        cpu: 'qemu64',
        memoryMb: 1024,
        gdbPort: 1234,
        freezeAtStartup: true,
      })

      expect(argv[0]).toBe('qemu-system-x86_64')
      expect(argv).toContain('-M')
      expect(argv).toContain('q35')
      expect(argv).toContain('-gdb')
      expect(argv).toContain('tcp:127.0.0.1:1234') // local only!
      expect(argv).toContain('-S') // freeze at startup
    })
  })

  describe('ASan & UBSan Diagnostic Parsers (TRACE-03, AC054, AC055, AC056)', () => {
    it('parses real ASan use-after-free crash log with allocation and free stacks', () => {
      const asanLog = `
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x000000401234 bp 0x7fff00 sp 0x7fff08
READ of size 4 at 0x602000000010 thread T0
    #0 0x401234 in main test.c:25
    #1 0x7fff1234 in __libc_start_main libc.so:100
freed by thread T0 here:
    #0 0x402000 in free asan_interceptors.cc:40
    #1 0x401200 in cleanup test.c:18
previously allocated by thread T0 here:
    #0 0x403000 in malloc asan_interceptors.cc:50
    #1 0x401180 in setup test.c:10
`
      const diag = SanitizerLogParser.parseAsan(asanLog)
      expect(diag).not.toBeNull()
      expect(diag!.errorType).toBe('heap-use-after-free')
      expect(diag!.faultAddress).toBe(0x602000000010n)
      expect(diag!.accessType).toBe('READ')
      expect(diag!.accessSize).toBe(4)
      expect(diag!.crashStack.length).toBe(2)
      expect(diag!.crashStack[0]!.functionName).toBe('main')
      expect(diag!.crashStack[0]!.sourceFile).toBe('test.c')
      expect(diag!.crashStack[0]!.lineNumber).toBe(25)

      expect(diag!.freeStack?.length).toBe(2)
      expect(diag!.freeStack?.[1]!.functionName).toBe('cleanup')

      expect(diag!.allocStack?.length).toBe(2)
      expect(diag!.allocStack?.[1]!.functionName).toBe('setup')
    })

    it('parses UBSan runtime error log', () => {
      const ubsanLog = `test.c:42:15: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'`
      const diag = SanitizerLogParser.parseUbsan(ubsanLog)
      expect(diag).not.toBeNull()
      expect(diag!.sanitizer).toBe('ubsan')
      expect(diag!.errorType).toBe('integer-overflow')
      expect(diag!.crashStack[0]!.sourceFile).toBe('test.c')
      expect(diag!.crashStack[0]!.lineNumber).toBe(42)
    })
  })

  describe('Experiment Runner, Reducer & Differential Testing (RUN-01..05, AC058..AC060, AC064)', () => {
    it('produces deterministic mutations with seeded PRNG', () => {
      const input = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
      const m1 = new DeterministicMutator(42)
      const mut1 = m1.mutate(input, 'bit_flip')

      const m2 = new DeterministicMutator(42)
      const mut2 = m2.mutate(input, 'bit_flip')

      expect(mut1).toEqual(mut2)
    })

    it('minimizes failing input using delta-debugging (ddmin) while strictly preserving the oracle (AC060)', async () => {
      // Craft a 64-byte input where the bug trigger is containing the sequence "CRASH"
      const input = new Uint8Array(64)
      input.fill(0x20) // spaces
      // Place "CRASH" at byte 20..24
      const crashBytes = new TextEncoder().encode('CRASH')
      input.set(crashBytes, 20)

      // Oracle: returns true if candidate contains 'CRASH'
      const oracle = (candidate: Uint8Array): boolean => {
        if (candidate.length < 5) return false
        for (let i = 0; i <= candidate.length - 5; i++) {
          if (
            candidate[i] === 0x43 && // 'C'
            candidate[i + 1] === 0x52 && // 'R'
            candidate[i + 2] === 0x41 && // 'A'
            candidate[i + 3] === 0x53 && // 'S'
            candidate[i + 4] === 0x48 // 'H'
          ) {
            return true
          }
        }
        return false
      }

      const res = await DeltaDebuggingReducer.reduce(input, oracle)
      expect(res.controlPassed).toBe(true) // empty buffer does not trigger bug
      expect(res.originalLength).toBe(64)
      expect(res.reducedLength).toBe(5) // Reduced exactly to "CRASH"!
      expect(new TextDecoder().decode(res.reducedBytes)).toBe('CRASH')
    })

    it('detects divergence in differential testing with timestamp normalization', () => {
      const runA = {
        experimentId: 'exp1',
        status: 'clean_exit' as const,
        exitCode: 0,
        stdout: 'Result: 42 at 2026-09-29T11:22:33Z',
        stderr: '',
        durationMs: 10,
        isTruncated: false,
      }

      // Run B differs only by timestamp
      const runB = {
        experimentId: 'exp2',
        status: 'clean_exit' as const,
        exitCode: 0,
        stdout: 'Result: 42 at 2026-09-29T11:25:00Z',
        stderr: '',
        durationMs: 12,
        isTruncated: false,
      }

      // Run C produces different result
      const runC = {
        experimentId: 'exp3',
        status: 'clean_exit' as const,
        exitCode: 0,
        stdout: 'Result: 99 at 2026-09-29T11:25:00Z',
        stderr: '',
        durationMs: 12,
        isTruncated: false,
      }

      const cmpAB = DifferentialComparator.compare(runA, runB, true)
      expect(cmpAB.isDivergent).toBe(false) // Timestamps normalized away!

      const cmpAC = DifferentialComparator.compare(runA, runC, true)
      expect(cmpAC.isDivergent).toBe(true) // Divergent output
      expect(cmpAC.stdoutMatch).toBe(false)
    })
  })
})
