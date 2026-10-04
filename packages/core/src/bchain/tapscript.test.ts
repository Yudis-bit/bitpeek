import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  auditTapscript, evaluateTapscript, calculateTapscriptSigopsBudget, calculateSerializedWitnessSize,
  classifyTapscriptOpcode, isTapscriptOpSuccess, disassembleTapscript, encodeTapscriptNumber,
  decodeTapscriptNumber, castTapscriptBool, type TapscriptEvalOptions,
} from './tapscript'

const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'))
const hex = (value: Uint8Array) => Buffer.from(value).toString('hex')
const { vectors } = JSON.parse(readFileSync(new URL('./fixtures/bip340-signing-vectors.json', import.meta.url), 'utf8')) as {
  vectors: { publicKey: string; message: string; signature: string }[]
}
const vector = vectors[0], pubkey = bytes(vector.publicKey), sig = bytes(vector.signature), message = bytes(vector.message)
function push(data: Uint8Array): Uint8Array {
  const prefix = data.length < 76 ? [data.length] : data.length <= 255 ? [0x4c, data.length] : [0x4d, data.length & 255, data.length >> 8]
  return new Uint8Array([...prefix, ...data])
}
function evaluate(scriptHex: string, witness: Uint8Array[] = [], options: TapscriptEvalOptions = {}) {
  const script = bytes(scriptHex)
  return evaluateTapscript(script, witness, { profile: 'published-bip',
    serializedWitnessSize: calculateSerializedWitnessSize([...witness, script, new Uint8Array(33)]), ...options })
}
function audit(scriptHex: string) {
  const script = bytes(scriptHex)
  return auditTapscript(script, { profile: 'published-bip', serializedWitnessSize: script.length + 40 })
}
const checksigScript = hex(push(pubkey)) + 'ac'

describe('Tapscript budget profiles and opcode preflight', () => {
  it.each([0, 1, 49, 50, 51, 252, 253, 520, 10000])('uses 50 + %s script bytes in the requested reference profile', length => {
    expect(calculateTapscriptSigopsBudget(new Uint8Array(length))).toBe(50 + length)
  })
  it('bases published BIP-342 budget on the full serialized witness including CompactSize', () => {
    const witness = [new Uint8Array(252), new Uint8Array(253), new Uint8Array(65536)]
    expect(calculateSerializedWitnessSize(witness)).toBe(1 + 253 + 256 + 65541)
    const script = bytes('51'), serializedWitnessSize = calculateSerializedWitnessSize([sig, script, new Uint8Array(33)])
    expect(calculateTapscriptSigopsBudget(script, { profile: 'published-bip', serializedWitnessSize })).toBe(serializedWitnessSize + 50)
  })
  it.each([undefined, 0, 35, -1, 1.5, Number.MAX_SAFE_INTEGER])('requires an adequate complete serialized witness size (%s)', size => {
    expect(() => calculateTapscriptSigopsBudget(bytes('51'), { profile: 'published-bip', serializedWitnessSize: size })).toThrow('serializedWitnessSize')
  })
  it('rejects profile mixing and unknown verification profiles', () => {
    expect(() => calculateTapscriptSigopsBudget(bytes('51'), { serializedWitnessSize: 40 })).toThrow('only to published-bip')
    expect(() => calculateTapscriptSigopsBudget(bytes('51'), { profile: 'unknown' as 'specification' })).toThrow('profile')
  })
  it.each([80, 98, 126, 129, 131, 134, 137, 138, 141, 142, 149, 153, 187, 254])('honors published OP_SUCCESS%d even in inactive/unreachable code and before stack limits', opcode => {
    expect(isTapscriptOpSuccess(opcode, 'published-bip')).toBe(true)
    const script = hex(new Uint8Array([0x00, 0x63, opcode, 0x4c]))
    const result = evaluate(script, [new Uint8Array(521)], { traceExecution: true })
    expect(result.success).toBe(true); expect(result.cryptographicSignaturesVerified).toBe(false)
    expect(audit(script)).toMatchObject({ hasOpSuccess: true, hasAnyoneCanSpendPath: true, isPermanentlyUnspendable: false })
  })
  it.each([0, 79, 81, 97, 99, 125, 130, 135, 136, 139, 140, 143, 148, 154, 186, 255])('does not assign OP_SUCCESS to published opcode %s', opcode => {
    expect(isTapscriptOpSuccess(opcode, 'published-bip')).toBe(false)
  })
  it('keeps specification assignments explicit and exempts CHECKSIGADD', () => {
    expect(classifyTapscriptOpcode(0x7c).kind).toBe('op-success')
    expect(classifyTapscriptOpcode(0x7c, 'published-bip').name).toBe('OP_SWAP')
    expect(classifyTapscriptOpcode(0xba).kind).toBe('signature')
    expect(classifyTapscriptOpcode(0x8d).kind).toBe('disabled')
  })
  it.each([-1, 256, 1.5])('rejects non-byte opcode %s', opcode => {
    expect(isTapscriptOpSuccess(opcode)).toBe(false)
    expect(() => classifyTapscriptOpcode(opcode)).toThrow('byte')
  })
  it('does not interpret data-push contents as OP_SUCCESS', () => {
    expect(evaluate('01507551').success).toBe(true)
    expect(audit('01507551').hasOpSuccess).toBe(false)
  })
  it.each(['4c', '4d01', '4e010000', '0201', '4c0250'])('rejects malformed push %s before reaching later OP_SUCCESS', script => {
    expect(evaluate(script).success).toBe(false)
    expect(audit(script).isPermanentlyUnspendable).toBe(true)
    expect(disassembleTapscript(bytes(script)).at(-1)).toContain('Truncated')
  })
})

describe('Tapscript concrete execution, stack and signature semantics', () => {
  it.each([0n, 1n, -1n, 127n, 128n, -128n, 255n, -255n, 32768n, 2147483647n])('round-trips signed script number %s', value => {
    expect(decodeTapscriptNumber(encodeTapscriptNumber(value))).toBe(value)
  })
  it.each(['', '00', '80', '0080', '0000'])('casts zero/negative-zero %s as false', value => {
    expect(castTapscriptBool(bytes(value))).toBe(false)
  })
  it.each(['01', '8000', '008000', '81'])('casts nonzero %s as true', value => {
    expect(castTapscriptBool(bytes(value))).toBe(true)
  })
  it.each([
    ['518b5287', '1ADD'], ['528c5187', '1SUB'], ['4f8f5187', 'NEGATE'], ['4f905187', 'ABS'],
    ['00915187', 'NOT'], ['51925187', '0NOTEQUAL'], ['5152935387', 'ADD'], ['5352945187', 'SUB'],
    ['51519a5187', 'BOOLAND'], ['00519b5187', 'BOOLOR'], ['52529c', 'NUMEQUAL'], ['51529e', 'NUMNOTEQUAL'],
    ['51529f', 'LESSTHAN'], ['5251a0', 'GREATERTHAN'], ['5151a1', 'LESSTHANOREQUAL'], ['5252a2', 'GREATERTHANOREQUAL'],
    ['5152a35187', 'MIN'], ['5152a45287', 'MAX'], ['525153a5', 'WITHIN'], ['51519d51', 'NUMEQUALVERIFY'],
  ])('executes arithmetic %s (%s)', script => { expect(evaluate(script).success).toBe(true) })
  it.each(['', '00', '6a', 'ae', 'af', 'ff', '75', '6c', '67', '68', '5163', '0069', '515288', '51529d'])('rejects failing script %s', script => {
    expect(evaluate(script).success).toBe(false)
  })
  it('requires MINIMALIF and permits both IF and NOTIF with empty/01', () => {
    expect(evaluate('6351670068', [bytes('01')]).success).toBe(true)
    expect(evaluate('6400675168', [bytes('01')]).success).toBe(true)
    expect(evaluate('6351670068', [bytes('02')]).failureReason).toContain('MINIMALIF')
    expect(evaluate('6351670068', [bytes('80')]).failureReason).toContain('MINIMALIF')
  })
  it('skips disabled opcodes in inactive branches but rejects VERIF there', () => {
    expect(evaluate('0063ae6851').success).toBe(true)
    expect(evaluate('0063656851').success).toBe(false)
  })
  it('checks oversized pushes even in inactive branches', () => {
    const script = new Uint8Array([0, 0x63, ...push(new Uint8Array(521)), 0x68, 0x51])
    expect(evaluate(hex(script)).failureReason).toContain('520 bytes')
  })
  it('enforces initial and combined main/alt stack limits', () => {
    expect(evaluate('51', Array.from({ length: 1001 }, () => bytes(''))).failureReason).toContain('1000')
    expect(evaluate('51', [new Uint8Array(521)]).failureReason).toContain('520')
    expect(evaluate('6b51', Array.from({ length: 1000 }, () => bytes('01'))).failureReason).toContain('1000')
    expect(evaluate('6b6c', [bytes('01')]).success).toBe(true)
  })
  it.each(['5176755187', '51527851886d51', '51527c51885287', '5152537b51886d51', '5152535470726d6d6d51'])('executes stack operations %s', script => {
    expect(evaluate(script).success).toBe(true)
  })
  it('enforces clean stack even when the final value is true', () => {
    expect(evaluate('5151').failureReason).toContain('exactly one')
    expect(evaluate('', [bytes('01')]).success).toBe(true)
  })
  it.each([['a6', 'ripemd160'], ['a7', 'sha1'], ['a8', 'sha256'], ['a9', 'hash160'], ['aa', 'hash256']])('matches independent %s digest', (opcode, algorithm) => {
    const input = bytes('01020304')
    const digest = algorithm === 'hash160' ? createHash('ripemd160').update(createHash('sha256').update(input).digest()).digest()
      : algorithm === 'hash256' ? createHash('sha256').update(createHash('sha256').update(input).digest()).digest()
      : createHash(algorithm).update(input).digest()
    expect(evaluate(opcode + hex(push(digest)) + '87', [input]).success).toBe(true)
  })
  it('cryptographically verifies OP_CHECKSIG against a published BIP-340 signature', () => {
    const result = evaluate(checksigScript, [sig], { message, traceExecution: true })
    expect(result).toMatchObject({ success: true, cryptographicSignaturesVerified: true, simulationMode: false, finalStack: ['01'] })
    expect(result.trace?.at(-1)?.opcodeName).toBe('OP_CHECKSIG')
    expect(result.budgetRemaining).toBe(calculateSerializedWitnessSize([sig, bytes(checksigScript), new Uint8Array(33)]))
  })
  it('executes OP_CHECKSIGADD and CHECKSIGVERIFY', () => {
    expect(evaluate(hex(push(pubkey)) + 'ba5187', [sig, bytes('')], { message })).toMatchObject({ success: true, cryptographicSignaturesVerified: true })
    expect(evaluate(hex(push(pubkey)) + 'ad51', [sig], { message }).success).toBe(true)
    expect(evaluate(hex(push(pubkey)) + 'ba5287', [sig, bytes('01')], { message }).success).toBe(true)
  })
  it('rejects invalid nonempty signatures and absent sighash context without fabricating success', () => {
    expect(evaluate(checksigScript, [sig]).failureReason).toContain('signature message')
    const bad = sig.slice(); bad[0] ^= 1
    expect(evaluate(checksigScript, [bad], { message }).failureReason).toContain('Schnorr verification failed')
    const simulated = evaluate(checksigScript, [bad], { simulationMode: true })
    expect(simulated).toMatchObject({ success: true, cryptographicSignaturesVerified: false, simulationMode: true })
  })
  it('does not charge empty signatures and rejects zero-length public keys', () => {
    const empty = evaluate(checksigScript + '915187', [bytes('')])
    expect(empty.success).toBe(true); expect(empty.cryptographicSignaturesVerified).toBe(false)
    expect(empty.budgetRemaining).toBe(50 + calculateSerializedWitnessSize([bytes(''), bytes(checksigScript + '915187'), new Uint8Array(33)]))
    expect(evaluate('00ac', [bytes('')]).failureReason).toContain('public key is empty')
  })
  it('handles unknown public key lengths as explicit consensus upgrade hooks', () => {
    expect(evaluate('0102ac', [bytes('01')])).toMatchObject({ success: true, cryptographicSignaturesVerified: false })
    expect(evaluate('0102ac', [bytes('')]).success).toBe(false)
  })
  it.each([0, 4, 0x80, 0xff])('rejects an invalid/explicit-default 65-byte sighash suffix %s', suffix => {
    expect(evaluate(checksigScript, [new Uint8Array([...sig, suffix])], { message }).failureReason).toContain('hash type')
  })
  it('passes exact opcode and CODESEPARATOR positions to a per-context sighash resolver', () => {
    const contexts: unknown[] = []
    const result = evaluate('006351ab68ab' + checksigScript, [sig], { signatureMessage: context => { contexts.push(context); return message } })
    expect(result.success).toBe(true)
    expect(contexts).toEqual([{ pc: 39, opcodePosition: 7, codeSeparatorPosition: 5, hashType: 0 }])
  })
  it('exhausts the script-byte reference budget and uses the larger published witness budget', () => {
    const witness = [sig, pubkey, sig, pubkey]
    expect(evaluateTapscript(bytes('adad51'), witness, { simulationMode: true }).failureReason).toContain('budget exhausted')
    expect(evaluate('adad51', witness, { message }).success).toBe(true)
  })
  it('bounds execution traces without changing the execution verdict', () => {
    const result = evaluate('61616151', [], { traceExecution: true, traceLimit: 2 })
    expect(result).toMatchObject({ success: true, stepsExecuted: 4, traceTruncated: true })
    expect(result.trace).toHaveLength(2)
    expect(() => evaluate('51', [], { traceLimit: -1 })).toThrow('traceLimit')
  })
  it('checks CLTV context and mismatched timestamp/height units', () => {
    const script = hex(push(encodeTapscriptNumber(100n))) + 'b17551'
    expect(evaluate(script, [], { lockTime: 100, inputSequence: 0xfffffffe }).success).toBe(true)
    expect(evaluate(script, [], { lockTime: 99, inputSequence: 0 }).success).toBe(false)
    expect(evaluate(script, [], { lockTime: 500000000, inputSequence: 0 }).failureReason).toContain('unit collision')
    expect(evaluate(script).failureReason).toContain('context')
  })
  it('checks CSV version, disable flags, time units and relative age', () => {
    const script = '55b27551'
    expect(evaluate(script, [], { transactionVersion: 2, inputSequence: 5 }).success).toBe(true)
    expect(evaluate(script, [], { transactionVersion: 1, inputSequence: 5 }).success).toBe(false)
    expect(evaluate(script, [], { transactionVersion: 2, inputSequence: 4 }).success).toBe(false)
    expect(evaluate(script, [], { transactionVersion: 2, inputSequence: 0x400005 }).failureReason).toContain('unit collision')
    expect(evaluate(hex(push(encodeTapscriptNumber(0x80000000n))) + 'b27551').success).toBe(true)
  })
})

describe('Tapscript bounded static safety analysis', () => {
  it.each(['6a', '516a', '00', 'ae', 'af', 'ff', '006a'])('proves permanently failing leaf %s', script => {
    expect(audit(script).isPermanentlyUnspendable).toBe(true)
  })
  it.each(['51', '00636a675168', '6351676a68', '01507551'])('finds a concrete signature-free public witness for %s', script => {
    expect(audit(script).hasAnyoneCanSpendPath).toBe(true)
  })
  it('does not infer permanent failure from missing witness data or an IF-consumed false constant', () => {
    expect(audit('006368').isPermanentlyUnspendable).toBe(false)
    expect(audit(checksigScript)).toMatchObject({ isPermanentlyUnspendable: false, hasAnyoneCanSpendPath: false, analysisComplete: false })
  })
  it('reports potential conditional sigops exhaustion and preserves branch choices', () => {
    const result = auditTapscript(bytes('63acacac676a68'))
    expect(result.branches).toHaveLength(2)
    expect(result.maxSigopsRequired).toBe(150)
    expect(result.findings.some(finding => finding.code === 'conditional-sigops-exhaustion')).toBe(true)
    expect(result.isPermanentlyUnspendable).toBe(false)
  })
  it('bounds path enumeration and does not turn partial analysis into a permanent-failure proof', () => {
    const result = auditTapscript(bytes('6363676a68676a68'), { maxBranches: 1 })
    expect(result.analysisComplete).toBe(false)
    expect(result.isPermanentlyUnspendable).toBe(false)
    expect(result.findings.some(finding => finding.code === 'analysis-incomplete')).toBe(true)
    expect(() => auditTapscript(bytes('51'), { maxBranches: 0 })).toThrow('maxBranches')
  })
  it('does not modify script or witness buffers', () => {
    const script = bytes(checksigScript), initial = sig.slice(), copies = [script.slice(), initial.slice()]
    evaluateTapscript(script, [initial], { message })
    expect([script, initial]).toEqual(copies)
  })
})
