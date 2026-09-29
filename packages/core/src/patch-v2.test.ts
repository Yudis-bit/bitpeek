import { describe, expect, it } from 'vitest'
import {
  validateOffsetPatch,
  verifyPatch,
  applyVerifiedPatch,
  type OffsetPatchFileV2,
  type OffsetPatchFileV1,
} from './patch'
import { sha256Hex } from './crypto'

describe('Patch Multi-Dialect & V2 Cryptographic Verification (AC037, AC038, AC039)', () => {
  const source = Uint8Array.from([0x01, 0x02, 0x03, 0x04])
  const target = Uint8Array.from([0x01, 0x99, 0x88, 0x04])

  it('validates and applies Patch v1 operations dialect', () => {
    const patchV1Ops: OffsetPatchFileV1 = {
      format: 'bitpeek-offset-patch',
      version: 1,
      targetLength: 4,
      operations: [
        { offset: 1, bytes: '99 88', precondition: '02 03' },
      ],
    }

    const val = validateOffsetPatch(patchV1Ops)
    expect(val.ok).toBe(true)
    if (val.ok) expect(val.dialect).toBe('v1-operations')

    const ver = verifyPatch(source, patchV1Ops)
    expect(ver.ok).toBe(true)

    const applied = applyVerifiedPatch(source, patchV1Ops)
    expect(applied.ok).toBe(true)
    if (applied.ok) {
      expect(Array.from(applied.target)).toEqual([0x01, 0x99, 0x88, 0x04])
    }
  })

  it('validates, verifies, and applies Patch v2 with mandatory SHA-256 integrity (AC038, AC039)', () => {
    const patchV2: OffsetPatchFileV2 = {
      format: 'bitpeek-offset-patch',
      version: 2,
      sourceLength: 4,
      targetLength: 4,
      sourceSha256: sha256Hex(source),
      targetSha256: sha256Hex(target),
      operations: [
        { offset: 1, bytes: '99 88', precondition: '02 03' },
      ],
    }

    const val = validateOffsetPatch(patchV2)
    expect(val.ok).toBe(true)
    if (val.ok) expect(val.dialect).toBe('v2')

    const ver = verifyPatch(source, patchV2)
    expect(ver.ok).toBe(true)
    if (ver.ok) {
      expect(ver.integrity).toBe('verified-hashes')
      expect(ver.sourceSha256Matches).toBe(true)
    }

    const applied = applyVerifiedPatch(source, patchV2)
    expect(applied.ok).toBe(true)
    if (applied.ok) {
      expect(Array.from(applied.target)).toEqual(Array.from(target))
      expect(applied.integrity).toBe('verified-hashes')
    }
  })

  it('rejects Patch v2 with invalid or missing SHA-256 hashes (AC038)', () => {
    const invalidV2 = {
      format: 'bitpeek-offset-patch',
      version: 2,
      sourceLength: 4,
      targetLength: 4,
      sourceSha256: 'short-hash',
      targetSha256: sha256Hex(target),
      operations: [{ offset: 1, bytes: '99 88' }],
    }
    const val = validateOffsetPatch(invalidV2)
    expect(val.ok).toBe(false)
    if (!val.ok) expect(val.error).toContain('64-character sourceSha256')
  })

  it('fails verification when target hash does not match after apply (AC038)', () => {
    const tamperedV2: OffsetPatchFileV2 = {
      format: 'bitpeek-offset-patch',
      version: 2,
      sourceLength: 4,
      targetLength: 4,
      sourceSha256: sha256Hex(source),
      targetSha256: '0000000000000000000000000000000000000000000000000000000000000000',
      operations: [{ offset: 1, bytes: '99 88' }],
    }
    const applied = applyVerifiedPatch(source, tamperedV2)
    expect(applied.ok).toBe(false)
    if (!applied.ok) expect(applied.error).toContain('Target SHA-256 mismatch')
  })
})
