import { describe, expect, it } from 'vitest'
import {
  validateOffsetPatch,
  verifyPatch,
  applyVerifiedPatch,
  type OffsetPatchFile,
} from './patch'
import { sha256Hex } from './crypto'

describe('Patch validation and application (F07)', () => {
  const ref = Uint8Array.from([0x00, 0x11, 0x22, 0x33, 0x44])
  const cur = Uint8Array.from([0x00, 0xaa, 0xbb, 0x33, 0x44, 0x55])

  const validPatch: OffsetPatchFile = {
    format: 'bitpeek-offset-patch',
    version: 1,
    semantics: 'reference-to-current',
    source: {
      name: 'ref.bin',
      length: 5,
      sha256: sha256Hex(ref),
    },
    target: {
      name: 'cur.bin',
      length: 6,
      sha256: sha256Hex(cur),
    },
    changes: [
      { offset: 1, remove: '1122', insert: 'AABB' },
      { offset: 5, remove: '', insert: '55' },
    ],
  }

  it('validates a correct patch schema and hashes', () => {
    const res = validateOffsetPatch(validPatch)
    expect(res.ok).toBe(true)
  })

  it('rejects patch with overlapping changes', () => {
    const invalid = {
      ...validPatch,
      changes: [
        { offset: 1, remove: '1122', insert: 'AABB' },
        { offset: 2, remove: '22', insert: 'CC' },
      ],
    }
    const res = validateOffsetPatch(invalid)
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error).toContain('overlaps')
  })

  it('rejects patch with non-hex digits', () => {
    const invalid = {
      ...validPatch,
      changes: [{ offset: 1, remove: 'ZZ', insert: 'AABB' }],
    }
    const res = validateOffsetPatch(invalid)
    expect(res.ok).toBe(false)
  })

  it('verifies and applies a valid patch atomically with verified-hashes integrity', () => {
    const verification = verifyPatch(ref, validPatch)
    expect(verification.ok).toBe(true)
    if (verification.ok) {
      expect(verification.integrity).toBe('verified-hashes')
    }

    const applied = applyVerifiedPatch(ref, validPatch)
    expect(applied.ok).toBe(true)
    if (applied.ok) {
      expect(Array.from(applied.target)).toEqual(Array.from(cur))
      expect(applied.integrity).toBe('verified-hashes')
    }
  })

  it('fails verification when source sha256 does not match', () => {
    const wrongHashPatch: OffsetPatchFile = {
      ...validPatch,
      source: {
        ...validPatch.source,
        sha256: '0000000000000000000000000000000000000000000000000000000000000000',
      },
    }
    const verification = verifyPatch(ref, wrongHashPatch)
    expect(verification.ok).toBe(false)
    if (!verification.ok) {
      expect(verification.error).toContain('Source SHA-256 mismatch')
    }
  })

  it('fails verification when precondition byte fails', () => {
    const corruptedRef = Uint8Array.from([0x00, 0x99, 0x22, 0x33, 0x44])
    const verification = verifyPatch(corruptedRef, {
      ...validPatch,
      source: { name: 'ref.bin', length: 5 }, // remove hash to test precondition directly
    })
    expect(verification.ok).toBe(false)
    if (!verification.ok) {
      expect(verification.error).toContain('Precondition failed at offset 1')
    }
  })

  it('supports legacy patches without sha256 as preconditions-only', () => {
    const legacyPatch: OffsetPatchFile = {
      format: 'bitpeek-offset-patch',
      version: 1,
      semantics: 'reference-to-current',
      source: { name: 'ref.bin', length: 5 },
      target: { name: 'cur.bin', length: 6 },
      changes: validPatch.changes,
    }

    const applied = applyVerifiedPatch(ref, legacyPatch)
    expect(applied.ok).toBe(true)
    if (applied.ok) {
      expect(applied.integrity).toBe('preconditions-only')
      expect(Array.from(applied.target)).toEqual(Array.from(cur))
    }
  })
})
