import { describe, expect, it } from 'vitest'
import { encodeText } from './bytes'
import {
  analysisProvenanceKey,
  applySourceInput,
  changeMode,
  createInspectionState,
  equalBytes,
  formatScopeLabel,
  getAnalysisScope,
  getDocumentScope,
  replaceDocument,
  restoreSource,
  selectEntireDocument,
  setInspectionSelection,
  updateDocument,
} from './inspection'

const MAX_BYTES = 256 * 1024

describe('inspection source and document state', () => {
  it('starts with one accepted source revision and selects the document', () => {
    const bytes = encodeText('Hello')
    const state = createInspectionState(bytes, 'text')

    expect(state.source).toEqual({
      mode: 'text',
      value: 'Hello',
      revision: 1,
      validity: 'valid',
      error: null,
    })
    expect(state.document.version).toBe(1)
    expect(state.document.sourceRevision).toBe(1)
    expect(state.document.selection).toEqual({ anchor: 0, focus: 4 })
    expect(state.document.bytes).not.toBe(bytes)
    expect(getAnalysisScope(state)).toMatchObject({
      scopeType: 'document',
      offsetStart: 0,
      offsetEnd: 4,
      byteCount: 5,
      documentByteCount: 5,
      status: 'current',
    })
  })

  it('resets the stale Hell selection when Hello is replaced by 16-byte mixed text', () => {
    let state = createInspectionState(encodeText('Hello'), 'text')
    state = setInspectionSelection(state, { anchor: 0, focus: 3 })
    expect(formatScopeLabel(getAnalysisScope(state))).toBe(
      'Selection · 0x0000–0x0003 · 4 of 5 bytes',
    )

    state = applySourceInput(state, 'Hello 👋 café', MAX_BYTES)
    expect(state.document.bytes).toHaveLength(16)
    expect(state.document.selection).toEqual({ anchor: 0, focus: 15 })
    expect(getAnalysisScope(state)).toMatchObject({
      scopeType: 'document',
      offsetStart: 0,
      offsetEnd: 15,
      byteCount: 16,
      documentByteCount: 16,
      documentVersion: 2,
      sourceVersion: 2,
      activeSourceVersion: 2,
      status: 'current',
    })
    expect(formatScopeLabel(getAnalysisScope(state))).toBe(
      'Entire document · 16 bytes',
    )
  })

  it('retains the last valid document through invalid-valid-invalid transitions', () => {
    let state = createInspectionState(Uint8Array.from([0xde, 0xad]), 'hex')

    state = applySourceInput(state, 'DE AX', MAX_BYTES)
    expect(state.source.validity).toBe('invalid')
    expect(state.source.error).toBe(
      'Invalid hexadecimal character at position 5.',
    )
    expect(Array.from(state.document.bytes)).toEqual([0xde, 0xad])
    expect(state.document.version).toBe(1)
    expect(state.document.sourceRevision).toBe(1)
    expect(getAnalysisScope(state)).toMatchObject({
      sourceVersion: 1,
      activeSourceVersion: 2,
      status: 'last-valid',
    })

    state = applySourceInput(state, 'BE EF', MAX_BYTES)
    expect(state.source.validity).toBe('valid')
    expect(Array.from(state.document.bytes)).toEqual([0xbe, 0xef])
    expect(state.document.version).toBe(2)
    expect(state.document.sourceRevision).toBe(3)
    expect(getAnalysisScope(state).status).toBe('current')

    state = applySourceInput(state, 'BE EG', MAX_BYTES)
    expect(state.source.validity).toBe('invalid')
    expect(Array.from(state.document.bytes)).toEqual([0xbe, 0xef])
    expect(state.document.version).toBe(2)
    expect(state.document.sourceRevision).toBe(3)
    expect(getAnalysisScope(state)).toMatchObject({
      sourceVersion: 3,
      activeSourceVersion: 4,
      status: 'last-valid',
    })
  })

  it('accepts a byte-equivalent source reformat without resetting selection or document version', () => {
    let state = createInspectionState(
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
      'hex',
      { anchor: 1, focus: 2 },
    )

    state = applySourceInput(state, '0xDE, 0xAD, 0xBE, 0xEF', MAX_BYTES)
    expect(state.document.version).toBe(1)
    expect(state.source.revision).toBe(2)
    expect(state.document.sourceRevision).toBe(2)
    expect(state.document.selection).toEqual({ anchor: 1, focus: 2 })
    expect(getAnalysisScope(state).status).toBe('current')
  })

  it('does not let an invalid active source revision masquerade as current', () => {
    const current = createInspectionState(
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
      'hex',
    )
    const stale = applySourceInput(current, 'DE AX', MAX_BYTES)
    const restored = restoreSource(stale)

    expect(getAnalysisScope(current).status).toBe('current')
    expect(getAnalysisScope(stale)).toMatchObject({
      sourceVersion: 1,
      activeSourceVersion: 2,
      status: 'last-valid',
    })
    expect(restored.source.value).toBe('DE AD BE EF')
    expect(restored.source.validity).toBe('valid')
    expect(restored.document.version).toBe(1)
    expect(getAnalysisScope(restored)).toMatchObject({
      sourceVersion: 3,
      activeSourceVersion: 3,
      status: 'current',
    })
  })

  it('treats over-limit input as invalid without replacing accepted bytes', () => {
    const initial = createInspectionState(Uint8Array.from([0xaa]), 'hex')
    const state = applySourceInput(initial, 'AA BB', 1)

    expect(state.source).toMatchObject({
      revision: 2,
      validity: 'invalid',
      error: 'Input exceeds the 1 byte workspace limit.',
    })
    expect(Array.from(state.document.bytes)).toEqual([0xaa])
    expect(state.document.version).toBe(1)
    expect(getAnalysisScope(state).status).toBe('last-valid')
  })
})

describe('document replacement, mutation, and selection', () => {
  it('always versions explicit replacement and clamps its supplied selection', () => {
    const initial = createInspectionState(Uint8Array.from([1, 2]), 'hex')
    const nextBytes = Uint8Array.from([3, 4, 5])
    const state = replaceDocument(initial, nextBytes, {
      anchor: -4,
      focus: 99,
    })

    expect(state.source).toMatchObject({
      value: '03 04 05',
      revision: 2,
      validity: 'valid',
    })
    expect(state.document.version).toBe(2)
    expect(state.document.sourceRevision).toBe(2)
    expect(state.document.selection).toEqual({ anchor: 0, focus: 2 })
    expect(state.document.bytes).not.toBe(nextBytes)
  })

  it('versions a mutation and preserves directional selection while clamping it', () => {
    let state = createInspectionState(
      Uint8Array.from([1, 2, 3, 4]),
      'decimal',
      { anchor: 3, focus: 1 },
    )
    state = updateDocument(state, Uint8Array.from([9, 8]))

    expect(state.source.value).toBe('9 8')
    expect(state.source.revision).toBe(2)
    expect(state.document.version).toBe(2)
    expect(state.document.sourceRevision).toBe(2)
    expect(state.document.selection).toEqual({ anchor: 1, focus: 1 })
    expect(getAnalysisScope(state)).toMatchObject({
      scopeType: 'selection',
      offsetStart: 1,
      offsetEnd: 1,
      byteCount: 1,
    })
  })

  it('changes representation without versioning the byte document', () => {
    const initial = createInspectionState(
      Uint8Array.from([0x48, 0x69]),
      'hex',
      { anchor: 1, focus: 1 },
    )
    const state = changeMode(initial, 'text')

    expect(state.source).toEqual({
      mode: 'text',
      value: 'Hi',
      revision: 2,
      validity: 'valid',
      error: null,
    })
    expect(state.document.version).toBe(1)
    expect(state.document.sourceRevision).toBe(2)
    expect(state.document.selection).toEqual({ anchor: 1, focus: 1 })
    expect(getAnalysisScope(state).status).toBe('current')
  })

  it('models empty documents and cleared selections explicitly', () => {
    let state = createInspectionState(new Uint8Array(), 'hex')
    expect(selectEntireDocument(0)).toBeNull()
    expect(state.document.selection).toBeNull()
    expect(getAnalysisScope(state)).toMatchObject({
      scopeType: 'none',
      offsetStart: null,
      offsetEnd: null,
      byteCount: 0,
      documentByteCount: 0,
    })
    expect(formatScopeLabel(getAnalysisScope(state))).toBe(
      'No selection · 0 of 0 bytes',
    )

    state = replaceDocument(state, Uint8Array.from([1, 2]), null)
    expect(getAnalysisScope(state)).toMatchObject({
      scopeType: 'none',
      documentByteCount: 2,
    })
  })
})

describe('analysis provenance', () => {
  it('keeps document-scoped evidence distinct from a partial selection', () => {
    const selected = createInspectionState(
      Uint8Array.from([0x89, 0x50, 0x4e, 0x47]),
      'hex',
      { anchor: 2, focus: 3 },
    )

    expect(getAnalysisScope(selected)).toMatchObject({
      scopeType: 'selection',
      offsetStart: 2,
      offsetEnd: 3,
      byteCount: 2,
    })
    expect(getDocumentScope(selected)).toMatchObject({
      scopeType: 'document',
      offsetStart: 0,
      offsetEnd: 3,
      byteCount: 4,
    })
  })

  it('changes for a document version or selected range, but not merely an invalid active source', () => {
    const whole = createInspectionState(
      Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
      'hex',
    )
    const wholeKey = analysisProvenanceKey(getAnalysisScope(whole))

    const invalid = applySourceInput(whole, 'DE AX', MAX_BYTES)
    expect(analysisProvenanceKey(getAnalysisScope(invalid))).toBe(wholeKey)

    const range = setInspectionSelection(whole, { anchor: 0, focus: 1 })
    expect(analysisProvenanceKey(getAnalysisScope(range))).not.toBe(wholeKey)

    const mutated = updateDocument(whole, whole.document.bytes)
    expect(mutated.document.version).toBe(2)
    expect(analysisProvenanceKey(getAnalysisScope(mutated))).not.toBe(wholeKey)
  })

  it('compares byte values independently of array identity', () => {
    expect(equalBytes(Uint8Array.from([1, 2]), Uint8Array.from([1, 2]))).toBe(
      true,
    )
    expect(equalBytes(Uint8Array.from([1, 2]), Uint8Array.from([1, 3]))).toBe(
      false,
    )
  })
})
