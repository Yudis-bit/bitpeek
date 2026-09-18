import {
  formatInput,
  getSelectionRange,
  parseInput,
  type ByteSelection,
  type InputMode,
} from './bytes'

export interface InspectionSource {
  mode: InputMode
  value: string
  revision: number
  validity: 'valid' | 'invalid'
  error: string | null
}

export interface ByteDocument {
  bytes: Uint8Array
  version: number
  sourceRevision: number
  selection: ByteSelection | null
}

export interface InspectionState {
  source: InspectionSource
  document: ByteDocument
}

export interface AnalysisScope {
  scopeType: 'none' | 'document' | 'selection'
  offsetStart: number | null
  offsetEnd: number | null
  byteCount: number
  documentByteCount: number
  documentVersion: number
  /** The source revision whose bytes the document currently represents. */
  sourceVersion: number
  /** The revision of the source text currently visible in the editor. */
  activeSourceVersion: number
  status: 'current' | 'last-valid'
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false
  }
  return true
}

export function selectEntireDocument(
  byteLength: number,
): ByteSelection | null {
  return byteLength > 0 ? { anchor: 0, focus: byteLength - 1 } : null
}

/**
 * Keeps anchor/focus direction intact for keyboard range extension while making
 * both endpoints safe for the current document.
 */
function normalizeSelection(
  selection: ByteSelection | null,
  byteLength: number,
): ByteSelection | null {
  if (selection === null || byteLength === 0) return null

  const finalOffset = byteLength - 1
  return {
    anchor: Math.max(0, Math.min(finalOffset, selection.anchor)),
    focus: Math.max(0, Math.min(finalOffset, selection.focus)),
  }
}

function formatLimit(maxBytes: number): string {
  if (maxBytes > 0 && maxBytes % 1024 === 0) {
    return `${maxBytes / 1024} KiB`
  }
  return `${maxBytes} ${maxBytes === 1 ? 'byte' : 'bytes'}`
}

export function createInspectionState(
  bytes: Uint8Array,
  mode: InputMode,
  selection?: ByteSelection | null,
): InspectionState {
  const documentBytes = bytes.slice()
  const documentSelection =
    selection === undefined
      ? selectEntireDocument(documentBytes.length)
      : normalizeSelection(selection, documentBytes.length)

  return {
    source: {
      mode,
      value: formatInput(documentBytes, mode),
      revision: 1,
      validity: 'valid',
      error: null,
    },
    document: {
      bytes: documentBytes,
      version: 1,
      sourceRevision: 1,
      selection: documentSelection,
    },
  }
}

export function applySourceInput(
  state: InspectionState,
  value: string,
  maxBytes: number,
): InspectionState {
  const revision = state.source.revision + 1
  const parsed = parseInput(value, state.source.mode)

  if (!parsed.ok) {
    return {
      ...state,
      source: {
        ...state.source,
        value,
        revision,
        validity: 'invalid',
        error: parsed.error,
      },
    }
  }

  if (parsed.bytes.length > maxBytes) {
    return {
      ...state,
      source: {
        ...state.source,
        value,
        revision,
        validity: 'invalid',
        error: `Input exceeds the ${formatLimit(maxBytes)} workspace limit.`,
      },
    }
  }

  const bytesChanged = !equalBytes(state.document.bytes, parsed.bytes)
  return {
    source: {
      ...state.source,
      value,
      revision,
      validity: 'valid',
      error: null,
    },
    document: {
      bytes: bytesChanged ? parsed.bytes.slice() : state.document.bytes,
      version: bytesChanged
        ? state.document.version + 1
        : state.document.version,
      sourceRevision: revision,
      selection: bytesChanged
        ? selectEntireDocument(parsed.bytes.length)
        : state.document.selection,
    },
  }
}

export function replaceDocument(
  state: InspectionState,
  bytes: Uint8Array,
  selection: ByteSelection | null,
): InspectionState {
  const revision = state.source.revision + 1
  const documentBytes = bytes.slice()

  return {
    source: {
      mode: state.source.mode,
      value: formatInput(documentBytes, state.source.mode),
      revision,
      validity: 'valid',
      error: null,
    },
    document: {
      bytes: documentBytes,
      version: state.document.version + 1,
      sourceRevision: revision,
      selection: normalizeSelection(selection, documentBytes.length),
    },
  }
}

export function updateDocument(
  state: InspectionState,
  bytes: Uint8Array,
): InspectionState {
  const revision = state.source.revision + 1
  const documentBytes = bytes.slice()

  return {
    source: {
      mode: state.source.mode,
      value: formatInput(documentBytes, state.source.mode),
      revision,
      validity: 'valid',
      error: null,
    },
    document: {
      bytes: documentBytes,
      version: state.document.version + 1,
      sourceRevision: revision,
      selection: normalizeSelection(
        state.document.selection,
        documentBytes.length,
      ),
    },
  }
}

export function changeMode(
  state: InspectionState,
  mode: InputMode,
): InspectionState {
  const revision = state.source.revision + 1

  return {
    source: {
      mode,
      value: formatInput(state.document.bytes, mode),
      revision,
      validity: 'valid',
      error: null,
    },
    document: {
      ...state.document,
      sourceRevision: revision,
    },
  }
}

export function restoreSource(state: InspectionState): InspectionState {
  const revision = state.source.revision + 1

  return {
    source: {
      ...state.source,
      value: formatInput(state.document.bytes, state.source.mode),
      revision,
      validity: 'valid',
      error: null,
    },
    document: {
      ...state.document,
      sourceRevision: revision,
    },
  }
}

export function setInspectionSelection(
  state: InspectionState,
  selection: ByteSelection | null,
): InspectionState {
  return {
    ...state,
    document: {
      ...state.document,
      selection: normalizeSelection(selection, state.document.bytes.length),
    },
  }
}

export function getAnalysisScope(state: InspectionState): AnalysisScope {
  const range = getSelectionRange(
    state.document.selection,
    state.document.bytes.length,
  )
  const status =
    state.source.validity === 'valid' &&
    state.source.revision === state.document.sourceRevision
      ? 'current'
      : 'last-valid'

  return {
    scopeType:
      range === null
        ? 'none'
        : range.length === state.document.bytes.length
          ? 'document'
          : 'selection',
    offsetStart: range?.start ?? null,
    offsetEnd: range?.end ?? null,
    byteCount: range?.length ?? 0,
    documentByteCount: state.document.bytes.length,
    documentVersion: state.document.version,
    sourceVersion: state.document.sourceRevision,
    activeSourceVersion: state.source.revision,
    status,
  }
}

export function getDocumentScope(state: InspectionState): AnalysisScope {
  const selectionScope = getAnalysisScope(state)
  const byteCount = state.document.bytes.length

  return {
    ...selectionScope,
    scopeType: byteCount === 0 ? 'none' : 'document',
    offsetStart: byteCount === 0 ? null : 0,
    offsetEnd: byteCount === 0 ? null : byteCount - 1,
    byteCount,
  }
}

export function analysisProvenanceKey(scope: AnalysisScope): string {
  return [
    `document:${scope.documentVersion}`,
    `source:${scope.sourceVersion}`,
    `scope:${scope.scopeType}`,
    `start:${scope.offsetStart ?? 'none'}`,
    `end:${scope.offsetEnd ?? 'none'}`,
    `bytes:${scope.byteCount}`,
    `document-bytes:${scope.documentByteCount}`,
  ].join('|')
}

function formatOffset(offset: number): string {
  return `0x${offset.toString(16).toUpperCase().padStart(4, '0')}`
}

function formatByteCount(byteCount: number): string {
  return `${byteCount} ${byteCount === 1 ? 'byte' : 'bytes'}`
}

export function formatScopeLabel(scope: AnalysisScope): string {
  if (scope.scopeType === 'document') {
    return `Entire document · ${formatByteCount(scope.byteCount)}`
  }
  if (scope.scopeType === 'selection') {
    return `Selection · ${formatOffset(scope.offsetStart ?? 0)}–${formatOffset(scope.offsetEnd ?? 0)} · ${scope.byteCount} of ${scope.documentByteCount} bytes`
  }
  return `No selection · 0 of ${scope.documentByteCount} bytes`
}
