import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BitInspector } from './components/BitInspector'
import { ByteTable } from './components/ByteTable'
import { ByteTools } from './components/ByteTools'
import { DiffBar } from './components/DiffBar'
import { Header } from './components/Header'
import { HelpDialog } from './components/HelpDialog'
import { InputEditor } from './components/InputEditor'
import { InterpretationPanel } from './components/InterpretationPanel'
import { ScopeBar } from './components/ScopeBar'
import { StringScannerDialog } from './components/StringScannerDialog'
import { SupportDialog } from './components/SupportDialog'
import { useClipboard } from './hooks/useClipboard'
import {
  findBytePattern,
  parseOffset,
  parseSearchPattern,
  type SearchMode,
} from './lib/analysis'
import {
  getSelectionRange,
  INPUT_MODES,
  isValidUtf8,
  setByte,
  sliceSelection,
  toggleBit,
  type ByteSelection,
  type InputMode,
} from './lib/bytes'
import { digestHex } from './lib/crypto'
import {
  createOffsetPatch,
  diffBytes,
  serializeOffsetPatch,
} from './lib/diff'
import {
  appendPatch,
  applyPatch,
  createPatch,
  transformRange,
  type BytePatch,
  type RangeOperation,
} from './lib/edits'
import {
  applySourceInput,
  changeMode,
  createInspectionState,
  equalBytes,
  getAnalysisScope,
  getDocumentScope,
  replaceDocument,
  restoreSource,
  setInspectionSelection,
  updateDocument,
} from './lib/inspection'
import { ETHEREUM_ADDRESS } from './lib/support'

const DEFAULT_BYTES = Uint8Array.from([
  0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80,
])
const MODE_STORAGE_KEY = 'bitpeek.inputMode'
const MAX_DOCUMENT_BYTES = 256 * 1024

interface HistoryState {
  undo: BytePatch[]
  redo: BytePatch[]
}

interface ComparisonDocument {
  name: string
  bytes: Uint8Array
}

function initialMode(): InputMode {
  const stored = window.localStorage.getItem(MODE_STORAGE_KEY)
  return INPUT_MODES.includes(stored as InputMode)
    ? (stored as InputMode)
    : 'hex'
}

function isTextEditingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement ||
    target.isContentEditable
  )
}

function downloadName(documentName: string | null, byteCount: number): string {
  if (!documentName) return 'bitpeek-' + byteCount + '-bytes.bin'
  if (documentName.toLowerCase().endsWith('.bitpeek.bin')) return documentName
  const finalDot = documentName.lastIndexOf('.')
  const stem = finalDot > 0 ? documentName.slice(0, finalDot) : documentName
  return stem + '.bitpeek.bin'
}

export default function App() {
  const [inspection, setInspection] = useState(() =>
    createInspectionState(DEFAULT_BYTES, initialMode(), {
      anchor: 0,
      focus: 3,
    }),
  )
  const [operationError, setOperationError] = useState<string | null>(null)
  const [documentName, setDocumentName] = useState<string | null>(null)
  const [documentDirty, setDocumentDirty] = useState(false)
  const [history, setHistory] = useState<HistoryState>({
    undo: [],
    redo: [],
  })
  const [searchMode, setSearchMode] = useState<SearchMode>('hex')
  const [searchQuery, setSearchQuery] = useState('')
  const [activeMatchIndex, setActiveMatchIndex] = useState(-1)
  const [comparison, setComparison] = useState<ComparisonDocument | null>(null)
  const [activeDifferenceIndex, setActiveDifferenceIndex] = useState(-1)
  const [stringsOpen, setStringsOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [supportOpen, setSupportOpen] = useState(
    () => window.location.hash === '#support',
  )
  const baselineRef = useRef<Uint8Array | null>(null)
  const { notice, copy } = useClipboard()

  const { source: sourceState, document: byteDocument } = inspection
  const { mode, value: source, error } = sourceState
  const { bytes, selection } = byteDocument

  const range = getSelectionRange(selection, bytes.length)
  const scope = useMemo(() => getAnalysisScope(inspection), [inspection])
  const documentScope = useMemo(() => getDocumentScope(inspection), [inspection])
  const stale = scope.status === 'last-valid'
  const selectedBytes = useMemo(
    () => sliceSelection(bytes, selection),
    [bytes, selection],
  )

  const search = useMemo(() => {
    const parsed = parseSearchPattern(searchQuery, searchMode)
    if (!parsed.ok) {
      return {
        error: parsed.error,
        offsets: [] as number[],
        patternLength: 0,
        truncated: false,
      }
    }
    const matches = findBytePattern(bytes, parsed.pattern)
    return {
      error: null,
      offsets: matches.offsets,
      patternLength: parsed.pattern.values.length,
      truncated: matches.truncated,
    }
  }, [bytes, searchMode, searchQuery])

  const comparisonDiff = useMemo(
    () => (comparison ? diffBytes(bytes, comparison.bytes) : null),
    [bytes, comparison],
  )
  const activeDifference =
    comparisonDiff && comparisonDiff.offsets.length > 0
      ? Math.min(activeDifferenceIndex, comparisonDiff.offsets.length - 1)
      : -1
  const activeDifferenceOffset =
    activeDifference >= 0
      ? (comparisonDiff?.offsets[activeDifference] ?? null)
      : null
  const currentDifferenceOffsets = useMemo(
    () =>
      comparisonDiff
        ? comparisonDiff.offsets.filter((offset) => offset < bytes.length)
        : [],
    [bytes.length, comparisonDiff],
  )

  const activeMatch =
    search.offsets.length === 0
      ? -1
      : Math.min(activeMatchIndex, search.offsets.length - 1)
  const activeSearchOffset =
    activeMatch >= 0 ? (search.offsets[activeMatch] ?? null) : null

  const handleSelectionChange = useCallback(
    (nextSelection: ByteSelection | null) => {
      setInspection((current) =>
        setInspectionSelection(current, nextSelection),
      )
    },
    [],
  )

  const applyWorkingBytes = useCallback(
    (nextBytes: Uint8Array) => {
      if (inspection.source.validity !== 'valid') return
      setInspection(updateDocument(inspection, nextBytes))
      setOperationError(null)
      setActiveMatchIndex(-1)
      if (documentName && baselineRef.current) {
        setDocumentDirty(!equalBytes(nextBytes, baselineRef.current))
      }
    },
    [documentName, inspection],
  )

  const handleUndo = useCallback(() => {
    const patch = history.undo.at(-1)
    if (!patch) return
    const nextBytes = applyPatch(bytes, patch, 'undo')
    setHistory({
      undo: history.undo.slice(0, -1),
      redo: [...history.redo, patch],
    })
    applyWorkingBytes(nextBytes)
  }, [applyWorkingBytes, bytes, history])

  const handleRedo = useCallback(() => {
    const patch = history.redo.at(-1)
    if (!patch) return
    const nextBytes = applyPatch(bytes, patch, 'redo')
    setHistory({
      undo: appendPatch(history.undo, patch),
      redo: history.redo.slice(0, -1),
    })
    applyWorkingBytes(nextBytes)
  }, [applyWorkingBytes, bytes, history])

  useEffect(() => {
    const handleGlobalKeys = (event: KeyboardEvent) => {
      const command = event.ctrlKey || event.metaKey
      if (command && event.key.toLowerCase() === 'f') {
        event.preventDefault()
        document.getElementById('byte-search')?.focus()
        return
      }
      if (command && event.key.toLowerCase() === 'g') {
        event.preventDefault()
        document.getElementById('byte-offset')?.focus()
        return
      }
      if (
        command &&
        event.key.toLowerCase() === 'z' &&
        !isTextEditingTarget(event.target)
      ) {
        event.preventDefault()
        if (event.shiftKey) handleRedo()
        else handleUndo()
        return
      }
      if (event.key === 'Escape' && !isTextEditingTarget(event.target)) {
        handleSelectionChange(null)
      }
    }
    window.addEventListener('keydown', handleGlobalKeys)
    return () => window.removeEventListener('keydown', handleGlobalKeys)
  }, [handleRedo, handleSelectionChange, handleUndo])

  useEffect(() => {
    const syncSupportHash = () => {
      setSupportOpen(window.location.hash === '#support')
    }
    window.addEventListener('hashchange', syncSupportHash)
    return () => window.removeEventListener('hashchange', syncSupportHash)
  }, [])

  const commitMutation = (
    nextBytes: Uint8Array,
    start: number,
    end: number,
    label: string,
  ) => {
    if (stale) return
    if (equalBytes(bytes, nextBytes)) return
    const patch = createPatch(bytes, nextBytes, start, end, label)
    setHistory((current) => ({
      undo: appendPatch(current.undo, patch),
      redo: [],
    }))
    applyWorkingBytes(nextBytes)
  }

  const handleSourceChange = (nextSource: string) => {
    const nextInspection = applySourceInput(
      inspection,
      nextSource,
      MAX_DOCUMENT_BYTES,
    )
    setInspection(nextInspection)
    setOperationError(null)

    if (nextInspection.document.version !== byteDocument.version) {
      setHistory({ undo: [], redo: [] })
      setActiveMatchIndex(-1)
    }
    if (
      nextInspection.source.validity === 'valid' &&
      documentName &&
      baselineRef.current
    ) {
      setDocumentDirty(
        !equalBytes(nextInspection.document.bytes, baselineRef.current),
      )
    }
  }

  const handleModeChange = (nextMode: InputMode) => {
    if (nextMode === mode) return
    if (stale) {
      setOperationError(
        'Restore or correct the current source before changing format.',
      )
      return
    }
    if (nextMode === 'text' && !isValidUtf8(bytes)) {
      setOperationError(
        'The byte document is not valid UTF-8. Inspect its UTF-8 diagnostic before replacing it as text.',
      )
      return
    }
    setInspection(changeMode(inspection, nextMode))
    window.localStorage.setItem(MODE_STORAGE_KEY, nextMode)
    setOperationError(null)
  }

  const handleRestoreSource = () => {
    setInspection(restoreSource(inspection))
    setOperationError(null)
  }

  const handleClear = () => {
    setInspection(replaceDocument(inspection, new Uint8Array(), null))
    setOperationError(null)
    setDocumentName(null)
    setDocumentDirty(false)
    baselineRef.current = null
    setHistory({ undo: [], redo: [] })
    setActiveMatchIndex(-1)
    setComparison(null)
    setActiveDifferenceIndex(-1)
  }

  const handleOpenFile = async (file: File) => {
    if (file.size > MAX_DOCUMENT_BYTES) {
      setOperationError('File exceeds the 256 KiB workspace limit.')
      return
    }
    try {
      const nextBytes = new Uint8Array(await file.arrayBuffer())
      setInspection((current) =>
        replaceDocument(
          current,
          nextBytes,
          nextBytes.length === 0
            ? null
            : { anchor: 0, focus: Math.min(7, nextBytes.length - 1) },
        ),
      )
      setOperationError(null)
      setDocumentName(file.name)
      setDocumentDirty(false)
      baselineRef.current = nextBytes.slice()
      setHistory({ undo: [], redo: [] })
      setActiveMatchIndex(-1)
    } catch {
      setOperationError('The selected file could not be read.')
    }
  }

  const handleOpenComparison = async (file: File) => {
    if (file.size > MAX_DOCUMENT_BYTES) {
      setOperationError('Comparison file exceeds the 256 KiB workspace limit.')
      return
    }
    try {
      const referenceBytes = new Uint8Array(await file.arrayBuffer())
      const nextDiff = diffBytes(bytes, referenceBytes)
      setComparison({ name: file.name, bytes: referenceBytes })
      setActiveDifferenceIndex(nextDiff.offsets.length > 0 ? 0 : -1)
      setOperationError(null)
      const firstOffset = nextDiff.offsets[0]
      if (firstOffset !== undefined && firstOffset < bytes.length) {
        handleSelectionChange({ anchor: firstOffset, focus: firstOffset })
      }
    } catch {
      setOperationError('The comparison file could not be read.')
    }
  }

  const handleSaveFile = () => {
    if (bytes.length === 0) return
    const name = downloadName(documentName, bytes.length)
    const blob = new Blob([bytes.slice().buffer], {
      type: 'application/octet-stream',
    })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = name
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1_000)
    setDocumentName(name)
    baselineRef.current = bytes.slice()
    setDocumentDirty(false)
  }

  const handleToggleBit = (bit: number) => {
    if (range === null || range.length !== 1) return
    commitMutation(
      toggleBit(bytes, range.start, bit),
      range.start,
      range.end,
      'Toggle bit ' + bit,
    )
  }

  const handleByteEdit = (index: number, value: number) => {
    commitMutation(setByte(bytes, index, value), index, index, 'Edit byte')
  }

  const handleTransform = (operation: RangeOperation) => {
    if (!range) return
    commitMutation(
      transformRange(bytes, range.start, range.end, operation),
      range.start,
      range.end,
      operation === 'reverse' ? 'Reverse selection' : 'Invert selection',
    )
  }

  const handleNavigateMatch = (direction: 1 | -1) => {
    if (search.error || search.offsets.length === 0) return
    const next =
      activeMatch < 0
        ? direction === 1
          ? 0
          : search.offsets.length - 1
        : (activeMatch + direction + search.offsets.length) %
          search.offsets.length
    const offset = search.offsets[next]
    if (offset === undefined) return
    setActiveMatchIndex(next)
    handleSelectionChange({
      anchor: offset,
      focus: offset + search.patternLength - 1,
    })
  }

  const handleGoToOffset = (input: string): string | null => {
    const parsed = parseOffset(input, bytes.length)
    if (!parsed.ok) return parsed.error
    handleSelectionChange({ anchor: parsed.value, focus: parsed.value })
    return null
  }

  const handleNavigateDifference = (direction: 1 | -1) => {
    if (!comparisonDiff || comparisonDiff.offsets.length === 0) return
    const next =
      activeDifference < 0
        ? direction === 1
          ? 0
          : comparisonDiff.offsets.length - 1
        : (activeDifference + direction + comparisonDiff.offsets.length) %
          comparisonDiff.offsets.length
    const offset = comparisonDiff.offsets[next]
    if (offset === undefined) return
    setActiveDifferenceIndex(next)
    if (offset < bytes.length) handleSelectionChange({ anchor: offset, focus: offset })
  }

  const createPatchText = async (): Promise<string> => {
    if (!comparison) return ''
    const [referenceSha256, currentSha256] = await Promise.all([
      digestHex(comparison.bytes, 'SHA-256'),
      digestHex(bytes, 'SHA-256'),
    ])
    return serializeOffsetPatch(
      createOffsetPatch(comparison.bytes, bytes, {
        referenceName: comparison.name,
        currentName: documentName ?? 'current.bin',
        referenceSha256,
        currentSha256,
      }),
    )
  }

  const handleCopyPatch = async () => {
    const value = await createPatchText()
    if (value) await copy(value, 'offset patch')
  }

  const handleDownloadPatch = async () => {
    const value = await createPatchText()
    if (!value) return
    const baseName = (documentName ?? 'current').replace(/\.[^.]+$/, '')
    const blob = new Blob([value], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = baseName + '.bitpeek.patch.json'
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1_000)
  }

  const openSupport = () => {
    window.history.replaceState(
      null,
      '',
      window.location.pathname + window.location.search + '#support',
    )
    setSupportOpen(true)
  }

  const closeSupport = () => {
    if (window.location.hash === '#support') {
      window.history.replaceState(
        null,
        '',
        window.location.pathname + window.location.search,
      )
    }
    setSupportOpen(false)
  }

  return (
    <div className="app-shell">
      <Header onHelp={() => setHelpOpen(true)} onSupport={openSupport} />
      <main className="workbench">
        <InputEditor
          mode={mode}
          source={source}
          error={error}
          operationError={operationError}
          stale={stale}
          byteCount={bytes.length}
          documentName={documentName}
          documentDirty={documentDirty}
          onModeChange={handleModeChange}
          onSourceChange={handleSourceChange}
          onOpenFile={(file) => void handleOpenFile(file)}
          onOpenComparison={(file) => void handleOpenComparison(file)}
          onSaveFile={handleSaveFile}
          onClear={handleClear}
          onCopy={() => void copy(source, mode + ' input')}
          onRestoreSource={handleRestoreSource}
        />

        <ByteTools
          byteCount={bytes.length}
          selectionLength={range?.length ?? 0}
          readOnly={stale}
          searchMode={searchMode}
          searchQuery={searchQuery}
          searchError={search.error}
          matchCount={search.offsets.length}
          activeMatch={activeMatch}
          matchesTruncated={search.truncated}
          canUndo={history.undo.length > 0}
          canRedo={history.redo.length > 0}
          undoLabel={history.undo.at(-1)?.label ?? null}
          redoLabel={history.redo.at(-1)?.label ?? null}
          onSearchModeChange={(nextMode) => {
            setSearchMode(nextMode)
            setActiveMatchIndex(-1)
          }}
          onSearchQueryChange={(query) => {
            setSearchQuery(query)
            setActiveMatchIndex(-1)
          }}
          onNavigateMatch={handleNavigateMatch}
          onGoToOffset={handleGoToOffset}
          onSelectAll={() => {
            if (bytes.length > 0) {
              handleSelectionChange({ anchor: 0, focus: bytes.length - 1 })
            }
          }}
          onTransform={handleTransform}
          onOpenStrings={() => setStringsOpen(true)}
          onUndo={handleUndo}
          onRedo={handleRedo}
        />

        {comparison && comparisonDiff ? (
          <DiffBar
            currentName={documentName ?? 'current bytes'}
            referenceName={comparison.name}
            currentBytes={bytes}
            referenceBytes={comparison.bytes}
            diff={comparisonDiff}
            activeIndex={activeDifference}
            onNavigate={handleNavigateDifference}
            onCopyPatch={() => void handleCopyPatch()}
            onDownloadPatch={() => void handleDownloadPatch()}
            onClose={() => {
              setComparison(null)
              setActiveDifferenceIndex(-1)
            }}
          />
        ) : null}

        <ScopeBar scope={scope} />

        <div className="split-workspace">
          <ByteTable
            bytes={bytes}
            selection={selection}
            readOnly={stale}
            searchOffsets={search.offsets}
            searchLength={search.patternLength}
            activeSearchOffset={activeSearchOffset}
            diffOffsets={currentDifferenceOffsets}
            activeDiffOffset={
              activeDifferenceOffset !== null &&
              activeDifferenceOffset < bytes.length
                ? activeDifferenceOffset
                : null
            }
            onSelectionChange={handleSelectionChange}
            onByteEdit={handleByteEdit}
          />
          <InterpretationPanel
            bytes={selectedBytes}
            documentBytes={bytes}
            scope={scope}
            documentScope={documentScope}
            onCopy={(value, label) => void copy(value, label)}
          />
        </div>

        <BitInspector
          bytes={selectedBytes}
          range={range}
          readOnly={stale}
          onToggle={handleToggleBit}
        />
      </main>

      <footer className="app-footer" id="privacy">
        <span>Runs locally in your browser. No uploads.</span>
        <span>
          Built by{' '}
          <a
            href="https://github.com/Yudis-bit"
            target="_blank"
            rel="noreferrer"
          >
            Yudis
          </a>
          <span aria-hidden="true"> · </span>
          <button type="button" className="footer-link" onClick={openSupport}>
            Support development
          </button>
        </span>
      </footer>

      <HelpDialog open={helpOpen} onClose={() => setHelpOpen(false)} />
      <StringScannerDialog
        open={stringsOpen}
        bytes={bytes}
        onClose={() => setStringsOpen(false)}
        onSelect={(offset, byteLength) => {
          handleSelectionChange({ anchor: offset, focus: offset + byteLength - 1 })
          setStringsOpen(false)
        }}
        onCopy={(value, label) => void copy(value, label)}
      />
      <SupportDialog
        open={supportOpen}
        onClose={closeSupport}
        onCopyAddress={() => void copy(ETHEREUM_ADDRESS, 'Ethereum address')}
      />
      <div className="copy-notice" role="status" aria-live="polite">
        {notice}
      </div>
    </div>
  )
}
