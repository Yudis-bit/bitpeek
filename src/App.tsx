import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BitInspector } from './components/BitInspector'
import { ByteTable } from './components/ByteTable'
import { ByteTools } from './components/ByteTools'
import { DiffBar } from './components/DiffBar'
import { InputEditor } from './components/InputEditor'
import { InterpretationPanel } from './components/InterpretationPanel'
import { StructureInspector } from './components/StructureInspector'
import { useClipboard } from './hooks/useClipboard'
import { findBytePattern, parseOffset, parseSearchPattern, type SearchMode } from './lib/analysis'
import {
  formatInput,
  getSelectionRange,
  isValidUtf8,
  parseInput,
  setByte,
  sliceSelection,
  toggleBit,
  type ByteSelection,
  type InputMode,
} from './lib/bytes'
import { digestHex } from './lib/crypto'
import { createOffsetPatch, diffBytes, serializeOffsetPatch } from './lib/diff'
import {
  createPatch,
  transformRange,
  type RangeOperation,
  type UnifiedHistoryState,
  createEmptyHistory,
  pushTransaction,
  applyUndo,
  applyRedo,
} from './lib/edits'
import { generateEvidenceReport } from './lib/evidence'
import { createSafeStorage, resolveInitialMode, MODE_STORAGE_KEY } from './lib/storage'
import { parseStructureByFormat, type CustomStructureSchema } from './lib/structures'
import { ETHEREUM_ADDRESS } from './lib/support'
import { ResizableSplit } from './components/ResizableSplit'
import { MAX_FILE_BYTES, type DocumentSnapshot } from './lib/workspace'
import { SelectionEditor } from './components/SelectionEditor'

const InvestigationPanel = lazy(() =>
  import('./components/InvestigationPanel').then((m) => ({ default: m.InvestigationPanel })),
)

const HelpDialog = lazy(() =>
  import('./components/HelpDialog').then((module) => ({
    default: module.HelpDialog,
  })),
)
const StringScannerDialog = lazy(() =>
  import('./components/StringScannerDialog').then((module) => ({
    default: module.StringScannerDialog,
  })),
)
const SupportDialog = lazy(() =>
  import('./components/SupportDialog').then((module) => ({
    default: module.SupportDialog,
  })),
)

const DEFAULT_BYTES = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80])
const MAX_DOCUMENT_BYTES = 256 * 1024
const storage = createSafeStorage()

interface ComparisonDocument {
  name: string
  bytes: Uint8Array
}

function requestedAction(): 'open' | 'compare' | null {
  const intent = new URLSearchParams(window.location.search).get('intent')
  if (intent === 'compare') return 'compare'
  if (intent === 'open' || intent === 'signature') return 'open'
  return null
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

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  return left.every((value, index) => right[index] === value)
}

function downloadName(documentName: string | null, byteCount: number): string {
  if (!documentName) return 'bitpeek-' + byteCount + '-bytes.bin'
  if (documentName.toLowerCase().endsWith('.bitpeek.bin')) return documentName
  const finalDot = documentName.lastIndexOf('.')
  const stem = finalDot > 0 ? documentName.slice(0, finalDot) : documentName
  return stem + '.bitpeek.bin'
}

export default function App({
  initial,
  onSnapshot,
  onOpenDocument,
}: {
  initial: DocumentSnapshot
  onSnapshot: (snapshot: DocumentSnapshot) => void
  onOpenDocument: (file: File) => void
}) {
  const rootRef = useRef<HTMLDivElement>(null)
  const [loaded, setLoaded] = useState(false)
  const [notes, setNotes] = useState(initial.notes)
  const notesUndo = useRef<(typeof notes)[]>([])
  const notesRedo = useRef<(typeof notes)[]>([])
  const [recipe, setRecipe] = useState(initial.recipe)
  const [investigationOpen, setInvestigationOpen] = useState(false)
  const [extraReference, setExtraReference] = useState<Blob | undefined>(initial.reference)
  const [mode, setMode] = useState<InputMode>(() => resolveInitialMode(storage))
  const [primaryAction] = useState(requestedAction)
  const [bytes, setBytes] = useState<Uint8Array>(() => DEFAULT_BYTES.slice())
  const [source, setSource] = useState(() => formatInput(DEFAULT_BYTES, mode))
  const [error, setError] = useState<string | null>(null)
  const [selection, setSelection] = useState<ByteSelection | null>({
    anchor: 0,
    focus: 3,
  })
  const [documentName, setDocumentName] = useState<string | null>(null)
  const [documentDirty, setDocumentDirty] = useState(false)
  const [history, setHistory] = useState<UnifiedHistoryState>(() => createEmptyHistory())
  const [structureOpen, setStructureOpen] = useState(false)
  const [mobileView, setMobileView] = useState<'bytes' | 'inspector' | 'structure'>('bytes')
  const [customSchema, setCustomSchema] = useState<CustomStructureSchema | null>(
    (initial.schema as CustomStructureSchema) ?? null,
  )
  const [structureFormat, setStructureFormat] = useState<string>(initial.format ?? 'auto')
  const [searchMode, setSearchMode] = useState<SearchMode>('hex')
  const [searchQuery, setSearchQuery] = useState('')
  const [activeMatchIndex, setActiveMatchIndex] = useState(-1)
  const [comparison, setComparison] = useState<ComparisonDocument | null>(null)
  const [activeDifferenceIndex, setActiveDifferenceIndex] = useState(-1)
  const [stringsOpen, setStringsOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [supportOpen, setSupportOpen] = useState(() => window.location.hash === '#support')
  const baselineRef = useRef<Uint8Array | null>(null)
  const { notice, copy } = useClipboard()
  const documentBlob = useMemo(() => new Blob([bytes as BlobPart]), [bytes])
  const comparisonBlob = useMemo(
    () => (comparison ? new Blob([comparison.bytes as BlobPart]) : undefined),
    [comparison],
  )

  useEffect(() => {
    let live = true
    void initial.blob
      .arrayBuffer()
      .then((buffer) => {
        if (!live) return
        const restored = new Uint8Array(buffer)
        setBytes(restored)
        setSource(formatInput(restored, mode))
        setDocumentName(initial.name)
        setDocumentDirty(initial.dirty)
        setSelection(initial.selection)
        baselineRef.current = restored.slice()
        setLoaded(true)
      })
      .catch(() => {
        if (live) setError('Could not restore this document.')
      })
    return () => {
      live = false
    }
    // The initial snapshot belongs to this tab; later edits are reported through onSnapshot.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initial])
  useEffect(() => {
    if (loaded)
      onSnapshot({
        id: initial.id,
        name: documentName ?? 'Untitled buffer',
        blob: documentBlob,
        dirty: documentDirty,
        selection,
        notes,
        recipe,
        reference: extraReference ?? comparisonBlob,
        referenceName: comparison?.name ?? initial.referenceName,
        format: structureFormat,
        schema: customSchema ?? undefined,
      })
  }, [
    loaded,
    initial.id,
    documentName,
    documentBlob,
    documentDirty,
    selection,
    notes,
    recipe,
    extraReference,
    comparisonBlob,
    comparison,
    initial.referenceName,
    structureFormat,
    customSchema,
    onSnapshot,
  ])

  const structure = useMemo(
    () => parseStructureByFormat(bytes, structureFormat, customSchema ?? undefined),
    [bytes, structureFormat, customSchema],
  )
  const showStructure = structureOpen

  const range = getSelectionRange(selection, bytes.length)
  const selectedBytes = useMemo(() => sliceSelection(bytes, selection), [bytes, selection])

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
    activeDifference >= 0 ? (comparisonDiff?.offsets[activeDifference] ?? null) : null
  const currentDifferenceOffsets = useMemo(
    () => (comparisonDiff ? comparisonDiff.offsets.filter((offset) => offset < bytes.length) : []),
    [bytes.length, comparisonDiff],
  )

  const activeMatch =
    search.offsets.length === 0 ? -1 : Math.min(activeMatchIndex, search.offsets.length - 1)
  const activeSearchOffset = activeMatch >= 0 ? (search.offsets[activeMatch] ?? null) : null
  const inputWarning =
    mode === 'text' && bytes.length > 0 && !isValidUtf8(bytes)
      ? 'Invalid UTF-8; editing text will replace undecodable bytes.'
      : null
  const statusOffset = range ? '0x' + range.start.toString(16).toUpperCase().padStart(8, '0') : '—'
  const statusSelection = range ? range.length + (range.length === 1 ? ' byte' : ' bytes') : 'none'

  const applyWorkingBytes = useCallback(
    (nextBytes: Uint8Array) => {
      setBytes(nextBytes)
      setNotes((current) => current.filter((note) => note.end < nextBytes.length))
      setSource(formatInput(nextBytes, mode))
      setError(null)
      setActiveMatchIndex(-1)
      if (documentName && baselineRef.current) {
        setDocumentDirty(!equalBytes(nextBytes, baselineRef.current))
      }
    },
    [documentName, mode],
  )

  const handleUndo = useCallback(() => {
    const res = applyUndo(bytes, history)
    if (!res) return
    setHistory(res.history)
    applyWorkingBytes(res.nextBytes)
    notesRedo.current.push(notes)
    const previous = notesUndo.current.pop()
    if (previous) setNotes(previous)
  }, [applyWorkingBytes, bytes, history, notes])

  const handleRedo = useCallback(() => {
    const res = applyRedo(bytes, history)
    if (!res) return
    setHistory(res.history)
    applyWorkingBytes(res.nextBytes)
    notesUndo.current.push(notes)
    const next = notesRedo.current.pop()
    if (next) setNotes(next)
  }, [applyWorkingBytes, bytes, history, notes])

  useEffect(() => {
    const handleGlobalKeys = (event: KeyboardEvent) => {
      if (rootRef.current?.parentElement?.dataset.active !== 'true') return
      const command = event.ctrlKey || event.metaKey
      if (command && event.key.toLowerCase() === 'f') {
        event.preventDefault()
        rootRef.current?.querySelector<HTMLElement>('[data-byte-search]')?.focus()
        return
      }
      if (command && event.key.toLowerCase() === 'g') {
        event.preventDefault()
        rootRef.current?.querySelector<HTMLElement>('[data-byte-offset]')?.focus()
        return
      }
      if (command && event.key.toLowerCase() === 'z' && !isTextEditingTarget(event.target)) {
        event.preventDefault()
        if (event.shiftKey) handleRedo()
        else handleUndo()
        return
      }
      if (event.key === 'Escape' && !isTextEditingTarget(event.target)) {
        setSelection(null)
      }
    }
    window.addEventListener('keydown', handleGlobalKeys)
    return () => window.removeEventListener('keydown', handleGlobalKeys)
  }, [handleRedo, handleUndo])

  useEffect(() => {
    const syncSupportHash = () => {
      setSupportOpen(window.location.hash === '#support')
    }
    window.addEventListener('hashchange', syncSupportHash)
    return () => window.removeEventListener('hashchange', syncSupportHash)
  }, [])

  const commitMutation = (nextBytes: Uint8Array, start: number, end: number, label: string) => {
    if (equalBytes(bytes, nextBytes)) return
    notesUndo.current.push(notes)
    notesRedo.current = []
    const patch = createPatch(bytes, nextBytes, start, end, label)
    setHistory((current) =>
      pushTransaction(current, {
        type: 'patch',
        patch,
        label,
      }),
    )
    applyWorkingBytes(nextBytes)
  }

  const handleSourceChange = (nextSource: string) => {
    setSource(nextSource)
    const result = parseInput(nextSource, mode)
    if (!result.ok) {
      setError(result.error)
      return
    }
    if (result.bytes.length > MAX_DOCUMENT_BYTES) {
      setError('Input exceeds the 256 KiB workspace limit.')
      return
    }

    setError(null)
    if (!equalBytes(bytes, result.bytes)) {
      notesUndo.current.push(notes)
      notesRedo.current = []
      setNotes((current) => current.filter((note) => note.end < result.bytes.length))
      setHistory((current) =>
        pushTransaction(current, {
          type: 'replace',
          before: bytes.slice(),
          after: result.bytes.slice(),
          label: 'Edit input',
        }),
      )
    }
    setBytes(result.bytes)
    setActiveMatchIndex(-1)
    if (documentName && baselineRef.current) {
      setDocumentDirty(!equalBytes(result.bytes, baselineRef.current))
    }
    setSelection((current) => {
      if (result.bytes.length === 0 || current === null) return null
      return {
        anchor: Math.min(current.anchor, result.bytes.length - 1),
        focus: Math.min(current.focus, result.bytes.length - 1),
      }
    })
  }

  const handleModeChange = (nextMode: InputMode) => {
    if (nextMode === mode) return
    setMode(nextMode)
    storage.setItem(MODE_STORAGE_KEY, nextMode)
    setSource(formatInput(bytes, nextMode))
    setError(null)
  }

  const handleClear = () => {
    if (
      documentDirty &&
      !window.confirm('You have unsaved edits in this buffer. Discard changes?')
    ) {
      return
    }
    setSource('')
    setBytes(new Uint8Array())
    setSelection(null)
    setError(null)
    setDocumentName(null)
    setDocumentDirty(false)
    baselineRef.current = null
    setHistory(createEmptyHistory())
    setActiveMatchIndex(-1)
    setComparison(null)
    setActiveDifferenceIndex(-1)
    setCustomSchema(null)
    setNotes([])
    notesUndo.current = []
    notesRedo.current = []
  }

  const handleOpenComparison = async (file: File) => {
    if (file.size > MAX_FILE_BYTES) {
      setError('Reference exceeds 512 MiB.')
      return
    }
    if (file.size > MAX_DOCUMENT_BYTES) {
      setExtraReference(file)
      setInvestigationOpen(true)
      return
    }
    try {
      const referenceBytes = new Uint8Array(await file.arrayBuffer())
      setExtraReference(undefined)
      const nextDiff = diffBytes(bytes, referenceBytes)
      setComparison({ name: file.name, bytes: referenceBytes })
      setActiveDifferenceIndex(nextDiff.offsets.length > 0 ? 0 : -1)
      setError(null)
      const firstOffset = nextDiff.offsets[0]
      if (firstOffset !== undefined && firstOffset < bytes.length) {
        setSelection({ anchor: firstOffset, focus: firstOffset })
      }
    } catch {
      setError('The comparison file could not be read.')
    }
  }

  const handleSaveFile = useCallback(() => {
    const name = downloadName(documentName, bytes.length)
    const blob = new Blob([bytes as unknown as BlobPart], {
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
  }, [bytes, documentName])

  useEffect(() => {
    const save = (event: KeyboardEvent) => {
      if (
        rootRef.current?.parentElement?.dataset.active === 'true' &&
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === 's'
      ) {
        event.preventDefault()
        handleSaveFile()
      }
    }
    window.addEventListener('keydown', save)
    return () => window.removeEventListener('keydown', save)
  }, [handleSaveFile])

  const handleExportEvidence = async () => {
    const resultData = structure
      ? {
          format: structure.format,
          status: structure.status,
          fieldCount: structure.fields.length,
          warnings: structure.warnings,
          selectedRange: range ? { start: range.start, end: range.end } : null,
        }
      : {
          byteCount: bytes.length,
          selection: range ? { start: range.start, end: range.end } : null,
        }

    const { humanSummary } = generateEvidenceReport(
      structure ? `${structure.format.toUpperCase()} structure inspection` : 'Byte inspection',
      bytes,
      resultData,
      {
        fileName: documentName ?? 'sample.bin',
        range: range ? { start: range.start, end: range.end } : undefined,
        warnings: structure?.warnings,
      },
    )

    await copy(humanSummary, 'evidence report summary')
  }

  const handleToggleBit = (bit: number) => {
    if (range === null || range.length !== 1) return
    commitMutation(toggleBit(bytes, range.start, bit), range.start, range.end, 'Toggle bit ' + bit)
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
        : (activeMatch + direction + search.offsets.length) % search.offsets.length
    const offset = search.offsets[next]
    if (offset === undefined) return
    setActiveMatchIndex(next)
    setSelection({
      anchor: offset,
      focus: offset + search.patternLength - 1,
    })
  }

  const handleGoToOffset = (input: string): string | null => {
    const parsed = parseOffset(input, bytes.length)
    if (!parsed.ok) return parsed.error
    setSelection({ anchor: parsed.value, focus: parsed.value })
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
    if (offset < bytes.length) setSelection({ anchor: offset, focus: offset })
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

  const closeSupport = () => {
    if (window.location.hash === '#support') {
      window.history.replaceState(null, '', window.location.pathname + window.location.search)
    }
    setSupportOpen(false)
  }

  return (
    <div ref={rootRef} className="app-shell" data-mobile-view={mobileView}>
      <div className="workspace-menubar">
        <div className="workspace-document">
          <span className="window-mark" aria-hidden="true">
            B
          </span>
          <span className="workspace-buffer-name">{documentName ?? 'Untitled buffer'}</span>
          <span className="document-state">
            {documentDirty ? 'Modified' : documentName ? 'Local file' : 'Scratchpad'}
          </span>
        </div>
        <div className="menubar-actions">
          <button
            className={investigationOpen ? 'menubar-btn is-active' : 'menubar-btn'}
            aria-pressed={investigationOpen}
            onClick={() => setInvestigationOpen((v) => !v)}
          >
            Investigate
          </button>
          <button
            type="button"
            className={showStructure ? 'menubar-btn is-active' : 'menubar-btn'}
            onClick={() => {
              setStructureOpen((prev) => !prev)
              setMobileView(showStructure ? 'bytes' : 'structure')
            }}
            aria-pressed={showStructure}
            title="Toggle structure inspector panel"
          >
            Structure {structure ? `(${structure.format.toUpperCase()})` : ''}
          </button>
          <button type="button" className="menubar-btn" onClick={() => setHelpOpen(true)}>
            Help & shortcuts
          </button>
        </div>
      </div>
      <div className="workbench">
        <InputEditor
          mode={mode}
          primaryAction={primaryAction}
          source={source}
          error={error}
          warning={inputWarning}
          byteCount={bytes.length}
          documentName={documentName}
          documentDirty={documentDirty}
          isDraftInvalid={error !== null}
          documentLoaded={true}
          onModeChange={handleModeChange}
          onSourceChange={handleSourceChange}
          onOpenFile={onOpenDocument}
          onOpenComparison={(file) => void handleOpenComparison(file)}
          onSaveFile={handleSaveFile}
          onClear={handleClear}
          onCopy={() => void copy(source, mode + ' input')}
          onCopyBytes={() => void copy(formatInput(bytes, mode), 'committed ' + mode + ' bytes')}
        />

        <ByteTools
          byteCount={bytes.length}
          selectionLength={range?.length ?? 0}
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
              setSelection({ anchor: 0, focus: bytes.length - 1 })
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

        <div className="mobile-workspace-switch" role="group" aria-label="Workspace view">
          <button
            type="button"
            aria-pressed={mobileView === 'bytes'}
            onClick={() => setMobileView('bytes')}
          >
            Bytes
          </button>
          <button
            type="button"
            aria-pressed={mobileView === 'inspector'}
            onClick={() => setMobileView('inspector')}
          >
            Inspector
          </button>
          <button
            type="button"
            aria-pressed={mobileView === 'structure'}
            onClick={() => {
              setStructureOpen(true)
              setMobileView('structure')
            }}
          >
            Structure
          </button>
        </div>

        <ResizableSplit structure={showStructure}>
          {showStructure ? (
            <StructureInspector
              documentSize={bytes.length}
              structure={structure}
              selectedFormat={structureFormat}
              onSelectFormat={(format) => setStructureFormat(format)}
              selectedRange={range}
              onSelectRange={(start, endInclusive) => {
                setSelection({ anchor: start, focus: endInclusive })
                setMobileView('bytes')
              }}
              onExportEvidence={() => void handleExportEvidence()}
              onLoadCustomSchema={(schemaJson) => {
                try {
                  const parsed = JSON.parse(schemaJson) as CustomStructureSchema
                  setCustomSchema(parsed)
                  setStructureFormat('custom-schema')
                } catch {
                  setError('Invalid custom schema JSON.')
                }
              }}
            />
          ) : null}
          <ByteTable
            bytes={bytes}
            selection={selection}
            searchOffsets={search.offsets}
            searchLength={search.patternLength}
            activeSearchOffset={activeSearchOffset}
            diffOffsets={currentDifferenceOffsets}
            activeDiffOffset={
              activeDifferenceOffset !== null && activeDifferenceOffset < bytes.length
                ? activeDifferenceOffset
                : null
            }
            onSelectionChange={setSelection}
            onByteEdit={handleByteEdit}
          />
          <InterpretationPanel
            bytes={selectedBytes}
            documentBytes={bytes}
            range={range}
            onCopy={(value, label) => void copy(value, label)}
          />
        </ResizableSplit>

        <BitInspector bytes={selectedBytes} range={range} onToggle={handleToggleBit} />
        <SelectionEditor
          size={bytes.length}
          range={range}
          onError={setError}
          onSplice={(start, remove, added, label) => {
            if (!remove && !added.length) return
            const length = bytes.length - remove + added.length
            if (length > MAX_DOCUMENT_BYTES) {
              setError('Scratchpad input exceeds 256 KiB. Open a file for larger documents.')
              return
            }
            const next = new Uint8Array(length)
            next.set(bytes.subarray(0, start))
            next.set(added, start)
            next.set(bytes.subarray(start + remove), start + added.length)
            notesUndo.current.push(notes)
            notesRedo.current = []
            setHistory((current) =>
              pushTransaction(current, {
                type: 'replace',
                before: bytes.slice(),
                after: next.slice(),
                label,
              }),
            )
            applyWorkingBytes(next)
            const delta = added.length - remove
            if (delta)
              setNotes(
                notes.flatMap((note) =>
                  note.end < start
                    ? [note]
                    : note.start >= start + remove
                      ? [{ ...note, start: note.start + delta, end: note.end + delta }]
                      : [],
                ),
              )
            setSelection(
              length
                ? {
                    anchor: Math.min(start, length - 1),
                    focus: Math.min(start + Math.max(1, added.length) - 1, length - 1),
                  }
                : null,
            )
          }}
        />
        {investigationOpen && (
          <Suspense fallback={<p className="workspace-message">Opening investigation tools…</p>}>
            <InvestigationPanel
              blob={documentBlob}
              name={documentName ?? 'Untitled buffer'}
              range={range}
              notes={notes}
              onNotes={setNotes}
              recipe={recipe}
              onRecipe={setRecipe}
              reference={extraReference ?? comparisonBlob}
              onReference={setExtraReference}
              onClose={() => setInvestigationOpen(false)}
              onSelect={(start, end) => {
                if (bytes.length) {
                  setSelection({
                    anchor: Math.min(start, bytes.length - 1),
                    focus: Math.min(end, bytes.length - 1),
                  })
                  setMobileView('bytes')
                }
              }}
              onApply={(next, label) => {
                if (next.length > MAX_DOCUMENT_BYTES) {
                  setError(
                    'Recipe output exceeds the scratchpad limit. Open the exported output in a large-file tab.',
                  )
                  return
                }
                notesUndo.current.push(notes)
                notesRedo.current = []
                setHistory((current) =>
                  pushTransaction(current, {
                    type: 'replace',
                    before: bytes.slice(),
                    after: next.slice(),
                    label,
                  }),
                )
                applyWorkingBytes(next)
              }}
            />
          </Suspense>
        )}
      </div>

      <div className="workspace-status" aria-label="Workspace status">
        <span className="local-status">
          <i aria-hidden="true" />
          Local processing
        </span>
        <span>{bytes.length.toLocaleString('en-US')} bytes</span>
        <span>Offset {statusOffset}</span>
        <span>Selection {statusSelection}</span>
        <span className="workspace-limit">Typed input ≤ 256 KiB · files ≤ 512 MiB</span>
      </div>

      <Suspense fallback={null}>
        {helpOpen ? <HelpDialog open onClose={() => setHelpOpen(false)} /> : null}
        {stringsOpen ? (
          <StringScannerDialog
            open
            bytes={bytes}
            onClose={() => setStringsOpen(false)}
            onSelect={(offset, byteLength) => {
              setSelection({ anchor: offset, focus: offset + byteLength - 1 })
              setStringsOpen(false)
            }}
            onCopy={(value, label) => void copy(value, label)}
          />
        ) : null}
        {supportOpen ? (
          <SupportDialog
            open
            onClose={closeSupport}
            onCopyAddress={() => void copy(ETHEREUM_ADDRESS, 'Ethereum address')}
          />
        ) : null}
      </Suspense>
      <div className="copy-notice" role="status" aria-live="polite">
        {notice}
      </div>
    </div>
  )
}
