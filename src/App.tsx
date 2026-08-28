import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BitInspector } from './components/BitInspector'
import { ByteTable } from './components/ByteTable'
import { ByteTools } from './components/ByteTools'
import { Header } from './components/Header'
import { HelpDialog } from './components/HelpDialog'
import { InputEditor } from './components/InputEditor'
import { InterpretationPanel } from './components/InterpretationPanel'
import { useClipboard } from './hooks/useClipboard'
import {
  findBytePattern,
  parseOffset,
  parseSearchPattern,
  type SearchMode,
} from './lib/analysis'
import {
  formatInput,
  getSelectionRange,
  INPUT_MODES,
  isValidUtf8,
  parseInput,
  setByte,
  sliceSelection,
  toggleBit,
  type ByteSelection,
  type InputMode,
} from './lib/bytes'
import {
  appendPatch,
  applyPatch,
  createPatch,
  transformRange,
  type BytePatch,
  type RangeOperation,
} from './lib/edits'

const DEFAULT_BYTES = Uint8Array.from([
  0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80,
])
const MODE_STORAGE_KEY = 'bitpeek.inputMode'
const MAX_DOCUMENT_BYTES = 256 * 1024

interface HistoryState {
  undo: BytePatch[]
  redo: BytePatch[]
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

export default function App() {
  const [mode, setMode] = useState<InputMode>(initialMode)
  const [bytes, setBytes] = useState<Uint8Array>(() => DEFAULT_BYTES.slice())
  const [source, setSource] = useState(() => formatInput(DEFAULT_BYTES, mode))
  const [error, setError] = useState<string | null>(null)
  const [selection, setSelection] = useState<ByteSelection | null>({
    anchor: 0,
    focus: 3,
  })
  const [documentName, setDocumentName] = useState<string | null>(null)
  const [documentDirty, setDocumentDirty] = useState(false)
  const [history, setHistory] = useState<HistoryState>({
    undo: [],
    redo: [],
  })
  const [searchMode, setSearchMode] = useState<SearchMode>('hex')
  const [searchQuery, setSearchQuery] = useState('')
  const [activeMatchIndex, setActiveMatchIndex] = useState(-1)
  const [helpOpen, setHelpOpen] = useState(false)
  const baselineRef = useRef<Uint8Array | null>(null)
  const { notice, copy } = useClipboard()

  const range = getSelectionRange(selection, bytes.length)
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

  const activeMatch =
    search.offsets.length === 0
      ? -1
      : Math.min(activeMatchIndex, search.offsets.length - 1)
  const activeSearchOffset =
    activeMatch >= 0 ? (search.offsets[activeMatch] ?? null) : null
  const inputWarning =
    mode === 'text' && bytes.length > 0 && !isValidUtf8(bytes)
      ? 'Invalid UTF-8; editing text will replace undecodable bytes.'
      : null

  const applyWorkingBytes = useCallback(
    (nextBytes: Uint8Array) => {
      setBytes(nextBytes)
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
        setSelection(null)
      }
    }
    window.addEventListener('keydown', handleGlobalKeys)
    return () => window.removeEventListener('keydown', handleGlobalKeys)
  }, [handleRedo, handleUndo])

  const commitMutation = (
    nextBytes: Uint8Array,
    start: number,
    end: number,
    label: string,
  ) => {
    if (equalBytes(bytes, nextBytes)) return
    const patch = createPatch(bytes, nextBytes, start, end, label)
    setHistory((current) => ({
      undo: appendPatch(current.undo, patch),
      redo: [],
    }))
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
    setBytes(result.bytes)
    setHistory({ undo: [], redo: [] })
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
    window.localStorage.setItem(MODE_STORAGE_KEY, nextMode)
    setSource(formatInput(bytes, nextMode))
    setError(null)
  }

  const handleClear = () => {
    setSource('')
    setBytes(new Uint8Array())
    setSelection(null)
    setError(null)
    setDocumentName(null)
    setDocumentDirty(false)
    baselineRef.current = null
    setHistory({ undo: [], redo: [] })
    setActiveMatchIndex(-1)
  }

  const handleOpenFile = async (file: File) => {
    if (file.size > MAX_DOCUMENT_BYTES) {
      setError('File exceeds the 256 KiB workspace limit.')
      return
    }
    try {
      const nextBytes = new Uint8Array(await file.arrayBuffer())
      setBytes(nextBytes)
      setSource(formatInput(nextBytes, mode))
      setError(null)
      setDocumentName(file.name)
      setDocumentDirty(false)
      baselineRef.current = nextBytes.slice()
      setHistory({ undo: [], redo: [] })
      setSelection(
        nextBytes.length === 0
          ? null
          : { anchor: 0, focus: Math.min(7, nextBytes.length - 1) },
      )
      setActiveMatchIndex(-1)
    } catch {
      setError('The selected file could not be read.')
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

  return (
    <div className="app-shell">
      <Header onHelp={() => setHelpOpen(true)} />
      <main className="workbench">
        <InputEditor
          mode={mode}
          source={source}
          error={error}
          warning={inputWarning}
          byteCount={bytes.length}
          documentName={documentName}
          documentDirty={documentDirty}
          onModeChange={handleModeChange}
          onSourceChange={handleSourceChange}
          onOpenFile={(file) => void handleOpenFile(file)}
          onSaveFile={handleSaveFile}
          onClear={handleClear}
          onCopy={() => void copy(source, mode + ' input')}
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
          onUndo={handleUndo}
          onRedo={handleRedo}
        />

        <div className="split-workspace">
          <ByteTable
            bytes={bytes}
            selection={selection}
            searchOffsets={search.offsets}
            searchLength={search.patternLength}
            activeSearchOffset={activeSearchOffset}
            onSelectionChange={setSelection}
            onByteEdit={handleByteEdit}
          />
          <InterpretationPanel
            bytes={selectedBytes}
            documentBytes={bytes}
            range={range}
            onCopy={(value, label) => void copy(value, label)}
          />
        </div>

        <BitInspector
          bytes={selectedBytes}
          range={range}
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
        </span>
      </footer>

      <HelpDialog open={helpOpen} onClose={() => setHelpOpen(false)} />
      <div className="copy-notice" role="status" aria-live="polite">
        {notice}
      </div>
    </div>
  )
}
