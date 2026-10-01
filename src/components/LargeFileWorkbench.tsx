import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { BlobByteSource } from '../../packages/core/src/byte-source'
import { PieceTable } from '../../packages/core/src/piece-table'
import type { StructureParseResult } from '../lib/structures'
import type { PatternMatches } from '../lib/analysis'
import { parseOffset, parseSearchPattern, type SearchMode } from '../lib/analysis'
import { getSelectionRange, type ByteSelection } from '../lib/bytes'
import { downloadBlob, MAX_FILE_BYTES, type DocumentSnapshot } from '../lib/workspace'
import { useJob } from '../hooks/useJob'
import { ByteTable } from './ByteTable'
import { SelectionEditor } from './SelectionEditor'
import { ByteTools } from './ByteTools'
import { InterpretationPanel } from './InterpretationPanel'
import { StructureInspector } from './StructureInspector'
import { ResizableSplit } from './ResizableSplit'
import { BitInspector } from './BitInspector'
import { useClipboard } from '../hooks/useClipboard'

const InvestigationPanel = lazy(() =>
  import('./InvestigationPanel').then((m) => ({ default: m.InvestigationPanel })),
)
const WINDOW_SIZE = 64 * 1024
interface SearchResult extends PatternMatches {
  patternLength: number
}

export default function LargeFileWorkbench({
  initial,
  onSnapshot,
  onOpenDocument,
}: {
  initial: DocumentSnapshot
  onSnapshot: (snapshot: DocumentSnapshot) => void
  onOpenDocument: (file: File) => void
}) {
  const [table] = useState(() => new PieceTable(new BlobByteSource(initial.blob)))
  const [revision, setRevision] = useState(0)
  const [name, setName] = useState(initial.name)
  const [dirty, setDirty] = useState(initial.dirty)
  const [selection, setSelection] = useState<ByteSelection | null>(initial.selection)
  const [page, setPage] = useState(() => Math.floor((initial.selection?.anchor ?? 0) / WINDOW_SIZE))
  const [windowData, setWindowData] = useState<{
    revision: number
    page: number
    bytes: Uint8Array
  } | null>(null)
  const [selected, setSelected] = useState<{
    revision: number
    start: number
    bytes: Uint8Array
  } | null>(null)
  const [notes, setNotes] = useState(initial.notes)
  const [recipe, setRecipe] = useState(initial.recipe)
  const [investigate, setInvestigate] = useState(false)
  const [reference, setReference] = useState<Blob | undefined>(initial.reference)
  const [structureOpen, setStructureOpen] = useState(false)
  const [schema, setSchema] = useState(initial.schema)
  const [structureFormat, setStructureFormat] = useState(initial.format ?? 'auto')
  const [structureData, setStructureData] = useState<{
    revision: number
    result: StructureParseResult | null
  } | null>(null)
  const [error, setError] = useState('')
  const [searchMode, setSearchMode] = useState<SearchMode>('hex')
  const [searchQuery, setSearchQuery] = useState('')
  const [searchData, setSearchData] = useState<{
    query: string
    mode: SearchMode
    revision: number
    result: SearchResult
  } | null>(null)
  const [activeMatch, setActiveMatch] = useState(-1)
  const notesUndo = useRef<(typeof notes)[]>([]),
    notesRedo = useRef<(typeof notes)[]>([])
  const [mobileView, setMobileView] = useState('bytes')
  const root = useRef<HTMLDivElement>(null)
  const tableRevision = useRef(0)
  const job = useJob(),
    searchJob = useJob()
  const { notice, copy } = useClipboard()
  const blob = useMemo(() => {
    void revision
    return new Blob(
      table
        .exportSegments()
        .map((segment) =>
          segment.added
            ? (segment.added as BlobPart)
            : initial.blob.slice(segment.start, segment.start + segment.length),
        ),
    )
  }, [initial.blob, revision, table])
  const size = blob.size
  const pageCount = Math.max(1, Math.ceil(size / WINDOW_SIZE))
  const currentPage = Math.min(page, pageCount - 1)
  const base = currentPage * WINDOW_SIZE
  const range = getSelectionRange(selection, size)
  const windowBytes =
    windowData?.revision === revision && windowData.page === currentPage
      ? windowData.bytes
      : new Uint8Array(0)
  const selectedBytes =
    selected?.revision === revision && selected.start === range?.start
      ? selected.bytes
      : new Uint8Array(0)
  const search =
    searchData?.query === searchQuery &&
    searchData.mode === searchMode &&
    searchData.revision === revision
      ? searchData.result
      : null
  const parsedSearch = parseSearchPattern(searchQuery, searchMode)
  const localSelection =
    range && selection && selection.focus >= base && selection.focus < base + windowBytes.length
      ? {
          anchor: Math.max(0, Math.min(windowBytes.length - 1, selection.anchor - base)),
          focus: selection.focus - base,
        }
      : null
  const mutate = useCallback(
    (trackNotes = true) => {
      if (trackNotes) {
        notesUndo.current.push(notes)
        notesRedo.current = []
      }
      tableRevision.current++
      setRevision(tableRevision.current)
      setDirty(true)
      setError('')
    },
    [notes],
  )
  const select = (start: number, end: number) => {
    if (!size) {
      setSelection(null)
      return
    }
    const anchor = Math.max(0, Math.min(size - 1, start)),
      focus = Math.max(0, Math.min(size - 1, end))
    setSelection({ anchor, focus })
    setPage(Math.floor(anchor / WINDOW_SIZE))
    setMobileView('bytes')
  }
  useEffect(() => {
    const controller = new AbortController()
    void table
      .read(base, Math.min(WINDOW_SIZE, Math.max(0, size - base)), controller.signal)
      .then((bytes) => {
        if (!controller.signal.aborted) setWindowData({ revision, page: currentPage, bytes })
      })
      .catch((err) => {
        if (!controller.signal.aborted) setError(err.message)
      })
    return () => controller.abort()
  }, [base, currentPage, revision, size, table])
  const rangeStart = range?.start ?? -1,
    rangeLength = range?.length ?? 0
  useEffect(() => {
    if (rangeStart < 0) return
    const controller = new AbortController()
    void table
      .read(rangeStart, Math.min(rangeLength, 64 * 1024), controller.signal)
      .then((bytes) => {
        if (!controller.signal.aborted) setSelected({ revision, start: rangeStart, bytes })
      })
      .catch((err) => {
        if (!controller.signal.aborted) setError(err.message)
      })
    return () => controller.abort()
  }, [rangeStart, rangeLength, revision, table])
  useEffect(() => {
    onSnapshot({
      id: initial.id,
      name,
      blob,
      dirty,
      selection,
      notes,
      recipe,
      reference,
      referenceName: initial.referenceName,
      format: structureFormat,
      schema,
    })
  }, [
    initial.id,
    name,
    blob,
    dirty,
    selection,
    notes,
    recipe,
    reference,
    initial.referenceName,
    structureFormat,
    schema,
    onSnapshot,
  ])
  const { run: searchRun, cancel: searchCancel } = searchJob
  useEffect(() => {
    const timer = setTimeout(() => {
      if (!searchQuery) return
      void searchRun<SearchResult>('search', { blob, query: searchQuery, mode: searchMode })
        .then((result) => setSearchData({ query: searchQuery, mode: searchMode, revision, result }))
        .catch((err) => {
          if (err.message !== 'Operation cancelled.') setError(err.message)
        })
    }, 350)
    return () => {
      clearTimeout(timer)
      searchCancel()
    }
  }, [blob, revision, searchMode, searchQuery, searchRun, searchCancel])
  const undo = useCallback(() => {
    if (table.undo()) {
      notesRedo.current.push(notes)
      const previous = notesUndo.current.pop()
      if (previous) setNotes(previous)
      mutate(false)
    }
  }, [mutate, table, notes])
  const redo = useCallback(() => {
    if (table.redo()) {
      notesUndo.current.push(notes)
      const next = notesRedo.current.pop()
      if (next) setNotes(next)
      mutate(false)
    }
  }, [mutate, table, notes])
  useEffect(() => {
    const keys = (e: KeyboardEvent) => {
      if (root.current?.parentElement?.dataset.active !== 'true') return
      const command = e.ctrlKey || e.metaKey
      if (command && e.key.toLowerCase() === 'f') {
        e.preventDefault()
        root.current?.querySelector<HTMLElement>('[data-byte-search]')?.focus()
      }
      if (command && e.key.toLowerCase() === 'g') {
        e.preventDefault()
        root.current?.querySelector<HTMLElement>('[data-byte-offset]')?.focus()
      }
      if (
        command &&
        e.key.toLowerCase() === 'z' &&
        !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)
      ) {
        e.preventDefault()
        if (e.shiftKey) redo()
        else undo()
      }
      if (command && e.key.toLowerCase() === 's') {
        e.preventDefault()
        downloadBlob(blob, name + '.bitpeek.bin')
        setDirty(false)
      }
    }
    window.addEventListener('keydown', keys)
    return () => window.removeEventListener('keydown', keys)
  }, [blob, name, redo, undo])
  const action = async (fn: () => Promise<void>) => {
    setError('')
    try {
      await fn()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }
  const parseStructure = (format = structureFormat, customSchema = schema) =>
    void action(async () => {
      const result = await job.run<StructureParseResult | null>('structure', {
        blob,
        format,
        schema: customSchema,
      })
      setStructureData({ revision, result })
      setStructureOpen(true)
    })
  const splice = (start: number, remove: number, added: Uint8Array, label: string) => {
    if (!remove && !added.length) return
    if (size - remove + added.length > MAX_FILE_BYTES) {
      setError('Result exceeds 512 MiB.')
      return
    }
    table.splice(start, remove, added, label)
    const delta = added.length - remove
    if (delta)
      setNotes((current) =>
        current.flatMap((note) => {
          if (note.end < start) return [note]
          if (note.start >= start + remove)
            return [{ ...note, start: note.start + delta, end: note.end + delta }]
          return []
        }),
      )
    mutate()
    const nextSize = table.size
    setSelection(
      nextSize
        ? {
            anchor: Math.min(start, nextSize - 1),
            focus: Math.min(start + Math.max(1, added.length) - 1, nextSize - 1),
          }
        : null,
    )
    setPage(Math.floor(Math.min(start, Math.max(0, nextSize - 1)) / WINDOW_SIZE))
  }
  const navigate = (direction: 1 | -1) => {
    if (!search?.offsets.length) return
    const next =
      activeMatch < 0
        ? direction === 1
          ? 0
          : search.offsets.length - 1
        : (activeMatch + direction + search.offsets.length) % search.offsets.length
    const offset = search.offsets[next]!
    setActiveMatch(next)
    select(offset, offset + search.patternLength - 1)
  }
  return (
    <div ref={root} className="app-shell" data-mobile-view={mobileView}>
      <div className="workspace-menubar">
        <div className="workspace-document">
          <span className="window-mark">B</span>
          <span className="workspace-buffer-name">{name}</span>
          <span className="document-state">{dirty ? 'Modified' : 'Local file'}</span>
        </div>
        <div className="menubar-actions">
          <button
            aria-pressed={structureOpen}
            onClick={() => {
              if (structureOpen) setStructureOpen(false)
              else parseStructure()
            }}
          >
            Structure
          </button>
          <button aria-pressed={investigate} onClick={() => setInvestigate((v) => !v)}>
            Investigate
          </button>
        </div>
      </div>
      <div className="input-panel">
        <div className="section-title-row">
          <h2 className="section-title">File workspace</h2>
          <span>{size.toLocaleString()} bytes · reads bytes on demand</span>
        </div>
        <div className="compact-actions">
          <label className="file-action">
            Open file
            <input
              type="file"
              aria-label="Open local file"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) onOpenDocument(file)
                e.target.value = ''
              }}
            />
          </label>
          <label className="file-action">
            Compare
            <input
              type="file"
              aria-label="Open comparison file"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) {
                  if (file.size > MAX_FILE_BYTES) setError('Reference exceeds 512 MiB.')
                  else {
                    setReference(file)
                    setInvestigate(true)
                  }
                }
                e.target.value = ''
              }}
            />
          </label>
          <button
            onClick={() => {
              downloadBlob(blob, name + '.bitpeek.bin')
              setDirty(false)
            }}
          >
            Save file
          </button>
          <button
            disabled={!range}
            onClick={() => {
              if (range)
                downloadBlob(blob.slice(range.start, range.end + 1), name + '.selection.bin')
            }}
          >
            Export selection
          </button>
          <input
            aria-label="Document name"
            value={name}
            onChange={(e) => setName(e.target.value.slice(0, 1024))}
          />
        </div>
      </div>
      <ByteTools
        byteCount={size}
        selectionLength={range?.length ?? 0}
        searchMode={searchMode}
        searchQuery={searchQuery}
        searchError={parsedSearch.ok ? null : parsedSearch.error}
        matchCount={search?.offsets.length ?? 0}
        activeMatch={activeMatch}
        matchesTruncated={search?.truncated ?? false}
        canUndo={table.canUndo()}
        canRedo={table.canRedo()}
        undoLabel={null}
        redoLabel={null}
        onSearchModeChange={(mode) => {
          setSearchMode(mode)
          setActiveMatch(-1)
        }}
        onSearchQueryChange={(query) => {
          setSearchQuery(query)
          setActiveMatch(-1)
        }}
        onNavigateMatch={navigate}
        onGoToOffset={(input) => {
          const parsed = parseOffset(input, size)
          if (!parsed.ok) return parsed.error
          select(parsed.value, parsed.value)
          return null
        }}
        onSelectAll={() => select(0, size - 1)}
        onTransform={(operation) =>
          void action(async () => {
            if (!range) return
            const result = await job.run<{ ok: boolean; finalBytes?: Uint8Array; error?: string }>(
              'recipe',
              {
                blob: blob.slice(range.start, range.end + 1),
                recipe: {
                  schemaVersion: 1,
                  recipeId: 'selection-transform',
                  inputs: [{ id: 'input' }],
                  steps: [{ id: 'transform', operation }],
                },
              },
            )
            if (!result.ok || !result.finalBytes)
              throw new Error(result.error ?? 'Transform failed.')
            if (tableRevision.current !== revision)
              throw new Error('Document changed during transform. Run it again.')
            splice(range.start, range.length, result.finalBytes, operation)
          })
        }
        onOpenStrings={() => setInvestigate(true)}
        onUndo={undo}
        onRedo={redo}
      />
      {error && (
        <p className="workspace-message input-error" role="alert">
          {error}
        </p>
      )}
      {(job.busy || searchJob.busy) && (
        <div className="job-status" role="status">
          <progress max={1} value={job.progress || undefined} />
          {searchJob.busy ? 'Searching file…' : 'Processing file…'}
          <button
            onClick={() => {
              job.cancel()
              searchJob.cancel()
            }}
          >
            Cancel
          </button>
        </div>
      )}
      {search?.nextCursor && (
        <div className="compact-actions page-toolbar">
          <button
            disabled={searchJob.busy}
            onClick={() =>
              void action(async () => {
                const result = await searchRun<SearchResult>('search', {
                  blob,
                  query: searchQuery,
                  mode: searchMode,
                  cursor: search.nextCursor,
                })
                setSearchData({ query: searchQuery, mode: searchMode, revision, result })
                setActiveMatch(-1)
              })
            }
          >
            Next search page
          </button>
        </div>
      )}
      <div className="page-toolbar">
        <button disabled={!currentPage} onClick={() => setPage((v) => Math.max(0, v - 1))}>
          Previous window
        </button>
        <span>
          Window {currentPage + 1} / {pageCount} · offset 0x{base.toString(16).toUpperCase()}
        </span>
        <button
          disabled={currentPage >= pageCount - 1}
          onClick={() => setPage((v) => Math.min(pageCount - 1, v + 1))}
        >
          Next window
        </button>
        <input
          aria-label="File window"
          type="range"
          min={0}
          max={pageCount - 1}
          value={currentPage}
          onChange={(e) => setPage(Number(e.target.value))}
        />
      </div>
      <div className="mobile-workspace-switch" role="group" aria-label="Workspace view">
        <button aria-pressed={mobileView === 'bytes'} onClick={() => setMobileView('bytes')}>
          Bytes
        </button>
        <button
          aria-pressed={mobileView === 'inspector'}
          onClick={() => setMobileView('inspector')}
        >
          Inspector
        </button>
        <button
          aria-pressed={mobileView === 'structure'}
          onClick={() => {
            parseStructure()
            setMobileView('structure')
          }}
        >
          Structure
        </button>
      </div>
      <ResizableSplit structure={structureOpen}>
        {structureOpen && (
          <StructureInspector
            documentSize={size}
            structure={structureData?.revision === revision ? structureData.result : null}
            selectedFormat={structureFormat}
            onSelectFormat={(format) => {
              setStructureFormat(format)
              parseStructure(format)
            }}
            selectedRange={range}
            onSelectRange={select}
            onExportEvidence={() => setInvestigate(true)}
            onLoadCustomSchema={(text) => {
              try {
                const parsedSchema = JSON.parse(text)
                setSchema(parsedSchema)
                setStructureFormat('custom-schema')
                parseStructure('custom-schema', parsedSchema)
              } catch {
                setError('Invalid custom schema JSON.')
              }
            }}
          />
        )}
        <ByteTable
          bytes={windowBytes}
          offsetBase={base}
          selection={localSelection}
          searchOffsets={(search?.offsets ?? [])
            .filter((n) => n >= base && n < base + WINDOW_SIZE)
            .map((n) => n - base)}
          searchLength={search?.patternLength ?? 0}
          activeSearchOffset={
            search && activeMatch >= 0 ? search.offsets[activeMatch]! - base : null
          }
          diffOffsets={[]}
          activeDiffOffset={null}
          onSelectionChange={(value) => {
            setSelection(value ? { anchor: value.anchor + base, focus: value.focus + base } : null)
          }}
          onByteEdit={(index, value) => {
            table.replace(base + index, Uint8Array.of(value))
            mutate()
          }}
        />
        <InterpretationPanel
          bytes={selectedBytes}
          documentBytes={windowBytes}
          documentOffset={base}
          range={
            range && selectedBytes.length
              ? {
                  start: range.start,
                  end: range.start + selectedBytes.length - 1,
                  length: selectedBytes.length,
                }
              : null
          }
          onCopy={(value, label) => void copy(value, label)}
        />
      </ResizableSplit>
      {range && selectedBytes.length > 0 && range.length > selectedBytes.length && (
        <p className="workspace-message">
          Inspector shows the first {selectedBytes.length.toLocaleString()} selected bytes. Use
          Investigate for whole-file hashes and analysis.
        </p>
      )}
      <BitInspector
        bytes={selectedBytes}
        range={range}
        onToggle={(bit) => {
          if (range?.length === 1 && selectedBytes.length) {
            table.replace(range.start, Uint8Array.of(selectedBytes[0]! ^ (1 << bit)))
            mutate()
          }
        }}
      />
      <SelectionEditor size={size} range={range} onError={setError} onSplice={splice} />
      {investigate && (
        <Suspense fallback={<p>Opening investigation tools…</p>}>
          <InvestigationPanel
            blob={blob}
            name={name}
            range={range}
            notes={notes}
            onNotes={setNotes}
            recipe={recipe}
            onRecipe={setRecipe}
            reference={reference}
            onReference={setReference}
            onClose={() => setInvestigate(false)}
            onSelect={select}
            onApply={(next, label) => splice(0, size, next, label)}
          />
        </Suspense>
      )}
      <div className="workspace-status">
        <span className="local-status">
          <i />
          Local processing
        </span>
        <span>{size.toLocaleString()} bytes</span>
        <span>Selection {range?.length ?? 0}</span>
        <span>512 MiB / file</span>
      </div>
      <div className="copy-notice" role="status">
        {notice}
      </div>
    </div>
  )
}
