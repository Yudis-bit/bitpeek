import { useState, type KeyboardEvent } from 'react'
import type { SearchMode } from '../lib/analysis'
import type { RangeOperation } from '../lib/edits'

interface ByteToolsProps {
  byteCount: number
  selectionLength: number
  searchMode: SearchMode
  searchQuery: string
  searchError: string | null
  matchCount: number
  activeMatch: number
  matchesTruncated: boolean
  canUndo: boolean
  canRedo: boolean
  undoLabel: string | null
  redoLabel: string | null
  onSearchModeChange: (mode: SearchMode) => void
  onSearchQueryChange: (query: string) => void
  onNavigateMatch: (direction: 1 | -1) => void
  onGoToOffset: (input: string) => string | null
  onSelectAll: () => void
  onTransform: (operation: RangeOperation) => void
  onOpenStrings: () => void
  onUndo: () => void
  onRedo: () => void
}

export function ByteTools({
  byteCount,
  selectionLength,
  searchMode,
  searchQuery,
  searchError,
  matchCount,
  activeMatch,
  matchesTruncated,
  canUndo,
  canRedo,
  undoLabel,
  redoLabel,
  onSearchModeChange,
  onSearchQueryChange,
  onNavigateMatch,
  onGoToOffset,
  onSelectAll,
  onTransform,
  onOpenStrings,
  onUndo,
  onRedo,
}: ByteToolsProps) {
  const [offset, setOffset] = useState('')
  const [offsetError, setOffsetError] = useState<string | null>(null)

  const goToOffset = () => {
    setOffsetError(onGoToOffset(offset))
  }

  const handleSearchKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault()
      onNavigateMatch(event.shiftKey ? -1 : 1)
    } else if (event.key === 'Escape') {
      onSearchQueryChange('')
      event.currentTarget.blur()
    }
  }

  const handleOffsetKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault()
      goToOffset()
    } else if (event.key === 'Escape') {
      setOffset('')
      setOffsetError(null)
      event.currentTarget.blur()
    }
  }

  const searchStatus =
    searchQuery.length === 0
      ? searchMode === 'hex'
        ? 'Use ?? or D? as wildcards'
        : 'UTF-8 text search'
      : searchError
        ? searchError
        : matchCount === 0
          ? 'No matches'
          : activeMatch >= 0
            ? String(activeMatch + 1) +
              ' / ' +
              String(matchCount) +
              (matchesTruncated ? '+' : '')
            : String(matchCount) + (matchesTruncated ? '+' : '') + ' matches'

  return (
    <section className="byte-tools" aria-labelledby="tools-heading">
      <h2 id="tools-heading" className="section-title tools-title">
        Tools
      </h2>

      <div className="tool-group search-tools">
        <label htmlFor="byte-search">Find</label>
        <select
          aria-label="Search format"
          value={searchMode}
          onChange={(event) =>
            onSearchModeChange(event.target.value as SearchMode)
          }
        >
          <option value="hex">Hex</option>
          <option value="text">Text</option>
        </select>
        <input
          id="byte-search"
          value={searchQuery}
          onChange={(event) => onSearchQueryChange(event.target.value)}
          onKeyDown={handleSearchKeyDown}
          placeholder={searchMode === 'hex' ? 'DE AD ?? EF' : 'UTF-8 text'}
          spellCheck={false}
          aria-invalid={searchError !== null}
          aria-describedby="search-status"
        />
        <span
          id="search-status"
          className={searchError ? 'tool-status is-error' : 'tool-status'}
        >
          {searchStatus}
        </span>
        <button
          type="button"
          onClick={() => onNavigateMatch(-1)}
          disabled={matchCount === 0 || searchError !== null}
        >
          Prev
        </button>
        <button
          type="button"
          onClick={() => onNavigateMatch(1)}
          disabled={matchCount === 0 || searchError !== null}
        >
          Next
        </button>
      </div>

      <div className="tool-divider" aria-hidden="true" />

      <div className="tool-group offset-tools">
        <label htmlFor="byte-offset">Go to</label>
        <input
          id="byte-offset"
          value={offset}
          onChange={(event) => {
            setOffset(event.target.value)
            setOffsetError(null)
          }}
          onKeyDown={handleOffsetKeyDown}
          placeholder="0x0000"
          spellCheck={false}
          aria-invalid={offsetError !== null}
          title={offsetError ?? 'Decimal or 0x-prefixed hexadecimal offset'}
        />
        <button type="button" onClick={goToOffset} disabled={byteCount === 0}>
          Go
        </button>
      </div>

      <div className="tool-divider" aria-hidden="true" />

      <div className="tool-group selection-tools" aria-label="Selection tools">
        <span className="tool-label">
          {selectionLength > 0 ? selectionLength + ' selected' : 'Selection'}
        </span>
        <button type="button" onClick={onSelectAll} disabled={byteCount === 0}>
          All
        </button>
        <button
          type="button"
          onClick={() => onTransform('reverse')}
          disabled={selectionLength < 2}
        >
          Reverse
        </button>
        <button
          type="button"
          onClick={() => onTransform('invert')}
          disabled={selectionLength === 0}
        >
          Invert
        </button>
      </div>

      <div className="tool-divider" aria-hidden="true" />

      <div className="tool-group analysis-tools" aria-label="Document analysis">
        <button
          type="button"
          onClick={onOpenStrings}
          disabled={byteCount === 0}
          title="Extract printable ASCII and UTF-16 strings"
        >
          Strings
        </button>
      </div>

      <div className="tool-divider" aria-hidden="true" />

      <div className="tool-group history-tools" aria-label="Edit history">
        <button
          type="button"
          onClick={onUndo}
          disabled={!canUndo}
          title={undoLabel ? 'Undo ' + undoLabel : 'Undo'}
        >
          Undo
        </button>
        <button
          type="button"
          onClick={onRedo}
          disabled={!canRedo}
          title={redoLabel ? 'Redo ' + redoLabel : 'Redo'}
        >
          Redo
        </button>
      </div>
    </section>
  )
}
