import { useState, type DragEvent } from 'react'
import { INPUT_MODES, type InputMode } from '../lib/bytes'

interface InputEditorProps {
  mode: InputMode
  primaryAction: 'open' | 'compare' | null
  source: string
  error: string | null
  warning: string | null
  byteCount: number
  documentName: string | null
  documentDirty: boolean
  onModeChange: (mode: InputMode) => void
  onSourceChange: (source: string) => void
  onOpenFile: (file: File) => void
  onOpenComparison: (file: File) => void
  onSaveFile: () => void
  onClear: () => void
  onCopy: () => void
}

const labels: Record<InputMode, string> = {
  hex: 'Hex',
  binary: 'Binary',
  decimal: 'Decimal',
  text: 'Text',
  base64: 'Base64',
}

const placeholders: Record<InputMode, string> = {
  hex: 'DE AD BE EF',
  binary: '11011110 10101101 10111110 11101111',
  decimal: '222 173 190 239',
  text: 'Enter UTF-8 text',
  base64: '3q2+7wABf4A=',
}

export function InputEditor({
  mode,
  primaryAction,
  source,
  error,
  warning,
  byteCount,
  documentName,
  documentDirty,
  onModeChange,
  onSourceChange,
  onOpenFile,
  onOpenComparison,
  onSaveFile,
  onClear,
  onCopy,
}: InputEditorProps) {
  const [dragging, setDragging] = useState(false)

  const openDroppedFile = (event: DragEvent<HTMLElement>) => {
    event.preventDefault()
    setDragging(false)
    const file = event.dataTransfer.files[0]
    if (file) onOpenFile(file)
  }

  return (
    <section
      className={dragging ? 'input-panel is-dragging' : 'input-panel'}
      aria-labelledby="input-heading"
      onDragEnter={(event) => {
        event.preventDefault()
        setDragging(true)
      }}
      onDragOver={(event) => event.preventDefault()}
      onDragLeave={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
          setDragging(false)
        }
      }}
      onDrop={openDroppedFile}
    >
      <div className="section-title-row">
        <div className="input-heading-group">
          <h2 id="input-heading" className="section-title">
            Input
          </h2>
          {documentName ? (
            <span className="document-name" title={documentName}>
              {documentName}
              {documentDirty ? ' · modified' : ''}
            </span>
          ) : null}
        </div>
        <span className="mode-hint">
          {dragging ? 'Drop file to inspect' : labels[mode] + ' source'}
        </span>
      </div>

      <div className="mode-tabs" role="group" aria-label="Input format">
        {INPUT_MODES.map((inputMode) => (
          <button
            key={inputMode}
            type="button"
            aria-pressed={mode === inputMode}
            className={mode === inputMode ? 'mode-tab is-active' : 'mode-tab'}
            onClick={() => onModeChange(inputMode)}
          >
            {labels[inputMode]}
          </button>
        ))}
      </div>

      <label className="sr-only" htmlFor="byte-source">
        {labels[mode]} byte input
      </label>
      <textarea
        id="byte-source"
        className={error ? 'source-editor has-error' : 'source-editor'}
        value={source}
        placeholder={placeholders[mode]}
        onChange={(event) => onSourceChange(event.target.value)}
        aria-invalid={error !== null}
        aria-describedby={
          error ? 'input-error' : warning ? 'input-warning' : 'input-summary'
        }
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
      />

      <div className="input-status-row">
        <div className="input-message">
          {error ? (
            <span id="input-error" className="input-error" role="alert">
              {error}
              {byteCount > 0 ? (
                <span className="last-valid-note">
                  {' '}
                  Inspector shows the last valid bytes.
                </span>
              ) : null}
            </span>
          ) : (
            <>
              <span id="input-summary" className="input-summary">
                {byteCount} {byteCount === 1 ? 'byte' : 'bytes'} ·{' '}
                {byteCount * 8} bits
              </span>
              {warning ? (
                <span id="input-warning" className="input-warning">
                  {warning}
                </span>
              ) : null}
            </>
          )}
        </div>
        <div className="compact-actions">
          <label
            className={
              primaryAction === 'open'
                ? 'file-action is-emphasized'
                : 'file-action'
            }
          >
            Open
            <input
              type="file"
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) onOpenFile(file)
                event.target.value = ''
              }}
            />
          </label>
          <label
            className={
              primaryAction === 'compare'
                ? 'file-action is-emphasized'
                : 'file-action'
            }
            title="Compare a local file by offset"
          >
            Compare
            <input
              type="file"
              aria-label="Open comparison file"
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) onOpenComparison(file)
                event.target.value = ''
              }}
            />
          </label>
          <button
            type="button"
            onClick={onSaveFile}
            disabled={byteCount === 0}
          >
            Save
          </button>
          <button type="button" onClick={onCopy} disabled={source.length === 0}>
            Copy
          </button>
          <button
            type="button"
            onClick={onClear}
            disabled={source.length === 0 && byteCount === 0}
          >
            Clear
          </button>
        </div>
      </div>
    </section>
  )
}
