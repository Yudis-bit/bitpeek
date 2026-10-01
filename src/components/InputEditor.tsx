import { useId, useState, type DragEvent } from 'react'
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
  isDraftInvalid?: boolean
  documentLoaded?: boolean
  onModeChange: (mode: InputMode) => void
  onSourceChange: (source: string) => void
  onOpenFile: (file: File) => void
  onOpenComparison: (file: File) => void
  onSaveFile: () => void
  onClear: () => void
  onCopy: () => void
  onCopyBytes?: () => void
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
  isDraftInvalid = false,
  documentLoaded = true,
  onModeChange,
  onSourceChange,
  onOpenFile,
  onOpenComparison,
  onSaveFile,
  onClear,
  onCopy,
  onCopyBytes,
}: InputEditorProps) {
  const scopeId = useId()
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
      aria-labelledby={scopeId + '-input-heading'}
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
          <h2 id={scopeId + '-input-heading'} className="section-title">
            Source input
          </h2>
          {documentName ? (
            <span className="document-name" title={documentName}>
              {documentName}
              {documentDirty ? ' · modified' : ''}
            </span>
          ) : null}
        </div>
        <span className="mode-hint">
          {dragging ? 'Drop your file here' : 'Paste data or drop a local file'}
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

      <label className="sr-only" htmlFor={scopeId + '-byte-source'}>
        {labels[mode]} byte input
      </label>
      <textarea
        rows={2}
        id={scopeId + '-byte-source'}
        data-byte-source
        className={error ? 'source-editor has-error' : 'source-editor'}
        value={source}
        placeholder={placeholders[mode]}
        onChange={(event) => onSourceChange(event.target.value)}
        aria-invalid={error !== null}
        aria-describedby={
          error
            ? scopeId + '-input-error'
            : warning
              ? scopeId + '-input-warning'
              : scopeId + '-input-summary'
        }
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
      />

      <div className="input-status-row">
        <div className="input-message">
          {error ? (
            <span id={scopeId + '-input-error'} className="input-error" role="alert">
              {error}
              {byteCount > 0 ? (
                <span className="last-valid-note">
                  {' '}
                  Inspector and export retain the last valid bytes ({byteCount} B).
                </span>
              ) : null}
            </span>
          ) : (
            <>
              <span id={scopeId + '-input-summary'} className="input-summary">
                {byteCount} {byteCount === 1 ? 'byte' : 'bytes'} · {byteCount * 8} bits
              </span>
              {warning ? (
                <span id={scopeId + '-input-warning'} className="input-warning">
                  {warning}
                </span>
              ) : null}
            </>
          )}
        </div>
        <div className="compact-actions">
          <label className={primaryAction === 'open' ? 'file-action is-emphasized' : 'file-action'}>
            Open file
            <input
              type="file"
              aria-label="Open local file"
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) onOpenFile(file)
                event.target.value = ''
              }}
            />
          </label>
          <label
            className={primaryAction === 'compare' ? 'file-action is-emphasized' : 'file-action'}
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
            className="save-action"
            onClick={onSaveFile}
            disabled={!documentLoaded}
            title={
              isDraftInvalid
                ? `Draft has syntax errors. Export will save last valid bytes (${byteCount} B).`
                : byteCount === 0
                  ? 'Save empty binary file (0 bytes)'
                  : `Save ${byteCount} bytes as binary file`
            }
          >
            {isDraftInvalid ? 'Save valid bytes' : 'Save file'}
          </button>
          <button
            type="button"
            onClick={onCopy}
            disabled={source.length === 0}
            title="Copy raw input text"
          >
            Copy input
          </button>
          {onCopyBytes && (
            <button
              type="button"
              onClick={onCopyBytes}
              disabled={byteCount === 0}
              title="Copy formatted committed bytes"
            >
              Copy bytes
            </button>
          )}
          <button
            type="button"
            onClick={onClear}
            disabled={source.length === 0 && byteCount === 0 && !documentLoaded}
          >
            Clear
          </button>
        </div>
      </div>
    </section>
  )
}
