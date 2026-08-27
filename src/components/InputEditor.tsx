import { INPUT_MODES, type InputMode } from '../lib/bytes'

interface InputEditorProps {
  mode: InputMode
  source: string
  error: string | null
  byteCount: number
  onModeChange: (mode: InputMode) => void
  onSourceChange: (source: string) => void
  onClear: () => void
  onCopy: () => void
}

const labels: Record<InputMode, string> = {
  hex: 'Hex',
  binary: 'Binary',
  decimal: 'Decimal',
  text: 'Text',
}

const placeholders: Record<InputMode, string> = {
  hex: 'DE AD BE EF',
  binary: '11011110 10101101 10111110 11101111',
  decimal: '222 173 190 239',
  text: 'Enter UTF-8 text',
}

export function InputEditor({
  mode,
  source,
  error,
  byteCount,
  onModeChange,
  onSourceChange,
  onClear,
  onCopy,
}: InputEditorProps) {
  return (
    <section className="input-panel" aria-labelledby="input-heading">
      <div className="section-title-row">
        <h2 id="input-heading" className="section-title">
          Input
        </h2>
        <span className="mode-hint">{labels[mode]} source</span>
      </div>

      <div className="mode-tabs" role="tablist" aria-label="Input format">
        {INPUT_MODES.map((inputMode) => (
          <button
            key={inputMode}
            type="button"
            role="tab"
            aria-selected={mode === inputMode}
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
        aria-describedby={error ? 'input-error' : 'input-summary'}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
      />

      <div className="input-status-row">
        <div className="input-message">
          {error ? (
            <span id="input-error" className="input-error" role="alert">
              {error}
            </span>
          ) : (
            <span id="input-summary" className="input-summary">
              {byteCount} {byteCount === 1 ? 'byte' : 'bytes'} · {byteCount * 8}{' '}
              bits
            </span>
          )}
        </div>
        <div className="compact-actions">
          <button type="button" onClick={onCopy} disabled={source.length === 0}>
            Copy
          </button>
          <button type="button" onClick={onClear} disabled={source.length === 0 && byteCount === 0}>
            Clear
          </button>
        </div>
      </div>
    </section>
  )
}
