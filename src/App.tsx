import { useEffect, useMemo, useState } from 'react'
import { BitInspector } from './components/BitInspector'
import { ByteTable } from './components/ByteTable'
import { Header } from './components/Header'
import { InputEditor } from './components/InputEditor'
import { InterpretationPanel } from './components/InterpretationPanel'
import { useClipboard } from './hooks/useClipboard'
import {
  formatInput,
  getSelectionRange,
  parseInput,
  sliceSelection,
  toggleBit,
  type ByteSelection,
  type InputMode,
} from './lib/bytes'

const DEFAULT_BYTES = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80])
const MODE_STORAGE_KEY = 'bitpeek.inputMode'

function initialMode(): InputMode {
  const stored = window.localStorage.getItem(MODE_STORAGE_KEY)
  return stored === 'hex' || stored === 'binary' || stored === 'decimal' || stored === 'text'
    ? stored
    : 'hex'
}

function isTextEditingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  return target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target.isContentEditable
}

export default function App() {
  const [mode, setMode] = useState<InputMode>(initialMode)
  const [bytes, setBytes] = useState<Uint8Array>(() => DEFAULT_BYTES.slice())
  const [source, setSource] = useState(() => formatInput(DEFAULT_BYTES, mode))
  const [error, setError] = useState<string | null>(null)
  const [selection, setSelection] = useState<ByteSelection | null>({ anchor: 0, focus: 3 })
  const { notice, copy } = useClipboard()

  const range = getSelectionRange(selection, bytes.length)
  const selectedBytes = useMemo(
    () => sliceSelection(bytes, selection),
    [bytes, selection],
  )

  useEffect(() => {
    const clearSelection = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !isTextEditingTarget(event.target)) {
        setSelection(null)
      }
    }
    window.addEventListener('keydown', clearSelection)
    return () => window.removeEventListener('keydown', clearSelection)
  }, [])

  const handleSourceChange = (nextSource: string) => {
    setSource(nextSource)
    const result = parseInput(nextSource, mode)
    if (!result.ok) {
      setError(result.error)
      return
    }

    setError(null)
    setBytes(result.bytes)
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
  }

  const handleToggleBit = (bit: number) => {
    if (range === null || range.length !== 1) return
    const nextBytes = toggleBit(bytes, range.start, bit)
    setBytes(nextBytes)
    setSource(formatInput(nextBytes, mode))
    setError(null)
  }

  return (
    <div className="app-shell">
      <Header />
      <main className="workbench">
        <InputEditor
          mode={mode}
          source={source}
          error={error}
          byteCount={bytes.length}
          onModeChange={handleModeChange}
          onSourceChange={handleSourceChange}
          onClear={handleClear}
          onCopy={() => void copy(source, `${mode} input`)}
        />

        <div className="split-workspace">
          <ByteTable
            bytes={bytes}
            selection={selection}
            onSelectionChange={setSelection}
          />
          <InterpretationPanel
            bytes={selectedBytes}
            range={range}
            onCopy={(value, label) => void copy(value, label)}
          />
        </div>

        <BitInspector bytes={selectedBytes} range={range} onToggle={handleToggleBit} />
      </main>

      <footer className="app-footer" id="privacy">
        <span>Runs locally in your browser. No uploads.</span>
        <span>
          Built by{' '}
          <a href="https://github.com/Yudis-bit" target="_blank" rel="noreferrer">
            Yudis
          </a>
        </span>
      </footer>

      <div className="copy-notice" role="status" aria-live="polite">
        {notice}
      </div>
    </div>
  )
}
