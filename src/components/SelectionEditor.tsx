import { useState } from 'react'
import { parseInput } from '../lib/bytes'

export function SelectionEditor({
  size,
  range,
  onSplice,
  onError,
}: {
  size: number
  range: { start: number; end: number } | null
  onSplice: (start: number, remove: number, added: Uint8Array, label: string) => void
  onError: (error: string) => void
}) {
  const [input, setInput] = useState('')
  return (
    <div className="page-toolbar">
      <input
        aria-label="Bytes to insert"
        placeholder="Hex bytes: DE AD BE EF"
        value={input}
        onChange={(e) => setInput(e.target.value)}
      />
      <div className="compact-actions">
        <button
          onClick={() => {
            const parsed = parseInput(input, 'hex')
            if (!parsed.ok) {
              onError(parsed.error)
              return
            }
            onSplice(range?.start ?? size, 0, parsed.bytes, 'Insert bytes')
            setInput('')
          }}
        >
          Insert bytes
        </button>
        <button
          disabled={!range}
          onClick={() => {
            const parsed = parseInput(input, 'hex')
            if (!parsed.ok) {
              onError(parsed.error)
              return
            }
            if (range)
              onSplice(range.start, range.end - range.start + 1, parsed.bytes, 'Replace selection')
            setInput('')
          }}
        >
          Replace selection
        </button>
        <button
          disabled={!range}
          onClick={() => {
            if (range)
              onSplice(
                range.start,
                range.end - range.start + 1,
                new Uint8Array(),
                'Delete selection',
              )
          }}
        >
          Delete selection
        </button>
      </div>
    </div>
  )
}
