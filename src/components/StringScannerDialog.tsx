import { useEffect, useMemo, useRef, useState } from 'react'
import {
  extractPrintableStrings,
  formatStringReport,
} from '../lib/strings'

interface StringScannerDialogProps {
  open: boolean
  bytes: Uint8Array
  onClose: () => void
  onSelect: (offset: number, byteLength: number) => void
  onCopy: (value: string, label: string) => void
}

function stringPreview(value: string): string {
  return value.length > 256 ? value.slice(0, 256) + '…' : value
}

export function StringScannerDialog({
  open,
  bytes,
  onClose,
  onSelect,
  onCopy,
}: StringScannerDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  const [minimumLength, setMinimumLength] = useState(4)
  const [filter, setFilter] = useState('')
  const scan = useMemo(
    () => extractPrintableStrings(bytes, minimumLength, 1_000),
    [bytes, minimumLength],
  )
  const filtered = useMemo(() => {
    const query = filter.toLocaleLowerCase()
    return query === ''
      ? scan.items
      : scan.items.filter((item) =>
          item.value.toLocaleLowerCase().includes(query),
        )
  }, [filter, scan.items])

  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return
    if (open && !dialog.open) dialog.showModal()
    if (!open && dialog.open) dialog.close()
  }, [open])

  return (
    <dialog
      ref={dialogRef}
      className="strings-dialog"
      aria-labelledby="strings-heading"
      onClose={onClose}
      onCancel={onClose}
    >
      <div className="dialog-heading">
        <div>
          <h2 id="strings-heading">String scanner</h2>
          <p>ASCII and ASCII-like UTF-16 · local analysis</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close string scanner">
          Close
        </button>
      </div>

      <div className="strings-toolbar">
        <label>
          Minimum length
          <input
            type="number"
            min="2"
            max="64"
            value={minimumLength}
            onChange={(event) => {
              const next = Number(event.target.value)
              if (Number.isInteger(next) && next >= 2 && next <= 64) {
                setMinimumLength(next)
              }
            }}
          />
        </label>
        <label>
          Filter
          <input
            type="search"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="Text contains…"
          />
        </label>
        <span className="strings-count">
          {filtered.length}
          {scan.truncated ? '+' : ''} results
        </span>
        <button
          type="button"
          onClick={() => onCopy(formatStringReport(filtered), 'string report')}
          disabled={filtered.length === 0}
        >
          Copy report
        </button>
      </div>

      <div className="strings-results">
        {filtered.length === 0 ? (
          <p className="dialog-empty">No matching strings.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">Offset</th>
                <th scope="col">Encoding</th>
                <th scope="col">Bytes</th>
                <th scope="col">Value</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={item.encoding + ':' + item.offset + ':' + item.byteLength}>
                  <td>
                    <code>
                      0x{item.offset.toString(16).toUpperCase().padStart(6, '0')}
                    </code>
                  </td>
                  <td>{item.encoding}</td>
                  <td>{item.byteLength}</td>
                  <td>
                    <button
                      type="button"
                      className="string-value"
                      title="Select these bytes in the inspector"
                      onClick={() => onSelect(item.offset, item.byteLength)}
                    >
                      {stringPreview(item.value)}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {scan.truncated ? (
        <p className="dialog-limit-note">
          Showing the first 1,000 results. Increase minimum length to narrow the scan.
        </p>
      ) : null}
    </dialog>
  )
}
