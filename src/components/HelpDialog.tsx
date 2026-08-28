import { useEffect, useRef } from 'react'

interface HelpDialogProps {
  open: boolean
  onClose: () => void
}

const shortcuts = [
  ['Ctrl / Cmd + F', 'Focus byte search'],
  ['Enter / Shift + Enter', 'Next / previous search match'],
  ['Ctrl / Cmd + G', 'Focus offset navigation'],
  ['Ctrl / Cmd + Z', 'Undo byte edit'],
  ['Ctrl / Cmd + Shift + Z', 'Redo byte edit'],
  ['Arrow keys', 'Move byte selection'],
  ['Shift + Arrow', 'Extend byte selection'],
  ['Enter or F2', 'Edit selected byte'],
  ['Escape', 'Clear selection or active tool'],
]

export function HelpDialog({ open, onClose }: HelpDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null)

  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return
    if (open && !dialog.open) dialog.showModal()
    if (!open && dialog.open) dialog.close()
  }, [open])

  return (
    <dialog
      ref={dialogRef}
      className="help-dialog"
      aria-labelledby="help-heading"
      onClose={onClose}
      onCancel={onClose}
    >
      <div className="dialog-heading">
        <div>
          <h2 id="help-heading">bitpeek</h2>
          <p>Byte Inspector</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close help">
          Close
        </button>
      </div>

      <section>
        <h3>Input</h3>
        <p>
          Paste Hex, Binary, Decimal, UTF-8 Text, or Base64. Opened files and
          pasted data up to 256 KiB never leave this browser.
        </p>
      </section>

      <section>
        <h3>Search</h3>
        <p>
          Hex search accepts complete bytes and wildcards. Use <code>??</code>{' '}
          for any byte or <code>D?</code> for a nibble wildcard.
        </p>
      </section>

      <section>
        <h3>Compare and patch</h3>
        <p>
          Compare loads a second local file and performs an offset-aligned byte
          diff. Navigate each change or export a reference-to-current JSON patch
          with SHA-256 source and target fingerprints.
        </p>
      </section>

      <section>
        <h3>Analysis</h3>
        <p>
          Selection analysis includes numeric interpretations, CRC, entropy,
          SHA-256, and SHA-512. Strings scans the document for printable ASCII
          and ASCII-like UTF-16 data.
        </p>
      </section>

      <section>
        <h3>Keyboard</h3>
        <dl className="shortcut-list">
          {shortcuts.map(([keys, action]) => (
            <div key={keys}>
              <dt>{keys}</dt>
              <dd>{action}</dd>
            </div>
          ))}
        </dl>
      </section>

      <p className="dialog-privacy">Runs locally. No uploads, accounts, or analytics.</p>
    </dialog>
  )
}
