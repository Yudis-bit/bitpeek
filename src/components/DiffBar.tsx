import type { ByteDiff } from '../lib/diff'

interface DiffBarProps {
  currentName: string
  referenceName: string
  currentBytes: Uint8Array
  referenceBytes: Uint8Array
  diff: ByteDiff
  activeIndex: number
  onNavigate: (direction: 1 | -1) => void
  onCopyPatch: () => void
  onDownloadPatch: () => void
  onClose: () => void
}

function byteValue(bytes: Uint8Array, offset: number): string {
  const value = bytes[offset]
  return value === undefined
    ? '—'
    : value.toString(16).toUpperCase().padStart(2, '0')
}

export function DiffBar({
  currentName,
  referenceName,
  currentBytes,
  referenceBytes,
  diff,
  activeIndex,
  onNavigate,
  onCopyPatch,
  onDownloadPatch,
  onClose,
}: DiffBarProps) {
  const activeOffset =
    activeIndex >= 0 ? (diff.offsets[activeIndex] ?? null) : null

  return (
    <section className="diff-bar" aria-labelledby="diff-heading">
      <div className="diff-main-row">
        <h2 id="diff-heading" className="section-title">
          Diff
        </h2>
        <div className="diff-documents">
          <span title={currentName}>{currentName}</span>
          <span aria-hidden="true">↔</span>
          <span title={referenceName}>{referenceName}</span>
        </div>
        <dl className="diff-counts" aria-label="Difference summary">
          <div>
            <dt>Modified</dt>
            <dd>{diff.modified}</dd>
          </div>
          <div>
            <dt>Current only</dt>
            <dd>{diff.currentOnly}</dd>
          </div>
          <div>
            <dt>Reference only</dt>
            <dd>{diff.referenceOnly}</dd>
          </div>
        </dl>
        <div className="diff-actions">
          <button
            type="button"
            onClick={() => onNavigate(-1)}
            disabled={diff.offsets.length === 0}
            aria-label="Previous byte difference"
          >
            Prev
          </button>
          <button
            type="button"
            onClick={() => onNavigate(1)}
            disabled={diff.offsets.length === 0}
            aria-label="Next byte difference"
          >
            Next
          </button>
          <button type="button" onClick={onCopyPatch}>
            Copy patch
          </button>
          <button type="button" onClick={onDownloadPatch}>
            Export
          </button>
          <button type="button" onClick={onClose} aria-label="Close comparison">
            Close
          </button>
        </div>
      </div>

      <div className="diff-detail-row" aria-live="polite">
        {activeOffset === null ? (
          <span>
            {diff.offsets.length === 0
              ? 'Buffers are identical.'
              : diff.offsets.length + ' differences · offset-aligned comparison'}
          </span>
        ) : (
          <>
            <span>
              Difference {activeIndex + 1} / {diff.offsets.length}
            </span>
            <code>
              0x{activeOffset.toString(16).toUpperCase().padStart(6, '0')}
            </code>
            <span>Current</span>
            <code>{byteValue(currentBytes, activeOffset)}</code>
            <span>Reference</span>
            <code>{byteValue(referenceBytes, activeOffset)}</code>
          </>
        )}
      </div>
    </section>
  )
}
