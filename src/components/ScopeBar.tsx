import type { AnalysisScope } from '../lib/inspection'

interface ScopeBarProps {
  scope: AnalysisScope
}

function formatOffset(offset: number, documentByteCount: number): string {
  const width = Math.max(
    4,
    Math.max(0, documentByteCount - 1).toString(16).length,
  )
  return '0x' + offset.toString(16).toUpperCase().padStart(width, '0')
}

export function ScopeBar({ scope }: ScopeBarProps) {
  const scopeName =
    scope.scopeType === 'document'
      ? 'Entire document'
      : scope.scopeType === 'selection'
        ? 'Selection'
        : scope.documentByteCount === 0
          ? 'Empty document'
          : 'No active selection'
  const range =
    scope.offsetStart === null || scope.offsetEnd === null
      ? 'No byte range'
      : formatOffset(scope.offsetStart, scope.documentByteCount) +
        '–' +
        formatOffset(scope.offsetEnd, scope.documentByteCount)
  const count =
    scope.scopeType === 'document'
      ? `${scope.byteCount} ${scope.byteCount === 1 ? 'byte' : 'bytes'}`
      : `${scope.byteCount} of ${scope.documentByteCount} bytes`

  return (
    <section
      className={
        scope.status === 'last-valid' ? 'scope-bar is-stale' : 'scope-bar'
      }
      aria-labelledby="analysis-scope-heading"
      aria-live="polite"
    >
      <div className="scope-primary">
        <span id="analysis-scope-heading" className="scope-kicker">
          Analysis scope
        </span>
        <strong>{scopeName}</strong>
      </div>
      <code className="scope-range">{range}</code>
      <span className="scope-count">{count}</span>
      {scope.status === 'last-valid' ? (
        <div id="stale-inspection-status" className="scope-stale-status">
          <strong>Last valid data</strong>
          <span>
            Current source is invalid. Derived values below use the previous
            valid byte document.
          </span>
        </div>
      ) : null}
    </section>
  )
}
