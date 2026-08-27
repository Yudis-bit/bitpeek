import { formatBinary, type SelectionRange } from '../lib/bytes'

interface BitInspectorProps {
  bytes: Uint8Array
  range: SelectionRange | null
  onToggle: (bit: number) => void
}

const BITS = [7, 6, 5, 4, 3, 2, 1, 0]

export function BitInspector({ bytes, range, onToggle }: BitInspectorProps) {
  const singleByte = bytes.length === 1 ? bytes[0] : undefined

  return (
    <section className="bits-panel" aria-labelledby="bits-heading">
      <div className="panel-heading bits-heading-row">
        <h2 id="bits-heading" className="section-title">
          Bits
        </h2>
        {singleByte !== undefined && range ? (
          <span className="selected-byte-summary">
            offset 0x{range.start.toString(16).toUpperCase().padStart(4, '0')} · 0x
            {singleByte.toString(16).toUpperCase().padStart(2, '0')} · {singleByte}
          </span>
        ) : null}
      </div>

      {range === null ? (
        <div className="bits-placeholder">Select one byte to inspect its bits.</div>
      ) : singleByte === undefined ? (
        <div className="multi-bit-view">
          <span>Selected binary</span>
          <code>{formatBinary(bytes)}</code>
          <small>Select exactly one byte to toggle individual bits.</small>
        </div>
      ) : (
        <div className="bit-grid" role="group" aria-label="Selected byte bits">
          <span className="bit-row-label">bit</span>
          {BITS.map((bit) => <span className="bit-index" key={`label-${bit}`}>{bit}</span>)}
          <span className="bit-row-label">value</span>
          {BITS.map((bit) => {
            const active = (singleByte & (1 << bit)) !== 0
            return (
              <button
                key={bit}
                type="button"
                className={active ? 'bit-toggle is-active' : 'bit-toggle'}
                aria-label={`Toggle bit ${bit}`}
                aria-pressed={active}
                onClick={() => onToggle(bit)}
              >
                {active ? '1' : '0'}
              </button>
            )
          })}
        </div>
      )}
    </section>
  )
}
