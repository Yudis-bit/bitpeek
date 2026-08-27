import {
  byteToAscii,
  getSelectionRange,
  type ByteSelection,
} from '../lib/bytes'
import {
  type KeyboardEvent,
  type PointerEvent,
  useEffect,
  useMemo,
  useRef,
} from 'react'

const BYTES_PER_ROW = 16
const COLUMN_LABELS = Array.from({ length: BYTES_PER_ROW }, (_, index) =>
  index.toString(16).toUpperCase().padStart(2, '0'),
)

interface ByteTableProps {
  bytes: Uint8Array
  selection: ByteSelection | null
  onSelectionChange: (selection: ByteSelection | null) => void
}

function isSelected(index: number, start: number, end: number): boolean {
  return index >= start && index <= end
}

export function ByteTable({
  bytes,
  selection,
  onSelectionChange,
}: ByteTableProps) {
  const dragging = useRef(false)
  const dragAnchor = useRef(0)
  const byteRefs = useRef(new Map<number, HTMLButtonElement>())
  const focusAfterRender = useRef<number | null>(null)
  const range = getSelectionRange(selection, bytes.length)

  const rows = useMemo(() => {
    const result: Array<{ offset: number; values: number[] }> = []
    for (let offset = 0; offset < bytes.length; offset += BYTES_PER_ROW) {
      result.push({
        offset,
        values: Array.from(bytes.slice(offset, offset + BYTES_PER_ROW)),
      })
    }
    return result
  }, [bytes])

  useEffect(() => {
    const stopDragging = () => {
      dragging.current = false
    }
    window.addEventListener('pointerup', stopDragging)
    window.addEventListener('pointercancel', stopDragging)
    return () => {
      window.removeEventListener('pointerup', stopDragging)
      window.removeEventListener('pointercancel', stopDragging)
    }
  }, [])

  useEffect(() => {
    const target = focusAfterRender.current
    if (target !== null) {
      byteRefs.current.get(target)?.focus()
      focusAfterRender.current = null
    }
  }, [selection])

  const selectFromPointer = (
    index: number,
    event: PointerEvent<HTMLButtonElement>,
  ) => {
    if (event.button !== 0) return
    event.currentTarget.focus()
    const anchor = event.shiftKey && selection ? selection.anchor : index
    dragging.current = true
    dragAnchor.current = anchor
    onSelectionChange({ anchor, focus: index })
    event.preventDefault()
  }

  const extendDrag = (index: number, event: PointerEvent<HTMLButtonElement>) => {
    if (dragging.current && (event.buttons & 1) === 1) {
      onSelectionChange({ anchor: dragAnchor.current, focus: index })
    }
  }

  const handleKeyDown = (
    index: number,
    event: KeyboardEvent<HTMLButtonElement>,
  ) => {
    let next: number
    switch (event.key) {
      case 'ArrowLeft':
        next = index - 1
        break
      case 'ArrowRight':
        next = index + 1
        break
      case 'ArrowUp':
        next = index - BYTES_PER_ROW
        break
      case 'ArrowDown':
        next = index + BYTES_PER_ROW
        break
      case 'Home':
        next = Math.floor(index / BYTES_PER_ROW) * BYTES_PER_ROW
        break
      case 'End':
        next = Math.min(
          bytes.length - 1,
          Math.floor(index / BYTES_PER_ROW) * BYTES_PER_ROW + 15,
        )
        break
      case 'Escape':
        onSelectionChange(null)
        event.currentTarget.blur()
        event.preventDefault()
        return
      default:
        return
    }

    event.preventDefault()
    const clamped = Math.max(0, Math.min(bytes.length - 1, next))
    focusAfterRender.current = clamped
    onSelectionChange(
      event.shiftKey
        ? { anchor: selection?.anchor ?? index, focus: clamped }
        : { anchor: clamped, focus: clamped },
    )
  }

  return (
    <section className="bytes-panel" aria-labelledby="bytes-heading">
      <div className="panel-heading">
        <h2 id="bytes-heading" className="section-title">
          Bytes
        </h2>
        <span>{rows.length} {rows.length === 1 ? 'row' : 'rows'} · 16 bytes/row</span>
      </div>

      {bytes.length === 0 ? (
        <div className="workspace-placeholder">No bytes to inspect.</div>
      ) : (
        <div className="byte-table-scroll">
          <div className="byte-table" role="grid" aria-label="Byte data">
            <div className="byte-table-header" role="row">
              <span className="offset-heading" role="columnheader">
                Offset
              </span>
              <div className="hex-column-headings" aria-label="Hex byte columns">
                {COLUMN_LABELS.map((label) => (
                  <span key={label}>{label}</span>
                ))}
              </div>
              <span className="ascii-heading" role="columnheader">
                ASCII
              </span>
            </div>

            {rows.map((row) => (
              <div className="byte-row" role="row" key={row.offset}>
                <span className="offset-cell" role="rowheader">
                  {row.offset.toString(16).toUpperCase().padStart(6, '0')}
                </span>
                <div className="hex-cells" role="gridcell">
                  {row.values.map((byte, column) => {
                    const index = row.offset + column
                    const selected = range
                      ? isSelected(index, range.start, range.end)
                      : false
                    return (
                      <button
                        key={index}
                        ref={(node) => {
                          if (node) byteRefs.current.set(index, node)
                          else byteRefs.current.delete(index)
                        }}
                        type="button"
                        className={selected ? 'byte-cell is-selected' : 'byte-cell'}
                        tabIndex={selection?.focus === index || (!selection && index === 0) ? 0 : -1}
                        aria-selected={selected}
                        aria-label={`Byte ${index}, hexadecimal ${byte
                          .toString(16)
                          .toUpperCase()
                          .padStart(2, '0')}`}
                        onPointerDown={(event) => selectFromPointer(index, event)}
                        onPointerEnter={(event) => extendDrag(index, event)}
                        onKeyDown={(event) => handleKeyDown(index, event)}
                      >
                        {byte.toString(16).toUpperCase().padStart(2, '0')}
                      </button>
                    )
                  })}
                </div>
                <div className="ascii-cells" role="gridcell" aria-label={`ASCII at offset ${row.offset}`}>
                  {row.values.map((byte, column) => {
                    const index = row.offset + column
                    const selected = range
                      ? isSelected(index, range.start, range.end)
                      : false
                    return (
                      <span
                        key={index}
                        className={selected ? 'ascii-cell is-selected' : 'ascii-cell'}
                      >
                        {byteToAscii(byte)}
                      </span>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}
