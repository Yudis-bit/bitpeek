import {
  byteToAscii,
  getSelectionRange,
  type ByteSelection,
} from '../lib/bytes'
import {
  type KeyboardEvent,
  type MouseEvent,
  type PointerEvent,
  type UIEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'

const BYTES_PER_ROW = 16
const ROW_HEIGHT = 27
const HEADER_HEIGHT = 26
const OVERSCAN_ROWS = 8
const COLUMN_LABELS = Array.from({ length: BYTES_PER_ROW }, (_, index) =>
  index.toString(16).toUpperCase().padStart(2, '0'),
)

interface ByteTableProps {
  bytes: Uint8Array
  selection: ByteSelection | null
  searchOffsets: number[]
  searchLength: number
  activeSearchOffset: number | null
  onSelectionChange: (selection: ByteSelection | null) => void
  onByteEdit: (index: number, value: number) => void
}

interface EditState {
  index: number
  value: string
  error: boolean
}

function isWithin(index: number, start: number, end: number): boolean {
  return index >= start && index <= end
}

export function ByteTable({
  bytes,
  selection,
  searchOffsets,
  searchLength,
  activeSearchOffset,
  onSelectionChange,
  onByteEdit,
}: ByteTableProps) {
  const dragging = useRef(false)
  const dragAnchor = useRef(0)
  const byteRefs = useRef(new Map<number, HTMLButtonElement>())
  const focusAfterRender = useRef<number | null>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportHeight, setViewportHeight] = useState(360)
  const [editing, setEditing] = useState<EditState | null>(null)
  const range = getSelectionRange(selection, bytes.length)
  const totalRows = Math.ceil(bytes.length / BYTES_PER_ROW)
  const bodyScrollTop = Math.max(0, scrollTop - HEADER_HEIGHT)
  const firstRow = Math.max(
    0,
    Math.floor(bodyScrollTop / ROW_HEIGHT) - OVERSCAN_ROWS,
  )
  const visibleRowCount =
    Math.ceil(viewportHeight / ROW_HEIGHT) + OVERSCAN_ROWS * 2
  const finalRow = Math.min(totalRows, firstRow + visibleRowCount)

  const rows = useMemo(() => {
    const result: Array<{ offset: number; values: number[] }> = []
    for (let row = firstRow; row < finalRow; row += 1) {
      const offset = row * BYTES_PER_ROW
      result.push({
        offset,
        values: Array.from(bytes.slice(offset, offset + BYTES_PER_ROW)),
      })
    }
    return result
  }, [bytes, finalRow, firstRow])

  const visibleMatchIndexes = useMemo(() => {
    const result = new Set<number>()
    if (searchLength === 0) return result
    const visibleStart = firstRow * BYTES_PER_ROW
    const visibleEnd = Math.min(
      bytes.length - 1,
      finalRow * BYTES_PER_ROW - 1,
    )
    for (const offset of searchOffsets) {
      const matchEnd = offset + searchLength - 1
      if (matchEnd < visibleStart || offset > visibleEnd) continue
      for (
        let index = Math.max(offset, visibleStart);
        index <= Math.min(matchEnd, visibleEnd);
        index += 1
      ) {
        result.add(index)
      }
    }
    return result
  }, [bytes.length, finalRow, firstRow, searchLength, searchOffsets])

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
    const viewport = scrollRef.current
    if (!viewport) return
    const resizeObserver = new ResizeObserver(() => {
      setViewportHeight(viewport.clientHeight)
    })
    resizeObserver.observe(viewport)
    setViewportHeight(viewport.clientHeight)
    return () => resizeObserver.disconnect()
  }, [])

  useEffect(() => {
    const focus = selection?.focus
    const viewport = scrollRef.current
    if (focus === undefined || !viewport) return
    const targetRow = Math.floor(focus / BYTES_PER_ROW)
    const targetTop = HEADER_HEIGHT + targetRow * ROW_HEIGHT
    const targetBottom = targetTop + ROW_HEIGHT
    const visibleTop = viewport.scrollTop + HEADER_HEIGHT
    const visibleBottom = viewport.scrollTop + viewport.clientHeight
    if (targetTop < visibleTop || targetBottom > visibleBottom) {
      viewport.scrollTop = Math.max(
        0,
        targetTop - Math.floor(viewport.clientHeight / 2),
      )
    }
  }, [selection])

  useEffect(() => {
    const target = focusAfterRender.current
    if (target === null) return
    const node = byteRefs.current.get(target)
    if (node) {
      node.focus()
      focusAfterRender.current = null
    }
  }, [firstRow, finalRow, selection])

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

  const selectFromKeyboardClick = (
    index: number,
    event: MouseEvent<HTMLButtonElement>,
  ) => {
    if (event.detail !== 0) return
    const anchor = event.shiftKey && selection ? selection.anchor : index
    onSelectionChange({ anchor, focus: index })
  }

  const extendDrag = (index: number, event: PointerEvent<HTMLButtonElement>) => {
    if (dragging.current && (event.buttons & 1) === 1) {
      onSelectionChange({ anchor: dragAnchor.current, focus: index })
    }
  }

  const startEditing = (index: number, value: number) => {
    setEditing({
      index,
      value: value.toString(16).toUpperCase().padStart(2, '0'),
      error: false,
    })
  }

  const commitEditing = (cancelInvalid: boolean) => {
    if (!editing) return
    if (/^[0-9a-fA-F]{2}$/.test(editing.value)) {
      onByteEdit(editing.index, Number.parseInt(editing.value, 16))
      setEditing(null)
    } else if (cancelInvalid) {
      setEditing(null)
    } else {
      setEditing({ ...editing, error: true })
    }
  }

  const handleKeyDown = (
    index: number,
    byte: number,
    event: KeyboardEvent<HTMLButtonElement>,
  ) => {
    if (event.key === 'Enter' || event.key === 'F2') {
      event.preventDefault()
      startEditing(index, byte)
      return
    }

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

  const handleScroll = (event: UIEvent<HTMLDivElement>) => {
    setScrollTop(event.currentTarget.scrollTop)
    setViewportHeight(event.currentTarget.clientHeight)
  }

  return (
    <section className="bytes-panel" aria-labelledby="bytes-heading">
      <div className="panel-heading">
        <h2 id="bytes-heading" className="section-title">
          Bytes
        </h2>
        <span>
          {bytes.length} {bytes.length === 1 ? 'byte' : 'bytes'} · {totalRows}{' '}
          {totalRows === 1 ? 'row' : 'rows'}
        </span>
      </div>

      {bytes.length === 0 ? (
        <div className="workspace-placeholder">No bytes to inspect.</div>
      ) : (
        <div
          ref={scrollRef}
          className="byte-table-scroll"
          onScroll={handleScroll}
        >
          <div className="byte-table" aria-label="Byte data">
            <div className="byte-table-header">
              <span className="offset-heading">Offset</span>
              <div className="hex-column-headings" aria-label="Hex byte columns">
                {COLUMN_LABELS.map((label) => (
                  <span key={label}>{label}</span>
                ))}
              </div>
              <span className="ascii-heading">ASCII</span>
            </div>

            <div
              className="virtual-byte-body"
              style={{ height: totalRows * ROW_HEIGHT }}
            >
              <div
                className="virtual-byte-rows"
                style={{ top: firstRow * ROW_HEIGHT }}
              >
                {rows.map((row) => (
                  <div className="byte-row" key={row.offset}>
                    <span className="offset-cell">
                      {row.offset.toString(16).toUpperCase().padStart(6, '0')}
                    </span>
                    <div className="hex-cells">
                      {row.values.map((byte, column) => {
                        const index = row.offset + column
                        const selected = range
                          ? isWithin(index, range.start, range.end)
                          : false
                        const searchMatch = visibleMatchIndexes.has(index)
                        const activeMatch =
                          activeSearchOffset !== null &&
                          isWithin(
                            index,
                            activeSearchOffset,
                            activeSearchOffset + searchLength - 1,
                          )
                        const classes = [
                          'byte-cell',
                          searchMatch ? 'is-match' : '',
                          activeMatch ? 'is-active-match' : '',
                          selected ? 'is-selected' : '',
                        ]
                          .filter(Boolean)
                          .join(' ')

                        return editing?.index === index ? (
                          <input
                            key={index}
                            className={
                              editing.error
                                ? 'byte-edit-input has-error'
                                : 'byte-edit-input'
                            }
                            value={editing.value}
                            maxLength={2}
                            autoFocus
                            aria-label={
                              'Edit byte ' + index + ' as hexadecimal'
                            }
                            aria-invalid={editing.error}
                            onChange={(event) => {
                              const value = event.target.value.toUpperCase()
                              if (/^[0-9A-F]{0,2}$/.test(value)) {
                                setEditing({ index, value, error: false })
                              }
                            }}
                            onBlur={() => commitEditing(true)}
                            onKeyDown={(event) => {
                              if (event.key === 'Enter') {
                                event.preventDefault()
                                commitEditing(false)
                              } else if (event.key === 'Escape') {
                                event.preventDefault()
                                setEditing(null)
                              }
                            }}
                          />
                        ) : (
                          <button
                            key={index}
                            ref={(node) => {
                              if (node) byteRefs.current.set(index, node)
                              else byteRefs.current.delete(index)
                            }}
                            type="button"
                            className={classes}
                            tabIndex={
                              selection?.focus === index ||
                              (!selection && index === 0)
                                ? 0
                                : -1
                            }
                            aria-pressed={selected}
                            aria-label={
                              'Byte ' +
                              index +
                              ', hexadecimal ' +
                              byte
                                .toString(16)
                                .toUpperCase()
                                .padStart(2, '0')
                            }
                            onPointerDown={(event) =>
                              selectFromPointer(index, event)
                            }
                            onPointerEnter={(event) => extendDrag(index, event)}
                            onClick={(event) =>
                              selectFromKeyboardClick(index, event)
                            }
                            onDoubleClick={() => startEditing(index, byte)}
                            onKeyDown={(event) =>
                              handleKeyDown(index, byte, event)
                            }
                          >
                            {byte
                              .toString(16)
                              .toUpperCase()
                              .padStart(2, '0')}
                          </button>
                        )
                      })}
                    </div>
                    <div
                      className="ascii-cells"
                      aria-label={'ASCII at offset ' + row.offset}
                    >
                      {row.values.map((byte, column) => {
                        const index = row.offset + column
                        const selected = range
                          ? isWithin(index, range.start, range.end)
                          : false
                        const searchMatch = visibleMatchIndexes.has(index)
                        return (
                          <span
                            key={index}
                            className={[
                              'ascii-cell',
                              searchMatch ? 'is-match' : '',
                              selected ? 'is-selected' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
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
          </div>
        </div>
      )}
    </section>
  )
}
