import { useRef, useState, type ReactNode } from 'react'

export function ResizableSplit({
  children,
  structure,
}: {
  children: ReactNode
  structure?: boolean
}) {
  const [width, setWidth] = useState(390)
  const [height, setHeight] = useState(410)
  const parent = useRef<HTMLDivElement>(null)
  return (
    <>
      <div
        ref={parent}
        className={'split-workspace resizable-workspace' + (structure ? ' has-structure' : '')}
        style={
          {
            '--inspector-width': width + 'px',
            '--workspace-height': height + 'px',
          } as React.CSSProperties
        }
      >
        {children}
        <div
          role="separator"
          aria-label="Resize inspector"
          aria-orientation="vertical"
          aria-valuemin={260}
          aria-valuemax={600}
          aria-valuenow={width}
          tabIndex={0}
          className="panel-resizer"
          onKeyDown={(e) => {
            if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
              e.preventDefault()
              setWidth((v) => Math.max(260, Math.min(600, v + (e.key === 'ArrowLeft' ? 20 : -20))))
            }
          }}
          onPointerDown={(e) => {
            e.currentTarget.setPointerCapture(e.pointerId)
          }}
          onPointerMove={(e) => {
            if (e.currentTarget.hasPointerCapture(e.pointerId) && parent.current)
              setWidth(
                Math.max(
                  260,
                  Math.min(600, parent.current.getBoundingClientRect().right - e.clientX),
                ),
              )
          }}
          onPointerUp={(e) => e.currentTarget.releasePointerCapture(e.pointerId)}
        />
      </div>
      <div className="layout-height">
        <label>
          Workspace height{' '}
          <input
            type="range"
            aria-label="Workspace height"
            min={320}
            max={900}
            step={10}
            value={height}
            onChange={(e) => setHeight(Number(e.target.value))}
          />
        </label>
      </div>
    </>
  )
}
