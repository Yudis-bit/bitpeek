import { useState } from 'react'
import type { StructureField, StructureParseResult } from '../lib/structures'
import type { SelectionRange } from '../lib/bytes'

interface StructureInspectorProps {
  structure: StructureParseResult | null
  selectedFormat?: string
  onSelectFormat?: (format: string) => void
  selectedRange: SelectionRange | null
  onSelectRange: (start: number, endInclusive: number) => void
  onExportEvidence: () => void
  onLoadCustomSchema?: (schemaJson: string) => void
}

export function StructureInspector({
  structure,
  selectedFormat = 'auto',
  onSelectFormat,
  selectedRange,
  onSelectRange,
  onExportEvidence,
  onLoadCustomSchema,
}: StructureInspectorProps) {
  const [collapsedNodes, setCollapsedNodes] = useState<Set<string>>(new Set())
  const [schemaModalOpen, setSchemaModalOpen] = useState(false)
  const [customSchemaText, setCustomSchemaText] = useState('')

  const formatSelector = onSelectFormat ? (
    <select
      aria-label="Format parser"
      className="compact-select"
      value={selectedFormat}
      onChange={(e) => onSelectFormat(e.target.value)}
      style={{
        height: '28px',
        padding: '2px 8px',
        fontSize: '12px',
        fontFamily: 'var(--mono)',
        background: 'var(--paper)',
        border: '1px solid var(--border)',
        color: 'var(--ink)',
      }}
    >
      <option value="auto">Auto Detect</option>
      <option value="elf">ELF (Linux/BSD)</option>
      <option value="pe">PE / COFF (Windows)</option>
      <option value="wasm">WASM (WebAssembly)</option>
      <option value="png">PNG Image</option>
      <option value="zip">ZIP Archive</option>
      <option value="gpt">GPT Partition Table</option>
      <option value="ubi">UBI Volume</option>
      <option value="squashfs">SquashFS Superblock</option>
      <option value="safetensors">SafeTensors Weights</option>
      <option value="bitcoin">Bitcoin TX</option>
      <option value="ethereum">Ethereum RLP</option>
      <option value="custom-schema">Custom Schema</option>
    </select>
  ) : null

  if (!structure) {
    return (
      <section className="structure-panel" aria-labelledby="structure-heading">
        <div className="section-title-row">
          <div className="structure-heading-group">
            <h2 id="structure-heading" className="section-title">
              Structure
            </h2>
            {formatSelector}
          </div>
        </div>
        <p className="empty-structure-note">
          No structured format recognized. Select a parser above (ELF, PE, WASM, PNG, ZIP, GPT, UBI, SquashFS, SafeTensors, Bitcoin, Ethereum), or load a custom schema.
        </p>
        <div className="compact-actions" style={{ marginTop: '10px' }}>
          {onLoadCustomSchema && (
            <button
              type="button"
              className="compact-button"
              onClick={() => {
                const sample = JSON.stringify(
                  {
                    schemaVersion: 2,
                    name: 'Header_V2',
                    magic: [0x42, 0x49, 0x54, 0x50],
                    fields: [
                      { name: 'magic', offset: 0, length: 4, type: 'hex' },
                      { name: 'version', offset: 4, length: 2, type: 'u16_le' },
                      { name: 'flags', offset: 6, length: 2, type: 'u16_le' },
                      { name: 'dataLength', offset: 8, length: 4, type: 'u32_le' },
                    ],
                  },
                  null,
                  2,
                )
                onLoadCustomSchema(sample)
              }}
            >
              Load Sample Schema
            </button>
          )}
          {onLoadCustomSchema && !schemaModalOpen && (
            <button
              type="button"
              className="secondary-button"
              onClick={() => setSchemaModalOpen(true)}
            >
              Custom Schema JSON
            </button>
          )}
        </div>
        {onLoadCustomSchema && schemaModalOpen ? (
          <div className="schema-input-dialog" style={{ marginTop: '12px' }}>
            <textarea
              aria-label="Custom structure schema JSON"
              className="source-editor"
              value={customSchemaText}
              onChange={(e) => setCustomSchemaText(e.target.value)}
              placeholder='Paste JSON schema: {"schemaVersion": 2, "name": "Header", ...}'
              rows={6}
            />
            <div className="compact-actions" style={{ marginTop: '6px' }}>
              <button
                type="button"
                className="compact-button"
                onClick={() => {
                  if (customSchemaText.trim()) {
                    onLoadCustomSchema(customSchemaText)
                    setSchemaModalOpen(false)
                  }
                }}
              >
                Apply Schema
              </button>
              <button
                type="button"
                className="compact-button"
                onClick={() => setSchemaModalOpen(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        ) : null}
      </section>
    )
  }

  const toggleCollapse = (id: string) => {
    setCollapsedNodes((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const renderFieldTree = (field: StructureField, depth = 0): React.ReactNode => {
    const isCollapsed = collapsedNodes.has(field.id)
    const hasChildren = field.children && field.children.length > 0
    const isSelected =
      selectedRange !== null &&
      selectedRange.start === field.range.start &&
      selectedRange.end === field.range.end - 1

    const isEnclosing =
      selectedRange !== null &&
      selectedRange.start >= field.range.start &&
      selectedRange.end < field.range.end

    return (
      <div
        key={field.id}
        className={`structure-node depth-${depth} status-${field.status} ${
          isSelected ? 'is-selected' : isEnclosing ? 'is-enclosing' : ''
        }`}
      >
        <div className="structure-node-row">
          {hasChildren ? (
            <button
              type="button"
              className="tree-toggle"
              aria-label={(isCollapsed ? 'Expand ' : 'Collapse ') + field.label}
              aria-expanded={!isCollapsed}
              onClick={() => toggleCollapse(field.id)}
            >
              {isCollapsed ? '▶' : '▼'}
            </button>
          ) : (
            <span className="tree-leaf-spacer" />
          )}

          <button
            type="button"
            className="structure-field-btn"
            onClick={() => onSelectRange(field.range.start, field.range.end - 1)}
            title={`Offset 0x${field.range.start.toString(16).toUpperCase()}..0x${field.range.end.toString(16).toUpperCase()} (${field.range.end - field.range.start} bytes)`}
          >
            <span className="field-label">{field.label}</span>
            <span className="field-range">
              [0x{field.range.start.toString(16).toUpperCase()}..0x{field.range.end.toString(16).toUpperCase()})
            </span>
            <span className="field-value">{String(field.interpretedValue)}</span>
            {field.status !== 'valid' && (
              <span className={`status-badge badge-${field.status}`}>
                {field.status}
              </span>
            )}
          </button>
        </div>

        {field.reason && (
          <div className="field-reason" role="note">
            {field.reason}
          </div>
        )}

        {hasChildren && !isCollapsed && (
          <div className="structure-node-children">
            {field.children!.map((child) => renderFieldTree(child, depth + 1))}
          </div>
        )}
      </div>
    )
  }

  return (
    <section className="structure-panel" aria-labelledby="structure-heading">
      <div className="section-title-row">
        <div className="structure-heading-group">
          <h2 id="structure-heading" className="section-title">
            Structure ({structure.format.toUpperCase()})
          </h2>
          <span className={`format-status status-${structure.status}`}>
            {structure.status}
          </span>
          {formatSelector}
        </div>
        <div className="structure-actions">
          <button
            type="button"
            className="compact-button"
            onClick={onExportEvidence}
            title="Generate and copy reproducible evidence report"
          >
            Copy Evidence
          </button>
        </div>
      </div>

      {structure.warnings.length > 0 && (
        <div className="structure-warnings" role="alert">
          {structure.warnings.map((w, idx) => (
            <div key={idx} className="warning-item">
              ⚠ {w}
            </div>
          ))}
        </div>
      )}

      <div className="structure-tree" aria-label="Structure fields">
        {structure.fields.map((f) => renderFieldTree(f, 0))}
      </div>
    </section>
  )
}
