import {
  decodeUtf8,
  formatAscii,
  formatBinary,
  formatDecimal,
  formatHex,
  formatUtf8Preview,
  signedBigEndian,
  signedLittleEndian,
  unsignedBigEndian,
  unsignedLittleEndian,
  type SelectionRange,
} from '../lib/bytes'

interface InterpretationPanelProps {
  bytes: Uint8Array
  range: SelectionRange | null
  onCopy: (value: string, label: string) => void
}

interface ValueWithCopyProps {
  value: string
  copyValue?: string
  label: string
  onCopy: (value: string, label: string) => void
}

function ValueWithCopy({ value, copyValue, label, onCopy }: ValueWithCopyProps) {
  return (
    <span className="value-with-copy">
      <code>{value}</code>
      <button type="button" className="inline-copy" onClick={() => onCopy(copyValue ?? value, label)}>
        Copy
      </button>
    </span>
  )
}

export function InterpretationPanel({
  bytes,
  range,
  onCopy,
}: InterpretationPanelProps) {
  const length = bytes.length
  const bitWidth = length * 8
  const hasInteger = length > 0 && length <= 8

  const unsignedBe = hasInteger ? unsignedBigEndian(bytes).toString() : ''
  const signedBe = hasInteger ? signedBigEndian(bytes).toString() : ''
  const unsignedLe = hasInteger ? unsignedLittleEndian(bytes).toString() : ''
  const signedLe = hasInteger ? signedLittleEndian(bytes).toString() : ''

  return (
    <aside className="interpretation-panel" aria-labelledby="interpretation-heading">
      <div className="panel-heading">
        <h2 id="interpretation-heading" className="section-title">
          Interpretation
        </h2>
      </div>

      {range === null ? (
        <div className="workspace-placeholder">Select one or more bytes.</div>
      ) : (
        <div className="inspector-content">
          <section className="inspector-section" aria-labelledby="selection-heading">
            <h3 id="selection-heading">Selection</h3>
            <dl className="property-list">
              <div>
                <dt>Offset</dt>
                <dd><code>0x{range.start.toString(16).toUpperCase().padStart(4, '0')}</code></dd>
              </div>
              <div>
                <dt>Length</dt>
                <dd>{length} {length === 1 ? 'byte' : 'bytes'} / {bitWidth} bits</dd>
              </div>
            </dl>
          </section>

          <section className="inspector-section" aria-labelledby="integer-heading">
            <h3 id="integer-heading">Integer · {bitWidth}-bit</h3>
            {length === 1 ? (
              <dl className="property-list numeric-list">
                <div>
                  <dt>uint8</dt>
                  <dd><ValueWithCopy value={unsignedBe} label="uint8" onCopy={onCopy} /></dd>
                </div>
                <div>
                  <dt>int8</dt>
                  <dd><ValueWithCopy value={signedBe} label="int8" onCopy={onCopy} /></dd>
                </div>
              </dl>
            ) : hasInteger ? (
              <div className="integer-table-wrap">
                <table className="integer-table">
                  <thead>
                    <tr>
                      <th scope="col" />
                      <th scope="col">Big endian</th>
                      <th scope="col">Little endian</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <th scope="row">Unsigned</th>
                      <td><ValueWithCopy value={unsignedBe} label="unsigned big endian" onCopy={onCopy} /></td>
                      <td><ValueWithCopy value={unsignedLe} label="unsigned little endian" onCopy={onCopy} /></td>
                    </tr>
                    <tr>
                      <th scope="row">Signed</th>
                      <td><ValueWithCopy value={signedBe} label="signed big endian" onCopy={onCopy} /></td>
                      <td><ValueWithCopy value={signedLe} label="signed little endian" onCopy={onCopy} /></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="inspector-note">Integer view supports selections up to 8 bytes.</p>
            )}
          </section>

          <section className="inspector-section" aria-labelledby="representations-heading">
            <h3 id="representations-heading">Representations</h3>
            <dl className="representation-list">
              <div>
                <dt>Hex</dt>
                <dd><ValueWithCopy value={formatHex(bytes)} label="hex" onCopy={onCopy} /></dd>
              </div>
              <div>
                <dt>Binary</dt>
                <dd><ValueWithCopy value={formatBinary(bytes)} label="binary" onCopy={onCopy} /></dd>
              </div>
              <div>
                <dt>Decimal bytes</dt>
                <dd><ValueWithCopy value={formatDecimal(bytes)} label="decimal bytes" onCopy={onCopy} /></dd>
              </div>
              <div>
                <dt>ASCII</dt>
                <dd><ValueWithCopy value={formatAscii(bytes)} label="ASCII" onCopy={onCopy} /></dd>
              </div>
              <div>
                <dt>UTF-8</dt>
                <dd><ValueWithCopy value={formatUtf8Preview(bytes) || '(empty)'} copyValue={decodeUtf8(bytes)} label="UTF-8 text" onCopy={onCopy} /></dd>
              </div>
            </dl>
          </section>
        </div>
      )}
    </aside>
  )
}
