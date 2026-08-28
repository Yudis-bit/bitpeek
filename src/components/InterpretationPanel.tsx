import { useEffect, useState } from 'react'
import {
  crc16CcittFalse,
  crc32Ieee,
  detectFileSignature,
  formatFloat,
  readFloat16,
  readFloat32,
  readFloat64,
  shannonEntropy,
  sum8,
  xor8,
} from '../lib/analysis'
import {
  decodeUtf8,
  formatAscii,
  formatBase64,
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
import { digestHex } from '../lib/crypto'

interface InterpretationPanelProps {
  bytes: Uint8Array
  documentBytes: Uint8Array
  range: SelectionRange | null
  onCopy: (value: string, label: string) => void
}

interface ValueWithCopyProps {
  value: string
  copyValue?: string | (() => string)
  label: string
  onCopy: (value: string, label: string) => void
}

function ValueWithCopy({
  value,
  copyValue,
  label,
  onCopy,
}: ValueWithCopyProps) {
  const copyCurrentValue = () => {
    const resolved =
      typeof copyValue === 'function' ? copyValue() : (copyValue ?? value)
    onCopy(resolved, label)
  }

  return (
    <span className="value-with-copy">
      <code>{value}</code>
      <button
        type="button"
        className="inline-copy"
        aria-label={'Copy ' + label}
        onClick={copyCurrentValue}
      >
        Copy
      </button>
    </span>
  )
}

function preview(
  bytes: Uint8Array,
  formatter: (value: Uint8Array) => string,
  limit = 128,
): string {
  if (bytes.length <= limit) return formatter(bytes)
  return (
    formatter(bytes.subarray(0, limit)) +
    ' … (first ' +
    limit +
    ' of ' +
    bytes.length +
    ' bytes)'
  )
}

function paddedHex(value: number, width: number): string {
  return '0x' + value.toString(16).toUpperCase().padStart(width, '0')
}

export function InterpretationPanel({
  bytes,
  documentBytes,
  range,
  onCopy,
}: InterpretationPanelProps) {
  const [digests, setDigests] = useState<{
    source: Uint8Array | null
    sha256: string | null
    sha512: string | null
    error: boolean
  }>({ source: null, sha256: null, sha512: null, error: false })
  const length = bytes.length
  const bitWidth = length * 8
  const hasInteger = length > 0 && length <= 8
  const signature = detectFileSignature(documentBytes)

  useEffect(() => {
    let active = true
    if (bytes.length === 0) return

    void Promise.all([
      digestHex(bytes, 'SHA-256'),
      digestHex(bytes, 'SHA-512'),
    ])
      .then(([sha256, sha512]) => {
        if (active) setDigests({ source: bytes, sha256, sha512, error: false })
      })
      .catch(() => {
        if (active) {
          setDigests({ source: bytes, sha256: null, sha512: null, error: true })
        }
      })

    return () => {
      active = false
    }
  }, [bytes])

  const currentDigests =
    digests.source === bytes
      ? digests
      : { source: null, sha256: null, sha512: null, error: false }

  const unsignedBe = hasInteger ? unsignedBigEndian(bytes).toString() : ''
  const signedBe = hasInteger ? signedBigEndian(bytes).toString() : ''
  const unsignedLe = hasInteger ? unsignedLittleEndian(bytes).toString() : ''
  const signedLe = hasInteger ? signedLittleEndian(bytes).toString() : ''

  let floatLabel: string | null = null
  let floatBe: string | null = null
  let floatLe: string | null = null
  if (length === 2) {
    floatLabel = 'float16'
    floatBe = formatFloat(readFloat16(bytes, 'big'))
    floatLe = formatFloat(readFloat16(bytes, 'little'))
  } else if (length === 4) {
    floatLabel = 'float32'
    floatBe = formatFloat(readFloat32(bytes, 'big'))
    floatLe = formatFloat(readFloat32(bytes, 'little'))
  } else if (length === 8) {
    floatLabel = 'float64'
    floatBe = formatFloat(readFloat64(bytes, 'big'))
    floatLe = formatFloat(readFloat64(bytes, 'little'))
  }

  return (
    <aside
      className="interpretation-panel"
      aria-labelledby="interpretation-heading"
    >
      <div className="panel-heading">
        <h2 id="interpretation-heading" className="section-title">
          Interpretation
        </h2>
        {signature ? <span>{signature.name}</span> : null}
      </div>

      {range === null ? (
        <div className="workspace-placeholder">Select one or more bytes.</div>
      ) : (
        <div className="inspector-content">
          <section
            className="inspector-section"
            aria-labelledby="selection-heading"
          >
            <h3 id="selection-heading">Selection</h3>
            <dl className="property-list">
              <div>
                <dt>Start</dt>
                <dd>
                  <code>
                    0x{range.start.toString(16).toUpperCase().padStart(4, '0')}
                  </code>
                </dd>
              </div>
              <div>
                <dt>End</dt>
                <dd>
                  <code>
                    0x{range.end.toString(16).toUpperCase().padStart(4, '0')}
                  </code>
                </dd>
              </div>
              <div>
                <dt>Length</dt>
                <dd>
                  {length} {length === 1 ? 'byte' : 'bytes'} / {bitWidth} bits
                </dd>
              </div>
            </dl>
          </section>

          <section
            className="inspector-section"
            aria-labelledby="integer-heading"
          >
            <h3 id="integer-heading">Integer · {bitWidth}-bit</h3>
            {length === 1 ? (
              <dl className="property-list numeric-list">
                <div>
                  <dt>uint8</dt>
                  <dd>
                    <ValueWithCopy
                      value={unsignedBe}
                      label="uint8"
                      onCopy={onCopy}
                    />
                  </dd>
                </div>
                <div>
                  <dt>int8</dt>
                  <dd>
                    <ValueWithCopy
                      value={signedBe}
                      label="int8"
                      onCopy={onCopy}
                    />
                  </dd>
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
                      <td>
                        <ValueWithCopy
                          value={unsignedBe}
                          label="unsigned big endian"
                          onCopy={onCopy}
                        />
                      </td>
                      <td>
                        <ValueWithCopy
                          value={unsignedLe}
                          label="unsigned little endian"
                          onCopy={onCopy}
                        />
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">Signed</th>
                      <td>
                        <ValueWithCopy
                          value={signedBe}
                          label="signed big endian"
                          onCopy={onCopy}
                        />
                      </td>
                      <td>
                        <ValueWithCopy
                          value={signedLe}
                          label="signed little endian"
                          onCopy={onCopy}
                        />
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="inspector-note">
                Integer view supports selections up to 8 bytes.
              </p>
            )}
          </section>

          {floatLabel && floatBe !== null && floatLe !== null ? (
            <section
              className="inspector-section"
              aria-labelledby="float-heading"
            >
              <h3 id="float-heading">Floating point</h3>
              <div className="integer-table-wrap">
                <table className="integer-table float-table">
                  <thead>
                    <tr>
                      <th scope="col" />
                      <th scope="col">Big endian</th>
                      <th scope="col">Little endian</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <th scope="row">{floatLabel}</th>
                      <td>
                        <ValueWithCopy
                          value={floatBe}
                          label={floatLabel + ' big endian'}
                          onCopy={onCopy}
                        />
                      </td>
                      <td>
                        <ValueWithCopy
                          value={floatLe}
                          label={floatLabel + ' little endian'}
                          onCopy={onCopy}
                        />
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          <section
            className="inspector-section"
            aria-labelledby="analysis-heading"
          >
            <h3 id="analysis-heading">Analysis</h3>
            <dl className="property-list numeric-list">
              <div>
                <dt>Magic</dt>
                <dd>
                  {signature
                    ? signature.name + ' · ' + signature.mime
                    : 'Unknown'}
                </dd>
              </div>
              <div>
                <dt>CRC-32</dt>
                <dd>
                  <ValueWithCopy
                    value={paddedHex(crc32Ieee(bytes), 8)}
                    label="CRC-32"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>CRC-16</dt>
                <dd>
                  <ValueWithCopy
                    value={paddedHex(crc16CcittFalse(bytes), 4)}
                    label="CRC-16"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>Sum-8</dt>
                <dd>
                  <ValueWithCopy
                    value={paddedHex(sum8(bytes), 2)}
                    label="Sum-8"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>XOR-8</dt>
                <dd>
                  <ValueWithCopy
                    value={paddedHex(xor8(bytes), 2)}
                    label="XOR-8"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>Entropy</dt>
                <dd>{shannonEntropy(bytes).toFixed(3)} bits / byte</dd>
              </div>
              <div>
                <dt>SHA-256</dt>
                <dd>
                  {currentDigests.sha256 ? (
                    <ValueWithCopy
                      value={currentDigests.sha256}
                      label="SHA-256"
                      onCopy={onCopy}
                    />
                  ) : (
                    <code>
                      {currentDigests.error ? 'Unavailable' : 'Computing…'}
                    </code>
                  )}
                </dd>
              </div>
              <div>
                <dt>SHA-512</dt>
                <dd>
                  {currentDigests.sha512 ? (
                    <ValueWithCopy
                      value={currentDigests.sha512}
                      label="SHA-512"
                      onCopy={onCopy}
                    />
                  ) : (
                    <code>
                      {currentDigests.error ? 'Unavailable' : 'Computing…'}
                    </code>
                  )}
                </dd>
              </div>
            </dl>
          </section>

          <section
            className="inspector-section"
            aria-labelledby="representations-heading"
          >
            <h3 id="representations-heading">Representations</h3>
            <dl className="representation-list">
              <div>
                <dt>Hex</dt>
                <dd>
                  <ValueWithCopy
                    value={preview(bytes, formatHex)}
                    copyValue={() => formatHex(bytes)}
                    label="hex"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>Binary</dt>
                <dd>
                  <ValueWithCopy
                    value={preview(bytes, formatBinary, 32)}
                    copyValue={() => formatBinary(bytes)}
                    label="binary"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>Decimal bytes</dt>
                <dd>
                  <ValueWithCopy
                    value={preview(bytes, formatDecimal, 64)}
                    copyValue={() => formatDecimal(bytes)}
                    label="decimal bytes"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>Base64</dt>
                <dd>
                  <ValueWithCopy
                    value={preview(bytes, formatBase64, 96)}
                    copyValue={() => formatBase64(bytes)}
                    label="Base64"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>ASCII</dt>
                <dd>
                  <ValueWithCopy
                    value={preview(bytes, formatAscii, 256)}
                    copyValue={() => formatAscii(bytes)}
                    label="ASCII"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>UTF-8</dt>
                <dd>
                  <ValueWithCopy
                    value={preview(bytes, formatUtf8Preview, 256) || '(empty)'}
                    copyValue={() => decodeUtf8(bytes)}
                    label="UTF-8 text"
                    onCopy={onCopy}
                  />
                </dd>
              </div>
            </dl>
          </section>
        </div>
      )}
    </aside>
  )
}
