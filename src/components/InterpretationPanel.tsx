import { useEffect, useMemo, useState } from 'react'
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
} from '../lib/bytes'
import { digestHex } from '../lib/crypto'
import {
  analysisProvenanceKey,
  formatScopeLabel,
  type AnalysisScope,
} from '../lib/inspection'
import { inspectUtf8, type Utf8Issue } from '../lib/utf8'

interface InterpretationPanelProps {
  bytes: Uint8Array
  documentBytes: Uint8Array
  scope: AnalysisScope
  documentScope: AnalysisScope
  onCopy: (value: string, label: string) => void
}

interface ValueWithCopyProps {
  value: string
  copyValue?: string | (() => string)
  label: string
  copyDisabled?: boolean
  disabledReason?: string
  onCopy: (value: string, label: string) => void
}

interface DigestState {
  provenanceKey: string | null
  status: 'idle' | 'computing' | 'ready' | 'error'
  sha256: string | null
  sha512: string | null
}

function ValueWithCopy({
  value,
  copyValue,
  label,
  copyDisabled = false,
  disabledReason,
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
        disabled={copyDisabled}
        title={copyDisabled ? disabledReason : undefined}
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

function offsetHex(offset: number, documentByteCount: number): string {
  const width = Math.max(
    4,
    Math.max(0, documentByteCount - 1).toString(16).length,
  )
  return '0x' + offset.toString(16).toUpperCase().padStart(width, '0')
}

function formatUtf8Issue(
  issue: Utf8Issue,
  baseOffset: number,
  documentByteCount: number,
): string {
  const start = issue.start + baseOffset
  const end = issue.end + baseOffset
  const offsets =
    start === end
      ? 'offset ' + offsetHex(start, documentByteCount)
      : 'offsets ' +
        offsetHex(start, documentByteCount) +
        '–' +
        offsetHex(end, documentByteCount)
  return offsets + ' · ' + issue.reason
}

export function InterpretationPanel({
  bytes,
  documentBytes,
  scope,
  documentScope,
  onCopy,
}: InterpretationPanelProps) {
  const [digests, setDigests] = useState<DigestState>({
    provenanceKey: null,
    status: 'idle',
    sha256: null,
    sha512: null,
  })
  const length = bytes.length
  const bitWidth = length * 8
  const hasInteger = length > 0 && length <= 8
  const signature = detectFileSignature(documentBytes)
  const provenanceKey = analysisProvenanceKey(scope)
  const copyDisabled = scope.status === 'last-valid'
  const copyDisabledReason = copyDisabled
    ? 'Copy is unavailable while the inspector shows previous valid data.'
    : undefined
  const utf8 = useMemo(() => inspectUtf8(bytes), [bytes])

  useEffect(() => {
    let active = true
    if (bytes.length === 0 || scope.scopeType === 'none') return

    void Promise.all([
      digestHex(bytes, 'SHA-256'),
      digestHex(bytes, 'SHA-512'),
    ])
      .then(([sha256, sha512]) => {
        if (active) {
          setDigests({
            provenanceKey,
            status: 'ready',
            sha256,
            sha512,
          })
        }
      })
      .catch(() => {
        if (active) {
          setDigests({
            provenanceKey,
            status: 'error',
            sha256: null,
            sha512: null,
          })
        }
      })

    return () => {
      active = false
    }
  }, [bytes, provenanceKey, scope.scopeType])

  const currentDigests =
    digests.provenanceKey === provenanceKey
      ? digests
      : {
          provenanceKey: null,
          status: 'computing' as const,
          sha256: null,
          sha512: null,
        }

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
        <span className="panel-scope-label">{formatScopeLabel(scope)}</span>
      </div>

      {scope.scopeType === 'none' ? (
        <div className="workspace-placeholder">Select one or more bytes.</div>
      ) : (
        <div className="inspector-content">
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
                    copyDisabled={copyDisabled}
                    disabledReason={copyDisabledReason}
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
                    copyDisabled={copyDisabled}
                    disabledReason={copyDisabledReason}
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
                    copyDisabled={copyDisabled}
                    disabledReason={copyDisabledReason}
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
                    copyDisabled={copyDisabled}
                    disabledReason={copyDisabledReason}
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div>
                <dt>UTF-8 text</dt>
                <dd>
                  <ValueWithCopy
                    value={preview(bytes, formatUtf8Preview, 256) || '(empty)'}
                    copyValue={() => decodeUtf8(bytes)}
                    label="UTF-8 text"
                    copyDisabled={copyDisabled || !utf8.valid}
                    disabledReason={
                      copyDisabled
                        ? copyDisabledReason
                        : 'Invalid UTF-8 cannot be copied as decoded text without replacing bytes.'
                    }
                    onCopy={onCopy}
                  />
                </dd>
              </div>
              <div className={utf8.valid ? 'utf8-status' : 'utf8-status is-invalid'}>
                <dt>UTF-8 validity</dt>
                <dd>
                  {utf8.valid ? (
                    <span className="validity-value is-valid">Valid UTF-8</span>
                  ) : (
                    <div className="utf8-diagnostic" role="status">
                      <strong>Invalid UTF-8</strong>
                      <span>
                        The preview marks undecodable sequences as \uFFFD; bytes are
                        unchanged.
                      </span>
                      <ul>
                        {utf8.issues.map((issue) => (
                          <li key={`${issue.start}-${issue.end}-${issue.reason}`}>
                            <code>
                              {formatUtf8Issue(
                                issue,
                                scope.offsetStart ?? 0,
                                scope.documentByteCount,
                              )}
                            </code>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </dd>
              </div>
              <div>
                <dt>Base64</dt>
                <dd>
                  <ValueWithCopy
                    value={preview(bytes, formatBase64, 96)}
                    copyValue={() => formatBase64(bytes)}
                    label="Base64"
                    copyDisabled={copyDisabled}
                    disabledReason={copyDisabledReason}
                    onCopy={onCopy}
                  />
                </dd>
              </div>
            </dl>
          </section>

          <section
            className="inspector-section"
            aria-labelledby="integer-heading"
          >
            <div className="inspector-section-heading">
              <h3 id="integer-heading">Integer · {bitWidth}-bit</h3>
              <span>{formatScopeLabel(scope)}</span>
            </div>
            {length === 1 ? (
              <dl className="property-list numeric-list">
                <div>
                  <dt>uint8</dt>
                  <dd>
                    <ValueWithCopy value={unsignedBe} label="uint8" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                  </dd>
                </div>
                <div>
                  <dt>int8</dt>
                  <dd>
                    <ValueWithCopy value={signedBe} label="int8" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
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
                        <ValueWithCopy value={unsignedBe} label="unsigned big endian" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                      </td>
                      <td>
                        <ValueWithCopy value={unsignedLe} label="unsigned little endian" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">Signed</th>
                      <td>
                        <ValueWithCopy value={signedBe} label="signed big endian" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                      </td>
                      <td>
                        <ValueWithCopy value={signedLe} label="signed little endian" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
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
            <section className="inspector-section" aria-labelledby="float-heading">
              <div className="inspector-section-heading">
                <h3 id="float-heading">Floating point</h3>
                <span>{formatScopeLabel(scope)}</span>
              </div>
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
                        <ValueWithCopy value={floatBe} label={floatLabel + ' big endian'} copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                      </td>
                      <td>
                        <ValueWithCopy value={floatLe} label={floatLabel + ' little endian'} copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          <section className="inspector-section" aria-labelledby="analysis-heading">
            <div className="inspector-section-heading">
              <h3 id="analysis-heading">Checksums &amp; hashes</h3>
              <span>{formatScopeLabel(scope)}</span>
            </div>
            <dl className="property-list numeric-list">
              <div>
                <dt>CRC-32</dt>
                <dd>
                  <ValueWithCopy value={paddedHex(crc32Ieee(bytes), 8)} label="CRC-32" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                </dd>
              </div>
              <div>
                <dt>CRC-16</dt>
                <dd>
                  <ValueWithCopy value={paddedHex(crc16CcittFalse(bytes), 4)} label="CRC-16" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                </dd>
              </div>
              <div>
                <dt>Sum-8</dt>
                <dd>
                  <ValueWithCopy value={paddedHex(sum8(bytes), 2)} label="Sum-8" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                </dd>
              </div>
              <div>
                <dt>XOR-8</dt>
                <dd>
                  <ValueWithCopy value={paddedHex(xor8(bytes), 2)} label="XOR-8" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                </dd>
              </div>
              <div>
                <dt>Entropy</dt>
                <dd>{shannonEntropy(bytes).toFixed(3)} bits / byte</dd>
              </div>
              <div>
                <dt>SHA-256</dt>
                <dd>
                  {currentDigests.status === 'ready' && currentDigests.sha256 ? (
                    <ValueWithCopy value={currentDigests.sha256} label="SHA-256" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                  ) : (
                    <code>{currentDigests.status === 'error' ? 'Unavailable' : 'Computing…'}</code>
                  )}
                </dd>
              </div>
              <div>
                <dt>SHA-512</dt>
                <dd>
                  {currentDigests.status === 'ready' && currentDigests.sha512 ? (
                    <ValueWithCopy value={currentDigests.sha512} label="SHA-512" copyDisabled={copyDisabled} disabledReason={copyDisabledReason} onCopy={onCopy} />
                  ) : (
                    <code>{currentDigests.status === 'error' ? 'Unavailable' : 'Computing…'}</code>
                  )}
                </dd>
              </div>
            </dl>
          </section>

          <section className="inspector-section document-evidence" aria-labelledby="document-evidence-heading">
            <div className="inspector-section-heading">
              <h3 id="document-evidence-heading">Document evidence</h3>
              <span>{formatScopeLabel(documentScope)}</span>
            </div>
            <dl className="property-list">
              <div>
                <dt>File signature</dt>
                <dd>{signature ? signature.name + ' · ' + signature.mime : 'Unknown'}</dd>
              </div>
            </dl>
          </section>
        </div>
      )}
    </aside>
  )
}
