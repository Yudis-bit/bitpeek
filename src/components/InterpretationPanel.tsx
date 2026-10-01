import { useId, useEffect, useMemo, useState } from 'react'
import { ReferenceDisassembler } from '../../packages/core/src/native/disassembler'
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
  documentOffset?: number
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

function ValueWithCopy({ value, copyValue, label, onCopy }: ValueWithCopyProps) {
  const copyCurrentValue = () => {
    const resolved = typeof copyValue === 'function' ? copyValue() : (copyValue ?? value)
    onCopy(resolved, label)
  }

  return (
    <span className="value-with-copy">
      <code>{value}</code>
      <button
        type="button"
        className="inline-copy"
        aria-label={'Copy ' + label}
        title={'Copy ' + label}
        onClick={copyCurrentValue}
      >
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          aria-hidden="true"
        >
          <rect x="8" y="8" width="12" height="12" rx="1" />
          <path d="M16 8V4H4v12h4" />
        </svg>
      </button>
    </span>
  )
}

function preview(bytes: Uint8Array, formatter: (value: Uint8Array) => string, limit = 128): string {
  if (bytes.length <= limit) return formatter(bytes)
  return (
    formatter(bytes.subarray(0, limit)) + ' … (first ' + limit + ' of ' + bytes.length + ' bytes)'
  )
}

function paddedHex(value: number, width: number): string {
  return '0x' + value.toString(16).toUpperCase().padStart(width, '0')
}

export function InterpretationPanel({
  bytes,
  documentBytes,
  documentOffset = 0,
  range,
  onCopy,
}: InterpretationPanelProps) {
  const scopeId = useId()
  const [view, setView] = useState<'values' | 'disasm' | 'analysis' | 'text'>('values')
  const [disasmArch, setDisasmArch] = useState<'x86_64' | 'aarch64'>('x86_64')
  const [digests, setDigests] = useState<{
    source: Uint8Array | null
    sha256: string | null
    sha512: string | null
    error: boolean
  }>({ source: null, sha256: null, sha512: null, error: false })

  const disasmTarget = bytes.length > 0 ? bytes : documentBytes.subarray(0, 128)
  const disasmInstructions = useMemo(() => {
    if (disasmTarget.length === 0) return []
    const base = range ? BigInt(range.start) : 0n
    return ReferenceDisassembler.disassemble(disasmTarget, {
      arch: disasmArch,
      baseAddress: base,
      maxInstructions: 64,
    })
  }, [disasmTarget, disasmArch, range])
  const length = bytes.length
  const bitWidth = length * 8
  const hasInteger = length > 0 && length <= 8
  const signature = detectFileSignature(documentBytes)

  useEffect(() => {
    let active = true
    if (bytes.length === 0) return

    void Promise.all([digestHex(bytes, 'SHA-256'), digestHex(bytes, 'SHA-512')])
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
    digests.source === bytes ? digests : { source: null, sha256: null, sha512: null, error: false }

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
    <aside className="interpretation-panel" aria-labelledby={scopeId + '-interpretation-heading'}>
      <div className="panel-heading">
        <h2 id={scopeId + '-interpretation-heading'} className="section-title">
          Inspector
        </h2>
        <span>{signature ? signature.name : 'Selected bytes'}</span>
      </div>

      <div className="inspector-tabs" role="group" aria-label="Inspector view">
        <button type="button" aria-pressed={view === 'values'} onClick={() => setView('values')}>
          Values
        </button>
        <button type="button" aria-pressed={view === 'disasm'} onClick={() => setView('disasm')}>
          Disasm
        </button>
        <button
          type="button"
          aria-pressed={view === 'analysis'}
          onClick={() => setView('analysis')}
        >
          Analysis
        </button>
        <button type="button" aria-pressed={view === 'text'} onClick={() => setView('text')}>
          Text & encoding
        </button>
      </div>

      {range === null ? (
        <div className="workspace-placeholder">Select one or more bytes.</div>
      ) : (
        <div className="inspector-content">
          <section className="inspector-section" aria-labelledby={scopeId + '-selection-heading'}>
            <h3 id={scopeId + '-selection-heading'}>Selection</h3>
            <dl className="property-list">
              <div>
                <dt>Start</dt>
                <dd>
                  <code>0x{range.start.toString(16).toUpperCase().padStart(4, '0')}</code>
                </dd>
              </div>
              <div>
                <dt>End</dt>
                <dd>
                  <code>0x{range.end.toString(16).toUpperCase().padStart(4, '0')}</code>
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
            aria-labelledby={scopeId + '-integer-heading'}
            hidden={view !== 'values'}
          >
            <h3 id={scopeId + '-integer-heading'}>Integer · {bitWidth}-bit</h3>
            {length === 1 ? (
              <dl className="property-list numeric-list">
                <div>
                  <dt>uint8</dt>
                  <dd>
                    <ValueWithCopy value={unsignedBe} label="uint8" onCopy={onCopy} />
                  </dd>
                </div>
                <div>
                  <dt>int8</dt>
                  <dd>
                    <ValueWithCopy value={signedBe} label="int8" onCopy={onCopy} />
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
                        <ValueWithCopy value={signedBe} label="signed big endian" onCopy={onCopy} />
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
              <p className="inspector-note">Integer view supports selections up to 8 bytes.</p>
            )}
          </section>

          {floatLabel && floatBe !== null && floatLe !== null ? (
            <section
              className="inspector-section"
              aria-labelledby={scopeId + '-float-heading'}
              hidden={view !== 'values'}
            >
              <h3 id={scopeId + '-float-heading'}>Floating point</h3>
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
            aria-labelledby={scopeId + '-disasm-heading'}
            hidden={view !== 'disasm'}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '8px',
              }}
            >
              <h3 id={scopeId + '-disasm-heading'} style={{ margin: 0 }}>
                Disassembly
              </h3>
              <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                <select
                  value={disasmArch}
                  onChange={(e) => setDisasmArch(e.target.value as 'x86_64' | 'aarch64')}
                  aria-label="Architecture"
                  style={{
                    padding: '2px 6px',
                    fontSize: '12px',
                    fontFamily: 'var(--mono)',
                    background: 'var(--paper)',
                    border: '1px solid var(--border)',
                    color: 'var(--ink)',
                  }}
                >
                  <option value="x86_64">x86-64</option>
                  <option value="aarch64">AArch64</option>
                </select>
                <button
                  type="button"
                  className="compact-button"
                  style={{ minHeight: '26px', padding: '2px 8px', fontSize: '12px' }}
                  onClick={() => {
                    const fullText = disasmInstructions
                      .map(
                        (i) =>
                          `0x${i.address.toString(16).toUpperCase().padStart(8, '0')}:  ${i.mnemonic.padEnd(8)} ${i.operands}`,
                      )
                      .join('\n')
                    onCopy(fullText, 'disassembly')
                  }}
                >
                  Copy ASM
                </button>
              </div>
            </div>
            {disasmInstructions.length === 0 ? (
              <p className="inspector-note">No code bytes to disassemble.</p>
            ) : (
              <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
                <table
                  style={{
                    width: '100%',
                    borderCollapse: 'collapse',
                    fontFamily: 'var(--mono)',
                    fontSize: '12px',
                  }}
                >
                  <tbody>
                    {disasmInstructions.map((inst, idx) => (
                      <tr
                        key={idx}
                        style={{
                          borderBottom: '1px solid var(--border-subtle)',
                          lineHeight: '1.6',
                        }}
                      >
                        <td style={{ color: 'var(--muted)', width: '75px', padding: '2px 4px' }}>
                          +0x{inst.address.toString(16).toUpperCase().padStart(4, '0')}
                        </td>
                        <td
                          style={{
                            color: 'var(--muted)',
                            width: '90px',
                            padding: '2px 4px',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {Array.from(inst.bytes)
                            .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
                            .join(' ')}
                        </td>
                        <td
                          style={{
                            padding: '2px 4px',
                            color: inst.isValid ? 'var(--ink)' : 'var(--error)',
                          }}
                        >
                          <strong>{inst.mnemonic}</strong> {inst.operands}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section
            className="inspector-section"
            aria-labelledby={scopeId + '-analysis-heading'}
            hidden={view !== 'analysis'}
          >
            <h3 id={scopeId + '-analysis-heading'}>Analysis</h3>
            <dl className="property-list numeric-list">
              <div>
                <dt>{documentOffset ? 'Window magic' : 'Magic'}</dt>
                <dd>{signature ? signature.name + ' · ' + signature.mime : 'Unknown'}</dd>
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
                  <ValueWithCopy value={paddedHex(sum8(bytes), 2)} label="Sum-8" onCopy={onCopy} />
                </dd>
              </div>
              <div>
                <dt>XOR-8</dt>
                <dd>
                  <ValueWithCopy value={paddedHex(xor8(bytes), 2)} label="XOR-8" onCopy={onCopy} />
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
                    <ValueWithCopy value={currentDigests.sha256} label="SHA-256" onCopy={onCopy} />
                  ) : (
                    <code>{currentDigests.error ? 'Unavailable' : 'Computing…'}</code>
                  )}
                </dd>
              </div>
              <div>
                <dt>SHA-512</dt>
                <dd>
                  {currentDigests.sha512 ? (
                    <ValueWithCopy value={currentDigests.sha512} label="SHA-512" onCopy={onCopy} />
                  ) : (
                    <code>{currentDigests.error ? 'Unavailable' : 'Computing…'}</code>
                  )}
                </dd>
              </div>
            </dl>
          </section>

          <section
            className="inspector-section"
            aria-labelledby={scopeId + '-representations-heading'}
            hidden={view !== 'text'}
          >
            <h3 id={scopeId + '-representations-heading'}>Representations</h3>
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
