import { useRef, useState } from 'react'
import { useJob } from '../hooks/useJob'
import { downloadBlob, MAX_FILE_BYTES, type Annotation } from '../lib/workspace'
import type { AlignedDiff } from '../lib/aligned-diff'
import type {
  RecipeFile,
  RecipeOperationName,
  RecipeRunResult,
} from '../../packages/core/src/recipe'
import type { StringScanResult } from '../../packages/core/src/strings'
import type { StructureField, StructureParseResult } from '../lib/structures'

export interface BinaryMap {
  size: number
  sha256: string
  frequencies: number[]
  blocks: { start: number; length: number; entropy: number }[]
}
interface RecipePreviewResult extends RecipeRunResult {
  preview: {
    changedBytes: number
    firstChanges: { offset: number; before: number | null; after: number | null }[]
  }
}
interface Props {
  blob: Blob
  name: string
  range: { start: number; end: number } | null
  notes: Annotation[]
  onNotes: (notes: Annotation[]) => void
  recipe?: RecipeFile
  onRecipe: (recipe: RecipeFile) => void
  onSelect: (start: number, end: number) => void
  onApply: (bytes: Uint8Array, label: string) => void
  reference?: Blob
  onReference?: (blob: Blob) => void
  onClose?: () => void
}
const tabs = ['Map', 'Changes', 'Notes', 'Recipes', 'Strings', 'Evidence'] as const
const operations: RecipeOperationName[] = [
  'reverse',
  'invert',
  'xor-mask',
  'fill',
  'byteswap',
  'hash',
  'find-pattern',
  'extract-strings',
  'inspect-scalar',
  'parse-structure',
  'secp256k1.audit',
]
const hex = (n: number) => '0x' + n.toString(16).toUpperCase()
const json = (value: unknown) =>
  JSON.stringify(value, (_key, val) => (typeof val === 'bigint' ? val.toString() : val), 2)
const emptyRecipe = (): RecipeFile => ({
  schemaVersion: 1,
  recipeId: crypto.randomUUID(),
  title: 'Binary investigation',
  inputs: [{ id: 'input' }],
  steps: [],
})

export function InvestigationPanel({
  blob,
  name,
  range,
  notes,
  onNotes,
  recipe: savedRecipe,
  onRecipe,
  onSelect,
  onApply,
  reference: suppliedReference,
  onReference,
  onClose,
}: Props) {
  const [tab, setTab] = useState<(typeof tabs)[number]>('Map')
  const [error, setError] = useState('')
  const [map, setMap] = useState<{ blob: Blob; data: BinaryMap } | null>(null)
  const [regions, setRegions] = useState<{ blob: Blob; fields: StructureField[] } | null>(null)
  const [reference, setReference] = useState<Blob | null>(null)
  const [comparisonBytes, setComparisonBytes] = useState<{
    blob: Blob
    reference: Blob
    current: string
    before: string
    currentStart: number
    referenceStart: number
  } | null>(null)
  const [diff, setDiff] = useState<{ blob: Blob; reference: Blob; data: AlignedDiff } | null>(null)
  const [fields, setFields] = useState<{
    blob: Blob
    reference: Blob
    rows: { label: string; before: string; after: string; start: number; end: number }[]
  } | null>(null)
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [editingNote, setEditingNote] = useState<string | null>(null)
  const [localRecipe, setLocalRecipe] = useState<RecipeFile>(emptyRecipe)
  const recipe = savedRecipe ?? localRecipe
  const setRecipe = (next: RecipeFile) => {
    setLocalRecipe(next)
    onRecipe(next)
  }
  const [operation, setOperation] = useState<RecipeOperationName>('reverse')
  const [parameter, setParameter] = useState('')
  const [preview, setPreview] = useState<{
    blob: Blob
    recipe: RecipeFile
    result: RecipePreviewResult
  } | null>(null)
  const [strings, setStrings] = useState<{ blob: Blob; data: StringScanResult } | null>(null)
  const [minimum, setMinimum] = useState(4)
  const importRef = useRef<HTMLInputElement>(null)
  const job = useJob()
  const refBlob = reference ?? suppliedReference
  const currentMap = map?.blob === blob ? map.data : null
  const currentRegions = regions?.blob === blob ? regions.fields : []
  const currentDiff = diff?.blob === blob && diff.reference === refBlob ? diff.data : null
  const currentFields = fields?.blob === blob && fields.reference === refBlob ? fields.rows : null
  const currentPreview = preview?.blob === blob && preview.recipe === recipe ? preview.result : null
  const currentStrings = strings?.blob === blob ? strings.data : null
  const perform = async (action: () => Promise<void>) => {
    setError('')
    try {
      await action()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }
  const scan = async () => {
    const data = await job.run<BinaryMap>('map', { blob })
    setMap({ blob, data })
    return data
  }
  const addStep = () => {
    if (recipe.steps.length >= 100) {
      setError('Maximum 100 steps per recipe.')
      return
    }
    const parameters: Record<string, unknown> = {}
    if (operation === 'xor-mask') parameters.mask = parameter || 'FF'
    if (operation === 'fill') parameters.fillByte = Number(parameter || 0)
    if (operation === 'byteswap') parameters.groupWidth = Number(parameter || 2)
    if (operation === 'find-pattern') {
      parameters.pattern = parameter
      parameters.mode = 'hex'
    }
    if (operation === 'inspect-scalar') {
      parameters.type = parameter || 'u32'
      parameters.endian = 'little'
    }
    if (operation === 'parse-structure') parameters.format = parameter || 'auto'
    if (operation === 'secp256k1.audit') parameters.format = parameter || 'auto'
    if (operation === 'hash') parameters.algorithm = 'sha256'
    setRecipe({
      ...recipe,
      steps: [
        ...recipe.steps,
        {
          id: crypto.randomUUID(),
          operation,
          range: range ? { start: range.start, end: range.end + 1 } : undefined,
          parameters,
        },
      ],
    })
  }
  const exportReport = async (format: 'json' | 'md') => {
    const analysis = currentMap ?? (await scan())
    const evidence = {
      schemaVersion: 1,
      tool: 'Bitpeek',
      file: { name, byteLength: blob.size, sha256: analysis.sha256 },
      selection: range,
      notes,
      changes: currentDiff,
      structureChanges: currentFields,
      analysis: { blocks: analysis.blocks },
      recipe: {
        ...recipe,
        inputs: [{ id: 'input', byteLength: blob.size, sha256: analysis.sha256 }],
      },
      createdAt: new Date().toISOString(),
    }
    const text =
      format === 'json'
        ? json(evidence)
        : `# ${name.replace(/[\r\n]/g, ' ')} — Binary investigation\n\nSHA-256: ${analysis.sha256}\n\nSize: ${blob.size} bytes\n\n${notes.map((n) => `## ${n.title.replace(/[\r\n]/g, ' ')}\n\nRange: ${hex(n.start)}–${hex(n.end)}\n\n${n.body}\n`).join('\n')}\n## Changes\n\n${json(currentDiff)}\n\n## Replay recipe\n\n\`\`\`json\n${json(evidence.recipe)}\n\`\`\`\n`
    downloadBlob(
      new Blob([text], { type: format === 'json' ? 'application/json' : 'text/markdown' }),
      name + '.evidence.' + format,
    )
  }
  const showComparison = async (currentStart: number, referenceStart: number) => {
    if (!refBlob) return
    const formatBytes = (buffer: ArrayBuffer) =>
      Array.from(new Uint8Array(buffer), (byte) =>
        byte.toString(16).toUpperCase().padStart(2, '0'),
      ).join(' ')
    const [a, b] = await Promise.all([
      blob.slice(currentStart, currentStart + 64).arrayBuffer(),
      refBlob.slice(referenceStart, referenceStart + 64).arrayBuffer(),
    ])
    setComparisonBytes({
      blob,
      reference: refBlob,
      current: formatBytes(a),
      before: formatBytes(b),
      currentStart,
      referenceStart,
    })
  }
  const compareFields = async () => {
    if (!refBlob) return
    const a = await job.run<StructureParseResult | null>('structure', { blob })
    const b = await job.run<StructureParseResult | null>('structure', { blob: refBlob })
    if (!a || !b || a.format !== b.format)
      throw new Error('Both files must have the same recognized structure format.')
    const flatten = (
      items: StructureField[],
      prefix = '',
    ): { path: string; field: StructureField }[] =>
      items.flatMap((f, i) => [
        { path: prefix + '/' + f.label + ':' + i, field: f },
        ...flatten(f.children ?? [], prefix + '/' + f.label + ':' + i),
      ])
    const before = new Map(flatten(b.fields).map((f) => [f.path, f.field]))
    const rows: NonNullable<typeof fields>['rows'] = []
    for (const { path, field } of flatten(a.fields)) {
      const previous = before.get(path)
      before.delete(path)
      if (
        !previous ||
        String(previous.interpretedValue) !== String(field.interpretedValue) ||
        previous.range.end - previous.range.start !== field.range.end - field.range.start
      )
        rows.push({
          label: path,
          before: previous ? String(previous.interpretedValue) : '—',
          after: String(field.interpretedValue),
          start: field.range.start,
          end: field.range.end - 1,
        })
    }
    for (const [path, field] of before)
      rows.push({
        label: path,
        before: String(field.interpretedValue),
        after: '—',
        start: -1,
        end: -1,
      })
    setFields({ blob, reference: refBlob, rows: rows.slice(0, 2000) })
  }
  return (
    <section className="investigation-panel" aria-label="Investigation workspace">
      <div className="panel-heading">
        <div className="investigation-tabs" role="tablist" aria-label="Investigation tools">
          {tabs.map((t) => (
            <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}>
              {t}
              {t === 'Notes' && notes.length ? ` (${notes.length})` : ''}
            </button>
          ))}
        </div>
        {onClose && (
          <button onClick={onClose} aria-label="Close investigation tools">
            Close
          </button>
        )}
      </div>
      <div className="investigation-content" role="tabpanel" aria-label={tab}>
        {job.busy && (
          <div className="job-status" role="status">
            <progress max={1} value={job.progress || undefined} />
            Processing locally {job.progress ? Math.round(job.progress * 100) + '%' : ''}
            <button onClick={job.cancel}>Cancel</button>
          </div>
        )}
        {error && (
          <p className="input-error" role="alert">
            {error}
          </p>
        )}
        {tab === 'Map' && (
          <>
            <div className="compact-actions">
              <button
                disabled={job.busy}
                onClick={() =>
                  void perform(async () => {
                    await scan()
                  })
                }
              >
                Analyze file
              </button>
              <button
                disabled={job.busy || blob.size > 64 * 1024 * 1024}
                onClick={() =>
                  void perform(async () => {
                    const parsed = await job.run<StructureParseResult | null>('structure', { blob })
                    if (!parsed) throw new Error('No recognized file structure.')
                    setRegions({
                      blob,
                      fields: parsed.fields
                        .flatMap((f) => [f, ...(f.children ?? [])])
                        .filter(
                          (f) =>
                            f.range.end > f.range.start &&
                            f.range.start >= 0 &&
                            f.range.start < blob.size,
                        )
                        .slice(0, 200),
                    })
                  })
                }
              >
                Map structure
              </button>
              <span>Entropy per region · click to inspect bytes</span>
            </div>
            {(currentRegions.length > 0 || notes.length > 0) && (
              <>
                <div className="file-minimap" aria-label="File regions">
                  {[
                    ...currentRegions.map((f) => ({
                      id: f.id,
                      title: f.label,
                      start: f.range.start,
                      end: Math.min(blob.size - 1, f.range.end - 1),
                    })),
                    ...notes,
                  ].map((item, i) => (
                    <button
                      key={item.id + ':' + i}
                      aria-label={item.title + ' at ' + hex(item.start)}
                      title={item.title + ' · ' + hex(item.start)}
                      style={{
                        left: (item.start / Math.max(1, blob.size)) * 100 + '%',
                        width: ((item.end - item.start + 1) / Math.max(1, blob.size)) * 100 + '%',
                      }}
                      onClick={() => onSelect(item.start, item.end)}
                    />
                  ))}
                </div>
                <div className="compact-actions">
                  {currentRegions.slice(0, 12).map((f, i) => (
                    <button
                      key={f.id + ':' + i}
                      onClick={() =>
                        onSelect(f.range.start, Math.min(blob.size - 1, f.range.end - 1))
                      }
                    >
                      {f.label}
                    </button>
                  ))}
                </div>
              </>
            )}
            {currentMap ? (
              <>
                <div className="entropy-map" aria-label="Entropy map">
                  {currentMap.blocks.map((block) => (
                    <button
                      key={block.start}
                      aria-label={`${hex(block.start)}, ${block.length} bytes, entropy ${block.entropy.toFixed(2)}`}
                      title={`${hex(block.start)} · ${block.entropy.toFixed(3)} bits/byte`}
                      style={{ height: Math.max(8, (block.entropy / 8) * 90) }}
                      onClick={() => onSelect(block.start, block.start + block.length - 1)}
                    />
                  ))}
                </div>
                <p className="map-legend">
                  0–8 bits/byte. High entropy can indicate compressed, encrypted, or other dense
                  data.
                </p>
                <div className="byte-distribution" aria-label="Byte frequency distribution">
                  {currentMap.frequencies.map((count, i) => (
                    <span
                      key={i}
                      title={`${hex(i)}: ${count} occurrences`}
                      style={{
                        height: Math.max(1, (count / Math.max(1, ...currentMap.frequencies)) * 64),
                      }}
                    />
                  ))}
                </div>
                <p className="hash-value">
                  SHA-256 <code>{currentMap.sha256}</code>
                </p>
              </>
            ) : (
              <p>
                Build a local entropy map, byte distribution, and streaming SHA-256 for this
                document.
              </p>
            )}
          </>
        )}
        {tab === 'Changes' && (
          <>
            <div className="compact-actions">
              <label className="file-action">
                Reference file
                <input
                  type="file"
                  aria-label="Choose aligned comparison reference"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) {
                      if (file.size > MAX_FILE_BYTES) setError('Reference exceeds 512 MiB.')
                      else {
                        setReference(file)
                        onReference?.(file)
                      }
                    }
                    e.target.value = ''
                  }}
                />
              </label>
              <button
                disabled={!refBlob || job.busy}
                onClick={() =>
                  void perform(async () => {
                    const data = await job.run<AlignedDiff>('diff', { blob, reference: refBlob })
                    setDiff({ blob, reference: refBlob!, data })
                  })
                }
              >
                Align & compare
              </button>
              <button disabled={!refBlob || job.busy} onClick={() => void perform(compareFields)}>
                Compare structure fields
              </button>
            </div>
            <p className="map-legend">
              Alignment uses exact anchors within 4 KiB. Large moves may appear as modifications.
            </p>
            {currentDiff && (
              <>
                <p>
                  {currentDiff.modified} modified · {currentDiff.inserted} inserted ·{' '}
                  {currentDiff.deleted} deleted
                  {currentDiff.truncated ? ' · first 2,000 regions shown' : ''}
                </p>
                <div className="result-list">
                  {currentDiff.changes.map((change, i) => (
                    <button
                      key={i}
                      onClick={() => {
                        if (blob.size)
                          onSelect(
                            Math.min(blob.size - 1, change.currentStart),
                            Math.min(
                              blob.size - 1,
                              change.currentStart + Math.max(1, change.currentLength) - 1,
                            ),
                          )
                        void perform(() =>
                          showComparison(change.currentStart, change.referenceStart),
                        )
                      }}
                    >
                      <strong>{change.kind}</strong>
                      <code>
                        {hex(change.referenceStart)} → {hex(change.currentStart)}
                      </code>
                      <span>
                        {change.referenceLength} → {change.currentLength} bytes
                      </span>
                    </button>
                  ))}
                  {!currentDiff.changes.length && <p>Files are identical.</p>}
                </div>
              </>
            )}
            {comparisonBytes?.blob === blob && comparisonBytes.reference === refBlob && (
              <div className="comparison-bytes">
                <div>
                  <strong>Reference · {hex(comparisonBytes.referenceStart)}</strong>
                  <pre>{comparisonBytes.before || 'End of file'}</pre>
                </div>
                <div>
                  <strong>Current · {hex(comparisonBytes.currentStart)}</strong>
                  <pre>{comparisonBytes.current || 'End of file'}</pre>
                </div>
              </div>
            )}
            {currentFields && (
              <div className="result-list">
                {currentFields.map((field, i) => (
                  <button
                    key={i}
                    disabled={field.start < 0 || field.start >= blob.size}
                    onClick={() => onSelect(field.start, Math.min(blob.size - 1, field.end))}
                  >
                    <strong>{field.label}</strong>
                    <span>
                      {field.before} → {field.after}
                    </span>
                  </button>
                ))}
                {!currentFields.length && <p>No interpreted field changes.</p>}
              </div>
            )}
          </>
        )}
        {tab === 'Notes' && (
          <>
            <div className="note-editor">
              <input
                aria-label="Annotation title"
                placeholder="Bookmark or finding title"
                maxLength={1000}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
              <textarea
                aria-label="Annotation details"
                placeholder="What did you find in these bytes?"
                maxLength={20000}
                value={body}
                onChange={(e) => setBody(e.target.value)}
              />
              <div className="compact-actions">
                <button
                  disabled={!range || !title.trim() || notes.length >= 2000}
                  onClick={() => {
                    if (!range) return
                    if (editingNote)
                      onNotes(
                        notes.map((n) =>
                          n.id === editingNote ? { ...n, title: title.trim(), body } : n,
                        ),
                      )
                    else
                      onNotes([
                        ...notes,
                        {
                          id: crypto.randomUUID(),
                          title: title.trim(),
                          body,
                          start: range.start,
                          end: range.end,
                          createdAt: new Date().toISOString(),
                        },
                      ])
                    setEditingNote(null)
                    setTitle('')
                    setBody('')
                  }}
                >
                  {editingNote ? 'Save annotation' : 'Annotate selection'}
                </button>
                <span>
                  {range
                    ? `${hex(range.start)}–${hex(range.end)}`
                    : 'Select bytes to add a bookmark.'}
                </span>
              </div>
            </div>
            <div className="annotation-list">
              {notes.map((note) => (
                <article key={note.id}>
                  <button
                    className="annotation-target"
                    onClick={() => onSelect(note.start, note.end)}
                  >
                    <strong>{note.title}</strong>
                    <code>
                      {hex(note.start)}–{hex(note.end)}
                    </code>
                  </button>
                  <p>{note.body}</p>
                  <button
                    onClick={() => {
                      setEditingNote(note.id)
                      setTitle(note.title)
                      setBody(note.body)
                      onSelect(note.start, note.end)
                    }}
                  >
                    Edit
                  </button>
                  <button
                    aria-label={`Delete annotation ${note.title}`}
                    onClick={() => onNotes(notes.filter((n) => n.id !== note.id))}
                  >
                    Delete
                  </button>
                </article>
              ))}
            </div>
          </>
        )}
        {tab === 'Recipes' && (
          <>
            <div className="compact-actions">
              <select
                aria-label="Recipe operation"
                value={operation}
                onChange={(e) => setOperation(e.target.value as RecipeOperationName)}
              >
                {operations.map((o) => (
                  <option key={o}>{o}</option>
                ))}
              </select>
              <input
                aria-label="Operation parameter"
                placeholder="Mask / value / width / format"
                value={parameter}
                onChange={(e) => setParameter(e.target.value)}
              />
              <button onClick={addStep}>Add step {range ? '(selection)' : '(whole file)'}</button>
            </div>
            <ol className="recipe-steps">
              {recipe.steps.map((step, i) => (
                <li key={step.id}>
                  <code>{step.operation}</code>
                  <span>
                    {step.range
                      ? `${hex(step.range.start)}–${hex(step.range.end)} (exclusive)`
                      : 'Whole file'}{' '}
                    {json(step.parameters)}
                  </span>
                  <div className="compact-actions">
                    <button
                      disabled={i === 0}
                      aria-label={`Move step ${i + 1} up`}
                      onClick={() => {
                        const steps = [...recipe.steps]
                        ;[steps[i - 1], steps[i]] = [steps[i]!, steps[i - 1]!]
                        setRecipe({ ...recipe, steps })
                      }}
                    >
                      ↑
                    </button>
                    <button
                      aria-label={`Remove step ${i + 1}`}
                      onClick={() =>
                        setRecipe({
                          ...recipe,
                          steps: recipe.steps.filter((s) => s.id !== step.id),
                        })
                      }
                    >
                      Remove
                    </button>
                  </div>
                </li>
              ))}
            </ol>
            <div className="compact-actions">
              <button
                disabled={job.busy || !recipe.steps.length}
                onClick={() =>
                  void perform(async () => {
                    const result = await job.run<RecipePreviewResult>('recipe', { blob, recipe })
                    setPreview({ blob, recipe, result })
                    if (!result.ok) throw new Error(result.error || 'Recipe failed.')
                  })
                }
              >
                Preview recipe
              </button>
              <button
                disabled={!currentPreview?.ok || !currentPreview.finalBytes || job.busy}
                onClick={() => {
                  if (currentPreview?.finalBytes) onApply(currentPreview.finalBytes, 'Apply recipe')
                }}
              >
                Apply preview
              </button>
              <button
                onClick={() =>
                  downloadBlob(
                    new Blob([json(recipe)], { type: 'application/json' }),
                    name + '.recipe.json',
                  )
                }
              >
                Export recipe
              </button>
              <button onClick={() => importRef.current?.click()}>Import recipe</button>
              <input
                ref={importRef}
                hidden
                type="file"
                accept=".json"
                onChange={(e) => {
                  const file = e.target.files?.[0]
                  e.target.value = ''
                  if (file)
                    void perform(async () => {
                      if (file.size > 256 * 1024) throw new Error('Recipe exceeds 256 KiB.')
                      const value = JSON.parse(await file.text())
                      const { validateRecipe } = await import('../../packages/core/src/recipe')
                      const validated = validateRecipe(value)
                      if (!validated.ok) throw new Error(validated.error)
                      if (
                        validated.recipe.steps.length > 100 ||
                        !validated.recipe.steps.every(
                          (s) => s && typeof s.id === 'string' && operations.includes(s.operation),
                        )
                      )
                        throw new Error('Invalid recipe steps.')
                      if (
                        validated.recipe.inputs.length !== 1 ||
                        validated.recipe.inputs[0]?.id !== 'input'
                      )
                        throw new Error('Use one recipe input named "input".')
                      setRecipe(validated.recipe)
                    })
                }}
              />
            </div>
            {currentPreview?.preview && (
              <>
                <p>
                  {currentPreview.preview.changedBytes} bytes would change. Apply preview creates
                  one undo step.
                </p>
                <div className="result-list">
                  {currentPreview.preview.firstChanges.map((change) => (
                    <div key={change.offset}>
                      <code>{hex(change.offset)}</code>
                      <span>
                        {change.before === null ? '—' : hex(change.before)} →{' '}
                        {change.after === null ? '—' : hex(change.after)}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
            {currentPreview && (
              <div className="result-list">
                {currentPreview.stepResults.map((s, i) => (
                  <div key={i}>
                    <strong>
                      {s.operation}: {s.status}
                    </strong>
                    <pre>
                      {s.error ||
                        (s.outputValue !== undefined
                          ? json(s.outputValue).slice(0, 4000)
                          : (s.outputHex ?? '').slice(0, 256))}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
        {tab === 'Strings' && (
          <>
            <div className="compact-actions">
              <label>
                Minimum characters{' '}
                <input
                  type="number"
                  min={2}
                  max={256}
                  aria-label="Minimum string length"
                  value={minimum}
                  onChange={(e) => setMinimum(Math.max(2, Math.min(256, Number(e.target.value))))}
                />
              </label>
              <button
                disabled={job.busy}
                onClick={() =>
                  void perform(async () => {
                    const data = await job.run<StringScanResult>('strings', {
                      blob,
                      minLength: minimum,
                    })
                    setStrings({ blob, data })
                  })
                }
              >
                Extract ASCII strings
              </button>
              {currentStrings?.nextCursor && (
                <button
                  disabled={job.busy}
                  onClick={() =>
                    void perform(async () => {
                      const data = await job.run<StringScanResult>('strings', {
                        blob,
                        minLength: minimum,
                        cursor: currentStrings.nextCursor,
                      })
                      setStrings({ blob, data })
                    })
                  }
                >
                  Next page
                </button>
              )}
            </div>
            <div className="result-list">
              {currentStrings?.items.map((s) => (
                <button
                  key={s.offset}
                  onClick={() => onSelect(s.offset, s.offset + s.byteLength - 1)}
                >
                  <code>{hex(s.offset)}</code>
                  <span>{s.value}</span>
                </button>
              ))}
            </div>
            {currentStrings && (
              <p>
                {currentStrings.items.length} strings
                {currentStrings.truncated ? ' · more available' : ''}
              </p>
            )}
          </>
        )}
        {tab === 'Evidence' && (
          <>
            <p>
              Export the file hash, annotated byte ranges, analysis, comparison results, and a
              recipe bound to this exact input.
            </p>
            <div className="compact-actions">
              <button disabled={job.busy} onClick={() => void perform(() => exportReport('json'))}>
                Export JSON evidence
              </button>
              <button disabled={job.busy} onClick={() => void perform(() => exportReport('md'))}>
                Export Markdown report
              </button>
            </div>
            <p>
              {notes.length} annotations · {currentDiff?.changes.length ?? 0} change regions ·{' '}
              {recipe.steps.length} replay steps
            </p>
            <details>
              <summary>CLI & MCP replay</summary>
              <pre>
                bitpeek hash "{name.replace(/["\r\n]/g, '')}" --algorithm sha256 --json{'\n'}bitpeek
                recipe run investigation.recipe.json --input input="{name.replace(/["\r\n]/g, '')}"
                --json
              </pre>
              <p>
                Export a recipe above. Its operations use the same engine as the CLI. The local MCP
                server can execute it with bitpeek_run_recipe.
              </p>
            </details>
          </>
        )}
      </div>
    </section>
  )
}
