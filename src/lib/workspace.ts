import type { ByteSelection } from './bytes'
import type { RecipeFile } from '../../packages/core/src/recipe'

export const MAX_FILE_BYTES = 512 * 1024 * 1024
export const MAX_TABS = 16
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024
export interface Annotation {
  id: string
  title: string
  body: string
  start: number
  end: number
  createdAt: string
}
export interface DocumentSnapshot {
  id: string
  name: string
  blob: Blob
  dirty: boolean
  selection: ByteSelection | null
  notes: Annotation[]
  recipe?: RecipeFile
  reference?: Blob
  referenceName?: string
  format?: string
  schema?: unknown
}
export interface SavedWorkspace {
  version: 1
  activeId: string
  documents: DocumentSnapshot[]
}

export function downloadBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = name
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

// Native Blob concatenation keeps file bodies out of JSON and avoids Base64 copies.
export function encodeProject(workspace: SavedWorkspace): Blob {
  const manifest = JSON.stringify({
    version: 1,
    activeId: workspace.activeId,
    documents: workspace.documents.map(({ blob, reference, ...doc }) => ({
      ...doc,
      size: blob.size,
      referenceSize: reference?.size,
    })),
  })
  const header = new TextEncoder().encode(manifest)
  if (header.length > MAX_MANIFEST_BYTES)
    throw new Error(
      'Project notes and settings exceed 4 MiB. Export notes separately or shorten them.',
    )
  const length = new Uint32Array([header.length])
  const prefix = new Uint8Array(12)
  prefix.set(new TextEncoder().encode('BITPEEK2'))
  new DataView(prefix.buffer).setUint32(8, length[0]!, true)
  return new Blob(
    [
      prefix,
      header,
      ...workspace.documents.flatMap((d) => (d.reference ? [d.blob, d.reference] : [d.blob])),
    ],
    { type: 'application/x-bitpeek-project' },
  )
}

export async function decodeProject(blob: Blob): Promise<SavedWorkspace> {
  const prefix = new Uint8Array(await blob.slice(0, 12).arrayBuffer())
  if (prefix.length !== 12 || new TextDecoder().decode(prefix.subarray(0, 8)) !== 'BITPEEK2')
    throw new Error('Not a Bitpeek project.')
  const size = new DataView(prefix.buffer).getUint32(8, true)
  if (size > MAX_MANIFEST_BYTES || size + 12 > blob.size)
    throw new Error('Invalid project manifest size.')
  const manifest = JSON.parse(await blob.slice(12, 12 + size).text())
  if (
    manifest.version !== 1 ||
    !Array.isArray(manifest.documents) ||
    !manifest.documents.length ||
    manifest.documents.length > MAX_TABS
  )
    throw new Error('Invalid project document list.')
  let offset = 12 + size
  const { validateRecipe } = await import('../../packages/core/src/recipe')
  const ids = new Set<string>()
  const documents: DocumentSnapshot[] = manifest.documents.map((doc: Record<string, unknown>) => {
    if (
      typeof doc.id !== 'string' ||
      ids.has(doc.id) ||
      typeof doc.name !== 'string' ||
      doc.name.length > 1024 ||
      !Number.isSafeInteger(doc.size) ||
      Number(doc.size) < 0 ||
      Number(doc.size) > MAX_FILE_BYTES ||
      offset + Number(doc.size) > blob.size
    )
      throw new Error('Invalid project document.')
    ids.add(doc.id)
    if (!Array.isArray(doc.notes) || doc.notes.length > 2000)
      throw new Error('Invalid annotations.')
    const notes = doc.notes as Annotation[]
    if (doc.recipe !== undefined) {
      const validation = validateRecipe(doc.recipe)
      if (!validation.ok) throw new Error(validation.error)
    }
    for (const note of notes) {
      if (
        !note ||
        typeof note.id !== 'string' ||
        typeof note.title !== 'string' ||
        typeof note.body !== 'string' ||
        typeof note.createdAt !== 'string' ||
        note.title.length > 1000 ||
        note.body.length > 20000 ||
        !Number.isSafeInteger(note.start) ||
        !Number.isSafeInteger(note.end) ||
        note.start < 0 ||
        note.end < note.start ||
        note.end >= Number(doc.size)
      )
        throw new Error('Invalid annotation range.')
    }
    let selection: ByteSelection | null = null
    const sel = doc.selection as ByteSelection | null
    if (
      sel &&
      Number.isSafeInteger(sel.anchor) &&
      Number.isSafeInteger(sel.focus) &&
      sel.anchor >= 0 &&
      sel.focus >= 0 &&
      sel.anchor < Number(doc.size) &&
      sel.focus < Number(doc.size)
    )
      selection = sel
    const body = blob.slice(offset, offset + Number(doc.size))
    offset += Number(doc.size)
    let reference: Blob | undefined
    if (doc.referenceSize !== undefined) {
      if (
        !Number.isSafeInteger(doc.referenceSize) ||
        Number(doc.referenceSize) < 0 ||
        Number(doc.referenceSize) > MAX_FILE_BYTES ||
        offset + Number(doc.referenceSize) > blob.size
      )
        throw new Error('Invalid reference file size.')
      reference = blob.slice(offset, offset + Number(doc.referenceSize))
      offset += Number(doc.referenceSize)
    }
    if (doc.format !== undefined && (typeof doc.format !== 'string' || doc.format.length > 64))
      throw new Error('Invalid format selection.')
    if (doc.schema !== undefined && JSON.stringify(doc.schema).length > 256 * 1024)
      throw new Error('Custom schema exceeds 256 KiB.')
    return {
      id: doc.id,
      name: doc.name,
      blob: body,
      dirty: doc.dirty === true,
      notes,
      selection,
      recipe: doc.recipe as RecipeFile | undefined,
      reference,
      referenceName:
        typeof doc.referenceName === 'string' ? doc.referenceName.slice(0, 1024) : undefined,
      format: doc.format as string | undefined,
      schema: doc.schema,
    }
  })
  if (offset !== blob.size) throw new Error('Unexpected trailing project data.')
  return {
    version: 1,
    activeId: ids.has(manifest.activeId) ? manifest.activeId : documents[0]!.id,
    documents,
  }
}

const storedBlobs = new Map<string, Blob>()

function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('bitpeek-workspace', 2)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains('sessions'))
        request.result.createObjectStore('sessions')
      if (!request.result.objectStoreNames.contains('binaries'))
        request.result.createObjectStore('binaries')
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
    request.onblocked = () =>
      reject(new Error('Close other Bitpeek tabs to update session storage.'))
  })
}

export async function storeSession(value: SavedWorkspace): Promise<void> {
  const db = await database()
  const nextBlobs = new Map<string, Blob>()
  const documents = value.documents.map(({ blob, reference, ...document }) => {
    nextBlobs.set('document:' + document.id, blob)
    if (reference) nextBlobs.set('reference:' + document.id, reference)
    return { ...document, hasReference: !!reference }
  })
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(['sessions', 'binaries'], 'readwrite')
      const files = tx.objectStore('binaries')
      for (const [key, blob] of nextBlobs) {
        if (storedBlobs.get(key) !== blob) files.put(blob, key)
      }
      const keys = files.getAllKeys()
      keys.onsuccess = () => {
        for (const key of keys.result) if (!nextBlobs.has(String(key))) files.delete(key)
      }
      tx.objectStore('sessions').put({ version: 2, activeId: value.activeId, documents }, 'last')
      tx.oncomplete = () => {
        storedBlobs.clear()
        for (const [key, blob] of nextBlobs) storedBlobs.set(key, blob)
        resolve()
      }
      tx.onerror = () => reject(tx.error)
      tx.onabort = () => reject(tx.error)
    })
  } finally {
    db.close()
  }
}

export async function loadSession(): Promise<SavedWorkspace | null> {
  const db = await database()
  try {
    return await new Promise<SavedWorkspace | null>((resolve, reject) => {
      const tx = db.transaction(['sessions', 'binaries'])
      const request = tx.objectStore('sessions').get('last')
      const getBlob = (key: string) =>
        new Promise<Blob>((done, fail) => {
          const req = tx.objectStore('binaries').get(key)
          req.onsuccess = () => {
            if (!(req.result instanceof Blob)) fail(new Error('Missing session file.'))
            else {
              storedBlobs.set(key, req.result)
              done(req.result)
            }
          }
          req.onerror = () => fail(req.error)
        })
      request.onsuccess = () => {
        const saved = request.result
        if (!saved) {
          resolve(null)
          return
        }
        if (saved.version === 1) {
          resolve(saved)
          return
        }
        if (
          saved.version !== 2 ||
          !Array.isArray(saved.documents) ||
          saved.documents.length > MAX_TABS
        ) {
          reject(new Error('Invalid saved session.'))
          return
        }
        const documents = saved.documents.map(
          async (doc: Omit<DocumentSnapshot, 'blob' | 'reference'> & { hasReference: boolean }) => {
            const bytes = getBlob('document:' + doc.id)
            const reference = doc.hasReference
              ? getBlob('reference:' + doc.id)
              : Promise.resolve(undefined)
            return { ...doc, blob: await bytes, reference: await reference }
          },
        )
        void Promise.all(documents)
          .then((documents) => resolve({ version: 1, activeId: saved.activeId, documents }))
          .catch(reject)
      }
      request.onerror = () => reject(request.error)
      tx.onabort = () => reject(tx.error)
    })
  } finally {
    db.close()
  }
}
