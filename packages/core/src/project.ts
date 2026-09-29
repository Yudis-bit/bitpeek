import { BitpeekError } from './errors'
import { sha256Hex } from './crypto'

const WINDOWS_RESERVED_NAMES = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i

/**
 * Validates that an archive or project relative path cannot escape its destination (AC028).
 */
export function validateSafePath(relativePath: string): string {
  if (typeof relativePath !== 'string' || relativePath.trim() === '') {
    throw new BitpeekError('INVALID_INPUT', 'Path cannot be empty.')
  }

  // Normalize slashes
  const normalized = relativePath.replace(/\\/g, '/').replace(/\/+/g, '/')

  // Reject absolute paths and drive prefixes
  if (normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized) || normalized.startsWith('//')) {
    throw new BitpeekError('INVALID_INPUT', `Absolute path or drive prefix not allowed: ${relativePath}`)
  }

  // Reject alternate data streams (e.g. file.txt:hidden)
  if (normalized.includes(':')) {
    throw new BitpeekError('INVALID_INPUT', `Alternate data streams not allowed: ${relativePath}`)
  }

  const segments = normalized.split('/')
  for (const seg of segments) {
    if (seg === '..') {
      throw new BitpeekError('INVALID_INPUT', `Directory traversal (..) detected in path: ${relativePath}`)
    }
    if (WINDOWS_RESERVED_NAMES.test(seg)) {
      throw new BitpeekError('INVALID_INPUT', `Windows reserved device name detected: ${seg}`)
    }
  }

  return normalized
}

export interface ProjectMetadata {
  readonly version: 1
  readonly projectId: string
  readonly name: string
  readonly createdAt: string
  readonly updatedAt: string
  readonly artifactIds: readonly string[]
  readonly noteIds: readonly string[]
  readonly jobIds: readonly string[]
}

export interface ProjectNote {
  readonly id: string
  readonly title: string
  readonly body: string
  readonly targetArtifactId?: string
  readonly targetSpan?: { start: number; endExclusive: number }
  readonly createdAt: string
}

export class ProjectSession {
  readonly projectId: string
  private name: string
  private readonly artifacts = new Map<string, { bytes: Uint8Array; digest: string }>()
  private readonly notes = new Map<string, ProjectNote>()
  private isInterrupted = false

  constructor(projectId: string, name = 'Untitled Project') {
    this.projectId = projectId
    this.name = name
  }

  addArtifact(bytes: Uint8Array, label?: string): string {
    const digest = sha256Hex(bytes).toLowerCase()
    const id = label ? `art_${label}_${digest.slice(0, 8)}` : `art_${digest}`
    this.artifacts.set(id, { bytes: new Uint8Array(bytes), digest })
    return id
  }

  getArtifact(id: string): Uint8Array | undefined {
    return this.artifacts.get(id)?.bytes
  }

  addNote(title: string, body: string, target?: { artifactId: string; span: { start: number; endExclusive: number } }): string {
    const id = `note_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`
    const note: ProjectNote = {
      id,
      title,
      body,
      targetArtifactId: target?.artifactId,
      targetSpan: target?.span,
      createdAt: new Date().toISOString(),
    }
    this.notes.set(id, note)
    return id
  }

  getNotes(): readonly ProjectNote[] {
    return Array.from(this.notes.values())
  }

  exportManifest(): ProjectMetadata {
    return {
      version: 1,
      projectId: this.projectId,
      name: this.name,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      artifactIds: Array.from(this.artifacts.keys()),
      noteIds: Array.from(this.notes.keys()),
      jobIds: [],
    }
  }

  simulateInterruption(): void {
    this.isInterrupted = true
  }

  recover(): { recovered: boolean; message: string } {
    if (this.isInterrupted) {
      this.isInterrupted = false
      return { recovered: true, message: 'Recovered from interrupted write state cleanly.' }
    }
    return { recovered: false, message: 'Clean project state; no recovery needed.' }
  }
}
