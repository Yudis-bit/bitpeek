import { BitpeekError } from './errors'
import type { ByteSpan, SourceIdentity } from './types'

export type ArtifactKind =
  | 'acquisition'
  | 'source-snapshot'
  | 'derived-bytes'
  | 'parsed-field'
  | 'trace'
  | 'measurement'
  | 'finding'
  | 'report'

export type DataQuality =
  | 'observed'
  | 'derived-deterministic'
  | 'inferred'
  | 'corrected-candidate'
  | 'uncorrectable'
  | 'truncated'
  | 'missing'

export interface ProvenanceArtifact {
  readonly id: string
  readonly kind: ArtifactKind
  readonly label: string
  readonly quality: DataQuality
  readonly sourceIdentity?: SourceIdentity
  readonly metadata?: Record<string, unknown>
}

export type MappingRelationKind =
  | 'exact-affine'
  | 'exact-piecewise'
  | 'bit-permutation'
  | 'scatter-gather'
  | 'many-to-one'
  | 'one-to-many'
  | 'region-dependency'
  | 'inferred'
  | 'unknown'

export interface MappingRelation {
  readonly fromSpan: ByteSpan
  readonly toSpan: ByteSpan
  readonly relation: MappingRelationKind
  readonly operationId: string
}

export interface DerivationEvent {
  readonly eventId: string
  readonly operationId: string
  readonly operationVersion: number
  readonly inputArtifactIds: readonly string[]
  readonly outputArtifactIds: readonly string[]
  readonly mappings: readonly MappingRelation[]
  readonly parameters?: Record<string, unknown>
  readonly determinism: 'deterministic' | 'measured'
  readonly timestamp: string
}

export interface TraceOriginResult {
  readonly querySpan: ByteSpan
  readonly origins: Array<{
    readonly artifactId: string
    readonly span: ByteSpan
    readonly relation: MappingRelationKind
    readonly operationId: string
  }>
  readonly precision: 'exact' | 'region' | 'unknown'
}

/**
 * Manages the acyclic derivation DAG, cross-layer span mapping, and uncertainty ledger.
 */
export class ProvenanceGraph {
  private artifacts = new Map<string, ProvenanceArtifact>()
  private derivations = new Map<string, DerivationEvent>()
  private outputToEvent = new Map<string, string>() // outputArtifactId -> eventId
  private inputToEvents = new Map<string, Set<string>>() // inputArtifactId -> Set<eventId>

  addArtifact(artifact: ProvenanceArtifact): void {
    if (this.artifacts.has(artifact.id)) {
      throw new BitpeekError('INVALID_INPUT', `Artifact with ID ${artifact.id} already exists in graph.`)
    }
    this.artifacts.set(artifact.id, artifact)
  }

  getArtifact(id: string): ProvenanceArtifact | undefined {
    return this.artifacts.get(id)
  }

  addDerivation(event: DerivationEvent): void {
    if (this.derivations.has(event.eventId)) {
      throw new BitpeekError('INVALID_INPUT', `Derivation event ${event.eventId} already exists.`)
    }

    // Verify all input artifacts exist
    for (const inId of event.inputArtifactIds) {
      if (!this.artifacts.has(inId)) {
        throw new BitpeekError('INVALID_INPUT', `Referenced input artifact ${inId} does not exist in graph.`)
      }
    }

    // Verify all output artifacts exist
    for (const outId of event.outputArtifactIds) {
      if (!this.artifacts.has(outId)) {
        throw new BitpeekError('INVALID_INPUT', `Referenced output artifact ${outId} does not exist in graph.`)
      }
    }

    // Cycle detection: ensure no output artifact is an ancestor of any input artifact (AC025)
    for (const outId of event.outputArtifactIds) {
      for (const inId of event.inputArtifactIds) {
        if (this.isAncestor(outId, inId)) {
          throw new BitpeekError(
            'INVALID_INPUT',
            `Cycle detected in provenance graph: output artifact ${outId} is already an ancestor of input ${inId}.`,
          )
        }
      }
    }

    this.derivations.set(event.eventId, event)
    for (const outId of event.outputArtifactIds) {
      this.outputToEvent.set(outId, event.eventId)
    }
    for (const inId of event.inputArtifactIds) {
      if (!this.inputToEvents.has(inId)) {
        this.inputToEvents.set(inId, new Set())
      }
      this.inputToEvents.get(inId)!.add(event.eventId)
    }
  }

  /**
   * Returns true if candidateAncestor is an ancestor of targetId in the DAG.
   */
  private isAncestor(candidateAncestor: string, targetId: string, visited = new Set<string>()): boolean {
    if (candidateAncestor === targetId) return true
    if (visited.has(targetId)) return false
    visited.add(targetId)

    const eventId = this.outputToEvent.get(targetId)
    if (!eventId) return false

    const event = this.derivations.get(eventId)
    if (!event) return false

    for (const parentId of event.inputArtifactIds) {
      if (this.isAncestor(candidateAncestor, parentId, visited)) {
        return true
      }
    }
    return false
  }

  /**
   * Traces back a span in a derived artifact to its originating spans in upstream artifacts (AC021, AC022).
   */
  traceOrigin(targetArtifactId: string, querySpan: ByteSpan, maxDepth = 16): TraceOriginResult {
    const eventId = this.outputToEvent.get(targetArtifactId)
    if (!eventId) {
      // It is a root artifact (e.g. original acquisition)
      return {
        querySpan,
        origins: [{
          artifactId: targetArtifactId,
          span: querySpan,
          relation: 'exact-affine',
          operationId: 'root',
        }],
        precision: 'exact',
      }
    }

    const event = this.derivations.get(eventId)!
    const matchingOrigins: Array<{
      artifactId: string
      span: ByteSpan
      relation: MappingRelationKind
      operationId: string
    }> = []

    let overallPrecision: 'exact' | 'region' | 'unknown' = 'exact'

    for (const mapping of event.mappings) {
      // Check intersection with querySpan
      const from = mapping.fromSpan
      if (from.start < querySpan.endExclusive && from.endExclusive > querySpan.start) {
        if (mapping.relation === 'region-dependency' || mapping.relation === 'inferred') {
          overallPrecision = 'region'
        }
        matchingOrigins.push({
          artifactId: mapping.toSpan.sourceId,
          span: mapping.toSpan,
          relation: mapping.relation,
          operationId: mapping.operationId,
        })
      }
    }

    // If no explicit mapping rule matched, fallback to region dependency on all input artifacts
    if (matchingOrigins.length === 0) {
      for (const inId of event.inputArtifactIds) {
        matchingOrigins.push({
          artifactId: inId,
          span: { sourceId: inId, start: 0, endExclusive: 0 },
          relation: 'region-dependency',
          operationId: event.operationId,
        })
      }
      overallPrecision = 'region'
    }

    return {
      querySpan,
      origins: matchingOrigins,
      precision: overallPrecision,
    }
  }

  get stats() {
    return {
      artifactsCount: this.artifacts.size,
      derivationsCount: this.derivations.size,
    }
  }
}

/**
 * Validity Map representing presence of valid data vs missing/unread data without filling with 0x00/0xff (AC009).
 */
export class ValidityMap {
  private readonly totalSize: number
  private validRanges: Array<{ start: number; endExclusive: number }> = []

  constructor(totalSize: number) {
    this.totalSize = totalSize
  }

  markValid(start: number, endExclusive: number): void {
    this.validRanges.push({ start, endExclusive })
    this.normalize()
  }

  private normalize(): void {
    if (this.validRanges.length <= 1) return
    this.validRanges.sort((a, b) => a.start - b.start)
    const merged: Array<{ start: number; endExclusive: number }> = []
    let cur = this.validRanges[0]!

    for (let i = 1; i < this.validRanges.length; i++) {
      const next = this.validRanges[i]!
      if (next.start <= cur.endExclusive) {
        cur = { start: cur.start, endExclusive: Math.max(cur.endExclusive, next.endExclusive) }
      } else {
        merged.push(cur)
        cur = next
      }
    }
    merged.push(cur)
    this.validRanges = merged
  }

  isValid(offset: number): boolean {
    for (const r of this.validRanges) {
      if (offset >= r.start && offset < r.endExclusive) return true
    }
    return false
  }

  get missingRanges(): Array<{ start: number; endExclusive: number }> {
    const missing: Array<{ start: number; endExclusive: number }> = []
    let cursor = 0
    for (const r of this.validRanges) {
      if (r.start > cursor) {
        missing.push({ start: cursor, endExclusive: r.start })
      }
      cursor = Math.max(cursor, r.endExclusive)
    }
    if (cursor < this.totalSize) {
      missing.push({ start: cursor, endExclusive: this.totalSize })
    }
    return missing
  }
}
