import { describe, expect, it } from 'vitest'
import { ProvenanceGraph, ValidityMap } from './provenance'
import { validateSafePath, ProjectSession } from './project'
import { validateRecipeV2, replayRecipeV2, type RecipeV2 } from './recipe-v2'
import {
  verifyEvidenceBundle,
  redactEvidenceBundle,
  type EvidenceBundleManifest,
} from './evidence-bundle'
import { sha256Hex } from './crypto'

describe('Provenance, Projects & Evidence (PROV-01..03, PROJ-01..03, EVID-02..04)', () => {
  it('detects and rejects derivation cycles in ProvenanceGraph (AC025)', () => {
    const graph = new ProvenanceGraph()
    graph.addArtifact({ id: 'art-A', kind: 'source-snapshot', label: 'A', quality: 'observed' })
    graph.addArtifact({ id: 'art-B', kind: 'derived-bytes', label: 'B', quality: 'derived-deterministic' })
    graph.addArtifact({ id: 'art-C', kind: 'derived-bytes', label: 'C', quality: 'derived-deterministic' })

    // A -> B
    graph.addDerivation({
      eventId: 'ev-1',
      operationId: 'op-1',
      operationVersion: 1,
      inputArtifactIds: ['art-A'],
      outputArtifactIds: ['art-B'],
      mappings: [],
      determinism: 'deterministic',
      timestamp: new Date().toISOString(),
    })

    // B -> C
    graph.addDerivation({
      eventId: 'ev-2',
      operationId: 'op-2',
      operationVersion: 1,
      inputArtifactIds: ['art-B'],
      outputArtifactIds: ['art-C'],
      mappings: [],
      determinism: 'deterministic',
      timestamp: new Date().toISOString(),
    })

    // Attempting C -> A forms a cycle and must be rejected
    expect(() => {
      graph.addDerivation({
        eventId: 'ev-3',
        operationId: 'op-cycle',
        operationVersion: 1,
        inputArtifactIds: ['art-C'],
        outputArtifactIds: ['art-A'],
        mappings: [],
        determinism: 'deterministic',
        timestamp: new Date().toISOString(),
      })
    }).toThrow(/Cycle detected/)
  })

  it('traces derived spans back to originating source spans (AC021, AC022)', () => {
    const graph = new ProvenanceGraph()
    graph.addArtifact({ id: 'raw.bin', kind: 'source-snapshot', label: 'Raw', quality: 'observed' })
    graph.addArtifact({ id: 'slice.bin', kind: 'derived-bytes', label: 'Slice', quality: 'derived-deterministic' })

    // Derivation: raw.bin [100, 200) -> slice.bin [0, 100)
    graph.addDerivation({
      eventId: 'dev-slice',
      operationId: 'slice',
      operationVersion: 1,
      inputArtifactIds: ['raw.bin'],
      outputArtifactIds: ['slice.bin'],
      mappings: [
        {
          fromSpan: { sourceId: 'slice.bin', start: 0, endExclusive: 100 },
          toSpan: { sourceId: 'raw.bin', start: 100, endExclusive: 200 },
          relation: 'exact-affine',
          operationId: 'slice',
        },
      ],
      determinism: 'deterministic',
      timestamp: new Date().toISOString(),
    })

    const trace = graph.traceOrigin('slice.bin', { sourceId: 'slice.bin', start: 10, endExclusive: 20 })
    expect(trace.precision).toBe('exact')
    expect(trace.origins).toHaveLength(1)
    expect(trace.origins[0]!.artifactId).toBe('raw.bin')
    expect(trace.origins[0]!.span.start).toBe(100)
    expect(trace.origins[0]!.span.endExclusive).toBe(200)
  })

  it('distinguishes missing bytes from observed zeros using ValidityMap (AC009)', () => {
    const vmap = new ValidityMap(100)
    // Mark [0, 20) and [40, 60) valid
    vmap.markValid(0, 20)
    vmap.markValid(40, 60)

    expect(vmap.isValid(10)).toBe(true)
    expect(vmap.isValid(25)).toBe(false) // missing
    expect(vmap.isValid(50)).toBe(true)
    expect(vmap.isValid(75)).toBe(false) // missing

    const missing = vmap.missingRanges
    expect(missing).toEqual([
      { start: 20, endExclusive: 40 },
      { start: 60, endExclusive: 100 },
    ])
  })

  it('rejects directory traversal, absolute paths, and Windows reserved names (AC028)', () => {
    expect(() => validateSafePath('../secret.txt')).toThrow(/traversal/)
    expect(() => validateSafePath('foo/../../bar.bin')).toThrow(/traversal/)
    expect(() => validateSafePath('/etc/passwd')).toThrow(/Absolute path/)
    expect(() => validateSafePath('C:\\Windows\\system32')).toThrow(/Absolute path/)
    expect(() => validateSafePath('data.bin:hidden_stream')).toThrow(/Alternate data streams/)
    expect(() => validateSafePath('AUX')).toThrow(/reserved device name/)
    expect(() => validateSafePath('sub/NUL.txt')).toThrow(/reserved device name/)
    expect(validateSafePath('artifacts/sample.bin')).toBe('artifacts/sample.bin')
  })

  it('validates and replays pure deterministic Recipe v2 without side effects (AC040, AC083)', () => {
    const inputBytes = Uint8Array.from([0x01, 0x02, 0x03, 0x04])
    const reversed = Uint8Array.from([0x04, 0x03, 0x02, 0x01])
    const expectedHash = sha256Hex(reversed).toLowerCase()

    const recipe: RecipeV2 = {
      recipeId: 'test-recipe-v2',
      version: 2,
      inputs: ['in-1'],
      steps: [
        {
          id: 'step-rev',
          operation: 'reverse',
          inputs: ['in-1'],
          expectedSha256: expectedHash,
        },
      ],
    }

    validateRecipeV2(recipe)
    const replay = replayRecipeV2(recipe, { 'in-1': inputBytes })
    expect(replay.ok).toBe(true)
    expect(Array.from(replay.results['step-rev']!.outputBytes!)).toEqual([0x04, 0x03, 0x02, 0x01])
    expect(replay.results['step-rev']!.matchesExpected).toBe(true)
  })

  it('verifies evidence bundle and detects tampering (AC082)', async () => {
    const artBytes = Uint8Array.from([0xaa, 0xbb, 0xcc])
    const artHash = sha256Hex(artBytes)

    const manifest: EvidenceBundleManifest = {
      manifestVersion: 2,
      bundleId: 'bundle-001',
      timestamp: new Date().toISOString(),
      targetName: 'firmware.bin',
      findings: [
        {
          id: 'find-1',
          title: 'Buffer Boundary',
          severity: 'high',
          observation: 'OOB observed at offset 10',
          targetArtifactId: 'art-1',
        },
      ],
      artifacts: {
        'art-1': { size: 3, sha256: artHash },
      },
    }

    // Good verification
    const good = await verifyEvidenceBundle(manifest, async (id) => (id === 'art-1' ? artBytes : undefined))
    expect(good.ok).toBe(true)
    expect(good.integrity).toBe('verified')

    // Tampered verification
    const tamperedBytes = Uint8Array.from([0xaa, 0x99, 0xcc])
    const tampered = await verifyEvidenceBundle(manifest, async (id) => (id === 'art-1' ? tamperedBytes : undefined))
    expect(tampered.ok).toBe(false)
    expect(tampered.integrity).toBe('tampered')
  })

  it('recursively redacts sentinels and sensitive hashes without leakage (AC081)', () => {
    const sensitive = 'SUPER_SECRET_TOKEN_123'
    const bundle: EvidenceBundleManifest = {
      manifestVersion: 2,
      bundleId: 'bundle-secret',
      timestamp: '2026-09-29',
      targetName: `firmware-${sensitive}.bin`,
      findings: [
        {
          id: 'find-1',
          title: `Secret leaked in ${sensitive}`,
          severity: 'critical',
          observation: `Key: ${sensitive}`,
          targetArtifactId: 'art-1',
        },
      ],
      artifacts: {
        'art-1': { size: 100, sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
      },
      logs: [`User logged with ${sensitive}`],
    }

    const redacted = redactEvidenceBundle(bundle, {
      sentinels: [sensitive],
      omitHashes: true,
    })

    const json = JSON.stringify(redacted)
    expect(json).not.toContain(sensitive)
    expect(json).toContain('[REDACTED]')
    expect(json).toContain('[REDACTED_HASH]')
  })
})
