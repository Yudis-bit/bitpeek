import { sha256Hex } from './crypto'

export interface EvidenceFinding {
  readonly id: string
  readonly title: string
  readonly severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  readonly observation: string
  readonly targetArtifactId: string
  readonly span?: { start: number; endExclusive: number }
  readonly reproductionCommand?: string
}

export interface EvidenceArtifactRecord {
  readonly size: number
  readonly sha256: string
  readonly isRedacted?: boolean
}

export interface EvidenceBundleManifest {
  readonly manifestVersion: 2
  readonly bundleId: string
  readonly timestamp: string
  readonly researcher?: string
  readonly targetName: string
  readonly findings: readonly EvidenceFinding[]
  readonly artifacts: Record<string, EvidenceArtifactRecord>
  readonly logs?: readonly string[]
  readonly notes?: readonly string[]
}

export interface BundleVerificationResult {
  readonly ok: boolean
  readonly integrity: 'verified' | 'tampered' | 'incomplete'
  readonly mismatches: readonly string[]
}

export async function verifyEvidenceBundle(
  manifest: EvidenceBundleManifest,
  artifactLoader: (id: string) => Promise<Uint8Array | undefined>,
): Promise<BundleVerificationResult> {
  const mismatches: string[] = []

  for (const [artId, meta] of Object.entries(manifest.artifacts)) {
    if (meta.isRedacted) continue

    const bytes = await artifactLoader(artId)
    if (!bytes) {
      mismatches.push(`Artifact "${artId}" is missing from bundle.`)
      continue
    }

    if (bytes.length !== meta.size) {
      mismatches.push(
        `Artifact "${artId}" size mismatch: expected ${meta.size} bytes, got ${bytes.length} bytes.`,
      )
      continue
    }

    const actualHash = sha256Hex(bytes).toLowerCase()
    if (actualHash !== meta.sha256.toLowerCase()) {
      mismatches.push(
        `Artifact "${artId}" SHA-256 integrity mismatch: expected ${meta.sha256}, got ${actualHash}.`,
      )
    }
  }

  if (mismatches.length > 0) {
    return {
      ok: false,
      integrity: 'tampered',
      mismatches,
    }
  }

  return {
    ok: true,
    integrity: 'verified',
    mismatches: [],
  }
}

export interface RedactionPolicy {
  sentinels: readonly string[]
  omitHashes?: boolean
}

/**
 * Recursively redacts sensitive strings, tokens, and hashes across nested objects, arrays, and fields (AC081).
 */
export function redactValue(value: unknown, policy: RedactionPolicy): unknown {
  if (typeof value === 'string') {
    let result = value

    // Redact sentinels
    for (const sentinel of policy.sentinels) {
      if (sentinel.length > 0) {
        result = result.replaceAll(sentinel, '[REDACTED]')
      }
    }

    // Optionally redact 64-char sha256 hex strings
    if (policy.omitHashes && /^[0-9a-fA-F]{64}$/.test(result)) {
      result = '[REDACTED_HASH]'
    }

    return result
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, policy))
  }

  if (typeof value === 'object' && value !== null) {
    const redactedObj: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) {
      if (policy.omitHashes && (k.toLowerCase().includes('sha256') || k.toLowerCase().includes('hash'))) {
        redactedObj[k] = '[REDACTED_HASH]'
      } else {
        redactedObj[k] = redactValue(v, policy)
      }
    }
    return redactedObj
  }

  return value
}

export function redactEvidenceBundle(
  manifest: EvidenceBundleManifest,
  policy: RedactionPolicy,
): EvidenceBundleManifest {
  return redactValue(manifest, policy) as EvidenceBundleManifest
}
