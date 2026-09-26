import { sha256Hex } from './crypto'

export interface RedactionOptions {
  hideFileName?: boolean
  hideHashes?: boolean
  hideRawBytes?: boolean
  hideStrings?: boolean
}

export interface EvidenceReportData {
  schemaVersion: 1
  operation: string
  version: string
  target: {
    name?: string
    length: number
    sha256?: string
  }
  range?: {
    start: number
    end: number // end-exclusive
  }
  parameters?: Record<string, unknown>
  result: Record<string, unknown>
  completeness: 'complete' | 'truncated' | 'partial'
  warnings?: string[]
  replayRecipe?: unknown
  metadata?: {
    timestamp?: string
    environment?: string
    tool?: string
  }
}

export function generateEvidenceReport(
  operation: string,
  bytes: Uint8Array,
  resultData: Record<string, unknown>,
  options: {
    fileName?: string
    range?: { start: number; end: number }
    parameters?: Record<string, unknown>
    warnings?: string[]
    completeness?: 'complete' | 'truncated' | 'partial'
    replayRecipe?: unknown
    redaction?: RedactionOptions
    version?: string
  } = {},
): { json: EvidenceReportData; humanSummary: string } {
  const redaction = options.redaction ?? {}
  const version = options.version ?? '1.0.0'
  const fullSha = sha256Hex(bytes)

  const report: EvidenceReportData = {
    schemaVersion: 1,
    operation,
    version,
    target: {
      name: redaction.hideFileName ? '[REDACTED]' : (options.fileName ?? 'document.bin'),
      length: bytes.length,
      sha256: redaction.hideHashes ? '[REDACTED]' : fullSha,
    },
    range: options.range,
    parameters: options.parameters,
    result: resultData,
    completeness: options.completeness ?? 'complete',
    warnings: options.warnings && options.warnings.length > 0 ? options.warnings : undefined,
    replayRecipe: options.replayRecipe,
    metadata: {
      timestamp: new Date().toISOString(),
      tool: `Bitpeek v${version}`,
    },
  }

  // Generate bounded Markdown human summary suitable for GitHub issue or PR
  let summary = `### Bitpeek Evidence: ${operation}\n\n`
  summary += `- **Target**: \`${report.target.name}\` (${report.target.length} bytes)\n`
  if (!redaction.hideHashes) {
    summary += `- **SHA-256**: \`${report.target.sha256}\`\n`
  }
  if (report.range) {
    summary += `- **Range**: \`0x${report.range.start.toString(16).toUpperCase()}..0x${report.range.end.toString(16).toUpperCase()}\` (${report.range.end - report.range.start} bytes)\n`
  }
  summary += `- **Status**: ${report.completeness}\n\n`

  summary += `**Findings & Result**:\n\`\`\`json\n${JSON.stringify(resultData, null, 2)}\n\`\`\`\n`

  if (report.warnings && report.warnings.length > 0) {
    summary += `\n**Warnings**:\n`
    for (const w of report.warnings) {
      summary += `- ${w}\n`
    }
  }

  if (report.replayRecipe) {
    summary += `\n**Replay Recipe**:\n\`\`\`json\n${JSON.stringify(report.replayRecipe, null, 2)}\n\`\`\`\n`
  }

  return {
    json: report,
    humanSummary: summary,
  }
}
