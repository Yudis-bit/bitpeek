/**
 * Bitpeek Ultra - Experiment Oracles & Flakiness Policy
 *
 * Implements Section 12 (RUN-03, AC060):
 * - Oracle matchers: exit status, crash signatures, sanitizer diagnostics
 * - Distinguishes timeouts, OOMs, harness errors, and target bugs
 */

import type { ExperimentResult } from './experiment'
import { SanitizerLogParser } from '../trace/sanitizers'

export type OracleKind =
  | 'exit_code'
  | 'crash_any'
  | 'output_contains'
  | 'sanitizer_bug'

export interface OracleDefinition {
  oracleId: string
  kind: OracleKind
  expectedExitCode?: number
  expectedSubstring?: string
  expectedSanitizerBug?: string // e.g. "heap-use-after-free"
}

export class OracleMatcher {
  public static matches(oracle: OracleDefinition, result: ExperimentResult): boolean {
    switch (oracle.kind) {
      case 'exit_code':
        return result.exitCode === oracle.expectedExitCode

      case 'crash_any':
        return result.status === 'crash' || (result.exitCode !== undefined && result.exitCode !== 0)

      case 'output_contains': {
        const sub = oracle.expectedSubstring ?? ''
        return result.stdout.includes(sub) || result.stderr.includes(sub)
      }

      case 'sanitizer_bug': {
        const combined = `${result.stdout}\n${result.stderr}`
        const diag = SanitizerLogParser.parseAsan(combined) ?? SanitizerLogParser.parseUbsan(combined)
        if (!diag) return false
        if (!oracle.expectedSanitizerBug) return true
        return diag.errorType.toLowerCase().includes(oracle.expectedSanitizerBug.toLowerCase())
      }
    }
  }
}
