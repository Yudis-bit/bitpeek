/**
 * Bitpeek Ultra - Differential Testing Engine
 *
 * Implements Section 12 (RUN-05, AC064):
 * - Canonical output comparison between two implementations/targets
 * - Documented normalization of volatile fields (timestamps, temp paths)
 */

import type { ExperimentResult } from './experiment'

export interface DifferentialComparisonResult {
  isDivergent: boolean
  statusMatch: boolean
  exitCodeMatch: boolean
  stdoutMatch: boolean
  stderrMatch: boolean
  divergenceSummary?: string
}

export class DifferentialComparator {
  /**
   * Compares two experiment results and identifies divergence.
   */
  public static compare(
    runA: ExperimentResult,
    runB: ExperimentResult,
    normalize = true,
  ): DifferentialComparisonResult {
    const stdoutA = normalize ? this.normalizeText(runA.stdout) : runA.stdout
    const stdoutB = normalize ? this.normalizeText(runB.stdout) : runB.stdout

    const stderrA = normalize ? this.normalizeText(runA.stderr) : runA.stderr
    const stderrB = normalize ? this.normalizeText(runB.stderr) : runB.stderr

    const statusMatch = runA.status === runB.status
    const exitCodeMatch = runA.exitCode === runB.exitCode
    const stdoutMatch = stdoutA === stdoutB
    const stderrMatch = stderrA === stderrB

    const isDivergent = !statusMatch || !exitCodeMatch || !stdoutMatch || !stderrMatch

    let divergenceSummary: string | undefined
    if (isDivergent) {
      const reasons: string[] = []
      if (!statusMatch) reasons.push(`status mismatch (${runA.status} vs ${runB.status})`)
      if (!exitCodeMatch) reasons.push(`exitCode mismatch (${runA.exitCode} vs ${runB.exitCode})`)
      if (!stdoutMatch) reasons.push('stdout mismatch')
      if (!stderrMatch) reasons.push('stderr mismatch')
      divergenceSummary = reasons.join(', ')
    }

    return {
      isDivergent,
      statusMatch,
      exitCodeMatch,
      stdoutMatch,
      stderrMatch,
      divergenceSummary,
    }
  }

  private static normalizeText(text: string): string {
    return text
      // Replace timestamps like 2026-09-29T11:22:33Z or 11:22:33
      .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/g, '[TIMESTAMP]')
      // Replace temp file paths like /tmp/abc or C:\Users\...\Temp\abc
      .replace(/(?:\/tmp|\/var\/tmp|[A-Z]:\\[^\s]+\\Temp)\\[a-zA-Z0-9_.-]+/gi, '[TEMP_FILE]')
      .trim()
  }
}
