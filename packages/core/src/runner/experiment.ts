/**
 * Bitpeek Ultra - Experiment Specifications & Process Execution Model
 *
 * Implements Section 12 (RUN-01, RUN-02, AC058, AC059):
 * - Immutable experiment specifications
 * - Isolation backend declaration (fixture, container, job_object)
 * - Resource limits (timeout, output size, memory)
 */

export interface ExperimentLimits {
  wallTimeMs: number
  maxOutputBytes?: number
  maxMemoryBytes?: number
}

export interface ExperimentSpec {
  experimentId: string
  targetExecutable: string
  argv: string[]
  envAllowlist?: Record<string, string>
  isolationBackend: 'fixture_mock' | 'windows_job' | 'container' | 'host_process'
  limits: ExperimentLimits
  seed: number
  oracleId?: string
}

export interface ExperimentResult {
  experimentId: string
  status: 'oracle_hit' | 'clean_exit' | 'crash' | 'timeout' | 'oom' | 'error'
  exitCode?: number
  stdout: string
  stderr: string
  durationMs: number
  isTruncated: boolean
  oracleMatched?: boolean
}
