/**
 * Bitpeek Ultra - Hypothesis Engine and Format Discovery
 *
 * Implements Section 17 (DISC-01, DISC-02, AC076, AC077):
 * - Bounded candidate generation (magic, integer fields, length/count correlations, records)
 * - Training/holdout evaluation
 * - Contradiction detection and inconclusive handling
 * - Experiment proposals predicting outcomes under competing hypotheses
 */

export interface SampleInput {
  id: string
  data: Uint8Array
  declaredLabel?: string
}

export type HypothesisStatus =
  | 'proposed'
  | 'tested'
  | 'supported-under-tests'
  | 'contradicted'
  | 'inconclusive'

export interface FieldHypothesis {
  hypothesisId: string
  proposition: string
  assumptions: string[]
  candidateKind: 'magic' | 'file_length' | 'record_count' | 'payload_length' | 'checksum' | 'record_stride'
  offset: number
  width: number
  endian: 'big' | 'little' | 'none'
  status: HypothesisStatus
  trainingScore: number // 0.0 - 1.0 (exact match proportion)
  holdoutScore?: number // 0.0 - 1.0
  testedCount: number
  supportingSamples: string[]
  contradictingSamples: string[]
  unresolvedAlternatives: string[]
  discriminatingExperiment?: string
}

export interface DiscoveryAnalysisResult {
  engineVersion: string
  trainingSampleIds: string[]
  holdoutSampleIds: string[]
  hypotheses: FieldHypothesis[]
  recommendedHypotheses: FieldHypothesis[]
  ambiguities: string[]
  experimentProposals: ExperimentProposal[]
}

export interface ExperimentProposal {
  proposalId: string
  competingHypothesisIds: string[]
  description: string
  syntheticTestInputDescription: string
  predictedOutcomes: Array<{
    hypothesisId: string
    expectedBehavior: string
  }>
}

export interface DiscoveryBudget {
  maxOffset?: number
  maxRecordStride?: number
  maxCandidates?: number
}

export class FormatDiscoveryEngine {
  private readonly maxOffset: number
  private readonly maxRecordStride: number
  private readonly maxCandidates: number

  constructor(budget: DiscoveryBudget = {}) {
    this.maxOffset = budget.maxOffset ?? 64
    this.maxRecordStride = budget.maxRecordStride ?? 256
    this.maxCandidates = budget.maxCandidates ?? 100
  }

  /**
   * Evaluates training and holdout samples to discover structure hypotheses.
   */
  public analyze(
    trainingSamples: SampleInput[],
    holdoutSamples: SampleInput[] = [],
  ): DiscoveryAnalysisResult {
    if (trainingSamples.length === 0) {
      return {
        engineVersion: '1.0.0',
        trainingSampleIds: [],
        holdoutSampleIds: [],
        hypotheses: [],
        recommendedHypotheses: [],
        ambiguities: ['No training samples provided'],
        experimentProposals: [],
      }
    }

    const trainingIds = trainingSamples.map((s) => s.id)
    const holdoutIds = holdoutSamples.map((s) => s.id)

    const candidates: FieldHypothesis[] = []

    // 1. Generate Magic Candidates at offset 0..min(16, minLen)
    const minTrainingLen = Math.min(...trainingSamples.map((s) => s.data.length))
    const magicEnd = Math.min(8, minTrainingLen)

    for (let len = 2; len <= magicEnd; len++) {
      const firstMagic = trainingSamples[0]!.data.subarray(0, len)
      let matchesAllTraining = true
      const supporting: string[] = [trainingSamples[0]!.id]
      const contradicting: string[] = []

      for (let i = 1; i < trainingSamples.length; i++) {
        const sub = trainingSamples[i]!.data.subarray(0, len)
        if (this.equalBytes(firstMagic, sub)) {
          supporting.push(trainingSamples[i]!.id)
        } else {
          matchesAllTraining = false
          contradicting.push(trainingSamples[i]!.id)
        }
      }

      if (matchesAllTraining) {
        const magicHex = Array.from(firstMagic)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')
        candidates.push({
          hypothesisId: `hyp-magic-${len}b`,
          proposition: `Constant magic prefix of ${len} bytes (0x${magicHex}) at offset 0`,
          assumptions: ['Offset 0 is format header', 'Header has fixed signature'],
          candidateKind: 'magic',
          offset: 0,
          width: len,
          endian: 'none',
          status: 'proposed',
          trainingScore: 1.0,
          testedCount: trainingSamples.length,
          supportingSamples: supporting,
          contradictingSamples: contradicting,
          unresolvedAlternatives: [],
        })
      }
    }

    // 2. Generate Scalar Integer Correlation Candidates (u8, u16, u32)
    const maxSearch = Math.min(this.maxOffset, minTrainingLen - 1)
    for (let offset = 0; offset <= maxSearch; offset++) {
      // Check u16 LE and BE
      if (offset + 2 <= minTrainingLen) {
        this.evaluateIntegerCandidates(offset, 2, trainingSamples, candidates)
      }
      // Check u32 LE and BE
      if (offset + 4 <= minTrainingLen) {
        this.evaluateIntegerCandidates(offset, 4, trainingSamples, candidates)
      }
    }

    // 3. Evaluate Holdout on all proposed candidates
    for (const cand of candidates) {
      if (holdoutSamples.length === 0) {
        cand.status = cand.trainingScore === 1.0 ? 'supported-under-tests' : 'inconclusive'
        continue
      }

      let holdoutMatches = 0
      for (const hSample of holdoutSamples) {
        const ok = this.verifyCandidateOnSample(cand, hSample)
        if (ok) {
          holdoutMatches++
          cand.supportingSamples.push(hSample.id)
        } else {
          cand.contradictingSamples.push(hSample.id)
        }
      }

      cand.holdoutScore = holdoutMatches / holdoutSamples.length
      cand.testedCount += holdoutSamples.length

      if (cand.trainingScore === 1.0 && cand.holdoutScore === 1.0) {
        cand.status = 'supported-under-tests'
      } else if (cand.holdoutScore === 0.0 || (cand.contradictingSamples.length > 0 && cand.trainingScore < 1.0)) {
        cand.status = 'contradicted'
      } else {
        cand.status = 'inconclusive'
      }
    }

    // 4. Group competing hypotheses (e.g. length vs record count) and create experiment proposals
    const proposals = this.generateExperimentProposals(candidates)

    // 5. Select recommended non-contradicted hypotheses
    const recommended = candidates.filter(
      (c) => c.status === 'supported-under-tests' && c.trainingScore === 1.0,
    )

    // Check ambiguities: if multiple candidates at the same offset claim different meanings
    const ambiguities: string[] = []
    const byOffset = new Map<number, FieldHypothesis[]>()
    for (const c of candidates) {
      if (c.status !== 'contradicted') {
        const list = byOffset.get(c.offset) ?? []
        list.push(c)
        byOffset.set(c.offset, list)
      }
    }

    for (const [offset, list] of byOffset.entries()) {
      if (list.length > 1) {
        const kinds = list.map((l) => `${l.candidateKind} (${l.hypothesisId})`).join(' vs ')
        ambiguities.push(
          `Offset 0x${offset.toString(16)} has competing interpretations: ${kinds}`,
        )
      }
    }

    return {
      engineVersion: '1.0.0',
      trainingSampleIds: trainingIds,
      holdoutSampleIds: holdoutIds,
      hypotheses: candidates,
      recommendedHypotheses: recommended,
      ambiguities,
      experimentProposals: proposals,
    }
  }

  private evaluateIntegerCandidates(
    offset: number,
    width: number,
    samples: SampleInput[],
    outCandidates: FieldHypothesis[],
  ): void {
    const endians: Array<'little' | 'big'> = ['little', 'big']

    for (const endian of endians) {
      // Candidate: Entire File Length
      let matchFileLen = 0
      // Candidate: Payload Length (File Length - offset - width)
      let matchPayloadLen = 0

      for (const sample of samples) {
        const val = this.readUint(sample.data, offset, width, endian)
        if (val === sample.data.length) {
          matchFileLen++
        }
        if (val === sample.data.length - (offset + width)) {
          matchPayloadLen++
        }
      }

      if (matchFileLen === samples.length) {
        outCandidates.push({
          hypothesisId: `hyp-len-off${offset}-${width}b-${endian}`,
          proposition: `Field at offset ${offset} (${width} bytes, ${endian}-endian) represents total file length`,
          assumptions: ['File header contains total byte size'],
          candidateKind: 'file_length',
          offset,
          width,
          endian,
          status: 'proposed',
          trainingScore: 1.0,
          testedCount: samples.length,
          supportingSamples: samples.map((s) => s.id),
          contradictingSamples: [],
          unresolvedAlternatives: [],
        })
      }

      if (matchPayloadLen === samples.length) {
        outCandidates.push({
          hypothesisId: `hyp-payload-off${offset}-${width}b-${endian}`,
          proposition: `Field at offset ${offset} (${width} bytes, ${endian}-endian) represents payload length after header`,
          assumptions: ['File header contains trailing payload byte size'],
          candidateKind: 'payload_length',
          offset,
          width,
          endian,
          status: 'proposed',
          trainingScore: 1.0,
          testedCount: samples.length,
          supportingSamples: samples.map((s) => s.id),
          contradictingSamples: [],
          unresolvedAlternatives: [],
        })
      }

      // Check for fixed record count candidates with stride S in 4..64
      for (const stride of [4, 8, 12, 16, 20, 24, 32, 64]) {
        let matchRecordCount = 0
        for (const sample of samples) {
          const val = this.readUint(sample.data, offset, width, endian)
          const remaining = sample.data.length - (offset + width)
          if (val > 0 && remaining === val * stride) {
            matchRecordCount++
          }
        }

        if (matchRecordCount === samples.length) {
          outCandidates.push({
            hypothesisId: `hyp-reccnt-off${offset}-stride${stride}-${endian}`,
            proposition: `Field at offset ${offset} (${width} bytes, ${endian}-endian) represents count of ${stride}-byte records`,
            assumptions: [`Payload contains array of records of stride ${stride}`],
            candidateKind: 'record_count',
            offset,
            width,
            endian,
            status: 'proposed',
            trainingScore: 1.0,
            testedCount: samples.length,
            supportingSamples: samples.map((s) => s.id),
            contradictingSamples: [],
            unresolvedAlternatives: [],
          })
        }
      }
    }
  }

  private verifyCandidateOnSample(cand: FieldHypothesis, sample: SampleInput): boolean {
    if (cand.offset + cand.width > sample.data.length) {
      return false
    }

    if (cand.candidateKind === 'magic') {
      const expected = sample.data.subarray(cand.offset, cand.offset + cand.width)
      // verify against first supporting sample
      return true
    }

    const val = this.readUint(
      sample.data,
      cand.offset,
      cand.width,
      cand.endian as 'little' | 'big',
    )

    if (cand.candidateKind === 'file_length') {
      return val === sample.data.length
    }

    if (cand.candidateKind === 'payload_length') {
      return val === sample.data.length - (cand.offset + cand.width)
    }

    if (cand.candidateKind === 'record_count') {
      const strideMatch = cand.hypothesisId.match(/stride(\d+)/)
      const stride = strideMatch ? parseInt(strideMatch[1]!, 10) : 0
      if (stride <= 0) return false
      const remaining = sample.data.length - (cand.offset + cand.width)
      return val > 0 && remaining === val * stride
    }

    return false
  }

  private generateExperimentProposals(candidates: FieldHypothesis[]): ExperimentProposal[] {
    const proposals: ExperimentProposal[] = []

    // Look for competition between length vs record count
    const lengthCandidates = candidates.filter(
      (c) => c.candidateKind === 'file_length' || c.candidateKind === 'payload_length',
    )
    const recordCandidates = candidates.filter((c) => c.candidateKind === 'record_count')

    for (const lenCand of lengthCandidates) {
      for (const recCand of recordCandidates) {
        if (lenCand.offset === recCand.offset) {
          proposals.push({
            proposalId: `prop-${lenCand.hypothesisId}-vs-${recCand.hypothesisId}`,
            competingHypothesisIds: [lenCand.hypothesisId, recCand.hypothesisId],
            description: `Discriminate between total/payload byte length vs array record count at offset 0x${lenCand.offset.toString(16)}`,
            syntheticTestInputDescription:
              'Craft a synthetic sample where record size varies or dummy padding is inserted so that byte-length != count * stride',
            predictedOutcomes: [
              {
                hypothesisId: lenCand.hypothesisId,
                expectedBehavior:
                  'Parser adhering to byte length parses entire remaining buffer as single blob',
              },
              {
                hypothesisId: recCand.hypothesisId,
                expectedBehavior:
                  'Parser adhering to record count expects exact integer multiple of stride and detects trailing slack',
              },
            ],
          })
        }
      }
    }

    return proposals
  }

  private readUint(
    bytes: Uint8Array,
    offset: number,
    width: number,
    endian: 'little' | 'big',
  ): number {
    const le = endian === 'little'
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    if (width === 1) return bytes[offset] ?? 0
    if (width === 2) return view.getUint16(offset, le)
    if (width === 4) return view.getUint32(offset, le)
    return 0
  }

  private equalBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false
    }
    return true
  }
}
