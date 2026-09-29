/**
 * Bitpeek Ultra - Delta-Debugging Testcase Reducer (ddmin)
 *
 * Implements Section 12 (RUN-04, AC060):
 * - Minimizes failing inputs using the ddmin delta-debugging algorithm
 * - Pure byte-level partitioning with budget limiting
 * - Verifies control input to ensure bug preservation
 */

export interface ReductionResult {
  originalLength: number
  reducedLength: number
  testsTried: number
  reducedBytes: Uint8Array
  isMinimalUnderTestedEdits: boolean
  controlPassed: boolean
}

export class DeltaDebuggingReducer {
  /**
   * Runs the ddmin algorithm over an input buffer to minimize it while preserving the oracle test.
   */
  public static async reduce(
    input: Uint8Array,
    oracle: (candidate: Uint8Array) => Promise<boolean> | boolean,
    maxTests = 1000,
  ): Promise<ReductionResult> {
    let testsTried = 0

    // 1. Verify initial input reproduces the bug
    testsTried++
    const initialReproduces = await oracle(input)
    if (!initialReproduces) {
      throw new Error('Initial input does not reproduce the bug under the provided oracle.')
    }

    // 2. Verify control input (empty buffer) does NOT reproduce
    testsTried++
    const emptyReproduces = await oracle(new Uint8Array(0))
    const controlPassed = !emptyReproduces

    let current = new Uint8Array(input)
    let n = 2 // initial number of chunks

    while (current.length >= 2 && n <= current.length && testsTried < maxTests) {
      const chunkSize = Math.ceil(current.length / n)
      let reducedInThisPass = false

      // Pass 1: Try removing each chunk
      for (let i = 0; i < n && testsTried < maxTests; i++) {
        const start = i * chunkSize
        const end = Math.min(start + chunkSize, current.length)
        if (start >= current.length) break

        const candidate = new Uint8Array(current.length - (end - start))
        candidate.set(current.subarray(0, start), 0)
        candidate.set(current.subarray(end), start)

        testsTried++
        const matched = await oracle(candidate)
        if (matched) {
          current = candidate
          n = Math.max(n - 1, 2)
          reducedInThisPass = true
          break
        }
      }

      if (reducedInThisPass) continue

      // Pass 2: Try keeping only each chunk
      for (let i = 0; i < n && testsTried < maxTests; i++) {
        const start = i * chunkSize
        const end = Math.min(start + chunkSize, current.length)
        if (start >= current.length) break

        const candidate = current.subarray(start, end)
        if (candidate.length === current.length) continue

        testsTried++
        const matched = await oracle(candidate)
        if (matched) {
          current = new Uint8Array(candidate)
          n = Math.max(n - 1, 2)
          reducedInThisPass = true
          break
        }
      }

      if (reducedInThisPass) continue

      // If neither succeeded, double n
      if (n === current.length) {
        break // Cannot partition further
      }
      n = Math.min(n * 2, current.length)
    }

    return {
      originalLength: input.length,
      reducedLength: current.length,
      testsTried,
      reducedBytes: current,
      isMinimalUnderTestedEdits: n >= current.length,
      controlPassed,
    }
  }
}
