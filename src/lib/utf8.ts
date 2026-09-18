export interface Utf8Issue {
  /** Inclusive byte offset relative to the inspected Uint8Array. */
  start: number
  /** Inclusive byte offset relative to the inspected Uint8Array. */
  end: number
  reason: string
}

export interface Utf8Inspection {
  valid: boolean
  issues: Utf8Issue[]
}

function isContinuation(byte: number): boolean {
  return byte >= 0x80 && byte <= 0xbf
}

function consumeCandidate(
  bytes: Uint8Array,
  start: number,
  expectedLength: number,
): number {
  let end = start
  const limit = Math.min(bytes.length, start + expectedLength)

  while (end + 1 < limit && isContinuation(bytes[end + 1] ?? 0)) {
    end += 1
  }

  return end
}

function continuationCountMessage(count: number): string {
  return `${count} more continuation byte${count === 1 ? '' : 's'}`
}

/**
 * Validates RFC 3629 UTF-8 without decoding or replacing malformed data.
 * Issue ranges are inclusive, non-overlapping, and relative to `bytes`.
 */
export function inspectUtf8(bytes: Uint8Array): Utf8Inspection {
  const issues: Utf8Issue[] = []
  let offset = 0

  while (offset < bytes.length) {
    const lead = bytes[offset] ?? 0

    if (lead <= 0x7f) {
      offset += 1
      continue
    }

    if (isContinuation(lead)) {
      issues.push({
        start: offset,
        end: offset,
        reason: 'Unexpected UTF-8 continuation byte.',
      })
      offset += 1
      continue
    }

    // C0 and C1 can only begin overlong encodings of ASCII code points.
    if (lead === 0xc0 || lead === 0xc1) {
      const end = consumeCandidate(bytes, offset, 2)
      issues.push({
        start: offset,
        end,
        reason: 'Overlong UTF-8 encoding is not permitted.',
      })
      offset = end + 1
      continue
    }

    // F5 through F7 have the shape of a four-byte sequence, but every value
    // they could encode is above Unicode's maximum scalar value.
    if (lead >= 0xf5 && lead <= 0xf7) {
      const end = consumeCandidate(bytes, offset, 4)
      issues.push({
        start: offset,
        end,
        reason: 'UTF-8 code point exceeds U+10FFFF.',
      })
      offset = end + 1
      continue
    }

    if (lead >= 0xf8) {
      issues.push({
        start: offset,
        end: offset,
        reason: 'Invalid UTF-8 leading byte.',
      })
      offset += 1
      continue
    }

    let expectedLength: number
    if (lead <= 0xdf) expectedLength = 2
    else if (lead <= 0xef) expectedLength = 3
    else expectedLength = 4

    const second = bytes[offset + 1]
    if (second !== undefined && isContinuation(second)) {
      let scalarIssue: string | null = null
      if ((lead === 0xe0 && second < 0xa0) || (lead === 0xf0 && second < 0x90)) {
        scalarIssue = 'Overlong UTF-8 encoding is not permitted.'
      } else if (lead === 0xed && second >= 0xa0) {
        scalarIssue = 'UTF-8 must not encode Unicode surrogate code points.'
      } else if (lead === 0xf4 && second > 0x8f) {
        scalarIssue = 'UTF-8 code point exceeds U+10FFFF.'
      }

      // The first continuation byte is enough to prove these candidates can
      // never encode a scalar value, even if later continuation bytes are absent.
      if (scalarIssue !== null) {
        const end = consumeCandidate(bytes, offset, expectedLength)
        issues.push({ start: offset, end, reason: scalarIssue })
        offset = end + 1
        continue
      }
    }

    let sequenceEnd = offset
    while (
      sequenceEnd + 1 < offset + expectedLength &&
      sequenceEnd + 1 < bytes.length &&
      isContinuation(bytes[sequenceEnd + 1] ?? 0)
    ) {
      sequenceEnd += 1
    }

    if (sequenceEnd + 1 < offset + expectedLength) {
      const remaining = offset + expectedLength - sequenceEnd - 1
      const truncated = sequenceEnd + 1 === bytes.length
      issues.push({
        start: offset,
        end: sequenceEnd,
        reason: truncated
          ? `Truncated UTF-8 sequence; expected ${continuationCountMessage(remaining)}.`
          : `Interrupted UTF-8 sequence; expected ${continuationCountMessage(remaining)}.`,
      })
      offset = sequenceEnd + 1
      continue
    }

    offset = sequenceEnd + 1
  }

  return { valid: issues.length === 0, issues }
}
