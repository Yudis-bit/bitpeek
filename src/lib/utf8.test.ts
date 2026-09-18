import { describe, expect, it } from 'vitest'
import { inspectUtf8, type Utf8Issue } from './utf8'

const encoder = new TextEncoder()

function inspect(values: number[]) {
  return inspectUtf8(Uint8Array.from(values))
}

function expectValid(text: string): void {
  expect(inspectUtf8(encoder.encode(text))).toEqual({ valid: true, issues: [] })
}

function expectIssues(values: number[], issues: Utf8Issue[]): void {
  expect(inspect(values)).toEqual({ valid: false, issues })
}

describe('UTF-8 validation', () => {
  it('accepts empty input, ASCII, and representative global text', () => {
    expectValid('')
    expectValid('Hello')
    expectValid('café')
    expectValid('👋')
    expectValid('中文')
    expectValid('العربية')
    expectValid('한국어')
  })

  it('accepts combining marks and invisible characters without normalization', () => {
    expectValid('e\u0301')
    expectValid('\u00e9')
    expectValid('A\u200b\u200d\u200e\u00a0B')

    expect(Array.from(encoder.encode('e\u0301'))).not.toEqual(
      Array.from(encoder.encode('\u00e9')),
    )
  })

  it('accepts every RFC 3629 boundary scalar', () => {
    expect(inspect([
      0x7f,
      0xc2, 0x80,
      0xdf, 0xbf,
      0xe0, 0xa0, 0x80,
      0xed, 0x9f, 0xbf,
      0xee, 0x80, 0x80,
      0xef, 0xbf, 0xbf,
      0xf0, 0x90, 0x80, 0x80,
      0xf4, 0x8f, 0xbf, 0xbf,
    ])).toEqual({ valid: true, issues: [] })
  })

  it('reports isolated continuation and invalid leading bytes individually', () => {
    expectIssues([0x80, 0x41, 0xbf, 0xff], [
      { start: 0, end: 0, reason: 'Unexpected UTF-8 continuation byte.' },
      { start: 2, end: 2, reason: 'Unexpected UTF-8 continuation byte.' },
      { start: 3, end: 3, reason: 'Invalid UTF-8 leading byte.' },
    ])
  })

  it('reports truncated sequences through their last available byte', () => {
    expectIssues([0xc2], [
      {
        start: 0,
        end: 0,
        reason: 'Truncated UTF-8 sequence; expected 1 more continuation byte.',
      },
    ])
    expectIssues([0xe2, 0x82], [
      {
        start: 0,
        end: 1,
        reason: 'Truncated UTF-8 sequence; expected 1 more continuation byte.',
      },
    ])
    expectIssues([0xf0, 0x9f, 0x91], [
      {
        start: 0,
        end: 2,
        reason: 'Truncated UTF-8 sequence; expected 1 more continuation byte.',
      },
    ])
  })

  it('rejects two-, three-, and four-byte overlong encodings', () => {
    const reason = 'Overlong UTF-8 encoding is not permitted.'
    expectIssues([0xc0, 0xaf, 0x41, 0xc1, 0xbf], [
      { start: 0, end: 1, reason },
      { start: 3, end: 4, reason },
    ])
    expectIssues([0xe0, 0x80, 0xaf, 0xf0, 0x80, 0x80, 0xaf], [
      { start: 0, end: 2, reason },
      { start: 3, end: 6, reason },
    ])
    expectIssues([0xe0, 0x80, 0x41, 0xf0, 0x8f], [
      { start: 0, end: 1, reason },
      { start: 3, end: 4, reason },
    ])
  })

  it('rejects UTF-8 encodings of surrogate code points', () => {
    const reason = 'UTF-8 must not encode Unicode surrogate code points.'
    expectIssues([0xed, 0xa0, 0x80, 0x41, 0xed, 0xbf, 0xbf], [
      { start: 0, end: 2, reason },
      { start: 4, end: 6, reason },
    ])
    expectIssues([0xed, 0xa0], [{ start: 0, end: 1, reason }])
  })

  it('rejects code points above U+10FFFF', () => {
    const reason = 'UTF-8 code point exceeds U+10FFFF.'
    expectIssues([0xf4, 0x90, 0x80, 0x80, 0x41, 0xf5, 0x80, 0x80, 0x80], [
      { start: 0, end: 3, reason },
      { start: 5, end: 8, reason },
    ])
    expectIssues([0xf4, 0x90, 0x41, 0xf7, 0xbf], [
      { start: 0, end: 1, reason },
      { start: 3, end: 4, reason },
    ])
  })

  it('recovers at the interrupting byte without swallowing later valid data', () => {
    expectIssues(
      [0x41, 0xe2, 0x82, 0x42, 0xa1, 0x43, 0xc2, 0xc2, 0xa2],
      [
        {
          start: 1,
          end: 2,
          reason: 'Interrupted UTF-8 sequence; expected 1 more continuation byte.',
        },
        {
          start: 4,
          end: 4,
          reason: 'Unexpected UTF-8 continuation byte.',
        },
        {
          start: 6,
          end: 6,
          reason: 'Interrupted UTF-8 sequence; expected 1 more continuation byte.',
        },
      ],
    )
  })

  it('uses inclusive, non-overlapping offsets relative to the provided view', () => {
    const backing = Uint8Array.from([0x41, 0x42, 0xe0, 0x80, 0x80, 0xff, 0x43])
    const result = inspectUtf8(backing.subarray(2, 6))

    expect(result).toEqual({
      valid: false,
      issues: [
        {
          start: 0,
          end: 2,
          reason: 'Overlong UTF-8 encoding is not permitted.',
        },
        { start: 3, end: 3, reason: 'Invalid UTF-8 leading byte.' },
      ],
    })
    expect(result.issues.every((issue, index, all) => {
      const previous = all[index - 1]
      return issue.start <= issue.end &&
        (previous === undefined || previous.end < issue.start)
    })).toBe(true)
  })
})
