export interface AlignedChange {
  kind: 'modified' | 'inserted' | 'deleted'
  currentStart: number
  referenceStart: number
  currentLength: number
  referenceLength: number
}
export interface AlignedDiff {
  changes: AlignedChange[]
  modified: number
  inserted: number
  deleted: number
  truncated: boolean
}

// Bounded anchor alignment: each mismatch searches at most 4 KiB ahead.
// Exact 16-byte anchor verification prevents hash collisions becoming alignments.
export async function alignedDiff(
  current: Blob,
  reference: Blob,
  progress?: (value: number) => void,
): Promise<AlignedDiff> {
  const result: AlignedDiff = {
    changes: [],
    modified: 0,
    inserted: 0,
    deleted: 0,
    truncated: false,
  }
  let a = 0,
    b = 0
  const emit = (ca: number, rb: number) => {
    const shared = Math.min(ca, rb)
    const add = (kind: AlignedChange['kind'], cl: number, rl: number) => {
      const previous = result.changes.at(-1)
      if (
        previous &&
        previous.kind === kind &&
        previous.currentStart + previous.currentLength === a &&
        previous.referenceStart + previous.referenceLength === b
      ) {
        previous.currentLength += cl
        previous.referenceLength += rl
      } else if (result.changes.length < 2000)
        result.changes.push({
          kind,
          currentStart: a,
          referenceStart: b,
          currentLength: cl,
          referenceLength: rl,
        })
      else result.truncated = true
      a += cl
      b += rl
    }
    if (shared) {
      result.modified += shared
      add('modified', shared, shared)
    }
    if (ca > shared) {
      result.inserted += ca - shared
      add('inserted', ca - shared, 0)
    }
    if (rb > shared) {
      result.deleted += rb - shared
      add('deleted', 0, rb - shared)
    }
  }
  while (a < current.size && b < reference.size) {
    const [x, y] = await Promise.all([
      current.slice(a, a + 65536).arrayBuffer(),
      reference.slice(b, b + 65536).arrayBuffer(),
    ]).then((v) => v.map((z) => new Uint8Array(z)))
    const left = x!,
      right = y!
    let same = 0
    while (same < Math.min(left.length, right.length) && left[same] === right[same]) same++
    if (same) {
      a += same
      b += same
      progress?.((a + b) / Math.max(1, current.size + reference.size))
      continue
    }
    const limitA = Math.min(4096, left.length - 16),
      limitB = Math.min(4096, right.length - 16)
    const key = (bytes: Uint8Array, i: number) => {
      let h = 2166136261
      for (let n = 0; n < 16; n++) h = Math.imul(h ^ bytes[i + n]!, 16777619)
      return h >>> 0
    }
    const anchors = new Map<number, number[]>()
    for (let j = 0; j <= limitB; j++) {
      const h = key(right, j)
      const values = anchors.get(h)
      if (values) {
        if (values.length < 8) values.push(j)
      } else anchors.set(h, [j])
    }
    let best: [number, number] | null = null
    for (let i = 0; i <= limitA && (!best || i < best[0] + best[1]); i++) {
      for (const j of anchors.get(key(left, i)) ?? []) {
        if ((!i && !j) || (best && i + j >= best[0] + best[1])) continue
        let equal = true
        for (let n = 0; n < 16; n++)
          if (left[i + n] !== right[j + n]) {
            equal = false
            break
          }
        if (equal) best = [i, j]
      }
    }
    if (best) emit(best[0], best[1])
    else {
      let suffix = 0
      if (
        left.length !== right.length &&
        left.length <= 4096 &&
        right.length <= 4096 &&
        a + left.length === current.size &&
        b + right.length === reference.size
      ) {
        while (
          suffix < Math.min(left.length, right.length) &&
          left[left.length - suffix - 1] === right[right.length - suffix - 1]
        )
          suffix++
      }
      if (suffix) emit(left.length - suffix, right.length - suffix)
      else {
        const n = Math.min(4096, left.length, right.length)
        for (let i = 0; i < n; i++) {
          if (left[i] === right[i]) {
            a++
            b++
          } else emit(1, 1)
        }
      }
    }
    progress?.((a + b) / Math.max(1, current.size + reference.size))
  }
  emit(current.size - a, reference.size - b)
  progress?.(1)
  return result
}
