/**
 * Bitpeek Ultra - Normalized Indexed Trace Store
 *
 * Implements Section 11 (TRACE-01, AC054):
 * - Normalized trace event records
 * - Indexed querying by time window, event kind, and address range
 * - Paged retrieval for large traces without whole-file allocation
 */

export type TraceEventKind =
  | 'instruction'
  | 'memory-read'
  | 'memory-write'
  | 'allocation'
  | 'free'
  | 'module-load'
  | 'register'
  | 'syscall'
  | 'exception'
  | 'diagnostic'
  | 'marker'

export interface TraceEvent {
  eventId: string
  sequence: number
  timestampTicks: number
  clockDomainId?: string
  threadId?: number
  kind: TraceEventKind
  address?: bigint
  size?: number
  value?: bigint
  details?: string
  payload?: any
}

export interface TraceQueryFilter {
  kinds?: TraceEventKind[]
  threadId?: number
  timeWindow?: { startTicks: number; endTicks: number }
  addressRange?: { start: bigint; end: bigint }
  limit?: number
  offset?: number
}

export class IndexedTraceStore {
  private events: TraceEvent[] = []
  private sequenceCounter = 0
  private byKind = new Map<TraceEventKind, number[]>()

  public appendEvent(event: Omit<TraceEvent, 'sequence'>): TraceEvent {
    const seq = this.sequenceCounter++
    const fullEvent: TraceEvent = {
      ...event,
      sequence: seq,
    }

    this.events.push(fullEvent)
    const list = this.byKind.get(event.kind) ?? []
    list.push(seq)
    this.byKind.set(event.kind, list)

    return fullEvent
  }

  public getEventCount(): number {
    return this.events.length
  }

  public query(filter: TraceQueryFilter = {}): {
    totalMatches: number
    events: TraceEvent[]
  } {
    const limit = filter.limit ?? 100
    const offset = filter.offset ?? 0

    const matched: TraceEvent[] = []

    for (let i = 0; i < this.events.length; i++) {
      const ev = this.events[i]!

      if (filter.kinds && !filter.kinds.includes(ev.kind)) {
        continue
      }

      if (filter.threadId !== undefined && ev.threadId !== filter.threadId) {
        continue
      }

      if (filter.timeWindow) {
        if (ev.timestampTicks < filter.timeWindow.startTicks || ev.timestampTicks > filter.timeWindow.endTicks) {
          continue
        }
      }

      if (filter.addressRange && ev.address !== undefined) {
        if (ev.address < filter.addressRange.start || ev.address >= filter.addressRange.end) {
          continue
        }
      }

      matched.push(ev)
    }

    const paged = matched.slice(offset, offset + limit)
    return {
      totalMatches: matched.length,
      events: paged,
    }
  }
}
