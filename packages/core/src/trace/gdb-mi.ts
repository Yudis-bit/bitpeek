/**
 * Bitpeek Ultra - GDB/MI (Machine Interface) Transport & Parser
 *
 * Implements Section 11 (TRACE-04, AC057):
 * - Structured GDB/MI async/result record parsing
 * - Token correlation
 * - Command allowlist and safety classification (read-only vs state-modifying)
 */

export type GdbMiRecordClass =
  | 'done'
  | 'running'
  | 'connected'
  | 'error'
  | 'exit'
  | 'stopped'
  | 'async'
  | 'stream'

export interface GdbMiRecord {
  token?: number
  type: 'result' | 'exec_async' | 'status_async' | 'notify_async' | 'console_stream' | 'target_stream' | 'log_stream'
  class?: GdbMiRecordClass
  payload?: any
  raw: string
}

export type GdbCommandCategory = 'read_only' | 'state_modifying' | 'forbidden'

export const GDB_COMMAND_ALLOWLIST: Record<string, GdbCommandCategory> = {
  '-data-read-memory': 'read_only',
  '-data-read-memory-bytes': 'read_only',
  '-data-evaluate-expression': 'read_only',
  '-stack-list-frames': 'read_only',
  '-stack-list-variables': 'read_only',
  '-thread-info': 'read_only',
  '-target-select': 'read_only',
  '-gdb-exit': 'read_only',
  '-exec-run': 'state_modifying',
  '-exec-continue': 'state_modifying',
  '-exec-step': 'state_modifying',
  '-exec-next': 'state_modifying',
  '-exec-interrupt': 'state_modifying',
  '-break-insert': 'state_modifying',
  '-break-delete': 'state_modifying',
}

export class GdbMiParser {
  /**
   * Classifies a GDB/MI command into read_only, state_modifying, or forbidden.
   */
  public static classifyCommand(command: string): GdbCommandCategory {
    const parts = command.trim().split(/\s+/)
    const cmd = parts[0]!
    return GDB_COMMAND_ALLOWLIST[cmd] ?? 'forbidden'
  }

  /**
   * Parses a single line of GDB/MI output.
   */
  public static parseLine(line: string): GdbMiRecord {
    const trimmed = line.trim()

    // 1. Stream records
    if (trimmed.startsWith('~')) {
      return {
        type: 'console_stream',
        class: 'stream',
        payload: this.parseCString(trimmed.substring(1)),
        raw: trimmed,
      }
    }
    if (trimmed.startsWith('@')) {
      return {
        type: 'target_stream',
        class: 'stream',
        payload: this.parseCString(trimmed.substring(1)),
        raw: trimmed,
      }
    }
    if (trimmed.startsWith('&')) {
      return {
        type: 'log_stream',
        class: 'stream',
        payload: this.parseCString(trimmed.substring(1)),
        raw: trimmed,
      }
    }

    // 2. Token extraction
    let token: number | undefined
    let rest = trimmed
    const tokenMatch = trimmed.match(/^([0-9]+)/)
    if (tokenMatch) {
      token = parseInt(tokenMatch[1]!, 10)
      rest = trimmed.substring(tokenMatch[1]!.length)
    }

    // 3. Result records: ^done, ^running, ^error
    if (rest.startsWith('^')) {
      const parts = rest.substring(1).split(',')
      const resClass = parts[0] as GdbMiRecordClass
      const payloadStr = rest.substring(1 + (parts[0]?.length ?? 0))
      return {
        token,
        type: 'result',
        class: resClass,
        payload: payloadStr.startsWith(',') ? payloadStr.substring(1) : undefined,
        raw: trimmed,
      }
    }

    // 4. Exec async records: *stopped, *running
    if (rest.startsWith('*')) {
      const parts = rest.substring(1).split(',')
      const cls = parts[0] as GdbMiRecordClass
      return {
        token,
        type: 'exec_async',
        class: cls,
        payload: rest.substring(1 + (parts[0]?.length ?? 0)),
        raw: trimmed,
      }
    }

    // 5. Notify / status async records: =thread-group-added, =breakpoint-modified
    if (rest.startsWith('=') || rest.startsWith('+')) {
      return {
        token,
        type: rest.startsWith('=') ? 'notify_async' : 'status_async',
        class: 'async',
        payload: rest.substring(1),
        raw: trimmed,
      }
    }

    return {
      token,
      type: 'result',
      raw: trimmed,
    }
  }

  private static parseCString(str: string): string {
    const trimmed = str.trim()
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
      try {
        return JSON.parse(trimmed)
      } catch {
        return trimmed.slice(1, -1)
      }
    }
    return trimmed
  }
}
