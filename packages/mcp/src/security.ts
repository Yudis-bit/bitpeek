import { realpath, stat } from 'node:fs/promises'
import { resolve, normalize, relative, isAbsolute } from 'node:path'
import { BitpeekError } from '../../core/src/index'

export interface McpSecurityPolicy {
  allowedInputRoots: string[]
  allowedOutputRoots: string[]
  maxOpenSessions: number
}

export interface McpSession {
  handle: string
  filePath: string
  canonicalPath: string
  size: number
  openedAt: number
  lastAccessedAt: number
}

export class McpSecurityManager {
  private policy: McpSecurityPolicy
  private sessions = new Map<string, McpSession>()

  constructor(policy?: Partial<McpSecurityPolicy>) {
    this.policy = {
      allowedInputRoots: policy?.allowedInputRoots ?? [process.cwd()],
      allowedOutputRoots: policy?.allowedOutputRoots ?? [process.cwd()],
      maxOpenSessions: policy?.maxOpenSessions ?? 20,
    }
  }

  async validateInputPath(filePath: string): Promise<string> {
    const absPath = resolve(filePath)
    let real: string
    try {
      real = await realpath(absPath)
    } catch (err: unknown) {
      throw new BitpeekError('IO_ERROR', `Cannot access file "${filePath}": ${String(err)}`)
    }

    const fileStat = await stat(real)
    if (!fileStat.isFile()) {
      throw new BitpeekError('INVALID_INPUT', `Path is not a regular file: "${filePath}".`)
    }

    const isAllowed = this.policy.allowedInputRoots.some((root) => {
      const canonicalRoot = resolve(root)
      const rel = relative(canonicalRoot, real)
      return !rel.startsWith('..') && !isAbsolute(rel)
    })

    if (!isAllowed) {
      throw new BitpeekError(
        'INVALID_INPUT',
        `Access denied: "${filePath}" is outside allowed input roots [${this.policy.allowedInputRoots.join(', ')}].`,
      )
    }

    return real
  }

  async validateOutputPath(outputPath: string): Promise<string> {
    const absPath = resolve(outputPath)
    const norm = normalize(absPath)

    const isAllowed = this.policy.allowedOutputRoots.some((root) => {
      const canonicalRoot = resolve(root)
      const rel = relative(canonicalRoot, norm)
      return !rel.startsWith('..') && !isAbsolute(rel)
    })

    if (!isAllowed) {
      throw new BitpeekError(
        'INVALID_INPUT',
        `Access denied: Output path "${outputPath}" is outside allowed output roots.`,
      )
    }

    return norm
  }

  createSession(canonicalPath: string, size: number): string {
    if (this.sessions.size >= this.policy.maxOpenSessions) {
      // Evict oldest session
      let oldestKey: string | null = null
      let oldestTime = Infinity
      for (const [key, sess] of this.sessions.entries()) {
        if (sess.lastAccessedAt < oldestTime) {
          oldestTime = sess.lastAccessedAt
          oldestKey = key
        }
      }
      if (oldestKey) this.sessions.delete(oldestKey)
    }

    const handle = `sess_${Math.random().toString(36).slice(2, 10)}_${Date.now().toString(36)}`
    const now = Date.now()
    this.sessions.set(handle, {
      handle,
      filePath: canonicalPath,
      canonicalPath,
      size,
      openedAt: now,
      lastAccessedAt: now,
    })
    return handle
  }

  getSession(handle: string): McpSession {
    const session = this.sessions.get(handle)
    if (!session) {
      throw new BitpeekError('INVALID_INPUT', `Session handle "${handle}" not found or expired.`)
    }
    session.lastAccessedAt = Date.now()
    return session
  }

  closeSession(handle: string): boolean {
    return this.sessions.delete(handle)
  }

  closeAll(): void {
    this.sessions.clear()
  }

  getActiveSessionsCount(): number {
    return this.sessions.size
  }
}
