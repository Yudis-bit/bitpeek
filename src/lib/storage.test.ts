import { describe, expect, it } from 'vitest'
import { createSafeStorage, resolveInitialMode, MODE_STORAGE_KEY } from './storage'

describe('createSafeStorage', () => {
  it('reads and writes to a standard mock storage', () => {
    const memory = new Map<string, string>()
    const mockStorage = {
      getItem: (k: string) => memory.get(k) ?? null,
      setItem: (k: string, v: string) => memory.set(k, v),
      removeItem: (k: string) => memory.delete(k),
      clear: () => memory.clear(),
      key: () => null,
      length: 0,
    } as unknown as Storage

    const safe = createSafeStorage(mockStorage)
    expect(safe.isFallback).toBe(false)
    safe.setItem('testKey', 'value123')
    expect(safe.getItem('testKey')).toBe('value123')
    safe.removeItem('testKey')
    expect(safe.getItem('testKey')).toBeNull()
  })

  it('falls back to in-memory store when storage getItem throws SecurityError', () => {
    const throwingStorage = {
      getItem: () => {
        throw new DOMException('The operation is insecure.', 'SecurityError')
      },
      setItem: () => {
        throw new DOMException('The operation is insecure.', 'SecurityError')
      },
      removeItem: () => {},
      clear: () => {},
      key: () => null,
      length: 0,
    } as unknown as Storage

    const safe = createSafeStorage(throwingStorage)
    // Initial probe fails setItem, so safe becomes fallback
    expect(safe.isFallback).toBe(true)
    // Read and write must still function seamlessly via memory fallback
    safe.setItem('mode', 'binary')
    expect(safe.getItem('mode')).toBe('binary')
  })

  it('falls back gracefully when storage is null or undefined', () => {
    const safe = createSafeStorage(null)
    expect(safe.isFallback).toBe(true)
    safe.setItem('pref', 'dark')
    expect(safe.getItem('pref')).toBe('dark')
    safe.clear()
    expect(safe.getItem('pref')).toBeNull()
  })
})

describe('resolveInitialMode', () => {
  it('prefers valid query parameter over stored preference', () => {
    const safe = createSafeStorage(null)
    safe.setItem(MODE_STORAGE_KEY, 'text')
    expect(resolveInitialMode(safe, '?mode=binary')).toBe('binary')
  })

  it('falls back to stored preference when query is missing or invalid', () => {
    const safe = createSafeStorage(null)
    safe.setItem(MODE_STORAGE_KEY, 'base64')
    expect(resolveInitialMode(safe, '?mode=invalidMode')).toBe('base64')
    expect(resolveInitialMode(safe, '')).toBe('base64')
  })

  it('defaults to hex when neither query nor storage provide a valid mode', () => {
    const safe = createSafeStorage(null)
    safe.setItem(MODE_STORAGE_KEY, 'corrupted_value')
    expect(resolveInitialMode(safe, '?mode=unknown')).toBe('hex')
  })
})
