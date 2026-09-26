import { INPUT_MODES, type InputMode } from './bytes'

export const MODE_STORAGE_KEY = 'bitpeek.inputMode'

export interface SafeStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
  clear(): void
  readonly isFallback: boolean
}

class MemoryStorage implements SafeStorage {
  private store = new Map<string, string>()
  readonly isFallback = true

  getItem(key: string): string | null {
    return this.store.get(key) ?? null
  }

  setItem(key: string, value: string): void {
    this.store.set(key, String(value))
  }

  removeItem(key: string): void {
    this.store.delete(key)
  }

  clear(): void {
    this.store.clear()
  }
}

export function createSafeStorage(preferredBackend?: Storage | null): SafeStorage {
  const memoryFallback = new MemoryStorage()

  if (!preferredBackend) {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        preferredBackend = window.localStorage
      }
    } catch {
      return memoryFallback
    }
  }

  if (!preferredBackend) {
    return memoryFallback
  }

  // Probe backend to verify read and write capability
  try {
    const probeKey = '__bitpeek_storage_probe__'
    preferredBackend.setItem(probeKey, '1')
    preferredBackend.removeItem(probeKey)
  } catch {
    return memoryFallback
  }

  const backend = preferredBackend

  return {
    getItem(key: string): string | null {
      try {
        return backend.getItem(key)
      } catch {
        return memoryFallback.getItem(key)
      }
    },
    setItem(key: string, value: string): void {
      try {
        backend.setItem(key, value)
      } catch {
        memoryFallback.setItem(key, value)
      }
    },
    removeItem(key: string): void {
      try {
        backend.removeItem(key)
      } catch {
        memoryFallback.removeItem(key)
      }
    },
    clear(): void {
      try {
        backend.clear()
      } catch {
        memoryFallback.clear()
      }
    },
    get isFallback(): boolean {
      return false
    },
  }
}

export function resolveInitialMode(
  storage: SafeStorage,
  searchQuery?: string,
): InputMode {
  try {
    if (searchQuery) {
      const requested = new URLSearchParams(searchQuery).get('mode')
      if (requested && INPUT_MODES.includes(requested as InputMode)) {
        return requested as InputMode
      }
    } else if (typeof window !== 'undefined' && window.location?.search) {
      const requested = new URLSearchParams(window.location.search).get('mode')
      if (requested && INPUT_MODES.includes(requested as InputMode)) {
        return requested as InputMode
      }
    }
  } catch {
    // Ignore URL parse failures
  }

  try {
    const stored = storage.getItem(MODE_STORAGE_KEY)
    if (stored && INPUT_MODES.includes(stored as InputMode)) {
      return stored as InputMode
    }
  } catch {
    // Fallback to default
  }

  return 'hex'
}
