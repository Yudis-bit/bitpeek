import { useCallback, useEffect, useRef, useState } from 'react'

interface ClipboardState {
  notice: string
  copy: (value: string, label: string) => Promise<void>
}

async function writeWithFallback(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value)
    return
  }

  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.append(textarea)
  textarea.select()
  const copied = document.execCommand('copy')
  textarea.remove()
  if (!copied) throw new Error('Clipboard command failed')
}

export function useClipboard(): ClipboardState {
  const [notice, setNotice] = useState('')
  const timeoutRef = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (timeoutRef.current !== null) window.clearTimeout(timeoutRef.current)
    },
    [],
  )

  const copy = useCallback(async (value: string, label: string) => {
    if (timeoutRef.current !== null) window.clearTimeout(timeoutRef.current)
    try {
      await writeWithFallback(value)
      setNotice(`Copied ${label}`)
    } catch {
      setNotice('Copy failed')
    }
    timeoutRef.current = window.setTimeout(() => setNotice(''), 1800)
  }, [])

  return { notice, copy }
}
