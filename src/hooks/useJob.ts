import { useCallback, useEffect, useRef, useState } from 'react'

export function useJob() {
  const worker = useRef<Worker | null>(null)
  const rejectCurrent = useRef<((error: Error) => void) | null>(null)
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState(0)
  const cancel = useCallback(() => {
    worker.current?.terminate()
    worker.current = null
    rejectCurrent.current?.(new Error('Operation cancelled.'))
    rejectCurrent.current = null
    setBusy(false)
  }, [])
  useEffect(
    () => () => {
      worker.current?.terminate()
      rejectCurrent.current?.(new Error('Operation cancelled.'))
    },
    [],
  )
  const run = useCallback(
    <T>(task: string, args: Record<string, unknown>): Promise<T> => {
      cancel()
      setBusy(true)
      setProgress(0)
      return new Promise<T>((resolve, reject) => {
        try {
          const instance = new Worker(new URL('../workers/analysis.worker.ts', import.meta.url), {
            type: 'module',
          })
          worker.current = instance
          rejectCurrent.current = reject
          const finish = () => {
            instance.terminate()
            if (worker.current === instance) {
              worker.current = null
              rejectCurrent.current = null
              setBusy(false)
            }
          }
          instance.onmessage = (event) => {
            if (event.data.progress !== undefined) {
              setProgress(event.data.progress)
              return
            }
            finish()
            if (event.data.error) reject(new Error(event.data.error))
            else resolve(event.data.result as T)
          }
          instance.onerror = (event) => {
            finish()
            reject(new Error(event.message || 'Background operation failed.'))
          }
          instance.postMessage({ task, ...args })
        } catch (error) {
          worker.current = null
          rejectCurrent.current = null
          setBusy(false)
          reject(error)
        }
      })
    },
    [cancel],
  )
  return { run, cancel, busy, progress }
}
