import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import App from '../App'
import {
  decodeProject,
  downloadBlob,
  encodeProject,
  loadSession,
  MAX_FILE_BYTES,
  MAX_TABS,
  storeSession,
  type DocumentSnapshot,
  type SavedWorkspace,
} from '../lib/workspace'
import { createSafeStorage } from '../lib/storage'

const LargeFileWorkbench = lazy(() => import('./LargeFileWorkbench'))
const settings = createSafeStorage()
interface Tab {
  id: string
  initial: DocumentSnapshot
  name: string
  dirty: boolean
}
const newDocument = (
  blob = new Blob([Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 0, 1, 0x7f, 0x80)]),
  name = 'Untitled buffer',
): DocumentSnapshot => ({
  id: crypto.randomUUID(),
  blob,
  name,
  dirty: false,
  notes: [],
  selection: blob.size ? { anchor: 0, focus: Math.min(7, blob.size - 1) } : null,
})
const asTab = (initial: DocumentSnapshot): Tab => ({
  id: initial.id,
  name: initial.name,
  dirty: initial.dirty,
  initial,
})

export default function Workspace() {
  const [tabs, setTabs] = useState<Tab[]>(() => [asTab(newDocument())])
  const [activeId, setActiveId] = useState(() => tabs[0]!.id)
  const [recovery, setRecovery] = useState<SavedWorkspace | null>(null)
  const [message, setMessage] = useState('')
  const [theme, setTheme] = useState(() =>
    settings.getItem('bitpeek:theme') === 'dark' ? 'dark' : 'light',
  )
  const [focus, setFocus] = useState(false)
  const [palette, setPalette] = useState(false)
  const [epoch, setEpoch] = useState(0)
  const [query, setQuery] = useState('')
  const snapshots = useRef(new Map(tabs.map((t) => [t.id, t.initial])))
  const currentTabs = useRef(tabs)
  const currentActive = useRef(activeId)
  const ready = useRef(false)
  const recoveryPending = useRef(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const projectInput = useRef<HTMLInputElement>(null)
  const dialog = useRef<HTMLDialogElement>(null)
  const paletteInput = useRef<HTMLInputElement>(null)
  const saveQueue = useRef(Promise.resolve())
  const session = useCallback(
    (): SavedWorkspace => ({
      version: 1,
      activeId: currentActive.current,
      documents: currentTabs.current.map((t) => snapshots.current.get(t.id) ?? t.initial),
    }),
    [],
  )
  const autosave = useCallback(() => {
    if (!ready.current || recoveryPending.current) return
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => {
      const value = session()
      saveQueue.current = saveQueue.current
        .catch(() => {})
        .then(() => storeSession(value))
        .catch(() =>
          setMessage('Session recovery storage is unavailable. Save a project to keep your work.'),
        )
    }, 800)
  }, [session])
  useEffect(() => {
    let live = true
    void loadSession()
      .then((value) => {
        if (live) {
          setRecovery(value)
          recoveryPending.current = !!value
          ready.current = true
          if (!value) autosave()
        }
      })
      .catch(() => {
        ready.current = true
      })
    return () => {
      live = false
      if (timer.current) clearTimeout(timer.current)
    }
  }, [autosave])
  useEffect(() => {
    currentTabs.current = tabs
    currentActive.current = activeId
    autosave()
  }, [tabs, activeId, autosave])
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    settings.setItem('bitpeek:theme', theme)
  }, [theme])
  useEffect(() => {
    document.body.classList.toggle('workbench-focus', focus)
    return () => document.body.classList.remove('workbench-focus')
  }, [focus])
  useEffect(() => {
    const node = dialog.current
    if (palette && node && !node.open) {
      node.showModal()
      paletteInput.current?.focus()
    } else if (!palette && node?.open) node.close()
  }, [palette])
  useEffect(() => {
    const keys = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPalette((p) => !p)
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'o') {
        event.preventDefault()
        fileInput.current?.click()
      }
    }
    const leave = (event: BeforeUnloadEvent) => {
      if (currentTabs.current.some((t) => snapshots.current.get(t.id)?.dirty))
        event.preventDefault()
    }
    window.addEventListener('keydown', keys)
    window.addEventListener('beforeunload', leave)
    return () => {
      window.removeEventListener('keydown', keys)
      window.removeEventListener('beforeunload', leave)
    }
  }, [])
  const update = useCallback(
    (snapshot: DocumentSnapshot) => {
      snapshots.current.set(snapshot.id, snapshot)
      setTabs((previous) => {
        const tab = previous.find((t) => t.id === snapshot.id)
        if (!tab || (tab.name === snapshot.name && tab.dirty === snapshot.dirty)) return previous
        return previous.map((t) =>
          t.id === snapshot.id ? { ...t, name: snapshot.name, dirty: snapshot.dirty } : t,
        )
      })
      autosave()
    },
    [autosave],
  )
  const open = (file?: File) => {
    if (file && file.size > MAX_FILE_BYTES) {
      setMessage('Files above 512 MiB exceed this workspace limit.')
      return
    }
    if (tabs.length >= MAX_TABS) {
      setMessage('Close a tab before opening another (maximum 16).')
      return
    }
    const initial = newDocument(file, file?.name)
    snapshots.current.set(initial.id, initial)
    setTabs((previous) => [...previous, asTab(initial)])
    setActiveId(initial.id)
    setMessage('')
  }
  const close = (id: string) => {
    if (
      snapshots.current.get(id)?.dirty &&
      !window.confirm('Close this tab and discard unsaved changes?')
    )
      return
    const remaining = tabs.filter((t) => t.id !== id)
    snapshots.current.delete(id)
    if (!remaining.length) {
      const initial = newDocument(new Blob([]))
      snapshots.current.set(initial.id, initial)
      remaining.push(asTab(initial))
    }
    setTabs(remaining)
    if (activeId === id) setActiveId(remaining[0]!.id)
  }
  const restore = (saved: SavedWorkspace) => {
    if (
      tabs.some((t) => snapshots.current.get(t.id)?.dirty) &&
      !window.confirm(
        'Replace the workspace with this project? Save your current project first if needed.',
      )
    )
      return
    recoveryPending.current = false
    setEpoch((v) => v + 1)
    snapshots.current = new Map(saved.documents.map((d) => [d.id, d]))
    setTabs(saved.documents.map(asTab))
    setActiveId(saved.activeId)
    setRecovery(null)
    setMessage('Project restored locally.')
  }
  const commands = [
    { label: 'Open local files', id: 'open' },
    { label: 'New scratchpad', id: 'new' },
    { label: 'Save workspace project', id: 'save' },
    { label: 'Open workspace project', id: 'project' },
    { label: 'Toggle focus view', id: 'focus' },
    { label: 'Toggle light / dark theme', id: 'theme' },
    { label: 'Find bytes', id: 'find' },
    { label: 'Go to offset', id: 'goto' },
    ...tabs.map((t) => ({ label: 'Switch to ' + t.name, id: t.id })),
  ].filter((command) => command.label.toLowerCase().includes(query.toLowerCase()))
  const saveProject = () => {
    try {
      downloadBlob(encodeProject(session()), 'workspace.bitpeek')
      setMessage('')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not save this project.')
    }
  }
  const executeCommand = (id: string) => {
    setPalette(false)
    if (id === 'open') fileInput.current?.click()
    else if (id === 'new') open()
    else if (id === 'save') saveProject()
    else if (id === 'project') projectInput.current?.click()
    else if (id === 'focus') setFocus((v) => !v)
    else if (id === 'theme') setTheme((v) => (v === 'light' ? 'dark' : 'light'))
    else if (id === 'find' || id === 'goto')
      document
        .querySelector<HTMLElement>(
          '[data-active="true"] ' + (id === 'find' ? '[data-byte-search]' : '[data-byte-offset]'),
        )
        ?.focus()
    else setActiveId(id)
  }
  return (
    <div className="workspace-container">
      <div className="project-toolbar">
        <div className="compact-actions">
          <button onClick={() => open()}>New</button>
          <button onClick={() => fileInput.current?.click()}>Open files</button>
          <button onClick={saveProject}>Save project</button>
          <button onClick={() => projectInput.current?.click()}>Open project</button>
          {recovery && (
            <>
              <button onClick={() => restore(recovery)}>Restore previous session</button>
              <button
                onClick={() => {
                  recoveryPending.current = false
                  setRecovery(null)
                  autosave()
                }}
              >
                Start fresh
              </button>
            </>
          )}
        </div>
        <div className="compact-actions">
          <button aria-pressed={focus} onClick={() => setFocus((v) => !v)}>
            Focus view
          </button>
          <button onClick={() => setTheme((v) => (v === 'light' ? 'dark' : 'light'))}>
            {theme === 'light' ? 'Dark' : 'Light'}
          </button>
          <button
            onClick={() => {
              setQuery('')
              setPalette(true)
            }}
          >
            Commands <kbd>Ctrl K</kbd>
          </button>
        </div>
      </div>
      <input
        ref={fileInput}
        hidden
        type="file"
        multiple
        onChange={(e) => {
          const files = Array.from(e.target.files ?? [])
          e.target.value = ''
          const available = MAX_TABS - tabs.length
          for (const file of files.slice(0, available)) open(file)
          if (files.length > available)
            setMessage('Opened the first files that fit the 16-tab limit.')
        }}
      />
      <input
        ref={projectInput}
        hidden
        type="file"
        accept=".bitpeek"
        onChange={(e) => {
          const file = e.target.files?.[0]
          e.target.value = ''
          if (file)
            void decodeProject(file)
              .then(restore)
              .catch((error) => setMessage(String(error.message)))
        }}
      />
      <div className="document-tabs" role="tablist" aria-label="Open documents">
        {tabs.map((tab) => (
          <div
            key={tab.id}
            className={tab.id === activeId ? 'document-tab is-active' : 'document-tab'}
          >
            <button
              role="tab"
              id={'tab-' + tab.id}
              aria-controls={'buffer-' + tab.id}
              aria-selected={tab.id === activeId}
              tabIndex={tab.id === activeId ? 0 : -1}
              onClick={() => setActiveId(tab.id)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                  e.preventDefault()
                  const i = tabs.findIndex((t) => t.id === tab.id)
                  const next =
                    tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length]!
                  setActiveId(next.id)
                  document.getElementById('tab-' + next.id)?.focus()
                }
              }}
            >
              <span>{tab.name}</span>
              {tab.dirty && <span aria-label="Modified">●</span>}
            </button>
            <button
              className="tab-close"
              aria-label={'Close ' + tab.name}
              onClick={() => close(tab.id)}
            >
              ×
            </button>
          </div>
        ))}
      </div>
      {message && (
        <div className="workspace-message" role="status">
          {message}
          <button aria-label="Dismiss message" onClick={() => setMessage('')}>
            ×
          </button>
        </div>
      )}
      {tabs.map((tab) => (
        <div
          key={epoch + ':' + tab.id}
          id={'buffer-' + tab.id}
          role="tabpanel"
          aria-labelledby={'tab-' + tab.id}
          hidden={tab.id !== activeId}
          data-active={tab.id === activeId}
        >
          <Suspense fallback={<p className="workspace-message">Opening local document…</p>}>
            {tab.initial.blob.size > 256 * 1024 ? (
              <LargeFileWorkbench initial={tab.initial} onSnapshot={update} onOpenDocument={open} />
            ) : (
              <App initial={tab.initial} onSnapshot={update} onOpenDocument={open} />
            )}
          </Suspense>
        </div>
      ))}
      <dialog
        ref={dialog}
        className="command-dialog"
        aria-label="Command palette"
        onCancel={() => setPalette(false)}
        onClose={() => setPalette(false)}
      >
        <div className="dialog-heading">
          <h2>Commands</h2>
          <button onClick={() => setPalette(false)}>Close</button>
        </div>
        <input
          ref={paletteInput}
          aria-label="Search commands"
          placeholder="Type a command or file name…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && commands[0]) executeCommand(commands[0].id)
          }}
        />
        <div className="result-list">
          {commands.map((c) => (
            <button key={c.id} onClick={() => executeCommand(c.id)}>
              {c.label}
            </button>
          ))}
        </div>
      </dialog>
    </div>
  )
}
