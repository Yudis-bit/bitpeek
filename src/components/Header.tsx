interface HeaderProps {
  onHelp: () => void
  onSupport: () => void
}

export function Header({ onHelp, onSupport }: HeaderProps) {
  return (
    <header className="app-header">
      <div className="brand">
        <span className="brand-name">bitpeek</span>
        <span className="brand-separator" aria-hidden="true" />
        <span className="brand-subtitle">Byte Inspector</span>
      </div>
      <nav className="header-actions" aria-label="Application links">
        <a
          href="https://github.com/Yudis-bit/bitpeek"
          target="_blank"
          rel="noreferrer"
        >
          GitHub
        </a>
        <button type="button" className="header-text-action" onClick={onSupport}>
          Support
        </button>
        <button
          type="button"
          className="help-link"
          onClick={onHelp}
          aria-label="Open bitpeek help"
        >
          ?
        </button>
      </nav>
    </header>
  )
}
