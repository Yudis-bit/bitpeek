interface HeaderProps {
  onHelp: () => void
}

export function Header({ onHelp }: HeaderProps) {
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
