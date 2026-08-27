export function Header() {
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
        <a className="help-link" href="#privacy" aria-label="About bitpeek">
          ?
        </a>
      </nav>
    </header>
  )
}
