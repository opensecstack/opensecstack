import { useState, useRef, useEffect, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useThemeToggle } from '../hooks/useThemeToggle'
import { platforms } from '../data/platforms'
import { useI18n } from '../i18n/useI18n'

/** Sun icon (shown in dark mode -- click to switch to light). */
function SunIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="5" />
      <line x1="12" y1="1" x2="12" y2="3" />
      <line x1="12" y1="21" x2="12" y2="23" />
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
      <line x1="1" y1="12" x2="3" y2="12" />
      <line x1="21" y1="12" x2="23" y2="12" />
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
    </svg>
  )
}

/** Moon icon (shown in light mode -- click to switch to dark). */
function MoonIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  )
}

/** Monitor icon (shown when following the system preference). */
function MonitorIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  )
}

/** Three-bar hamburger icon (mobile menu trigger). */
function MenuIcon({ open }: { open: boolean }) {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {open ? (
        <>
          <line x1="18" y1="6" x2="6" y2="18" />
          <line x1="6" y1="6" x2="18" y2="18" />
        </>
      ) : (
        <>
          <line x1="3" y1="6" x2="21" y2="6" />
          <line x1="3" y1="12" x2="21" y2="12" />
          <line x1="3" y1="18" x2="21" y2="18" />
        </>
      )}
    </svg>
  )
}

// ---- Search data ----
interface SearchItem {
  label: string
  href: string
  route?: string
}

function buildSearchItems(): SearchItem[] {
  const items: SearchItem[] = platforms.map(p => ({
    label: p.name,
    href: `#${p.sectionId}`,
  }))
  items.push(
    { label: 'CITADEL', href: '#citadel' },
    { label: 'CitadelOS Desktop', href: '#citadelos', route: '/citadelos' },
    { label: 'CitadelOS Mobile', href: '#citadelos', route: '/citadelos/mobile' },
  )
  return items
}

/**
 * useIsMobile watches window width and returns true below the given
 * breakpoint. Resizing the window updates the value live so the navbar
 * swaps layouts when someone rotates a tablet or drags the browser
 * window smaller during a demo.
 */
function useIsMobile(breakpoint = 820): boolean {
  const [isMobile, setIsMobile] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false
    return window.innerWidth < breakpoint
  })

  useEffect(() => {
    function onResize() {
      setIsMobile(window.innerWidth < breakpoint)
    }
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [breakpoint])

  return isMobile
}

export default function Navbar() {
  const { theme, resolved, setTheme } = useThemeToggle()
  const { t } = useI18n()
  const navigate = useNavigate()
  const isMobile = useIsMobile()

  // All platform sections (generated from data/platforms so every platform
  // stays reachable from the nav, not just a hand-picked subset).
  const platformLinks = useMemo(
    () => platforms.map(p => ({ label: p.name, href: `#${p.sectionId}` })),
    []
  )

  // Non-platform nav entries (kept as special cases).
  const otherLinks = [
    { label: t('nav.citadel'), href: '#citadel' },
    { label: t('nav.sdks'), href: '#sdks' },
    { label: t('nav.roadmap'), href: '#roadmap' },
    { label: 'Docs', href: '/docs' },
  ]

  // Flat list used by the mobile drawer, where a dropdown doesn't make
  // sense -- everything is already in a scrollable column.
  // Includes the CitadelOS Mobile route so the drawer has full parity with
  // desktop search (buildSearchItems indexes it separately from the
  // CitadelOS desktop button below).
  const mobileLinks = [
    { label: t('nav.platforms'), href: '#platforms' },
    ...platformLinks,
    ...otherLinks,
    { label: 'CitadelOS (Mobile)', href: '/citadelos/mobile' },
  ]

  // ---- Search state ----
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const wrapperRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const searchItems = useMemo(buildSearchItems, [])

  // ---- Mobile menu state ----
  const [menuOpen, setMenuOpen] = useState(false)

  // ---- Theme dropdown state ----
  const [themeOpen, setThemeOpen] = useState(false)
  const themeRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (themeRef.current && !themeRef.current.contains(e.target as Node)) {
        setThemeOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  // ---- Platforms dropdown state ----
  const [platformsOpen, setPlatformsOpen] = useState(false)
  const platformsRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (platformsRef.current && !platformsRef.current.contains(e.target as Node)) {
        setPlatformsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  const filtered = useMemo(() => {
    if (!query.trim()) return []
    const q = query.toLowerCase()
    return searchItems.filter(item => item.label.toLowerCase().includes(q))
  }, [query, searchItems])

  // Close on outside click.
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  // Close on Escape (search dropdown + mobile drawer).
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setOpen(false)
        setMenuOpen(false)
        setThemeOpen(false)
        setPlatformsOpen(false)
        inputRef.current?.blur()
      }
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [])

  // Close the mobile drawer when the viewport grows back to desktop width,
  // otherwise the drawer stays visible as an orphan panel.
  useEffect(() => {
    if (!isMobile) setMenuOpen(false)
  }, [isMobile])

  function handleSelect(item: SearchItem) {
    setOpen(false)
    setQuery('')
    if (item.route) {
      navigate(item.route)
    } else {
      const el = document.querySelector(item.href)
      if (el) el.scrollIntoView({ behavior: 'smooth' })
    }
  }

  function handleNavClick(href: string) {
    setMenuOpen(false)
    // Route paths (e.g. /docs) navigate; in-page anchors scroll.
    if (href.startsWith('/')) { navigate(href); return }
    const el = document.querySelector(href)
    if (el) el.scrollIntoView({ behavior: 'smooth' })
  }

  const isDark = resolved === 'dark'

  return (
    <nav style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
      background: isDark ? 'rgba(3,3,8,0.7)' : 'rgba(248,250,252,0.75)',
      backdropFilter: 'blur(20px) saturate(150%)',
      borderBottom: isDark
        ? '1px solid rgba(0,240,255,0.06)'
        : '1px solid rgba(0,0,0,0.06)',
      padding: isMobile ? '0 1rem' : '0 2rem',
      height: 56,
      display: 'flex', alignItems: 'center', gap: isMobile ? '0.75rem' : '2rem',
    }}>
      {/* Logo */}
      <a href="#" style={{
        fontWeight: 800, fontSize: '1.1rem', letterSpacing: '0.04em',
        background: 'linear-gradient(135deg, #00f0ff, #7c3aed)',
        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
        textDecoration: 'none',
        marginRight: isMobile ? 'auto' : undefined,
      }}>
        SIN
      </a>

      {/* ---------- Desktop layout ---------- */}
      {!isMobile && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', marginLeft: 'auto', fontSize: '0.85rem' }}>
            <div ref={platformsRef} style={{ position: 'relative' }}>
              <button
                onClick={() => setPlatformsOpen(o => !o)}
                aria-haspopup="menu"
                aria-expanded={platformsOpen}
                style={{
                  background: 'transparent', border: 'none', cursor: 'pointer',
                  color: isDark ? '#8892a8' : '#64748b',
                  fontSize: '0.85rem', fontFamily: 'inherit',
                  padding: 0, display: 'flex', alignItems: 'center', gap: 4,
                  transition: 'color 0.2s, text-shadow 0.2s',
                }}
              >
                {t('nav.platforms')}
                <span aria-hidden="true" style={{ fontSize: '0.65rem' }}>▾</span>
              </button>
              {platformsOpen && (
                <div role="menu" style={{
                  position: 'absolute', top: 28, left: 0, minWidth: 200,
                  maxHeight: '70vh', overflowY: 'auto',
                  background: isDark ? 'rgba(10,10,20,0.97)' : 'rgba(255,255,255,0.98)',
                  border: isDark ? '1px solid rgba(0,240,255,0.18)' : '1px solid rgba(0,0,0,0.1)',
                  borderRadius: 10, padding: 6,
                  boxShadow: isDark ? '0 8px 30px rgba(0,0,0,0.5)' : '0 8px 30px rgba(0,0,0,0.12)',
                  backdropFilter: 'blur(12px)', zIndex: 200,
                }}>
                  {platformLinks.map(pl => (
                    <a
                      key={pl.href}
                      href={pl.href}
                      role="menuitem"
                      onClick={() => setPlatformsOpen(false)}
                      style={{
                        display: 'block', width: '100%', padding: '8px 10px', borderRadius: 7,
                        color: isDark ? '#c8d0e0' : '#334155',
                        fontSize: '0.85rem', fontFamily: 'inherit',
                        textDecoration: 'none',
                        transition: 'background 0.15s, color 0.15s',
                      }}
                    >
                      {pl.label}
                    </a>
                  ))}
                </div>
              )}
            </div>

            {otherLinks.map(l => (
              <a key={l.href} href={l.href} style={{
                color: isDark ? '#8892a8' : '#64748b',
                textDecoration: 'none',
                transition: 'color 0.2s, text-shadow 0.2s',
              }}>
                {l.label}
              </a>
            ))}
          </div>

          {/* Search */}
          <div ref={wrapperRef} style={{ position: 'relative' }}>
            <div style={{
              display: 'flex', alignItems: 'center',
              background: isDark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.04)',
              border: isDark
                ? '1px solid rgba(0,240,255,0.1)'
                : '1px solid rgba(0,0,0,0.08)',
              borderRadius: 8, padding: '0 10px', height: 32,
            }}>
              <span style={{ fontSize: '0.8rem', marginRight: 6, color: '#64748b', lineHeight: 1 }}>
                {'\u2315'}
              </span>
              <input
                ref={inputRef}
                type="text"
                value={query}
                placeholder={t('nav.search.placeholder')}
                onChange={e => { setQuery(e.target.value); setOpen(true) }}
                onFocus={() => { if (query.trim()) setOpen(true) }}
                aria-label="Search the site"
                className="search-input"
                style={{
                  background: 'transparent', border: 'none',
                  color: isDark ? '#e2e8f0' : '#1e293b',
                  fontSize: '0.8rem', width: 150,
                  fontFamily: 'inherit',
                }}
              />
            </div>

            {open && filtered.length > 0 && (
              <div style={{
                position: 'absolute', top: 38, left: 0, minWidth: 220,
                background: isDark ? 'rgba(10,10,20,0.92)' : 'rgba(255,255,255,0.95)',
                backdropFilter: 'blur(20px) saturate(150%)',
                border: isDark
                  ? '1px solid rgba(0,240,255,0.12)'
                  : '1px solid rgba(0,0,0,0.08)',
                borderRadius: 10, padding: '6px 0',
                boxShadow: isDark
                  ? '0 8px 30px rgba(0,0,0,0.5)'
                  : '0 8px 30px rgba(0,0,0,0.12)',
                zIndex: 200,
              }}>
                {filtered.map(item => (
                  <button
                    key={item.label}
                    onClick={() => handleSelect(item)}
                    style={{
                      display: 'block', width: '100%', padding: '8px 14px',
                      background: 'transparent', border: 'none', cursor: 'pointer',
                      color: isDark ? '#c8d0e0' : '#334155',
                      fontSize: '0.82rem', textAlign: 'left',
                      fontFamily: 'inherit',
                      transition: 'background 0.15s, color 0.15s',
                    }}
                    onMouseEnter={e => {
                      const btn = e.currentTarget
                      btn.style.background = isDark ? 'rgba(0,240,255,0.08)' : 'rgba(124,58,237,0.06)'
                      btn.style.color = isDark ? '#00f0ff' : '#7c3aed'
                    }}
                    onMouseLeave={e => {
                      const btn = e.currentTarget
                      btn.style.background = 'transparent'
                      btn.style.color = isDark ? '#c8d0e0' : '#334155'
                    }}
                  >
                    {item.label}
                    {item.route && (
                      <span style={{ marginLeft: 8, fontSize: '0.7rem', color: '#64748b' }}>
                        {item.route}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>

          <div ref={themeRef} style={{ position: 'relative' }}>
            <button
              onClick={() => setThemeOpen(o => !o)}
              aria-label="Theme"
              aria-haspopup="menu"
              aria-expanded={themeOpen}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                width: 34, height: 34, borderRadius: 9,
                background: isDark ? 'rgba(0,240,255,0.06)' : 'rgba(124,58,237,0.06)',
                border: isDark
                  ? '1px solid rgba(0,240,255,0.2)'
                  : '1px solid rgba(124,58,237,0.2)',
                color: isDark ? '#00f0ff' : '#7c3aed',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              {theme === 'light' ? <SunIcon /> : theme === 'dark' ? <MoonIcon /> : <MonitorIcon />}
            </button>
            {themeOpen && (
              <div role="menu" style={{
                position: 'absolute', top: 42, right: 0, minWidth: 150,
                background: isDark ? 'rgba(10,10,20,0.97)' : 'rgba(255,255,255,0.98)',
                border: isDark ? '1px solid rgba(0,240,255,0.18)' : '1px solid rgba(0,0,0,0.1)',
                borderRadius: 10, padding: 6,
                boxShadow: isDark ? '0 8px 30px rgba(0,0,0,0.5)' : '0 8px 30px rgba(0,0,0,0.12)',
                backdropFilter: 'blur(12px)', zIndex: 200,
              }}>
                {([
                  { key: 'light', label: 'Light', icon: <SunIcon /> },
                  { key: 'dark', label: 'Dark', icon: <MoonIcon /> },
                  { key: 'system', label: 'System', icon: <MonitorIcon /> },
                ] as const).map(opt => {
                  const active = theme === opt.key
                  return (
                    <button
                      key={opt.key}
                      role="menuitemradio"
                      aria-checked={active}
                      onClick={() => { setTheme(opt.key); setThemeOpen(false) }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 10, width: '100%',
                        padding: '8px 10px', borderRadius: 7, border: 'none', cursor: 'pointer',
                        background: active ? (isDark ? 'rgba(0,240,255,0.1)' : 'rgba(124,58,237,0.08)') : 'transparent',
                        color: active ? (isDark ? '#00f0ff' : '#7c3aed') : (isDark ? '#c8d0e0' : '#334155'),
                        fontSize: '0.85rem', fontWeight: active ? 600 : 500, fontFamily: 'inherit',
                        transition: 'background 0.15s',
                      }}
                    >
                      <span style={{ display: 'flex', width: 16 }}>{opt.icon}</span>
                      <span style={{ flex: 1, textAlign: 'left' }}>{opt.label}</span>
                      {active && <span style={{ fontSize: '0.9rem' }}>✓</span>}
                    </button>
                  )
                })}
              </div>
            )}
          </div>

          <Link to="/citadelos" style={{
            padding: '7px 14px', borderRadius: 9, fontSize: '0.8rem', fontWeight: 600,
            background: 'rgba(124,58,237,0.08)', border: '1px solid rgba(124,58,237,0.25)',
            color: 'var(--violet)', textDecoration: 'none', transition: 'all 0.2s',
          }}>
            {t('nav.citadelos')}
          </Link>

          <a
            href="https://github.com/opensecstack/opensecstack"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              padding: '7px 18px', borderRadius: 9, fontSize: '0.8rem', fontWeight: 600,
              background: 'rgba(0,240,255,0.06)',
              border: '1px solid rgba(0,240,255,0.2)',
              color: '#00f0ff', textDecoration: 'none',
              transition: 'all 0.2s',
              boxShadow: '0 0 12px rgba(0,240,255,0.08)',
            }}
          >
            {t('nav.github')}
          </a>
        </>
      )}

      {/* ---------- Mobile layout ---------- */}
      {isMobile && (
        <>
          {/* Compact theme toggle (stays visible in the top bar so it's one
              tap away, not buried in the drawer). */}
          <button
            onClick={() => setTheme(theme === 'light' ? 'dark' : theme === 'dark' ? 'system' : 'light')}
            aria-label={`Theme: ${theme}. Tap to change.`}
            title={`Theme: ${theme}`}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: 34, height: 34, borderRadius: 9,
              background: isDark ? 'rgba(0,240,255,0.06)' : 'rgba(124,58,237,0.06)',
              border: isDark
                ? '1px solid rgba(0,240,255,0.2)'
                : '1px solid rgba(124,58,237,0.2)',
              color: isDark ? '#00f0ff' : '#7c3aed',
              cursor: 'pointer',
            }}
          >
            {theme === 'light' ? <SunIcon /> : theme === 'dark' ? <MoonIcon /> : <MonitorIcon />}
          </button>

          <button
            onClick={() => setMenuOpen(v => !v)}
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={menuOpen}
            aria-controls="mobile-menu"
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: 40, height: 40, borderRadius: 9,
              background: isDark ? 'rgba(0,240,255,0.06)' : 'rgba(0,0,0,0.04)',
              border: isDark
                ? '1px solid rgba(0,240,255,0.2)'
                : '1px solid rgba(0,0,0,0.12)',
              color: isDark ? '#00f0ff' : '#1e293b',
              cursor: 'pointer',
            }}
          >
            <MenuIcon open={menuOpen} />
          </button>

          {/* Drawer — positioned absolutely beneath the fixed bar so it
              hangs below without forcing layout shifts elsewhere. */}
          {menuOpen && (
            <div
              id="mobile-menu"
              role="menu"
              style={{
                position: 'fixed', top: 56, left: 0, right: 0,
                maxHeight: 'calc(100vh - 56px)',
                overflowY: 'auto',
                padding: '1rem 1.25rem 1.5rem',
                background: isDark ? 'rgba(3,3,8,0.96)' : 'rgba(248,250,252,0.98)',
                backdropFilter: 'blur(24px) saturate(150%)',
                borderBottom: isDark
                  ? '1px solid rgba(0,240,255,0.1)'
                  : '1px solid rgba(0,0,0,0.08)',
                display: 'flex', flexDirection: 'column', gap: '0.5rem',
                zIndex: 99,
              }}
            >
              {mobileLinks.map(l => (
                <a
                  key={l.href}
                  href={l.href}
                  role="menuitem"
                  onClick={e => { e.preventDefault(); handleNavClick(l.href) }}
                  style={{
                    padding: '0.75rem 0.25rem',
                    color: isDark ? '#c8d0e0' : '#334155',
                    textDecoration: 'none',
                    fontSize: '1rem',
                    borderBottom: isDark
                      ? '1px solid rgba(255,255,255,0.04)'
                      : '1px solid rgba(0,0,0,0.05)',
                  }}
                >
                  {l.label}
                </a>
              ))}

              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
                <Link
                  to="/citadelos"
                  onClick={() => setMenuOpen(false)}
                  style={{
                    flex: 1, minWidth: 120, textAlign: 'center',
                    padding: '0.6rem 0.75rem', borderRadius: 9,
                    fontSize: '0.8rem', fontWeight: 600,
                    background: 'rgba(124,58,237,0.1)',
                    border: '1px solid rgba(124,58,237,0.35)',
                    color: 'var(--violet)', textDecoration: 'none',
                  }}
                >
                  {t('nav.citadelos')}
                </Link>
                <a
                  href="https://github.com/opensecstack/opensecstack"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    flex: 1, minWidth: 100, textAlign: 'center',
                    padding: '0.6rem 0.75rem', borderRadius: 9,
                    fontSize: '0.8rem', fontWeight: 600,
                    background: 'rgba(0,240,255,0.08)',
                    border: '1px solid rgba(0,240,255,0.3)',
                    color: '#00f0ff', textDecoration: 'none',
                  }}
                >
                  {t('nav.github')}
                </a>
              </div>
            </div>
          )}
        </>
      )}
    </nav>
  )
}
