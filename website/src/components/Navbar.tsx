import { useState, useRef, useEffect, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useThemeToggle } from '../hooks/useThemeToggle'
import { platforms } from '../data/platforms'
import { useI18n } from '../i18n/useI18n'

/** Sun icon (shown in dark mode -- click to switch to light) */
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

/** Moon icon (shown in light mode -- click to switch to dark) */
function MoonIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
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

export default function Navbar() {
  const { mode, toggle: toggleTheme } = useThemeToggle()
  const { lang, t, toggle: toggleLang } = useI18n()
  const navigate = useNavigate()

  const links = [
    { label: t('nav.platforms'), href: '#platforms' },
    { label: t('nav.apiguard'), href: '#apiguard' },
    { label: t('nav.nis2'), href: '#nis2compass' },
    { label: t('nav.citadel'), href: '#citadel' },
    { label: t('nav.sdks'), href: '#sdks' },
    { label: t('nav.roadmap'), href: '#roadmap' },
  ]

  // ---- Search state ----
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const wrapperRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const searchItems = useMemo(buildSearchItems, [])

  const filtered = useMemo(() => {
    if (!query.trim()) return []
    const q = query.toLowerCase()
    return searchItems.filter(item => item.label.toLowerCase().includes(q))
  }, [query, searchItems])

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  // Close on Escape
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setOpen(false)
        inputRef.current?.blur()
      }
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [])

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

  const isDark = mode === 'dark'

  return (
    <nav style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
      background: isDark ? 'rgba(3,3,8,0.7)' : 'rgba(248,250,252,0.75)',
      backdropFilter: 'blur(20px) saturate(150%)',
      borderBottom: isDark
        ? '1px solid rgba(0,240,255,0.06)'
        : '1px solid rgba(0,0,0,0.06)',
      padding: '0 2rem', height: 56,
      display: 'flex', alignItems: 'center', gap: '2rem',
    }}>
      {/* Logo */}
      <a href="#" style={{
        fontWeight: 800, fontSize: '1.1rem', letterSpacing: '0.04em',
        background: 'linear-gradient(135deg, #00f0ff, #7c3aed)',
        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
        textDecoration: 'none',
      }}>
        SIN
      </a>

      {/* Nav links */}
      <div style={{ display: 'flex', gap: '1.5rem', marginLeft: 'auto', fontSize: '0.85rem' }}>
        {links.map(l => (
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
            style={{
              background: 'transparent', border: 'none', outline: 'none',
              color: isDark ? '#e2e8f0' : '#1e293b',
              fontSize: '0.8rem', width: 150,
              fontFamily: 'inherit',
            }}
          />
        </div>

        {/* Dropdown */}
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

      {/* Theme toggle */}
      <button
        onClick={toggleTheme}
        aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
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
        {isDark ? <SunIcon /> : <MoonIcon />}
      </button>

      {/* Language toggle */}
      <button
        onClick={toggleLang}
        title={lang === 'en' ? 'Switch to Albanian' : 'Switch to English'}
        style={{
          padding: '5px 10px', borderRadius: 7, fontSize: '0.75rem', fontWeight: 700,
          background: 'rgba(124,58,237,0.08)',
          border: '1px solid rgba(124,58,237,0.25)',
          color: '#a78bfa', cursor: 'pointer',
          fontFamily: 'inherit',
          transition: 'all 0.2s',
          letterSpacing: '0.04em',
        }}
      >
        {lang === 'en' ? 'EN' : 'AL'}
      </button>

      {/* CitadelOS link */}
      <Link to="/citadelos" style={{
        padding: '7px 14px', borderRadius: 9, fontSize: '0.8rem', fontWeight: 600,
        background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)',
        color: '#ef4444', textDecoration: 'none', transition: 'all 0.2s',
      }}>
        {t('nav.citadelos')}
      </Link>

      {/* GitHub link */}
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
    </nav>
  )
}
