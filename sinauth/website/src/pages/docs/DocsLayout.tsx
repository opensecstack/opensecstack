import { useState, useEffect, useMemo } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import Navbar from '../../components/Navbar'
import Footer from '../../components/Footer'

interface NavItem {
  label: string
  path?: string
  children?: NavItem[]
}

const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: 'Getting Started',
    items: [
      { label: 'Introduction',  path: '/docs/intro' },
      { label: 'Quick Start',   path: '/docs/quickstart' },
      { label: 'Installation',  path: '/docs/installation' },
    ],
  },
  {
    section: 'Configuration',
    items: [
      { label: 'Environment Vars', path: '/docs/config' },
      { label: 'Database Setup',   path: '/docs/database' },
    ],
  },
  {
    section: 'Authentication',
    items: [
      { label: 'PKCE Flow',  path: '/docs/pkce' },
      { label: 'Popup SSO',  path: '/docs/popup-sso' },
    ],
  },
  {
    section: 'SDKs',
    items: [
      { label: 'Go SDK',         path: '/docs/sdk-go' },
      { label: 'TypeScript SDK', path: '/docs/sdk-ts' },
    ],
  },
  {
    section: 'API Reference',
    items: [
      { label: 'Auth Endpoints',  path: '/docs/api-auth' },
      { label: 'Admin Endpoints', path: '/docs/api-admin' },
    ],
  },
]

// Extra search keywords per page (beyond the visible label)
const KEYWORDS: Record<string, string> = {
  '/docs/intro':        'introduction overview what is sinauth oauth oidc identity provider',
  '/docs/quickstart':   'quick start getting started docker run setup first steps',
  '/docs/installation': 'install binary docker compose build from source requirements',
  '/docs/config':       'configuration environment variables env settings smtp issuer secret',
  '/docs/database':     'database postgres postgresql migrations schema connection url',
  '/docs/pkce':         'pkce authorization code flow code challenge verifier s256 oauth2',
  '/docs/popup-sso':    'popup sso single sign on window login social return url',
  '/docs/sdk-go':       'go sdk golang verify jwt middleware server library',
  '/docs/sdk-ts':       'typescript sdk javascript browser node verify decode token client',
  '/docs/api-auth':     'api auth endpoints login register token userinfo authorize discovery',
  '/docs/api-admin':    'api admin endpoints users clients sessions audit groups providers',
}

const SEARCH_ENTRIES = NAV.flatMap(group =>
  group.items
    .filter(item => item.path)
    .map(item => ({
      label:    item.label,
      path:     item.path!,
      section:  group.section,
      haystack: `${item.label} ${group.section} ${KEYWORDS[item.path!] ?? ''}`.toLowerCase(),
    })),
)

interface DocsLayoutProps {
  children: React.ReactNode
  breadcrumbs: string[]
  toc?: { id: string; label: string; level?: 2 | 3 }[]
  editPath?: string
  prev?: { label: string; path: string }
  next?: { label: string; path: string }
}

export default function DocsLayout({
  children,
  breadcrumbs,
  toc = [],
  editPath,
  prev,
  next,
}: DocsLayoutProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [activeId, setActiveId] = useState<string>('')
  const [query, setQuery] = useState('')

  const results = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return []
    const terms = q.split(/\s+/)
    return SEARCH_ENTRIES.filter(e => terms.every(t => e.haystack.includes(t)))
  }, [query])

  // Close sidebar + clear search on route change
  useEffect(() => {
    setSidebarOpen(false)
    setQuery('')
  }, [location.pathname])

  // Active TOC tracking
  useEffect(() => {
    if (!toc.length) return
    const observer = new IntersectionObserver(
      entries => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id)
            break
          }
        }
      },
      { rootMargin: '-20px 0px -70% 0px' },
    )
    toc.forEach(item => {
      const el = document.getElementById(item.id)
      if (el) observer.observe(el)
    })
    return () => observer.disconnect()
  }, [toc])

  return (
    <div style={{ background: '#07080f', minHeight: '100vh' }}>
      <Navbar />

      <div className="docs-layout">
        {/* Sidebar overlay on mobile */}
        {sidebarOpen && (
          <div
            onClick={() => setSidebarOpen(false)}
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0,0,0,0.6)',
              zIndex: 49,
            }}
          />
        )}

        {/* Sidebar */}
        <aside className={`docs-sidebar ${sidebarOpen ? 'open' : ''}`}>
          {/* Sidebar logo */}
          <div className="docs-sidebar-logo">
            <Link
              to="/"
              style={{
                textDecoration: 'none',
                fontSize: 15,
                fontWeight: 700,
                letterSpacing: '-0.02em',
              }}
            >
              <span style={{ color: '#1a2d7a' }}>sin</span>
              <span style={{ color: '#2f4bc7' }}>auth</span>
            </Link>
            <span className="docs-sidebar-badge">Docs</span>
          </div>

          {/* Search */}
          <div style={{ position: 'relative', margin: '0 0 20px' }}>
            <svg
              width="14" height="14" viewBox="0 0 24 24" fill="none"
              stroke="#64748b" strokeWidth="2"
              style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }}
            >
              <circle cx="11" cy="11" r="8" />
              <path d="M21 21l-4.35-4.35" />
            </svg>
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Escape') setQuery('')
                if (e.key === 'Enter' && results.length) navigate(results[0].path)
              }}
              placeholder="Search docs…"
              style={{
                width: '100%',
                boxSizing: 'border-box',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 8,
                padding: '8px 10px 8px 32px',
                color: '#e2e8f0',
                fontSize: '0.82rem',
                outline: 'none',
              }}
            />
          </div>

          {query.trim() ? (
            /* Search results */
            <div className="docs-sidebar-section">
              {results.length === 0 ? (
                <div style={{ color: '#64748b', fontSize: '0.82rem', padding: '4px 2px' }}>
                  No results for "{query}"
                </div>
              ) : (
                results.map(r => (
                  <Link key={r.path} to={r.path} className="docs-sidebar-link">
                    {r.label}
                    <span style={{ display: 'block', color: '#475569', fontSize: '0.68rem', marginTop: 1 }}>
                      {r.section}
                    </span>
                  </Link>
                ))
              )}
            </div>
          ) : (
            /* Nav */
            NAV.map(group => (
              <div key={group.section} className="docs-sidebar-section">
                <div className="docs-sidebar-section-title">{group.section}</div>
                {group.items.map(item => {
                  const isActive = item.path === location.pathname
                  return (
                    <Link
                      key={item.label}
                      to={item.path ?? '#'}
                      className={`docs-sidebar-link ${isActive ? 'active' : ''}`}
                    >
                      {item.label}
                    </Link>
                  )
                })}
              </div>
            ))
          )}
        </aside>

        {/* Content + Footer column */}
        <div className="docs-main-column">
        <div className="docs-content-wrapper">
          <main className="docs-content-inner">
            {/* Breadcrumb + Edit link row */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 12,
                flexWrap: 'wrap',
                gap: 8,
              }}
            >
              <div className="docs-breadcrumb">
                {breadcrumbs.map((crumb, i) => (
                  <span key={crumb} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    {i > 0 && <span>/</span>}
                    <span style={{ color: i === breadcrumbs.length - 1 ? '#e2e8f0' : undefined }}>
                      {crumb}
                    </span>
                  </span>
                ))}
              </div>
              {editPath && (
                <a
                  href={`https://github.com/opensecstack/sinauth/edit/main/website/src/pages/docs/${editPath}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="docs-edit-link"
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                  </svg>
                  Edit on GitHub
                </a>
              )}
            </div>

            {children}

            {/* Prev / Next */}
            {(prev || next) && (
              <div className="docs-prev-next">
                {prev ? (
                  <Link to={prev.path} className="docs-prev-next-btn">
                    <span className="docs-prev-next-label">← Previous</span>
                    <span className="docs-prev-next-title">{prev.label}</span>
                  </Link>
                ) : (
                  <div />
                )}
                {next ? (
                  <Link
                    to={next.path}
                    className="docs-prev-next-btn"
                    style={{ textAlign: 'right' }}
                  >
                    <span className="docs-prev-next-label">Next →</span>
                    <span className="docs-prev-next-title">{next.label}</span>
                  </Link>
                ) : (
                  <div />
                )}
              </div>
            )}
          </main>

          {/* TOC */}
          {toc.length > 0 && (
            <div className="docs-toc">
              <div className="docs-toc-title">On this page</div>
              {toc.map(item => (
                <a
                  key={item.id}
                  href={`#${item.id}`}
                  className={`docs-toc-link ${activeId === item.id ? 'active' : ''}`}
                  style={{ paddingLeft: item.level === 3 ? 22 : 10 }}
                >
                  {item.label}
                </a>
              ))}
            </div>
          )}
        </div>
        <Footer />
        </div>
      </div>

      {/* Mobile sidebar toggle */}
      <button
        className="docs-sidebar-toggle"
        onClick={() => setSidebarOpen(o => !o)}
        aria-label="Toggle sidebar"
      >
        {sidebarOpen ? '✕' : '☰'}
      </button>

    </div>
  )
}
