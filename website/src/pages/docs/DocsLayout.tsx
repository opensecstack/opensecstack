import { useState, useEffect, useMemo } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import Navbar from '../../components/Navbar'
import Footer from '../../components/Footer'

interface NavItem {
  label: string
  path?: string
}

export const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: 'Getting Started',
    items: [
      { label: 'Introduction', path: '/docs/intro' },
      { label: 'Quick Start', path: '/docs/quickstart' },
      { label: 'Installation', path: '/docs/installation' },
      { label: 'Local Development', path: '/docs/local-dev' },
    ],
  },
  {
    section: 'Architecture',
    items: [
      { label: 'Overview', path: '/docs/architecture' },
      { label: 'SDK & Contracts', path: '/docs/contracts' },
      { label: 'Time Dimension Segmentation', path: '/docs/tds' },
      { label: 'CITADEL Integration', path: '/docs/citadel-integration' },
      { label: 'Webhooks & Events', path: '/docs/webhooks' },
    ],
  },
  {
    section: 'Platforms',
    items: [
      { label: 'Overview', path: '/docs/platforms' },
      { label: 'APIGuard', path: '/docs/platforms/apiguard' },
      { label: 'NIS2 Compass', path: '/docs/platforms/nis2compass' },
      { label: 'IRFlow', path: '/docs/platforms/irflow' },
      { label: 'ThreatFlow', path: '/docs/platforms/threatflow' },
      { label: 'OpenScrub', path: '/docs/platforms/openscrub' },
      { label: 'CyberPath', path: '/docs/platforms/cyberpath' },
      { label: 'SecureLab', path: '/docs/platforms/securelab' },
      { label: 'OpenCSIRT', path: '/docs/platforms/opencsirt' },
      { label: 'VertGuard', path: '/docs/platforms/vertguard' },
      { label: 'SIN Community', path: '/docs/platforms/community' },
    ],
  },
  {
    section: 'Identity',
    items: [
      { label: 'Identity (sinauth)', path: '/docs/identity' },
    ],
  },
  {
    section: 'CITADEL Governance',
    items: [
      { label: 'Overview', path: '/docs/governance' },
      { label: 'MARSHAL Engine', path: '/docs/citadel/marshal' },
      { label: 'WORM Chain & TripleHash', path: '/docs/citadel/worm' },
      { label: 'Separation of Duties', path: '/docs/citadel/sod' },
      { label: 'AUGUR & VIGIL', path: '/docs/citadel/augur-vigil' },
      { label: 'Evidence & Audit', path: '/docs/citadel/evidence' },
    ],
  },
  {
    section: 'SDK',
    items: [
      { label: 'Go', path: '/docs/sdk/go' },
      { label: 'Python', path: '/docs/sdk/python' },
      { label: 'TypeScript', path: '/docs/sdk/typescript' },
      { label: 'Rust', path: '/docs/sdk/rust' },
    ],
  },
  {
    section: 'Compliance',
    items: [
      { label: 'NIS2 & EU AI Act', path: '/docs/nis2' },
    ],
  },
  {
    section: 'Operations',
    items: [
      { label: 'Deployment', path: '/docs/deployment' },
      { label: 'Security', path: '/docs/security' },
      { label: 'Versioning & Releases', path: '/docs/releases' },
    ],
  },
]

// Extra search keywords per page (beyond the visible label)
const KEYWORDS: Record<string, string> = {
  '/docs/intro':        'introduction overview what is opensecstack sin ecosystem security platforms',
  '/docs/quickstart':   'quick start getting started docker compose run setup first steps',
  '/docs/installation': 'install docker compose kubernetes helm build from source requirements',
  '/docs/architecture': 'architecture diagram data flow citadel sdk contracts layers languages',
  '/docs/contracts':    'sdk contracts event schemas scan ioc stix incident webhook hmac json',
  '/docs/platforms':    'platforms overview apiguard nis2compass irflow threatflow openscrub cyberpath securelab opencsirt vertguard community',
  '/docs/platforms/apiguard':    'apiguard api security testing owasp api top 10 cvss sarif scan',
  '/docs/platforms/nis2compass': 'nis2 compass compliance article 21 23 assessment evidence notification',
  '/docs/platforms/irflow':      'irflow incident response orchestration playbook webhook rbac notification',
  '/docs/platforms/threatflow':  'threatflow threat intelligence ioc stix taxii mitre attack correlation',
  '/docs/platforms/openscrub':   'openscrub ddos mitigation xdp ebpf gobgp blackhole kernel',
  '/docs/platforms/cyberpath':   'cyberpath security training docker wasm labs certification nis2 evidence',
  '/docs/platforms/securelab':   'securelab attack simulation mitre attack detection validation scenarios',
  '/docs/platforms/opencsirt':   'opencsirt csirt taxii stix csaf advisory nis2 article 23 peer federation',
  '/docs/platforms/vertguard':   'vertguard ai attack defence prompt injection deepfake c2pa mitre atlas llm',
  '/docs/platforms/community':   'sin community knowledge hub posts tags search meilisearch notifications',
  '/docs/identity':     'identity sinauth sso oidc oauth pkce jwks rs256 single sign on login',
  '/docs/governance':   'governance citadel marshal worm triplehash nds augur audit chain ed25519',
  '/docs/deployment':   'deployment docker compose kubernetes k8s helm ports topology env secrets',
  '/docs/security':     'security maturity tiers post quantum vulnerability disclosure mtls jwks',
  '/docs/local-dev':       'local development make dev hot reload ide setup vscode jetbrains env',
  '/docs/tds':             'tds time dimension segmentation latency tiers second minute hour hand scanner',
  '/docs/citadel-integration': 'citadel integration kerkese marshal governed action worm evidence verdict execute refuse hard stop',
  '/docs/webhooks':        'webhooks events hmac sha256 signature replay window per-source secret wire format',
  '/docs/nis2':            'nis2 article 21 23 eu ai act nis3 compliance mapping measures notification',
  '/docs/releases':        'versioning releases semver compatibility matrix deprecation policy post quantum timeline',
  '/docs/sdk/go':          'go sdk golang client install verify jwt server library',
  '/docs/sdk/python':      'python sdk pip client async assessment scan',
  '/docs/sdk/typescript':  'typescript sdk npm node browser client webhook router verify',
  '/docs/sdk/rust':        'rust sdk cargo tokio reqwest async client',
  '/docs/citadel/marshal':     'marshal engine 5 gate authn authz nds augur worm kerkese verdict execute refuse hard stop',
  '/docs/citadel/worm':        'worm chain triplehash sha256 sha512 blake3 ed25519 anchor append only audit log verification',
  '/docs/citadel/sod':         'separation of duties nds gate 3 operator verifier role groups cryptographic',
  '/docs/citadel/augur-vigil': 'augur behavioural heuristics off-hours high frequency data export vigil health monitor green amber red',
  '/docs/citadel/evidence':    'evidence custody chain manifest auditor walkthrough export verify anchors',
}

const SEARCH_ENTRIES = NAV.flatMap(group =>
  group.items
    .filter(item => item.path)
    .map(item => ({
      label: item.label,
      path: item.path!,
      section: group.section,
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

export default function DocsLayout({ children, breadcrumbs, toc = [], editPath, prev, next }: DocsLayoutProps) {
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

  useEffect(() => {
    setSidebarOpen(false)
    setQuery('')
  }, [location.pathname])

  useEffect(() => {
    if (!toc.length) return
    const observer = new IntersectionObserver(
      entries => {
        for (const entry of entries) {
          if (entry.isIntersecting) { setActiveId(entry.target.id); break }
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
    <div style={{ background: 'var(--bg)', minHeight: '100vh' }}>
      <Navbar />

      <div className="docs-layout">
        {sidebarOpen && (
          <div onClick={() => setSidebarOpen(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 49 }} />
        )}

        <aside className={`docs-sidebar ${sidebarOpen ? 'open' : ''}`}>
          <div className="docs-sidebar-logo">
            <span style={{ fontSize: 15, fontWeight: 800, letterSpacing: '-0.02em' }}>
              <span className="gradient-text">SIN</span>
            </span>
            <span className="docs-sidebar-badge">Docs</span>
          </div>

          <div style={{ position: 'relative', margin: '0 16px 20px' }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2"
              style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }}>
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
                width: '100%', boxSizing: 'border-box',
                background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 8, padding: '8px 10px 8px 32px', color: 'var(--text)', fontSize: '0.82rem', outline: 'none',
              }}
            />
          </div>

          {query.trim() ? (
            <div className="docs-sidebar-section">
              {results.length === 0 ? (
                <div style={{ color: '#64748b', fontSize: '0.82rem', padding: '4px 20px' }}>No results for "{query}"</div>
              ) : (
                results.map(r => (
                  <Link key={r.path} to={r.path} className="docs-sidebar-link">
                    {r.label}
                    <span style={{ display: 'block', color: '#475569', fontSize: '0.68rem', marginTop: 1 }}>{r.section}</span>
                  </Link>
                ))
              )}
            </div>
          ) : (
            NAV.map(group => (
              <div key={group.section} className="docs-sidebar-section">
                <div className="docs-sidebar-section-title">{group.section}</div>
                {group.items.map(item => (
                  <Link
                    key={item.label}
                    to={item.path ?? '#'}
                    className={`docs-sidebar-link ${item.path === location.pathname ? 'active' : ''}`}
                  >
                    {item.label}
                  </Link>
                ))}
              </div>
            ))
          )}
        </aside>

        <div className="docs-main-column">
          <div className="docs-content-wrapper">
            <main className="docs-content-inner">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
                <div className="docs-breadcrumb">
                  {breadcrumbs.map((crumb, i) => (
                    <span key={crumb} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {i > 0 && <span>/</span>}
                      <span style={{ color: i === breadcrumbs.length - 1 ? 'var(--text)' : undefined }}>{crumb}</span>
                    </span>
                  ))}
                </div>
                {editPath && (
                  <a
                    href={`https://github.com/opensecstack/opensecstack/edit/main/website/src/pages/docs/${editPath}`}
                    target="_blank" rel="noopener noreferrer" className="docs-edit-link"
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

              {(prev || next) && (
                <div className="docs-prev-next">
                  {prev ? (
                    <Link to={prev.path} className="docs-prev-next-btn">
                      <span className="docs-prev-next-label">← Previous</span>
                      <span className="docs-prev-next-title">{prev.label}</span>
                    </Link>
                  ) : <div />}
                  {next ? (
                    <Link to={next.path} className="docs-prev-next-btn" style={{ textAlign: 'right' }}>
                      <span className="docs-prev-next-label">Next →</span>
                      <span className="docs-prev-next-title">{next.label}</span>
                    </Link>
                  ) : <div />}
                </div>
              )}

              <button
                className="docs-back-to-top"
                onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="12" y1="19" x2="12" y2="5" />
                  <polyline points="5 12 12 5 19 12" />
                </svg>
                Back to the top
              </button>
            </main>

            {toc.length > 0 && (
              <div className="docs-toc">
                <div className="docs-toc-title">On this page</div>
                {toc.map(item => (
                  <a key={item.id} href={`#${item.id}`}
                    className={`docs-toc-link ${activeId === item.id ? 'active' : ''}`}
                    style={{ paddingLeft: item.level === 3 ? 22 : 10 }}>
                    {item.label}
                  </a>
                ))}
              </div>
            )}
          </div>
          <Footer />
        </div>
      </div>

      <button className="docs-sidebar-toggle" onClick={() => setSidebarOpen(o => !o)} aria-label="Toggle sidebar">
        {sidebarOpen ? '✕' : '☰'}
      </button>
    </div>
  )
}
