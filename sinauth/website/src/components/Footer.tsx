import { Link } from 'react-router-dom'

const columns = [
  {
    title: 'Product',
    links: [
      { label: 'Features', href: '/#features' },
      { label: 'Docs', href: '/docs/quickstart' },
      { label: 'Changelog', href: 'https://github.com/opensecstack/sinauth/releases', external: true },
    ],
  },
  {
    title: 'Developers',
    links: [
      { label: 'Quick Start', href: '/docs/quickstart' },
      { label: 'SDK Go', href: '/docs/sdk-go' },
      { label: 'SDK TypeScript', href: '/docs/sdk-ts' },
      { label: 'API Reference', href: '/docs/api-auth' },
    ],
  },
  {
    title: 'Community',
    links: [
      { label: 'GitHub', href: 'https://github.com/opensecstack/sinauth', external: true },
      { label: 'Issues', href: 'https://github.com/opensecstack/sinauth/issues', external: true },
      { label: 'Contributing', href: 'https://github.com/opensecstack/sinauth/blob/main/CONTRIBUTING.md', external: true },
    ],
  },
]

export default function Footer() {
  return (
    <footer
      style={{
        background: '#050610',
        borderTop: '1px solid rgba(47,75,199,0.15)',
        padding: '60px 0 32px',
      }}
    >
      <div
        style={{
          maxWidth: 1200,
          margin: '0 auto',
          padding: '0 40px',
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr 1fr 1fr',
            gap: 40,
            marginBottom: 48,
          }}
          className="footer-grid"
        >
          {/* Brand column */}
          <div>
            <div
              style={{
                fontSize: 18,
                fontWeight: 700,
                marginBottom: 10,
                letterSpacing: '-0.02em',
              }}
            >
              <span style={{ color: '#1a2d7a' }}>sin</span>
              <span style={{ color: '#2f4bc7' }}>auth</span>
            </div>
            <p
              style={{
                color: '#8892a8',
                fontSize: '0.82rem',
                lineHeight: 1.7,
                marginBottom: 12,
                maxWidth: 200,
              }}
            >
              Open-source OAuth2/OIDC identity provider
            </p>
            <p style={{ color: '#64748b', fontSize: '0.78rem' }}>
              © 2026 OpenSecStack
            </p>
          </div>

          {/* Link columns */}
          {columns.map(col => (
            <div key={col.title}>
              <h4
                style={{
                  fontSize: '0.72rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                  color: '#8892a8',
                  marginBottom: 16,
                }}
              >
                {col.title}
              </h4>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
                {col.links.map(link => (
                  <li key={link.label}>
                    {link.external ? (
                      <a
                        href={link.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          color: '#64748b',
                          fontSize: '0.85rem',
                          textDecoration: 'none',
                          transition: 'color 0.15s',
                        }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#e2e8f0')}
                        onMouseLeave={e => (e.currentTarget.style.color = '#64748b')}
                      >
                        {link.label}
                      </a>
                    ) : (
                      <Link
                        to={link.href}
                        style={{
                          color: '#64748b',
                          fontSize: '0.85rem',
                          textDecoration: 'none',
                          transition: 'color 0.15s',
                        }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#e2e8f0')}
                        onMouseLeave={e => (e.currentTarget.style.color = '#64748b')}
                      >
                        {link.label}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div
          style={{
            paddingTop: 24,
            borderTop: '1px solid rgba(255,255,255,0.05)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          <span style={{ color: '#3d4a5c', fontSize: '0.78rem' }}>
            Licensed under Apache 2.0
          </span>
          <a
            href="https://sinauth.dev"
            style={{ color: '#3d4a5c', fontSize: '0.78rem', textDecoration: 'none' }}
          >
            sinauth.dev
          </a>
        </div>
      </div>

      <style>{`
        @media (max-width: 900px) {
          .footer-grid {
            grid-template-columns: 1fr 1fr !important;
          }
        }
        @media (max-width: 560px) {
          .footer-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </footer>
  )
}
