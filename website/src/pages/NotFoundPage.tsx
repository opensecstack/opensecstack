import { Link } from 'react-router-dom'
import { useThemeToggle } from '../hooks/useThemeToggle'

/**
 * SPA 404 page. Unknown routes previously fell through to the static
 * `public/404.html`, which broke the back-button and lost the theme/language
 * state. This component renders inside the SPA so navigation continues to
 * feel like the rest of the site.
 */
export default function NotFoundPage() {
  const { resolved } = useThemeToggle()
  const isDark = resolved === 'dark'

  return (
    <main style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem',
      background: isDark ? '#030308' : '#f8fafc',
      color: isDark ? '#e2e8f0' : '#1e293b',
      fontFamily: 'inherit',
    }}>
      <p style={{
        fontSize: '0.75rem',
        letterSpacing: '0.2em',
        textTransform: 'uppercase',
        color: isDark ? '#64748b' : '#94a3b8',
        margin: 0,
      }}>
        Error 404
      </p>

      <h1 style={{
        fontSize: 'clamp(3rem, 8vw, 5rem)',
        margin: '0.5rem 0',
        background: 'linear-gradient(135deg, #00f0ff, #7c3aed, #e040fb)',
        WebkitBackgroundClip: 'text',
        WebkitTextFillColor: 'transparent',
      }}>
        Off the map
      </h1>

      <p style={{
        maxWidth: 520,
        textAlign: 'center',
        color: isDark ? '#8892a8' : '#475569',
        fontSize: '1rem',
        lineHeight: 1.6,
        margin: '0.5rem 0 2rem',
      }}>
        That page isn&apos;t part of the OpenSecStack site. It may have moved,
        been renamed, or never existed.
      </p>

      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', justifyContent: 'center' }}>
        <Link to="/" style={{
          padding: '10px 20px',
          borderRadius: 10,
          fontSize: '0.85rem',
          fontWeight: 600,
          background: 'rgba(0,240,255,0.08)',
          border: '1px solid rgba(0,240,255,0.3)',
          color: '#00f0ff',
          textDecoration: 'none',
        }}>
          Back to the homepage
        </Link>
        <a href="https://github.com/opensecstack/opensecstack"
          target="_blank"
          rel="noopener noreferrer"
          style={{
            padding: '10px 20px',
            borderRadius: 10,
            fontSize: '0.85rem',
            fontWeight: 600,
            background: 'rgba(124,58,237,0.08)',
            border: '1px solid rgba(124,58,237,0.3)',
            color: '#a78bfa',
            textDecoration: 'none',
          }}>
          Browse the repo
        </a>
      </div>
    </main>
  )
}
