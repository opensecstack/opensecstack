import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { loginWithPopup, PopupUser } from '../lib/sinauthPopup'

const SINAUTH_URL  = import.meta.env.VITE_SINAUTH_URL      ?? 'http://localhost:8100'
const SINAUTH_SITE = import.meta.env.VITE_SINAUTH_SITE_URL ?? 'http://localhost:5174'
const CLIENT_ID = 'homepage'

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [user, setUser] = useState<PopupUser | null>(null)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [loggingIn, setLoggingIn] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 10)
    window.addEventListener('scroll', onScroll)
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const handleLogin = async () => {
    setLoggingIn(true)
    setLoginError(null)
    try {
      const u = await loginWithPopup(SINAUTH_URL, CLIENT_ID, SINAUTH_SITE)
      setUser(u)
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Login failed'
      if (msg !== 'Popup closed') setLoginError(msg)
    } finally {
      setLoggingIn(false)
    }
  }

  const navLinkStyle: React.CSSProperties = {
    color: '#8892a8',
    fontSize: '0.875rem',
    fontWeight: 500,
    textDecoration: 'none',
    padding: '4px 0',
    transition: 'color 0.15s',
  }

  return (
    <nav
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        height: 60,
        zIndex: 200,
        background: scrolled
          ? 'rgba(7,8,15,0.92)'
          : 'rgba(7,8,15,0.7)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        borderBottom: scrolled ? '1px solid rgba(47,75,199,0.18)' : '1px solid transparent',
        transition: 'all 0.3s',
      }}
    >
      <div
        style={{
          maxWidth: 1200,
          margin: '0 auto',
          padding: '0 40px',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 32,
        }}
      >
        {/* Logo */}
        <Link
          to="/"
          style={{
            textDecoration: 'none',
            fontSize: 20,
            fontWeight: 700,
            letterSpacing: '-0.02em',
            flexShrink: 0,
          }}
        >
          <span style={{ color: '#1a2d7a' }}>sin</span>
          <span style={{ color: '#2f4bc7' }}>auth</span>
        </Link>

        {/* Center links — desktop */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 32,
          }}
          className="navbar-center"
        >
          <a
            href="/#features"
            style={navLinkStyle}
            onMouseEnter={e => (e.currentTarget.style.color = '#e2e8f0')}
            onMouseLeave={e => (e.currentTarget.style.color = '#8892a8')}
          >
            Features
          </a>
          <Link
            to="/docs/intro"
            style={navLinkStyle}
            onMouseEnter={e => (e.currentTarget.style.color = '#e2e8f0')}
            onMouseLeave={e => (e.currentTarget.style.color = '#8892a8')}
          >
            Docs
          </Link>
          <Link
            to="/docs/sdk"
            style={navLinkStyle}
            onMouseEnter={e => (e.currentTarget.style.color = '#e2e8f0')}
            onMouseLeave={e => (e.currentTarget.style.color = '#8892a8')}
          >
            SDKs
          </Link>
          <a
            href="https://github.com/opensecstack/sinauth"
            target="_blank"
            rel="noopener noreferrer"
            style={navLinkStyle}
            onMouseEnter={e => (e.currentTarget.style.color = '#e2e8f0')}
            onMouseLeave={e => (e.currentTarget.style.color = '#8892a8')}
          >
            GitHub
          </a>
        </div>

        {/* Right side */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
          {loginError && (
            <span style={{ fontSize: '0.75rem', color: '#f87171' }}>{loginError}</span>
          )}

          {user ? (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                background: 'rgba(99,102,241,0.1)',
                border: '1px solid rgba(99,102,241,0.2)',
                borderRadius: 20,
                padding: '4px 12px 4px 4px',
              }}
            >
              <div
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg, #6366f1, #2f4bc7)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  color: 'white',
                }}
              >
                {(user.display_name ?? user.username).charAt(0).toUpperCase()}
              </div>
              <span style={{ fontSize: '0.8rem', color: '#e2e8f0', fontWeight: 500 }}>
                {user.display_name ?? user.username}
              </span>
            </div>
          ) : (
            <button
              onClick={handleLogin}
              disabled={loggingIn}
              style={{
                background: '#2f4bc7',
                color: 'white',
                border: 'none',
                borderRadius: 7,
                padding: '7px 16px',
                fontSize: '0.83rem',
                fontWeight: 600,
                cursor: loggingIn ? 'wait' : 'pointer',
                opacity: loggingIn ? 0.7 : 1,
                transition: 'all 0.2s',
                letterSpacing: '0.01em',
              }}
              onMouseEnter={e => {
                if (!loggingIn) (e.currentTarget as HTMLButtonElement).style.background = '#3d5ce0'
              }}
              onMouseLeave={e => {
                ;(e.currentTarget as HTMLButtonElement).style.background = '#2f4bc7'
              }}
            >
              {loggingIn ? 'Opening…' : 'Try it live'}
            </button>
          )}

          {/* Hamburger */}
          <button
            onClick={() => setMenuOpen(o => !o)}
            aria-label="Toggle menu"
            style={{
              display: 'none',
              background: 'none',
              border: 'none',
              color: '#8892a8',
              cursor: 'pointer',
              padding: 4,
              fontSize: '1.2rem',
            }}
            className="navbar-hamburger"
          >
            {menuOpen ? '✕' : '☰'}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {menuOpen && (
        <div
          style={{
            position: 'absolute',
            top: 60,
            left: 0,
            right: 0,
            background: 'rgba(7,8,15,0.98)',
            backdropFilter: 'blur(16px)',
            borderBottom: '1px solid rgba(47,75,199,0.18)',
            padding: '16px 24px',
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
          }}
        >
          {['Features', 'Docs', 'SDKs', 'GitHub'].map(label => (
            <a
              key={label}
              href={
                label === 'Features' ? '/#features'
                : label === 'Docs' ? '/docs/intro'
                : label === 'SDKs' ? '/docs/sdk'
                : 'https://github.com/opensecstack/sinauth'
              }
              target={label === 'GitHub' ? '_blank' : undefined}
              rel={label === 'GitHub' ? 'noopener noreferrer' : undefined}
              style={{ color: '#e2e8f0', fontSize: '0.95rem', textDecoration: 'none' }}
              onClick={() => {
                setMenuOpen(false)
                if (label === 'Docs') navigate('/docs/intro')
              }}
            >
              {label}
            </a>
          ))}
        </div>
      )}

      <style>{`
        @media (max-width: 768px) {
          .navbar-center { display: none !important; }
          .navbar-hamburger { display: flex !important; }
        }
      `}</style>
    </nav>
  )
}
