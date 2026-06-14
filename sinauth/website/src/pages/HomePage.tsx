import { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { motion, useInView } from 'framer-motion'
import Navbar from '../components/Navbar'
import Footer from '../components/Footer'
import CodeBlock from '../components/CodeBlock'
import { loginWithPopup, PopupUser } from '../lib/sinauthPopup'

const SINAUTH_URL  = import.meta.env.VITE_SINAUTH_URL      ?? 'http://localhost:8100'
const SINAUTH_SITE = import.meta.env.VITE_SINAUTH_SITE_URL ?? 'http://localhost:5174'
const CLIENT_ID = 'homepage'

const features = [
  {
    icon: '🔐',
    title: 'PKCE Authorization Code',
    desc: 'RFC 7636 compliant. No client secrets needed for public clients. Secure by default for SPAs and mobile apps.',
  },
  {
    icon: '🌐',
    title: 'Social SSO',
    desc: 'Google & GitHub out of the box. Pluggable provider architecture for any OAuth2-compatible IdP.',
  },
  {
    icon: '🛡️',
    title: 'TOTP & WebAuthn',
    desc: 'RFC 6238 authenticator apps. Hardware key support for phishing-resistant multi-factor authentication.',
  },
  {
    icon: '👥',
    title: 'RBAC & Groups',
    desc: 'Fine-grained role-based access control. Policy engine with group hierarchy and attribute-based rules.',
  },
  {
    icon: '🏢',
    title: 'SAML 2.0 SP',
    desc: 'Enterprise IdP federation. AD FS, Okta, and Entra ID compatible. XML signature validation included.',
  },
  {
    icon: '🔗',
    title: 'Triple-Hash Audit',
    desc: 'SHA-256 + SHA-512 + BLAKE3 WORM chain. Tamper-detectable audit log for compliance and forensics.',
  },
]

const platforms = [
  'website', 'SIN', 'community', 'CITADEL', 'NIS2Compass', 'APIGuard',
  'ThreatFlow', 'IRFlow', 'OpenScrub', 'CyberPath', 'SecureLab', 'OpenCSIRT', 'VertGuard',
]

const dockerYaml = `# docker-compose.yml
services:
  sinauth:
    image: ghcr.io/opensecstack/sinauth:latest
    environment:
      DATABASE_URL: postgres://sinauth:secret@db/sinauth
      SINAUTH_SITE_URL: https://auth.yourdomain.com
      SINAUTH_JWT_PRIVATE_KEY_PATH: /keys/private.pem
    ports:
      - "8080:8080"
    volumes:
      - ./keys:/keys:ro
    depends_on:
      - db

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: sinauth
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: sinauth
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:`

const terminalSnippet = `docker compose up sinauth
# Ready at http://localhost:8080`

const goSnippet = `import "github.com/opensecstack/sinauth/sdk/go/sinauth"

client := sinauth.New("https://auth.example.com")
claims, err := client.Verify(r.Context(), token)
if err != nil {
    http.Error(w, "unauthorized", 401)
    return
}
// claims.Sub = user ID, claims.Roles = []string
fmt.Println("user:", claims.Sub)`

const tsSnippet = `import { SinauthClient, loginWithPopup } from '@opensecstack/sinauth'

const client = new SinauthClient('https://auth.example.com')
const tokens = await loginWithPopup(client, {
  clientId: 'my-app',
  redirectUri: 'https://app.example.com/callback',
})

// Verify on the server side
const claims = await client.verify(tokens.accessToken)
console.log('user:', claims.sub)`

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
}

function AnimatedSection({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })

  return (
    <motion.div
      ref={ref}
      initial="hidden"
      animate={inView ? 'visible' : 'hidden'}
      variants={fadeUp}
      style={style}
    >
      {children}
    </motion.div>
  )
}

function MockLoginCard() {
  const [tab, setTab] = useState<'signin' | 'register'>('signin')

  return (
    <div
      style={{
        width: 340,
        background: 'rgba(10,12,30,0.95)',
        border: '1px solid rgba(47,75,199,0.3)',
        borderRadius: 16,
        padding: 28,
        boxShadow: '0 24px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(99,102,241,0.1)',
        backdropFilter: 'blur(24px)',
      }}
    >
      {/* Logo */}
      <div style={{ textAlign: 'center', marginBottom: 20 }}>
        <div style={{ marginBottom: 8 }}>
          <svg width="44" height="44" viewBox="0 0 52 52" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="52" height="52" rx="14" fill="#1a2d7a"/>
            <circle cx="26" cy="16" r="9" fill="#0ea5e9"/>
            <circle cx="34.7" cy="31" r="9" fill="#6366f1"/>
            <circle cx="17.3" cy="31" r="9" fill="#6366f1"/>
            <circle cx="26" cy="26" r="6.5" fill="#1a2d7a"/>
            <circle cx="26" cy="16" r="3" fill="#1a2d7a"/>
            <circle cx="34.7" cy="31" r="3" fill="#1a2d7a"/>
            <circle cx="17.3" cy="31" r="3" fill="#1a2d7a"/>
          </svg>
        </div>
        <div style={{ fontSize: 16, fontWeight: 700 }}>
          <span style={{ color: '#1a2d7a' }}>sin</span>
          <span style={{ color: '#2f4bc7' }}>auth</span>
        </div>
      </div>

      {/* Tabs */}
      <div
        style={{
          display: 'flex',
          background: 'rgba(255,255,255,0.04)',
          borderRadius: 8,
          padding: 3,
          marginBottom: 20,
        }}
      >
        {(['signin', 'register'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              flex: 1,
              padding: '6px 0',
              borderRadius: 6,
              border: 'none',
              fontSize: '0.8rem',
              fontWeight: 500,
              cursor: 'pointer',
              transition: 'all 0.2s',
              background: tab === t ? '#2f4bc7' : 'none',
              color: tab === t ? 'white' : '#8892a8',
            }}
          >
            {t === 'signin' ? 'Sign In' : 'Register'}
          </button>
        ))}
      </div>

      {/* Form fields */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {tab === 'register' && (
          <div
            style={{
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 8,
              padding: '9px 12px',
              color: '#4a5568',
              fontSize: '0.82rem',
            }}
          >
            Display name
          </div>
        )}
        <div
          style={{
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 8,
            padding: '9px 12px',
            color: '#4a5568',
            fontSize: '0.82rem',
          }}
        >
          Email address
        </div>
        <div
          style={{
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 8,
            padding: '9px 12px',
            color: '#4a5568',
            fontSize: '0.82rem',
          }}
        >
          Password
        </div>

        <div
          style={{
            background: '#2f4bc7',
            borderRadius: 8,
            padding: '9px 12px',
            color: 'white',
            fontSize: '0.82rem',
            fontWeight: 600,
            textAlign: 'center',
            marginTop: 4,
          }}
        >
          {tab === 'signin' ? 'Sign In' : 'Create Account'}
        </div>

        {/* Divider */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            margin: '4px 0',
          }}
        >
          <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.07)' }} />
          <span style={{ color: '#4a5568', fontSize: '0.72rem' }}>or continue with</span>
          <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.07)' }} />
        </div>

        {/* Social buttons */}
        <div style={{ display: 'flex', gap: 8 }}>
          {[
            { label: 'Google', color: '#ea4335' },
            { label: 'GitHub', color: '#e2e8f0' },
          ].map(p => (
            <div
              key={p.label}
              style={{
                flex: 1,
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 8,
                padding: '7px 0',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
                color: '#8892a8',
                fontSize: '0.78rem',
              }}
            >
              <span style={{ color: p.color, fontSize: 10, fontWeight: 700 }}>●</span>
              {p.label}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function HomePage() {
  const [user, setUser] = useState<PopupUser | null>(null)
  const [loggingIn, setLoggingIn] = useState(false)
  const [loginError, setLoginError] = useState<string | null>(null)
  const [scrolled, setScrolled] = useState(false)

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

  // Grid pattern background
  const gridStyle: React.CSSProperties = {
    position: 'absolute',
    inset: 0,
    backgroundImage: `
      linear-gradient(rgba(47,75,199,0.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(47,75,199,0.05) 1px, transparent 1px)
    `,
    backgroundSize: '60px 60px',
    pointerEvents: 'none',
  }

  useEffect(() => {
    document.title = 'sinauth — Open-Source Identity'
  }, [])

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 300)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <div style={{ minHeight: '100vh', background: '#07080f' }}>
      <Navbar />

      {/* ==================== HERO ==================== */}
      <section
        style={{
          position: 'relative',
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          paddingTop: 80,
          overflow: 'hidden',
        }}
      >
        <div style={gridStyle} />
        {/* Radial glow */}
        <div
          style={{
            position: 'absolute',
            top: '30%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: 700,
            height: 700,
            background: 'radial-gradient(circle, rgba(47,75,199,0.12) 0%, transparent 70%)',
            pointerEvents: 'none',
          }}
        />

        <div className="section-container" style={{ width: '100%', position: 'relative', zIndex: 1 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 64,
              flexWrap: 'wrap',
            }}
          >
            {/* Left content */}
            <div style={{ flex: '1 1 480px', maxWidth: 580 }}>
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
              >
                {/* Badge */}
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 8,
                    background: 'rgba(47,75,199,0.1)',
                    border: '1px solid rgba(47,75,199,0.25)',
                    borderRadius: 20,
                    padding: '5px 14px',
                    marginBottom: 28,
                  }}
                >
                  <span
                    style={{
                      display: 'inline-block',
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      background: '#6366f1',
                    }}
                  />
                  <span style={{ fontSize: '0.78rem', color: '#8892a8', letterSpacing: '0.03em' }}>
                    v1.0 · Open Source · Apache 2.0
                  </span>
                </div>

                <h1
                  style={{
                    fontSize: 'clamp(2.5rem, 5vw, 4rem)',
                    fontWeight: 800,
                    lineHeight: 1.1,
                    letterSpacing: '-0.03em',
                    marginBottom: 20,
                  }}
                >
                  <span style={{ color: '#e2e8f0' }}>Identity.</span>
                  <br />
                  <span className="gradient-text">Without Compromise.</span>
                </h1>

                <p
                  style={{
                    fontSize: 'clamp(1rem, 1.5vw, 1.15rem)',
                    color: '#8892a8',
                    lineHeight: 1.75,
                    marginBottom: 32,
                    maxWidth: 480,
                  }}
                >
                  OAuth2/OIDC identity provider with PKCE, Social SSO, TOTP, RBAC,
                  and SAML 2.0. Self-host in minutes. Built for the open web.
                </p>

                {/* CTAs */}
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 28 }}>
                  <Link
                    to="/docs/quickstart"
                    style={{
                      background: '#2f4bc7',
                      color: 'white',
                      padding: '12px 28px',
                      borderRadius: 9,
                      fontSize: '0.95rem',
                      fontWeight: 600,
                      textDecoration: 'none',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                      transition: 'all 0.2s',
                      boxShadow: '0 4px 20px rgba(47,75,199,0.35)',
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.background = '#3d5ce0'
                      e.currentTarget.style.transform = 'translateY(-1px)'
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.background = '#2f4bc7'
                      e.currentTarget.style.transform = 'translateY(0)'
                    }}
                  >
                    Get Started →
                  </Link>

                  {user ? (
                    <div
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 8,
                        border: '1px solid rgba(99,102,241,0.3)',
                        borderRadius: 9,
                        padding: '11px 20px',
                        background: 'rgba(99,102,241,0.08)',
                      }}
                    >
                      <div
                        style={{
                          width: 24,
                          height: 24,
                          borderRadius: '50%',
                          background: 'linear-gradient(135deg, #6366f1, #2f4bc7)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '0.7rem',
                          fontWeight: 700,
                          color: 'white',
                        }}
                      >
                        {(user.display_name ?? user.username).charAt(0).toUpperCase()}
                      </div>
                      <span style={{ color: '#e2e8f0', fontSize: '0.9rem', fontWeight: 500 }}>
                        Welcome, {user.display_name ?? user.username}
                      </span>
                    </div>
                  ) : (
                    <button
                      onClick={handleLogin}
                      disabled={loggingIn}
                      style={{
                        background: 'transparent',
                        color: '#e2e8f0',
                        border: '1px solid rgba(255,255,255,0.15)',
                        padding: '12px 28px',
                        borderRadius: 9,
                        fontSize: '0.95rem',
                        fontWeight: 600,
                        cursor: loggingIn ? 'wait' : 'pointer',
                        opacity: loggingIn ? 0.7 : 1,
                        transition: 'all 0.2s',
                      }}
                      onMouseEnter={e => {
                        const el = e.currentTarget as HTMLButtonElement
                        el.style.borderColor = 'rgba(99,102,241,0.4)'
                        el.style.background = 'rgba(99,102,241,0.06)'
                      }}
                      onMouseLeave={e => {
                        const el = e.currentTarget as HTMLButtonElement
                        el.style.borderColor = 'rgba(255,255,255,0.15)'
                        el.style.background = 'transparent'
                      }}
                    >
                      {loggingIn ? 'Opening popup…' : 'Try it live'}
                    </button>
                  )}
                </div>

                {loginError && (
                  <p style={{ color: '#f87171', fontSize: '0.8rem', marginBottom: 16 }}>
                    {loginError}
                  </p>
                )}

                {/* Terminal snippet */}
                <div
                  style={{
                    background: '#0d1117',
                    border: '1px solid rgba(47,75,199,0.2)',
                    borderRadius: 10,
                    padding: '12px 16px',
                    maxWidth: 400,
                  }}
                >
                  <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
                    {['#ff5f57', '#ffbd2e', '#28c840'].map(c => (
                      <div
                        key={c}
                        style={{ width: 10, height: 10, borderRadius: '50%', background: c }}
                      />
                    ))}
                  </div>
                  <pre
                    style={{
                      fontFamily: 'var(--mono)',
                      fontSize: '0.82rem',
                      color: '#e2e8f0',
                      margin: 0,
                      lineHeight: 1.7,
                    }}
                  >
                    <span style={{ color: '#f472b6' }}>$</span>{' '}
                    <span style={{ color: '#86efac' }}>docker compose up sinauth</span>
                    {'\n'}
                    <span style={{ color: '#64748b' }}># Ready at http://localhost:8080</span>
                  </pre>
                </div>
              </motion.div>
            </div>

            {/* Right: mock login card */}
            <motion.div
              initial={{ opacity: 0, x: 40 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              style={{ flex: '0 0 auto' }}
            >
              <MockLoginCard />
            </motion.div>
          </div>
        </div>
      </section>

      {/* ==================== STATS BAR ==================== */}
      <div
        style={{
          background: 'rgba(47,75,199,0.06)',
          borderTop: '1px solid rgba(47,75,199,0.12)',
          borderBottom: '1px solid rgba(47,75,199,0.12)',
          padding: '14px 0',
        }}
      >
        <div className="section-container">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 0,
              flexWrap: 'wrap',
            }}
          >
            {[
              '13 Platforms',
              '4 SDKs',
              'RS256 JWT',
              'PKCE',
              'Triple-Hash WORM Audit',
            ].map((stat, i, arr) => (
              <span key={stat} style={{ display: 'flex', alignItems: 'center' }}>
                <span
                  style={{
                    fontSize: '0.82rem',
                    color: '#8892a8',
                    fontWeight: 500,
                    padding: '0 20px',
                  }}
                >
                  <span style={{ color: '#6366f1', fontWeight: 700 }}>{stat.split(' ')[0]}</span>
                  {' '}
                  {stat.split(' ').slice(1).join(' ')}
                </span>
                {i < arr.length - 1 && (
                  <span
                    style={{
                      color: 'rgba(99,102,241,0.25)',
                      fontSize: '1.1rem',
                    }}
                  >
                    ·
                  </span>
                )}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ==================== FEATURES ==================== */}
      <section id="features" style={{ padding: '96px 0' }}>
        <div className="section-container">
          <AnimatedSection>
            <div style={{ textAlign: 'center', marginBottom: 56 }}>
              <h2
                style={{
                  fontSize: 'clamp(1.8rem, 3vw, 2.5rem)',
                  fontWeight: 800,
                  letterSpacing: '-0.02em',
                  marginBottom: 12,
                }}
              >
                Everything identity needs
              </h2>
              <p style={{ color: '#8892a8', fontSize: '1.05rem', maxWidth: 480, margin: '0 auto' }}>
                Production-ready from day one. No duct tape required.
              </p>
            </div>
          </AnimatedSection>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
              gap: 20,
            }}
          >
            {features.map((f, i) => (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-40px' }}
                transition={{ duration: 0.45, delay: i * 0.07 }}
                className="glass-card"
                style={{
                  padding: '28px 28px 26px',
                  transition: 'border-color 0.2s, transform 0.2s',
                  cursor: 'default',
                }}
                whileHover={{ y: -4, transition: { duration: 0.2 } }}
              >
                <div
                  style={{
                    fontSize: '1.5rem',
                    marginBottom: 14,
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: 44,
                    height: 44,
                    background: 'rgba(99,102,241,0.1)',
                    borderRadius: 10,
                  }}
                >
                  {f.icon}
                </div>
                <h3
                  style={{
                    fontSize: '1rem',
                    fontWeight: 700,
                    marginBottom: 8,
                    color: '#e2e8f0',
                  }}
                >
                  {f.title}
                </h3>
                <p style={{ color: '#8892a8', fontSize: '0.875rem', lineHeight: 1.7 }}>
                  {f.desc}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ==================== QUICK START ==================== */}
      <section
        style={{
          padding: '96px 0',
          background: 'rgba(10,12,28,0.6)',
          borderTop: '1px solid rgba(47,75,199,0.1)',
          borderBottom: '1px solid rgba(47,75,199,0.1)',
        }}
      >
        <div className="section-container">
          <AnimatedSection>
            <div style={{ textAlign: 'center', marginBottom: 56 }}>
              <h2
                style={{
                  fontSize: 'clamp(1.8rem, 3vw, 2.5rem)',
                  fontWeight: 800,
                  letterSpacing: '-0.02em',
                  marginBottom: 12,
                }}
              >
                Up in 5 minutes
              </h2>
              <p style={{ color: '#8892a8', fontSize: '1.05rem' }}>
                From zero to production-ready identity in one Docker command.
              </p>
            </div>
          </AnimatedSection>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1.4fr',
              gap: 48,
              alignItems: 'start',
            }}
            className="quickstart-grid"
          >
            {/* Steps */}
            <div>
              {[
                {
                  n: '01',
                  title: 'Clone & configure',
                  desc: 'Clone the repo and copy the example .env. Generate your RS256 key pair with the included script.',
                },
                {
                  n: '02',
                  title: 'Run with Docker Compose',
                  desc: 'One command spins up sinauth + Postgres. The admin UI is at /admin, the OAuth2 endpoints at /oauth.',
                },
                {
                  n: '03',
                  title: 'Register your first client',
                  desc: 'Use the admin panel or REST API to create an OAuth2 client. Copy the client_id into your app.',
                },
                {
                  n: '04',
                  title: 'Integrate the SDK',
                  desc: 'Drop in the Go or TypeScript SDK. Five lines of code and your app is authenticating users.',
                },
              ].map((step, i) => (
                <motion.div
                  key={step.n}
                  initial={{ opacity: 0, x: -20 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true, margin: '-40px' }}
                  transition={{ duration: 0.4, delay: i * 0.1 }}
                  style={{
                    display: 'flex',
                    gap: 20,
                    marginBottom: 32,
                  }}
                >
                  <div
                    style={{
                      flexShrink: 0,
                      width: 40,
                      height: 40,
                      borderRadius: 10,
                      background: 'rgba(47,75,199,0.15)',
                      border: '1px solid rgba(47,75,199,0.25)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontFamily: 'var(--mono)',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      color: '#6366f1',
                    }}
                  >
                    {step.n}
                  </div>
                  <div>
                    <h4 style={{ fontWeight: 600, marginBottom: 4, color: '#e2e8f0' }}>
                      {step.title}
                    </h4>
                    <p style={{ color: '#8892a8', fontSize: '0.875rem', lineHeight: 1.7 }}>
                      {step.desc}
                    </p>
                  </div>
                </motion.div>
              ))}
            </div>

            {/* Code */}
            <AnimatedSection>
              <CodeBlock code={dockerYaml} language="yaml" filename="docker-compose.yml" />
            </AnimatedSection>
          </div>
        </div>

        <style>{`
          @media (max-width: 900px) {
            .quickstart-grid { grid-template-columns: 1fr !important; }
          }
        `}</style>
      </section>

      {/* ==================== SDK SECTION ==================== */}
      <section style={{ padding: '96px 0' }}>
        <div className="section-container">
          <AnimatedSection>
            <div style={{ textAlign: 'center', marginBottom: 56 }}>
              <h2
                style={{
                  fontSize: 'clamp(1.8rem, 3vw, 2.5rem)',
                  fontWeight: 800,
                  letterSpacing: '-0.02em',
                  marginBottom: 12,
                }}
              >
                Native SDKs
              </h2>
              <p style={{ color: '#8892a8', fontSize: '1.05rem' }}>
                Idiomatic clients for every stack. Verify JWTs, handle PKCE, refresh tokens.
              </p>
            </div>
          </AnimatedSection>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(480px, 1fr))',
              gap: 24,
            }}
          >
            {/* Go SDK */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.45 }}
              className="glass-card"
              style={{ padding: 28 }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  marginBottom: 18,
                }}
              >
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 8,
                    background: 'rgba(0,173,216,0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    color: '#00add8',
                    fontFamily: 'var(--mono)',
                  }}
                >
                  Go
                </div>
                <div>
                  <h3 style={{ fontWeight: 700, fontSize: '0.95rem', color: '#e2e8f0' }}>Go SDK</h3>
                  <p style={{ color: '#8892a8', fontSize: '0.75rem' }}>
                    github.com/opensecstack/sinauth/sdk/go
                  </p>
                </div>
              </div>
              <CodeBlock code={goSnippet} language="go" />
            </motion.div>

            {/* TypeScript SDK */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.45, delay: 0.1 }}
              className="glass-card"
              style={{ padding: 28 }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  marginBottom: 18,
                }}
              >
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 8,
                    background: 'rgba(49,120,198,0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.65rem',
                    fontWeight: 700,
                    color: '#3178c6',
                    fontFamily: 'var(--mono)',
                  }}
                >
                  TS
                </div>
                <div>
                  <h3 style={{ fontWeight: 700, fontSize: '0.95rem', color: '#e2e8f0' }}>TypeScript SDK</h3>
                  <p style={{ color: '#8892a8', fontSize: '0.75rem' }}>
                    @opensecstack/sinauth
                  </p>
                </div>
              </div>
              <CodeBlock code={tsSnippet} language="typescript" />
            </motion.div>

            {/* Python — coming soon */}
            {[
              { lang: 'Python', pkg: 'opensecstack-sinauth (PyPI)', badge: 'Py', color: '#3776ab' },
              { lang: 'Java', pkg: 'io.opensecstack:sinauth (Maven)', badge: 'J', color: '#f89820' },
            ].map((sdk, i) => (
              <motion.div
                key={sdk.lang}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.45, delay: 0.15 + i * 0.1 }}
                className="glass-card"
                style={{
                  padding: 28,
                  opacity: 0.6,
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'center',
                  minHeight: 140,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                  <div
                    style={{
                      width: 32,
                      height: 32,
                      borderRadius: 8,
                      background: `rgba(${sdk.color === '#3776ab' ? '55,118,171' : '248,152,32'},0.15)`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.7rem',
                      fontWeight: 700,
                      color: sdk.color,
                      fontFamily: 'var(--mono)',
                    }}
                  >
                    {sdk.badge}
                  </div>
                  <div>
                    <h3 style={{ fontWeight: 700, fontSize: '0.95rem', color: '#e2e8f0' }}>
                      {sdk.lang} SDK
                    </h3>
                    <p style={{ color: '#8892a8', fontSize: '0.75rem' }}>{sdk.pkg}</p>
                  </div>
                  <span
                    style={{
                      marginLeft: 'auto',
                      background: 'rgba(251,191,36,0.1)',
                      border: '1px solid rgba(251,191,36,0.2)',
                      color: '#fbbf24',
                      borderRadius: 12,
                      padding: '2px 10px',
                      fontSize: '0.7rem',
                      fontWeight: 600,
                    }}
                  >
                    Coming soon
                  </span>
                </div>
                <p style={{ color: '#4a5568', fontSize: '0.82rem' }}>
                  In active development. Star the repo to get notified on release.
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ==================== INTEGRATION SECTION ==================== */}
      <section
        style={{
          padding: '80px 0',
          background: 'rgba(10,12,28,0.5)',
          borderTop: '1px solid rgba(47,75,199,0.1)',
          borderBottom: '1px solid rgba(47,75,199,0.1)',
        }}
      >
        <div className="section-container">
          <AnimatedSection>
            <div style={{ textAlign: 'center', marginBottom: 48 }}>
              <h2
                style={{
                  fontSize: 'clamp(1.6rem, 2.5vw, 2.2rem)',
                  fontWeight: 800,
                  letterSpacing: '-0.02em',
                  marginBottom: 10,
                }}
              >
                Built for the OpenSecStack ecosystem
              </h2>
              <p style={{ color: '#8892a8', fontSize: '0.95rem' }}>
                13 platforms. One identity layer.
              </p>
            </div>
          </AnimatedSection>

          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: 10,
              justifyContent: 'center',
            }}
          >
            {platforms.map((p, i) => (
              <motion.div
                key={p}
                initial={{ opacity: 0, scale: 0.9 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.3, delay: i * 0.04 }}
                style={{
                  background: 'rgba(15,18,40,0.7)',
                  border: '1px solid rgba(47,75,199,0.18)',
                  borderRadius: 24,
                  padding: '8px 18px',
                  fontSize: '0.82rem',
                  color: '#8892a8',
                  fontWeight: 500,
                  backdropFilter: 'blur(8px)',
                  transition: 'all 0.2s',
                  cursor: 'default',
                }}
                whileHover={{
                  borderColor: 'rgba(99,102,241,0.4)',
                  color: '#e2e8f0',
                  background: 'rgba(99,102,241,0.06)',
                  transition: { duration: 0.2 },
                }}
              >
                {p}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ==================== FINAL CTA ==================== */}
      <section style={{ padding: '120px 0' }}>
        <div className="section-container">
          <AnimatedSection>
            <div
              style={{
                textAlign: 'center',
                maxWidth: 600,
                margin: '0 auto',
              }}
            >
              <div
                style={{
                  display: 'inline-block',
                  background: 'radial-gradient(ellipse at center, rgba(47,75,199,0.15) 0%, transparent 70%)',
                  borderRadius: 24,
                  padding: '56px 40px',
                  border: '1px solid rgba(47,75,199,0.15)',
                  width: '100%',
                }}
              >
                <h2
                  style={{
                    fontSize: 'clamp(1.8rem, 3vw, 2.6rem)',
                    fontWeight: 800,
                    letterSpacing: '-0.02em',
                    marginBottom: 14,
                    lineHeight: 1.2,
                  }}
                >
                  Start protecting your users today
                </h2>
                <p style={{ color: '#8892a8', fontSize: '1rem', marginBottom: 32 }}>
                  Open source, self-hosted, no vendor lock-in. Your users, your data.
                </p>

                <div
                  style={{
                    display: 'flex',
                    gap: 12,
                    justifyContent: 'center',
                    flexWrap: 'wrap',
                    marginBottom: 20,
                  }}
                >
                  <Link
                    to="/docs/quickstart"
                    style={{
                      background: '#2f4bc7',
                      color: 'white',
                      padding: '13px 28px',
                      borderRadius: 9,
                      fontSize: '0.95rem',
                      fontWeight: 600,
                      textDecoration: 'none',
                      boxShadow: '0 4px 20px rgba(47,75,199,0.35)',
                      transition: 'all 0.2s',
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.background = '#3d5ce0'
                      e.currentTarget.style.transform = 'translateY(-1px)'
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.background = '#2f4bc7'
                      e.currentTarget.style.transform = 'translateY(0)'
                    }}
                  >
                    Self-host for free
                  </Link>

                  <a
                    href="https://github.com/opensecstack/sinauth"
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      background: 'transparent',
                      color: '#e2e8f0',
                      border: '1px solid rgba(255,255,255,0.15)',
                      padding: '13px 28px',
                      borderRadius: 9,
                      fontSize: '0.95rem',
                      fontWeight: 600,
                      textDecoration: 'none',
                      transition: 'all 0.2s',
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.borderColor = 'rgba(99,102,241,0.4)'
                      e.currentTarget.style.background = 'rgba(99,102,241,0.06)'
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.borderColor = 'rgba(255,255,255,0.15)'
                      e.currentTarget.style.background = 'transparent'
                    }}
                  >
                    View on GitHub
                  </a>
                </div>

                <p style={{ color: '#4a5568', fontSize: '0.78rem' }}>
                  Apache 2.0 license. No vendor lock-in.
                </p>
              </div>
            </div>
          </AnimatedSection>
        </div>
      </section>

      <Footer />

      {/* Back to Top */}
      {scrolled && (
        <button
          onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          title="Back to top"
          style={{
            position: 'fixed',
            bottom: 32,
            right: 32,
            width: 44,
            height: 44,
            borderRadius: '50%',
            background: 'rgba(99,102,241,0.15)',
            border: '1px solid rgba(99,102,241,0.35)',
            color: '#a5b4fc',
            fontSize: '1.1rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backdropFilter: 'blur(12px)',
            transition: 'all 0.2s',
            zIndex: 100,
          }}
          onMouseEnter={e => {
            const el = e.currentTarget
            el.style.background = 'rgba(99,102,241,0.3)'
            el.style.borderColor = 'rgba(99,102,241,0.6)'
            el.style.transform = 'translateY(-2px)'
          }}
          onMouseLeave={e => {
            const el = e.currentTarget
            el.style.background = 'rgba(99,102,241,0.15)'
            el.style.borderColor = 'rgba(99,102,241,0.35)'
            el.style.transform = 'translateY(0)'
          }}
        >
          ↑
        </button>
      )}
    </div>
  )
}
