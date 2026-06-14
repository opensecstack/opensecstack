import { useState } from 'react'
import { loginWithPopup } from '../sinauth'
import './Landing.css'

interface Props {
  onLogin: (token: string) => void
}

const FEATURES = [
  {
    icon: '📋',
    title: 'Article 21(2) measures',
    text: 'Assess each of the Article 21(2) cybersecurity risk-management measures with structured, repeatable evaluations across your organisations.',
  },
  {
    icon: '⏱',
    title: 'Article 23 incident timers',
    text: 'Stay ahead of NIS2 reporting deadlines with built-in Article 23 incident-reporting timers for early warning, notification, and final reports.',
  },
  {
    icon: '📑',
    title: 'Auditable evidence',
    text: 'Generate auditable compliance evidence and reports that demonstrate your posture to authorities, auditors, and leadership.',
  },
]

export default function Landing({ onLogin }: Props) {
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSignIn() {
    setLoading(true)
    setError(null)
    try {
      const tokens = await loginWithPopup()
      localStorage.setItem('nis2compass_token', tokens.access_token)
      onLogin(tokens.access_token)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="landing">
      <nav className="landing-nav">
        <div className="landing-brand">
          <span className="landing-brand-icon">&#x2316;</span>
          <span className="landing-brand-text">NIS2 Compass</span>
        </div>
        <button className="landing-signin" onClick={handleSignIn} disabled={loading}>
          {loading ? 'Opening…' : 'Sign in'}
        </button>
      </nav>

      <header className="landing-hero">
        <span className="landing-eyebrow">NIS2 Compliance, Measurable</span>
        <h1 className="landing-title">NIS2 Compass</h1>
        <p className="landing-tagline">Turn NIS2 obligations into measurable, auditable progress.</p>
        <p className="landing-desc">
          NIS2 Compass guides your organisation through the Directive's requirements,
          turning Article 21 measures and Article 23 reporting duties into clear
          assessments, deadlines, and evidence you can act on.
        </p>
        <button className="landing-cta" onClick={handleSignIn} disabled={loading}>
          {loading ? 'Opening…' : 'Sign in'}
        </button>
        {error && <p className="landing-error">{error}</p>}
      </header>

      <section className="landing-features">
        {FEATURES.map((f) => (
          <div className="landing-card" key={f.title}>
            <span className="landing-card-icon">{f.icon}</span>
            <h3 className="landing-card-title">{f.title}</h3>
            <p className="landing-card-text">{f.text}</p>
          </div>
        ))}
      </section>

      <footer className="landing-footer">Part of the SIN ecosystem</footer>
    </div>
  )
}
