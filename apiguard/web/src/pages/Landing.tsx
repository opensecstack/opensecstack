import { useState } from 'react'
import { loginWithPopup } from '../sinauth'
import './Landing.css'

interface Props {
  onLogin: (token: string) => void
}

const FEATURES = [
  {
    icon: '🎯',
    title: 'OWASP API Security Top 10',
    text: 'Automated scanning mapped to the OWASP API Security Top 10, surfacing broken authorization, injection, and misconfiguration risks.',
  },
  {
    icon: '🧬',
    title: 'Spec-aware fuzzing',
    text: 'OpenAPI/spec-aware fuzzing exercises every endpoint, parameter, and schema to uncover edge-case failures real traffic would miss.',
  },
  {
    icon: '📜',
    title: 'Findings & audit trail',
    text: 'Track findings end to end with a complete, tamper-evident audit trail and CITADEL governance over every action.',
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
      localStorage.setItem('apiguard_token', tokens.access_token)
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
          <span className="landing-brand-icon">🛡</span>
          <span className="landing-brand-text">APIGuard</span>
        </div>
        <button className="landing-signin" onClick={handleSignIn} disabled={loading}>
          {loading ? 'Opening…' : 'Sign in'}
        </button>
      </nav>

      <header className="landing-hero">
        <span className="landing-eyebrow">API Security Testing</span>
        <h1 className="landing-title">APIGuard</h1>
        <p className="landing-tagline">Find the flaws in your APIs before attackers do.</p>
        <p className="landing-desc">
          APIGuard continuously tests your APIs for security weaknesses, combining
          OWASP-aligned scanning with spec-aware fuzzing and governed audit trails so
          your team ships secure interfaces with confidence.
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
