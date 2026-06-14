import { useState } from 'react'
import { loginWithPopup } from '../sinauth'
import './Login.css'

interface Props {
  onLogin: (token: string) => void
}

export default function Login({ onLogin }: Props) {
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
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-logo">
          <span className="login-logo-icon">🛡</span>
          <span className="login-logo-text">APIGuard</span>
        </div>
        <h1 className="login-title">Sign in</h1>
        <p className="login-subtitle">Access the dashboard via your OpenSecStack account.</p>
        {error && <p className="login-error">{error}</p>}
        <button className="login-btn" onClick={handleSignIn} disabled={loading}>
          {loading ? 'Opening…' : 'Sign in with sinauth'}
        </button>
      </div>
    </div>
  )
}
