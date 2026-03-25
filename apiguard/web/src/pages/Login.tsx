import { useState, type FormEvent } from 'react'
import { api } from '../api'
import './Login.css'

interface Props {
  onLogin: (token: string) => void
}

export default function Login({ onLogin }: Props) {
  const [apiKey, setApiKey] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!apiKey.trim()) return
    setLoading(true)
    setError(null)
    try {
      const token = await api.auth.login(apiKey.trim())
      localStorage.setItem('apiguard_token', token)
      onLogin(token)
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
        <p className="login-subtitle">Enter your API key to access the dashboard.</p>
        <form onSubmit={handleSubmit} className="login-form">
          <label className="login-label" htmlFor="api-key">API Key</label>
          <input
            id="api-key"
            className="login-input"
            type="password"
            placeholder="Enter your API key"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            autoComplete="current-password"
            disabled={loading}
          />
          {error && <p className="login-error">{error}</p>}
          <button className="login-btn" type="submit" disabled={loading || !apiKey.trim()}>
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}
