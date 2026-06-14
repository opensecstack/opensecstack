import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '@/api/auth'
import { AuthLayout, FloatInput, SocialButtons, OrDivider, PrimaryBtn, ErrorMsg } from '@/components/AuthLayout'

const BRAND = '#6366f1'
const apiBase = import.meta.env.VITE_API_BASE ?? ''

export default function Login() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '', totp: '' })
  const [keepLoggedIn, setKeepLoggedIn] = useState(false)
  const [requireTOTP, setRequireTOTP] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const set = (k: keyof typeof form) => (v: string) => setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await login(form.username, form.password, form.totp || undefined)
      if (res.require_totp) { setRequireTOTP(true); setLoading(false); return }
      if (keepLoggedIn) {
        localStorage.setItem('sinauth_token', res.access_token)
      } else {
        sessionStorage.setItem('sinauth_token', res.access_token)
        localStorage.removeItem('sinauth_token')
      }
      navigate('/admin/users')
    } catch (err: unknown) {
      const e = err as { response?: { data?: { error?: string } } }
      setError(e.response?.data?.error || 'Incorrect email or password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthLayout>
      <h1 style={{ fontSize: 26, fontWeight: 800, color: '#0f172a', margin: '0 0 6px', letterSpacing: -0.5 }}>
        Welcome back
      </h1>
      <p style={{ fontSize: 14, color: '#64748b', margin: '0 0 28px' }}>
        Sign in to your account to continue.
      </p>

      <SocialButtons apiBase={apiBase} />
      <OrDivider />

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {!requireTOTP ? (
          <>
            <FloatInput label="Email address" value={form.username} onChange={set('username')}
              autoFocus autoComplete="username" required />
            <FloatInput label="Password" type="password" value={form.password} onChange={set('password')}
              autoComplete="current-password" required />

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '4px 0' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#374151', cursor: 'pointer', userSelect: 'none' }}>
                <input type="checkbox" checked={keepLoggedIn} onChange={e => setKeepLoggedIn(e.target.checked)}
                  style={{ width: 15, height: 15, accentColor: BRAND, cursor: 'pointer' }} />
                Keep me logged in
              </label>
              <a href="/reset-password" style={{ fontSize: 13, color: BRAND, textDecoration: 'none', fontWeight: 600 }}>
                Forgot password?
              </a>
            </div>
          </>
        ) : (
          <div style={{ textAlign: 'center' }}>
            <p style={{ fontSize: 14, color: '#64748b', marginBottom: 16 }}>
              Enter the 6-digit code from your authenticator app.
            </p>
            <input
              value={form.totp} maxLength={6} autoFocus required
              onChange={e => set('totp')(e.target.value)}
              placeholder="000000"
              style={{
                width: '100%', boxSizing: 'border-box', textAlign: 'center',
                fontSize: 28, fontWeight: 700, letterSpacing: 12,
                border: 'none', borderRadius: 10, padding: '14px',
                outline: 'none', background: '#f0f0f3', color: '#0f172a',
              }}
            />
          </div>
        )}

        <ErrorMsg msg={error} />

        <PrimaryBtn loading={loading}>
          {loading ? 'Signing in…' : requireTOTP ? 'Verify code' : 'Sign in'}
        </PrimaryBtn>
      </form>

      <p style={{ textAlign: 'center', fontSize: 13, color: '#64748b', marginTop: 24 }}>
        Don't have an account?{' '}
        <a href="/register" style={{ color: BRAND, textDecoration: 'none', fontWeight: 700 }}>
          Create one
        </a>
      </p>
    </AuthLayout>
  )
}
