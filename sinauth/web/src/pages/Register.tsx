import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { register } from '@/api/auth'
import { AuthLayout, FloatInput, SocialButtons, OrDivider, PrimaryBtn, ErrorMsg } from '@/components/AuthLayout'

const BRAND = '#6366f1'
const apiBase = import.meta.env.VITE_API_BASE ?? ''

export default function Register() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ firstName: '', lastName: '', email: '', password: '', confirm: '' })
  const [terms, setTerms] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)

  const set = (k: keyof typeof form) => (v: string) => setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (form.password !== form.confirm) { setError('Passwords do not match.'); return }
    if (!terms) { setError('Please accept the Terms & Conditions to continue.'); return }
    setLoading(true)
    setError('')
    try {
      const username = form.email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '_')
      await register(username, form.email, form.password)
      setSuccess(true)
      setTimeout(() => navigate('/login'), 3000)
    } catch (err: unknown) {
      const e = err as { response?: { data?: { error?: string } } }
      setError(e.response?.data?.error || 'Registration failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <AuthLayout>
        <div style={{ textAlign: 'center', padding: '40px 0' }}>
          <div style={{ width: 64, height: 64, borderRadius: '50%', background: '#f0fdf4', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 24px' }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M4 12l5 5L20 7" stroke="#16a34a" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 800, color: '#0f172a', margin: '0 0 10px' }}>Account created!</h2>
          <p style={{ fontSize: 14, color: '#64748b', margin: 0 }}>Redirecting you to sign in…</p>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout>
      <h1 style={{ fontSize: 26, fontWeight: 800, color: '#0f172a', margin: '0 0 6px', letterSpacing: -0.5 }}>
        Create your account
      </h1>
      <p style={{ fontSize: 14, color: '#64748b', margin: '0 0 28px' }}>
        Join OpenSecStack and access all platforms with one account.
      </p>

      <SocialButtons apiBase={apiBase} />
      <OrDivider />

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <FloatInput label="First name" value={form.firstName} onChange={set('firstName')} required autoFocus autoComplete="given-name" />
          <FloatInput label="Last name"  value={form.lastName}  onChange={set('lastName')}  required autoComplete="family-name" />
        </div>
        <FloatInput label="Email address" type="email" value={form.email}    onChange={set('email')}    required autoComplete="email" />
        <FloatInput label="Password"      type="password"       value={form.password} onChange={set('password')} required minLength={8} autoComplete="new-password" />
        <FloatInput label="Confirm password" type="password"    value={form.confirm}  onChange={set('confirm')}  required autoComplete="new-password" />

        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 13, color: '#374151', cursor: 'pointer', margin: '4px 0' }}>
          <input type="checkbox" checked={terms} onChange={e => setTerms(e.target.checked)}
            style={{ accentColor: BRAND, marginTop: 2, flexShrink: 0, width: 15, height: 15 }} />
          <span>
            I agree to the{' '}
            <a href="#" style={{ color: BRAND, textDecoration: 'none', fontWeight: 600 }}>Terms of Service</a>
            {' '}and{' '}
            <a href="#" style={{ color: BRAND, textDecoration: 'none', fontWeight: 600 }}>Privacy Policy</a>
          </span>
        </label>

        <ErrorMsg msg={error} />

        <PrimaryBtn loading={loading}>
          {loading ? 'Creating account…' : 'Create account'}
        </PrimaryBtn>
      </form>

      <p style={{ textAlign: 'center', fontSize: 13, color: '#64748b', marginTop: 24 }}>
        Already have an account?{' '}
        <a href="/login" style={{ color: BRAND, textDecoration: 'none', fontWeight: 700 }}>
          Sign in
        </a>
      </p>
    </AuthLayout>
  )
}
