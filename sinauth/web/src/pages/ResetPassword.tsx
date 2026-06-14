import { useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import axios from 'axios'
import { AuthLayout, FloatInput, PrimaryBtn, ErrorMsg } from '@/components/AuthLayout'

const BRAND = '#6366f1'
const apiBase = import.meta.env.VITE_API_BASE ?? ''

export default function ResetPassword() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const token = params.get('token') ?? ''

  const [email, setEmail] = useState('')
  const [emailSent, setEmailSent] = useState(false)
  const [emailError, setEmailError] = useState('')
  const [emailLoading, setEmailLoading] = useState(false)

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleForgot = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setEmailLoading(true)
    setEmailError('')
    try {
      await axios.post(`${apiBase}/api/v1/auth/forgot-password`, { email })
      setEmailSent(true)
    } catch (err: unknown) {
      const e = err as { response?: { data?: { error?: string } } }
      setEmailError(e.response?.data?.error || 'Something went wrong. Please try again.')
    } finally {
      setEmailLoading(false)
    }
  }

  const handleReset = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (password !== confirm) { setError('Passwords do not match.'); return }
    setLoading(true)
    setError('')
    try {
      await axios.post(`${apiBase}/api/v1/auth/reset-password`, { token, new_password: password })
      setDone(true)
      setTimeout(() => navigate('/login'), 3000)
    } catch (err: unknown) {
      const e = err as { response?: { data?: { error?: string } } }
      setError(e.response?.data?.error || 'Link expired or invalid. Please request a new one.')
    } finally {
      setLoading(false)
    }
  }

  // ── Forgot: email sent ────────────────────────────────────────────────────
  if (!token && emailSent) {
    return (
      <AuthLayout>
        <div style={{ textAlign: 'center', padding: '32px 0' }}>
          <div style={{ width: 64, height: 64, borderRadius: '50%', background: '#eff6ff', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 24px' }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" stroke="#3b82f6" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 800, color: '#0f172a', margin: '0 0 10px' }}>Check your inbox</h2>
          <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.6, margin: '0 0 8px' }}>
            We sent password reset instructions to
          </p>
          <p style={{ fontSize: 14, fontWeight: 700, color: '#0f172a', margin: '0 0 32px' }}>{email}</p>
          <button onClick={() => navigate('/login')}
            style={{ background: 'none', border: 'none', color: BRAND, fontSize: 14, fontWeight: 700, cursor: 'pointer' }}>
            ← Back to sign in
          </button>
        </div>
      </AuthLayout>
    )
  }

  // ── Reset: password updated ───────────────────────────────────────────────
  if (token && done) {
    return (
      <AuthLayout>
        <div style={{ textAlign: 'center', padding: '40px 0' }}>
          <div style={{ width: 64, height: 64, borderRadius: '50%', background: '#f0fdf4', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 24px' }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M4 12l5 5L20 7" stroke="#16a34a" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 800, color: '#0f172a', margin: '0 0 10px' }}>Password updated!</h2>
          <p style={{ fontSize: 14, color: '#64748b', margin: 0 }}>Redirecting you to sign in…</p>
        </div>
      </AuthLayout>
    )
  }

  // ── Forgot: enter email ───────────────────────────────────────────────────
  if (!token) {
    return (
      <AuthLayout>
        <button onClick={() => navigate('/login')} style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', color: '#64748b', fontSize: 13, fontWeight: 600, cursor: 'pointer', padding: 0, marginBottom: 28 }}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M10 12L6 8l4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          Back to sign in
        </button>

        <h1 style={{ fontSize: 26, fontWeight: 800, color: '#0f172a', margin: '0 0 6px', letterSpacing: -0.5 }}>
          Forgot your password?
        </h1>
        <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.6, margin: '0 0 28px' }}>
          Enter the email you used to create your account and we'll send you a reset link.
        </p>

        <form onSubmit={handleForgot} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <FloatInput label="Email address" type="email" value={email} onChange={setEmail} required autoFocus autoComplete="email" />
          <ErrorMsg msg={emailError} />
          <PrimaryBtn loading={emailLoading}>
            {emailLoading ? 'Sending…' : 'Send reset link'}
          </PrimaryBtn>
        </form>
      </AuthLayout>
    )
  }

  // ── Reset: set new password ───────────────────────────────────────────────
  return (
    <AuthLayout>
      <h1 style={{ fontSize: 26, fontWeight: 800, color: '#0f172a', margin: '0 0 6px', letterSpacing: -0.5 }}>
        Set a new password
      </h1>
      <p style={{ fontSize: 14, color: '#64748b', margin: '0 0 28px' }}>
        Choose a strong password with at least 8 characters.
      </p>

      <form onSubmit={handleReset} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <FloatInput label="New password"     type="password" value={password} onChange={setPassword} required minLength={8} autoFocus autoComplete="new-password" />
        <FloatInput label="Confirm password" type="password" value={confirm}  onChange={setConfirm}  required autoComplete="new-password" />
        <ErrorMsg msg={error} />
        <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
          <button type="button" onClick={() => navigate('/login')} style={{
            flex: 1, background: '#f0f0f3', color: '#374151', border: 'none',
            borderRadius: 10, padding: '13px 16px', fontSize: 15, fontWeight: 600, cursor: 'pointer',
          }}>
            Cancel
          </button>
          <div style={{ flex: 2 }}>
            <PrimaryBtn loading={loading}>
              {loading ? 'Saving…' : 'Update password'}
            </PrimaryBtn>
          </div>
        </div>
      </form>
    </AuthLayout>
  )
}
