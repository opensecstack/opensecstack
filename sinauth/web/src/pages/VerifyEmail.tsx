import { useEffect, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import axios from 'axios'

export default function VerifyEmail() {
  const [params] = useSearchParams()
  const token = params.get('token') ?? ''
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading')
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (!token) {
      setStatus('error')
      setMessage('No verification token provided.')
      return
    }
    axios.get(`/api/v1/auth/verify-email?token=${encodeURIComponent(token)}`)
      .then(() => {
        setStatus('success')
        setMessage('Your email has been verified.')
      })
      .catch((err: unknown) => {
        const e = err as { response?: { data?: { error?: string } } }
        setStatus('error')
        setMessage(e.response?.data?.error || 'Invalid or expired verification link.')
      })
  }, [token])

  const icon = status === 'loading' ? null
    : status === 'success'
      ? <span style={{ fontSize: 48 }}>✓</span>
      : <span style={{ fontSize: 48 }}>✗</span>

  const color = status === 'success' ? '#16a34a' : '#dc2626'

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f9fafb' }}>
      <div style={{ background: 'white', borderRadius: 16, padding: 40, width: '100%', textAlign: 'center' }}>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: '#1a2d7a', margin: '0 0 32px' }}>sin<span style={{ color: '#6366f1' }}>auth</span></h1>
        {status === 'loading' ? (
          <p style={{ color: '#6b7280', fontSize: 15 }}>Verifying your email…</p>
        ) : (
          <>
            <div style={{ color, marginBottom: 16 }}>{icon}</div>
            <p style={{ color, fontSize: 15, fontWeight: 500, margin: '0 0 24px' }}>{message}</p>
            <Link to="/login" style={{ color: '#2f4bc7', fontSize: 14, textDecoration: 'none' }}>
              Back to sign in
            </Link>
          </>
        )}
      </div>
    </div>
  )
}
