import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

export default function SocialCallback() {
  const navigate = useNavigate()

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const token = params.get('social_token')
    if (token) {
      localStorage.setItem('sinauth_token', token)
      window.history.replaceState({}, '', '/')
      navigate('/admin/users', { replace: true })
    } else {
      // No social token — just redirect to login normally.
      navigate('/login', { replace: true })
    }
  }, [navigate])

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f9fafb' }}>
      <p style={{ color: '#6b7280', fontSize: 15 }}>Signing in…</p>
    </div>
  )
}
