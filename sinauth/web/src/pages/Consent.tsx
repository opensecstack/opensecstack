import { useSearchParams } from 'react-router-dom'
import { api } from '@/api/client'
import { useState } from 'react'

export default function Consent() {
  const [params] = useSearchParams()
  const [loading, setLoading] = useState(false)
  const clientName = params.get('client_name') || 'This application'
  const scopes = (params.get('scope') || '').split(' ').filter(Boolean)

  const decide = async (allow: boolean) => {
    setLoading(true)
    const form = new URLSearchParams(Object.fromEntries(params))
    form.set('decision', allow ? 'allow' : 'deny')
    await api.post('/oauth/consent', form.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    setLoading(false)
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f9fafb' }}>
      <div style={{ background: 'white', borderRadius: 16, boxShadow: '0 4px 24px rgba(0,0,0,0.08)', padding: 32, width: '100%', maxWidth: 360 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700, margin: '0 0 8px' }}>{clientName}</h1>
        <p style={{ color: '#6b7280', fontSize: 14, margin: '0 0 24px' }}>is requesting access to your account</p>
        <div style={{ background: '#f9fafb', borderRadius: 8, padding: 16, marginBottom: 24 }}>
          <p style={{ fontSize: 11, fontWeight: 600, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 1, margin: '0 0 8px' }}>Requested permissions</p>
          <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 4 }}>
            {scopes.map(s => (
              <li key={s} style={{ fontSize: 14, color: '#374151', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3b5bdb', flexShrink: 0 }} />
                {s}
              </li>
            ))}
          </ul>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button onClick={() => decide(false)} disabled={loading}
            style={{ flex: 1, border: '1px solid #d1d5db', background: 'white', borderRadius: 8, padding: '10px 16px', fontSize: 14, cursor: 'pointer' }}>
            Deny
          </button>
          <button onClick={() => decide(true)} disabled={loading}
            style={{ flex: 1, background: '#2f4bc7', color: 'white', border: 'none', borderRadius: 8, padding: '10px 16px', fontSize: 14, cursor: 'pointer' }}>
            Allow
          </button>
        </div>
      </div>
    </div>
  )
}
