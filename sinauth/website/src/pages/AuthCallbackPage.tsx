import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'

const MESSAGE_TYPE = 'sinauth_callback'

export default function AuthCallbackPage() {
  const [searchParams] = useSearchParams()

  useEffect(() => {
    const code = searchParams.get('code')
    const state = searchParams.get('state')
    const error = searchParams.get('error')

    if (window.opener) {
      window.opener.postMessage(
        {
          type: MESSAGE_TYPE,
          code: code ?? undefined,
          state: state ?? undefined,
          error: error ?? undefined,
        },
        window.location.origin,
      )
      setTimeout(() => window.close(), 100)
    }
  }, [searchParams])

  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#07080f',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 20,
      }}
    >
      <div
        style={{
          width: 48,
          height: 48,
          border: '3px solid rgba(99,102,241,0.2)',
          borderTopColor: '#6366f1',
          borderRadius: '50%',
          animation: 'spin 0.8s linear infinite',
        }}
      />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <p style={{ color: '#8892a8', fontSize: '0.9rem' }}>Completing sign in…</p>
    </div>
  )
}
