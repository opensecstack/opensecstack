import { useEffect } from 'react'
import { Helmet } from 'react-helmet-async'

const MESSAGE_TYPE = 'sinauth_callback'

export default function AuthCallbackPage() {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code  = params.get('code')
    const state = params.get('state')
    const error = params.get('error')

    if (!window.opener) return

    window.opener.postMessage(
      error
        ? { type: MESSAGE_TYPE, error }
        : { type: MESSAGE_TYPE, code, state },
      window.location.origin,
    )
    window.close()
  }, [])

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center',
      justifyContent: 'center', background: '#030308', color: '#8892a8',
      fontFamily: 'system-ui, sans-serif', fontSize: 14,
    }}>
      <Helmet>
        <title>Signing in… | opensecstack</title>
        <meta name="description" content="Completing the sinauth OAuth sign-in redirect." />
        <meta name="robots" content="noindex" />
      </Helmet>
      Completing sign in…
    </div>
  )
}
