import { useEffect } from 'react'

export default function AuthCallback(): JSX.Element {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code  = params.get('code')
    const state = params.get('state')
    const error = params.get('error')
    if (window.opener) {
      window.opener.postMessage(
        error
          ? { type: 'sinauth_callback', error }
          : { type: 'sinauth_callback', code, state },
        window.location.origin,
      )
      window.close()
    }
  }, [])

  return (
    <div className="flex h-screen items-center justify-center">
      <p className="text-sm text-gray-500">Completing sign in…</p>
    </div>
  )
}
