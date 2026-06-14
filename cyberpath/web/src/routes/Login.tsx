import { useState } from 'react'
import { useNavigate, useSearchParams, useLocation } from 'react-router-dom'
import { loginWithPopup, decodeJWT } from '@/lib/sinauth'
import { useAuth, type AuthUser } from '@/state/auth'

export default function Login(): JSX.Element {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  function resolveRedirect(): string {
    const next = searchParams.get('next')
    if (next && next.startsWith('/')) return next
    const state = location.state as { from?: { pathname?: string } } | null
    const fromPath = state?.from?.pathname
    if (fromPath && fromPath.startsWith('/')) return fromPath
    return '/tracks'
  }

  async function handleLogin(): Promise<void> {
    setPending(true)
    setError(null)
    try {
      const tokens = await loginWithPopup()
      const payload = decodeJWT(tokens.access_token)
      const user: AuthUser = {
        id:           (payload.sub as string)   ?? '',
        email:        (payload.email as string) ?? '',
        display_name: (payload.name as string)  ?? (payload.email as string) ?? '',
        locale:       'en',
        role:         (payload.role as AuthUser['role']) ?? 'learner',
      }
      login(user, tokens)
      navigate(resolveRedirect(), { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50">
      <div className="w-full max-w-sm rounded-md bg-white p-8 shadow-sm">
        <div className="mb-6 text-center">
          <h1 className="text-xl font-semibold text-slate-900">CyberPath</h1>
          <p className="mt-1 text-sm text-slate-500">Sign in to continue</p>
        </div>
        {error && <p className="mb-4 rounded bg-red-50 p-2 text-sm text-red-600">{error}</p>}
        <button
          onClick={handleLogin}
          disabled={pending}
          className="flex w-full items-center justify-center gap-2 rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-500 disabled:opacity-60"
        >
          {pending ? 'Opening…' : 'Sign in with sinauth'}
        </button>
      </div>
    </div>
  )
}
