import { useState } from 'react'
import { useNavigate, useLocation, type Location } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { loginWithPopup, decodeJWT } from '@/lib/sinauth'
import { useAuthStore } from '@/store/authStore'
import { jwtExpiryMs } from '@/lib/jwt'

export default function Login(): JSX.Element {
  const navigate = useNavigate()
  const location = useLocation()
  const fromState = (location.state as { from?: Location } | null)?.from
  const redirectTo = fromState?.pathname ? `${fromState.pathname}${fromState.search ?? ''}` : '/dashboard'
  const setToken = useAuthStore((s) => s.setToken)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function handleLogin(): Promise<void> {
    setPending(true)
    setError(null)
    try {
      const tokens = await loginWithPopup()
      const payload = decodeJWT(tokens.access_token)
      const expMs = jwtExpiryMs(tokens.access_token) ?? Date.now() + 3600_000
      setToken(tokens.access_token, (payload.role as string) ?? 'viewer', (payload.sub as string) ?? '', expMs)
      navigate(redirectTo, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="w-full max-w-sm bg-white rounded-md shadow-sm border border-slate-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <ShieldCheck className="h-6 w-6 text-slate-900" />
          <h1 className="text-lg font-semibold text-slate-900">SecureLab</h1>
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
