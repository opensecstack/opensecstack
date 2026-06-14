import { useState } from 'react'
import { useNavigate, useLocation, type Location } from 'react-router-dom'
import { loginWithPopup } from '../lib/sinauth'
import { setToken } from '../lib/auth'

export default function Login() {
  const navigate = useNavigate()
  const location = useLocation()
  const fromState = (location.state as { from?: Location } | null)?.from
  const redirectTo = fromState?.pathname ? `${fromState.pathname}${fromState.search ?? ''}` : '/dashboard'
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  async function handleLogin(): Promise<void> {
    setPending(true)
    setError('')
    try {
      const tokens = await loginWithPopup()
      setToken(tokens.access_token)
      navigate(redirectTo, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-96 bg-slate-900 p-8 rounded-lg border border-slate-800">
        <h1 className="text-xl font-semibold mb-1 text-indigo-400">VertGuard</h1>
        <p className="text-xs text-slate-400 mb-6">Sign in to access vulnerability management.</p>
        {error && <p className="text-rose-400 text-xs mb-4">{error}</p>}
        <button
          onClick={handleLogin}
          disabled={pending}
          className="w-full bg-indigo-500 hover:bg-indigo-400 disabled:opacity-60 rounded py-2 text-sm font-medium"
        >
          {pending ? 'Opening…' : 'Sign in with sinauth'}
        </button>
      </div>
    </div>
  )
}
