import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck, Swords, Radar, GitBranch } from 'lucide-react'
import { loginWithPopup, decodeJWT } from '@/lib/sinauth'
import { useAuthStore } from '@/store/authStore'
import { jwtExpiryMs } from '@/lib/jwt'

const FEATURES = [
  {
    icon: Swords,
    title: 'Run adversary scenarios safely',
    body: 'Execute curated, controlled attack simulations in an isolated lab to exercise your defenses without risk to production.',
  },
  {
    icon: Radar,
    title: 'Validate detection coverage',
    body: 'Map every simulated technique to MITRE ATT&CK and measure exactly which detections fired — and which gaps remain.',
  },
  {
    icon: GitBranch,
    title: 'Feed the wider stack',
    body: 'Simulation results flow into IRFlow, OpenScrub and ThreatFlow so findings drive real incident response and mitigation.',
  },
]

export default function Landing(): JSX.Element {
  const navigate = useNavigate()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const setToken = useAuthStore((s) => s.setToken)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (isAuthenticated()) navigate('/dashboard', { replace: true })
  }, [isAuthenticated, navigate])

  async function handleLogin(): Promise<void> {
    setPending(true)
    setError(null)
    try {
      const tokens = await loginWithPopup()
      const payload = decodeJWT(tokens.access_token)
      const expMs = jwtExpiryMs(tokens.access_token) ?? Date.now() + 3600_000
      setToken(tokens.access_token, (payload.role as string) ?? 'viewer', (payload.sub as string) ?? '', expMs)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-indigo-600" />
            <span className="text-lg font-semibold">SecureLab</span>
          </div>
          <button
            onClick={handleLogin}
            disabled={pending}
            className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-60"
          >
            {pending ? 'Opening…' : 'Sign in'}
          </button>
        </div>
      </header>

      <main className="flex-1">
        <section className="mx-auto max-w-6xl px-6 py-20 text-center sm:py-28">
          <h1 className="text-4xl font-bold tracking-tight sm:text-6xl">SecureLab</h1>
          <p className="mt-4 text-xl font-medium text-indigo-600 sm:text-2xl">
            Attack Simulation &amp; Detection Validation
          </p>
          <p className="mx-auto mt-6 max-w-2xl text-base text-slate-600 sm:text-lg">
            SecureLab lets blue teams run realistic adversary scenarios in a safe, controlled lab and prove
            their detections actually work. Close coverage gaps before a real attacker finds them.
          </p>
          {error && (
            <p className="mx-auto mt-6 max-w-md rounded bg-red-50 p-2 text-sm text-red-600">{error}</p>
          )}
          <div className="mt-10">
            <button
              onClick={handleLogin}
              disabled={pending}
              className="rounded-md bg-indigo-600 px-8 py-3 text-base font-semibold text-white transition hover:bg-indigo-500 disabled:opacity-60"
            >
              {pending ? 'Opening…' : 'Sign in'}
            </button>
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-6 pb-24">
          <div className="grid gap-6 sm:grid-cols-3">
            {FEATURES.map(({ icon: Icon, title, body }) => (
              <div key={title} className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
                <Icon className="h-8 w-8 text-indigo-600" />
                <h3 className="mt-4 text-lg font-semibold">{title}</h3>
                <p className="mt-2 text-sm text-slate-600">{body}</p>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-200 bg-white py-6 text-center text-sm text-slate-500">
        Part of the SIN ecosystem
      </footer>
    </div>
  )
}
