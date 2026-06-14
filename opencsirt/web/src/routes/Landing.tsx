import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldAlert, Share2, FileWarning, Users } from 'lucide-react'
import { loginWithPopup } from '@/lib/sinauth'
import { useAuth } from '@/state/auth'

const FEATURES = [
  {
    icon: Share2,
    title: 'TAXII 2.1 threat-intel exchange',
    body: 'Publish and consume structured threat intelligence over standards-based TAXII 2.1 collections with your trusted partners.',
  },
  {
    icon: FileWarning,
    title: 'CSAF 2.0 security advisories',
    body: 'Author, track and distribute machine-readable security advisories in the CSAF 2.0 format for rapid, consistent disclosure.',
  },
  {
    icon: Users,
    title: 'Coordinated incident response',
    body: 'Coordinate incidents across constituencies and peer CSIRTs, backed by a peer-trust registry for verified collaboration.',
  },
]

export default function Landing(): JSX.Element {
  const navigate = useNavigate()
  const isAuthenticated = useAuth((s) => s.isAuthenticated)
  const setToken = useAuth((s) => s.setToken)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (isAuthenticated()) navigate('/incidents', { replace: true })
  }, [isAuthenticated, navigate])

  async function handleLogin(): Promise<void> {
    setPending(true)
    setError(null)
    try {
      const tokens = await loginWithPopup()
      setToken(tokens.access_token)
      navigate('/incidents', { replace: true })
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
            <ShieldAlert className="h-6 w-6 text-indigo-600" />
            <span className="text-lg font-semibold">OpenCSIRT</span>
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
          <h1 className="text-4xl font-bold tracking-tight sm:text-6xl">OpenCSIRT</h1>
          <p className="mt-4 text-xl font-medium text-indigo-600 sm:text-2xl">CSIRT Operations</p>
          <p className="mx-auto mt-6 max-w-2xl text-base text-slate-600 sm:text-lg">
            OpenCSIRT is the operations hub for computer security incident response teams. Exchange threat
            intelligence, publish advisories and coordinate incidents with peers — all from one trusted platform.
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
