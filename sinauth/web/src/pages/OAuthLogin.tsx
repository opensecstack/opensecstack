import { useState, useRef } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import axios from 'axios'

// ── Brand ────────────────────────────────────────────────────────────────────
const BRAND = '#6366f1'
const BRAND_DARK = '#1a2d7a'

// ── Floating-label input ─────────────────────────────────────────────────────
function FloatInput({
  label, type = 'text', name, value, onChange, required,
  autoFocus, autoComplete,
}: {
  label: string; type?: string; name: string; value: string
  onChange: (v: string) => void; required?: boolean
  autoFocus?: boolean; autoComplete?: string
}) {
  const [focused, setFocused] = useState(false)
  const [show, setShow] = useState(false)
  const lifted = focused || value.length > 0
  const isPassword = type === 'password'

  return (
    <div style={{ position: 'relative', marginBottom: 0 }}>
      <label style={{
        position: 'absolute', left: 14, top: lifted ? 6 : 16,
        fontSize: lifted ? 11 : 15, color: focused ? BRAND : '#9ca3af',
        transition: 'all 0.15s', pointerEvents: 'none', fontWeight: lifted ? 500 : 400,
      }}>
        {label}
      </label>
      <input
        name={name} value={value} required={required} autoFocus={autoFocus}
        autoComplete={autoComplete}
        type={isPassword ? (show ? 'text' : 'password') : type}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onChange={e => onChange(e.target.value)}
        style={{
          width: '100%', boxSizing: 'border-box',
          border: 'none',
          borderRadius: 8, padding: '22px 44px 8px 14px',
          fontSize: 15, outline: 'none', background: '#f3f4f6',
        }}
      />
      {isPassword && (
        <button type="button" onClick={() => setShow(s => !s)}
          style={{
            position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
            background: 'none', border: 'none', cursor: 'pointer', color: '#9ca3af',
            display: 'flex', alignItems: 'center',
          }}>
          {show
            ? <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            : <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          }
        </button>
      )}
    </div>
  )
}

// ── Google SVG ───────────────────────────────────────────────────────────────
function GoogleIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 48 48">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
    </svg>
  )
}

// ── GitHub SVG ───────────────────────────────────────────────────────────────
function GitHubIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  )
}

// ── Main component ────────────────────────────────────────────────────────────
export default function OAuthLogin() {
  const [params] = useSearchParams()
  const [view, setView] = useState<'signin' | 'register'>(
    params.get('view') === 'register' ? 'register' : 'signin'
  )

  const apiBase = import.meta.env.VITE_API_BASE ?? ''

  // Gjirafa-style returnUrl: /oauth/authorize?client_id=...&scope=...&...
  const returnUrl = params.get('returnUrl') ?? ''
  let formAction: string
  let oauthParams: Record<string, string>

  if (returnUrl) {
    // All OAuth params are already encoded in returnUrl — just forward to API
    formAction = `${apiBase}${returnUrl}`
    const inner = new URLSearchParams(returnUrl.split('?')[1] ?? '')
    oauthParams = {
      client_id:             inner.get('client_id') ?? '',
      redirect_uri:          inner.get('redirect_uri') ?? '',
      scope:                 inner.get('scope') ?? '',
      state:                 inner.get('state') ?? '',
      code_challenge:        inner.get('code_challenge') ?? '',
      code_challenge_method: inner.get('code_challenge_method') ?? 'S256',
      nonce:                 inner.get('nonce') ?? '',
      response_type:         'code',
    }
  } else {
    // Legacy: individual params in the URL
    formAction = `${apiBase}/oauth/authorize`
    oauthParams = {
      client_id:             params.get('client_id') ?? '',
      redirect_uri:          params.get('redirect_uri') ?? '',
      scope:                 params.get('scope') ?? '',
      state:                 params.get('state') ?? '',
      code_challenge:        params.get('code_challenge') ?? '',
      code_challenge_method: params.get('code_challenge_method') ?? 'S256',
      nonce:                 params.get('nonce') ?? '',
      response_type:         'code',
    }
  }

  // oauth_return for social buttons — lets backend complete the OAuth flow after social auth
  const oauthReturn = encodeURIComponent(btoa(JSON.stringify(oauthParams)))

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'white' }}>
      {/* header */}
      <div style={{ padding: '32px 0 0', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 8 }}>
          <svg width="56" height="56" viewBox="0 0 52 52" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="26" cy="16" r="9" fill="#0ea5e9"/>
            <circle cx="34.7" cy="31" r="9" fill={BRAND}/>
            <circle cx="17.3" cy="31" r="9" fill={BRAND}/>
            <circle cx="26" cy="26" r="6.5" fill="white"/>
            <circle cx="26" cy="16" r="3" fill="white"/>
            <circle cx="34.7" cy="31" r="3" fill="white"/>
            <circle cx="17.3" cy="31" r="3" fill="white"/>
          </svg>
        </div>
        <div style={{ fontSize: 22, fontWeight: 800, color: BRAND_DARK, letterSpacing: -0.5 }}>
          sin<span style={{ color: BRAND }}>auth</span>
        </div>
      </div>

      {/* card */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: '24px 32px' }}>
        <div style={{ width: '100%' }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: '#111827', textAlign: 'center', marginBottom: 24 }}>
            {view === 'signin' ? 'Sign in to your account' : 'Create your account'}
          </h1>

          {/* Social buttons */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 24 }}>
            <a href={`${apiBase}/api/v1/auth/google?oauth_return=${oauthReturn}`}
              style={{ textDecoration: 'none' }}>
              <button type="button" style={{
                width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12,
                background: '#f3f4f6', border: 'none', borderRadius: 8,
                padding: '12px 16px', fontSize: 15, fontWeight: 500, color: '#374151', cursor: 'pointer',
              }}>
                <GoogleIcon /> Sign in with Google
              </button>
            </a>
            <a href={`${apiBase}/api/v1/auth/github?oauth_return=${oauthReturn}`}
              style={{ textDecoration: 'none' }}>
              <button type="button" style={{
                width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12,
                background: '#f3f4f6', border: 'none', borderRadius: 8,
                padding: '12px 16px', fontSize: 15, fontWeight: 500, color: '#374151', cursor: 'pointer',
              }}>
                <GitHubIcon /> Sign in with GitHub
              </button>
            </a>
          </div>

          {/* Or divider */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
            <div style={{ flex: 1, height: 1, background: '#e5e7eb' }} />
            <span style={{ color: '#9ca3af', fontSize: 14 }}>Or</span>
            <div style={{ flex: 1, height: 1, background: '#e5e7eb' }} />
          </div>

          {view === 'signin'
            ? <SignInForm formAction={formAction} oauthParams={returnUrl ? {} : oauthParams} onRegister={() => setView('register')} />
            : <RegisterForm formAction={formAction} oauthParams={returnUrl ? {} : oauthParams} onSignIn={() => setView('signin')} />
          }
        </div>
      </div>

      {/* footer */}
      <div style={{ padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #f3f4f6' }}>
        <span style={{ fontSize: 13, color: '#6b7280' }}>English</span>
        <div style={{ display: 'flex', gap: 20 }}>
          <a href="#" style={{ fontSize: 13, color: '#6b7280', textDecoration: 'none' }}>Terms & Conditions</a>
          <a href="#" style={{ fontSize: 13, color: '#6b7280', textDecoration: 'none' }}>Privacy</a>
        </div>
      </div>
    </div>
  )
}

// ── Sign In form (POSTs directly to /oauth/authorize) ────────────────────────
function SignInForm({ formAction, oauthParams, onRegister }: {
  formAction: string
  oauthParams: Record<string, string>
  onRegister: () => void
}) {
  const formRef = useRef<HTMLFormElement>(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password) return
    setLoading(true)
    setError('')
    // Direct form POST — server will redirect on success/failure
    formRef.current?.submit()
  }

  return (
    <form ref={formRef} action={formAction} method="POST"
      onSubmit={handleSubmit}
      style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Hidden OAuth params */}
      {Object.entries(oauthParams).map(([k, v]) => v
        ? <input key={k} type="hidden" name={k} value={v} />
        : null
      )}

      <FloatInput label="Email address" name="username" value={username}
        onChange={setUsername} required autoFocus autoComplete="username" />
      <FloatInput label="Password" type="password" name="password" value={password}
        onChange={setPassword} required autoComplete="current-password" />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4 }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, color: '#374151', cursor: 'pointer' }}>
          <input type="checkbox" name="keep_me_logged_in" style={{ accentColor: BRAND }} />
          Keep me logged in
        </label>
        <Link to="/reset-password" style={{ fontSize: 14, color: BRAND, textDecoration: 'none', fontWeight: 500 }}>
          Forgot password?
        </Link>
      </div>

      {error && <p style={{ color: '#dc2626', fontSize: 14, margin: 0 }}>{error}</p>}

      <button type="submit" disabled={loading} style={{
        width: '100%', background: loading ? '#93a4e4' : BRAND, color: 'white',
        border: 'none', borderRadius: 8, padding: '14px 16px',
        fontSize: 16, fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer', marginTop: 8,
      }}>
        {loading ? 'Signing in…' : 'Sign In'}
      </button>

      <p style={{ textAlign: 'center', fontSize: 14, color: '#6b7280', margin: '8px 0 0' }}>
        Don't have an account?{' '}
        <button type="button" onClick={onRegister}
          style={{ background: 'none', border: 'none', color: BRAND, fontWeight: 600, cursor: 'pointer', fontSize: 14, padding: 0 }}>
          Register
        </button>
      </p>
    </form>
  )
}

// ── Register form ────────────────────────────────────────────────────────────
function RegisterForm({ formAction, oauthParams, onSignIn }: {
  formAction: string
  oauthParams: Record<string, string>
  onSignIn: () => void
}) {
  const loginFormRef = useRef<HTMLFormElement>(null)
  const [form, setForm] = useState({ firstName: '', lastName: '', email: '', password: '' })
  const [terms, setTerms] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)

  // After register succeeds, auto-submit the OAuth login form
  const [autoCredentials, setAutoCredentials] = useState({ username: '', password: '' })

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!terms) { setError('Please accept the Terms & Conditions to continue.'); return }
    setLoading(true)
    setError('')
    try {
      const apiOrigin = new URL(formAction).origin
      await axios.post(`${apiOrigin}/api/v1/auth/register`, {
        username: form.email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '_'),
        email: form.email,
        password: form.password,
        display_name: `${form.firstName} ${form.lastName}`.trim(),
      })
      setAutoCredentials({ username: form.email, password: form.password })
      setDone(true)
      // Auto-submit login after brief pause
      setTimeout(() => loginFormRef.current?.submit(), 400)
    } catch (err: unknown) {
      const e = err as { response?: { data?: { error?: string } } }
      setError(e.response?.data?.error ?? 'Registration failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const set = (k: keyof typeof form) => (v: string) => setForm(f => ({ ...f, [k]: v }))

  return (
    <>
      {/* Hidden form for auto-login after register */}
      <form ref={loginFormRef} action={formAction} method="POST" style={{ display: 'none' }}>
        {Object.entries(oauthParams).map(([k, v]) => v
          ? <input key={k} type="hidden" name={k} value={v} />
          : null
        )}
        <input type="hidden" name="username" value={autoCredentials.username} />
        <input type="hidden" name="password" value={autoCredentials.password} />
      </form>

      <form onSubmit={handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <FloatInput label="First Name" name="firstName" value={form.firstName}
          onChange={set('firstName')} required autoFocus />
        <FloatInput label="Last Name" name="lastName" value={form.lastName}
          onChange={set('lastName')} required />
        <FloatInput label="Email" type="email" name="email" value={form.email}
          onChange={set('email')} required autoComplete="email" />
        <FloatInput label="Password" type="password" name="password" value={form.password}
          onChange={set('password')} required autoComplete="new-password" />

        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 13, color: '#374151', cursor: 'pointer', marginTop: 4 }}>
          <input type="checkbox" checked={terms} onChange={e => setTerms(e.target.checked)}
            style={{ accentColor: BRAND, marginTop: 2, flexShrink: 0 }} />
          <span>
            By registering an account, you agree to our{' '}
            <a href="#" style={{ color: BRAND, textDecoration: 'none', fontWeight: 500 }}>Terms & Conditions</a>
            {' '}and{' '}
            <a href="#" style={{ color: BRAND, textDecoration: 'none', fontWeight: 500 }}>Privacy</a>{' '}
            <span style={{ color: '#dc2626' }}>*</span>
          </span>
        </label>

        {error && <p style={{ color: '#dc2626', fontSize: 14, margin: 0 }}>{error}</p>}
        {done && <p style={{ color: '#16a34a', fontSize: 14, margin: 0 }}>Account created! Signing you in…</p>}

        <button type="submit" disabled={loading || done} style={{
          width: '100%', background: loading || done ? '#93a4e4' : BRAND, color: 'white',
          border: 'none', borderRadius: 8, padding: '14px 16px',
          fontSize: 16, fontWeight: 600, cursor: loading || done ? 'not-allowed' : 'pointer', marginTop: 8,
        }}>
          {loading ? 'Creating account…' : done ? 'Signing in…' : 'Continue'}
        </button>

        <p style={{ textAlign: 'center', fontSize: 14, color: '#6b7280', margin: '8px 0 0' }}>
          Already have an account?{' '}
          <button type="button" onClick={onSignIn}
            style={{ background: 'none', border: 'none', color: BRAND, fontWeight: 600, cursor: 'pointer', fontSize: 14, padding: 0 }}>
            Sign In
          </button>
        </p>
      </form>
    </>
  )
}
