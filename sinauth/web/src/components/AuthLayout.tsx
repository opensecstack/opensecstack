import { useState } from 'react'

const BRAND = '#6366f1'


// ── Full-width flat shell (matches OAuthLogin popup) ─────────────────────────
export function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'white', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      {/* Header */}
      <div style={{ padding: '32px 0 0', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 8 }}>
          <svg width="56" height="56" viewBox="0 0 52 52" fill="none">
            <circle cx="26" cy="16" r="9" fill="#0ea5e9"/>
            <circle cx="34.7" cy="31" r="9" fill="#6366f1"/>
            <circle cx="17.3" cy="31" r="9" fill="#6366f1"/>
            <circle cx="26" cy="26" r="6.5" fill="white"/>
            <circle cx="26" cy="16" r="3" fill="white"/>
            <circle cx="34.7" cy="31" r="3" fill="white"/>
            <circle cx="17.3" cy="31" r="3" fill="white"/>
          </svg>
        </div>
        <div style={{ fontSize: 22, fontWeight: 800, color: '#1a2d7a', letterSpacing: -0.5 }}>
          sin<span style={{ color: '#6366f1' }}>auth</span>
        </div>
      </div>

      {/* Content */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: '24px 32px' }}>
        <div style={{ width: '100%' }}>
          {children}
        </div>
      </div>
    </div>
  )
}

// ── Floating-label input ──────────────────────────────────────────────────────
export function FloatInput({
  label, type = 'text', name, value, onChange, required,
  autoFocus, autoComplete, minLength,
}: {
  label: string; type?: string; name?: string; value: string
  onChange: (v: string) => void; required?: boolean
  autoFocus?: boolean; autoComplete?: string; minLength?: number
}) {
  const [focused, setFocused] = useState(false)
  const [show, setShow] = useState(false)
  const lifted = focused || value.length > 0
  const isPassword = type === 'password'

  return (
    <div style={{ position: 'relative' }}>
      <label style={{
        position: 'absolute', left: 14, top: lifted ? 7 : 17,
        fontSize: lifted ? 11 : 15, color: focused ? BRAND : '#9ca3af',
        transition: 'all 0.15s', pointerEvents: 'none', fontWeight: lifted ? 600 : 400,
      }}>
        {label}
      </label>
      <input
        name={name} value={value} required={required} autoFocus={autoFocus}
        autoComplete={autoComplete} minLength={minLength}
        type={isPassword ? (show ? 'text' : 'password') : type}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        onChange={e => onChange(e.target.value)}
        style={{
          width: '100%', boxSizing: 'border-box',
          border: 'none',
          borderRadius: 10, padding: '22px 44px 8px 14px',
          fontSize: 15, outline: 'none',
          background: '#f0f0f3',
          transition: 'background 0.15s',
        }}
      />
      {isPassword && (
        <button type="button" tabIndex={-1} onClick={() => setShow(s => !s)}
          style={{ position: 'absolute', right: 13, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#9ca3af', display: 'flex', alignItems: 'center', padding: 4 }}>
          {show
            ? <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            : <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          }
        </button>
      )}
    </div>
  )
}

// ── Social buttons ────────────────────────────────────────────────────────────
export function SocialButtons({ apiBase, suffix = '' }: { apiBase: string; suffix?: string }) {
  const s: React.CSSProperties = {
    width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
    background: '#f0f0f3', border: 'none', borderRadius: 10,
    padding: '11px 16px', fontSize: 14, fontWeight: 600, color: '#374151', cursor: 'pointer',
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <a href={`${apiBase}/api/v1/auth/google${suffix}`} style={{ textDecoration: 'none' }}>
        <button type="button" style={s}>
          <svg width="18" height="18" viewBox="0 0 48 48">
            <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
            <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
            <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
            <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
          </svg>
          Continue with Google
        </button>
      </a>
      <a href={`${apiBase}/api/v1/auth/github${suffix}`} style={{ textDecoration: 'none' }}>
        <button type="button" style={s}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
          </svg>
          Continue with GitHub
        </button>
      </a>
    </div>
  )
}

// ── Or divider ────────────────────────────────────────────────────────────────
export function OrDivider({ label = 'or continue with email' }: { label?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, margin: '20px 0' }}>
      <div style={{ flex: 1, height: 1, background: '#e5e7eb' }} />
      <span style={{ fontSize: 12, color: '#9ca3af', fontWeight: 500, whiteSpace: 'nowrap' }}>{label}</span>
      <div style={{ flex: 1, height: 1, background: '#e5e7eb' }} />
    </div>
  )
}

// ── Primary button ────────────────────────────────────────────────────────────
export function PrimaryBtn({ children, loading, disabled, onClick, type = 'submit' }: {
  children: React.ReactNode; loading?: boolean; disabled?: boolean
  onClick?: () => void; type?: 'submit' | 'button'
}) {
  return (
    <button type={type} disabled={loading || disabled} onClick={onClick} style={{
      width: '100%', background: loading || disabled ? '#a5b4fc' : BRAND, color: 'white',
      border: 'none', borderRadius: 10, padding: '14px 16px',
      fontSize: 15, fontWeight: 700, cursor: loading || disabled ? 'not-allowed' : 'pointer',
      letterSpacing: 0.1, transition: 'background 0.15s',
    }}>
      {children}
    </button>
  )
}

// ── Error message ─────────────────────────────────────────────────────────────
export function ErrorMsg({ msg }: { msg: string }) {
  if (!msg) return null
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 8, padding: '10px 12px' }}>
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ flexShrink: 0, marginTop: 1 }}>
        <circle cx="8" cy="8" r="7" stroke="#dc2626" strokeWidth="1.5"/>
        <path d="M8 4.5v4M8 10.5v.5" stroke="#dc2626" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
      <span style={{ fontSize: 13, color: '#dc2626', lineHeight: 1.4 }}>{msg}</span>
    </div>
  )
}

// ── Success message ───────────────────────────────────────────────────────────
export function SuccessMsg({ msg }: { msg: string }) {
  if (!msg) return null
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: '10px 12px' }}>
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ flexShrink: 0, marginTop: 1 }}>
        <circle cx="8" cy="8" r="7" stroke="#16a34a" strokeWidth="1.5"/>
        <path d="M5 8l2.5 2.5L11 5.5" stroke="#16a34a" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
      <span style={{ fontSize: 13, color: '#16a34a', lineHeight: 1.4 }}>{msg}</span>
    </div>
  )
}
