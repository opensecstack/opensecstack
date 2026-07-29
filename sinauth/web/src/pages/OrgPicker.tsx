import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { listMyOrganizations, type OrganizationMembership } from '@/api/organizations'

// ── Brand (matches OAuthLogin.tsx) ─────────────────────────────────────────
const BRAND = '#6366f1'
const BRAND_DARK = '#1a2d7a'

const ORG_TYPE_LABEL: Record<OrganizationMembership['org_type'], string> = {
  government: 'Government',
  private: 'Private',
  ecommerce: 'E-commerce',
  ngo: 'NGO',
}

// ── Org-picker step ──────────────────────────────────────────────────────────
// Mirrors OAuthLogin.tsx's routing/submission pattern exactly: sinauth's
// /oauth/authorize redirects here (302) — with the *same* query-string
// convention it uses for /oauth/login (returnUrl-wrapped or legacy raw
// params) — whenever the authenticated user belongs to 2+ organizations
// and the request didn't already pin one down via `organization_id`.
//
// This page re-submits the original /oauth/authorize request as a real
// browser form POST (not an AJAX call) so the server's eventual redirect
// to redirect_uri actually navigates the browser, exactly like the sign-in
// form in OAuthLogin.tsx does. The user is already authenticated at this
// point (session cookie from the prior /oauth/authorize submission), so no
// credentials are re-collected here — only `organization_id` is added.
export default function OrgPicker() {
  const [params] = useSearchParams()
  const [orgs, setOrgs] = useState<OrganizationMembership[] | null>(null)
  const [loadError, setLoadError] = useState('')
  const [submitting, setSubmitting] = useState<string | null>(null)
  const formRef = useRef<HTMLFormElement>(null)
  const orgIdInputRef = useRef<HTMLInputElement>(null)

  const apiBase = import.meta.env.VITE_API_BASE ?? ''

  // Same returnUrl vs legacy-params handling as OAuthLogin.tsx.
  const returnUrl = params.get('returnUrl') ?? ''
  let formAction: string
  let oauthParams: Record<string, string>

  if (returnUrl) {
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

  useEffect(() => {
    let cancelled = false
    listMyOrganizations()
      .then(data => { if (!cancelled) setOrgs(data) })
      .catch(() => { if (!cancelled) setLoadError('Could not load your organizations. Please try again.') })
    return () => { cancelled = true }
  }, [])

  const choose = (orgId: string) => {
    if (submitting) return
    setSubmitting(orgId)
    // Set the hidden field directly on the DOM node before submitting —
    // setSubmitting() above won't have re-rendered yet, so the React-bound
    // `value` prop would still reflect the previous (empty) state.
    if (orgIdInputRef.current) orgIdInputRef.current.value = orgId
    // Real form POST (not fetch/axios) — mirrors SignInForm in OAuthLogin.tsx
    // so the server's redirect response actually navigates the browser.
    formRef.current?.submit()
  }

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
        <div style={{ width: '100%', maxWidth: 420 }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: '#111827', textAlign: 'center', marginBottom: 4 }}>
            Choose an organization
          </h1>
          <p style={{ fontSize: 14, color: '#6b7280', textAlign: 'center', margin: '0 0 24px' }}>
            You belong to more than one organization. Pick the one to continue as.
          </p>

          {/* Hidden form re-submitted on selection — same mechanism as
              OAuthLogin.tsx's SignInForm (direct browser POST). */}
          <form ref={formRef} action={formAction} method="POST" style={{ display: 'none' }}>
            {Object.entries(oauthParams).map(([k, v]) => v
              ? <input key={k} type="hidden" name={k} value={v} />
              : null
            )}
            <input ref={orgIdInputRef} type="hidden" name="organization_id" defaultValue="" />
          </form>

          {orgs === null && !loadError && (
            <p style={{ textAlign: 'center', color: '#9ca3af', fontSize: 14 }}>Loading your organizations…</p>
          )}

          {loadError && (
            <p style={{ textAlign: 'center', color: '#dc2626', fontSize: 14 }}>{loadError}</p>
          )}

          {orgs !== null && !loadError && orgs.length === 0 && (
            <p style={{ textAlign: 'center', color: '#6b7280', fontSize: 14 }}>
              No organizations are associated with your account. Contact your administrator if you
              believe this is a mistake.
            </p>
          )}

          {orgs !== null && orgs.length > 0 && (
            <div role="list" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {orgs.map(org => (
                <button
                  key={org.organization_id}
                  role="listitem"
                  type="button"
                  onClick={() => choose(org.organization_id)}
                  disabled={submitting !== null}
                  aria-label={`Continue as ${org.legal_name}`}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
                    width: '100%', textAlign: 'left',
                    background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 8,
                    padding: '14px 16px', cursor: submitting !== null ? 'not-allowed' : 'pointer',
                    opacity: submitting !== null && submitting !== org.organization_id ? 0.5 : 1,
                  }}
                >
                  <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <span style={{ fontSize: 15, fontWeight: 600, color: '#111827' }}>{org.legal_name}</span>
                    <span style={{ fontSize: 13, color: '#6b7280' }}>{org.slug}</span>
                  </span>
                  <span style={{
                    fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5,
                    color: BRAND, background: '#eef2ff', borderRadius: 12, padding: '3px 8px', flexShrink: 0,
                  }}>
                    {ORG_TYPE_LABEL[org.org_type] ?? org.org_type}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* footer */}
      <div style={{ padding: '16px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #f3f4f6' }}>
        <span style={{ fontSize: 13, color: '#6b7280' }}>English</span>
      </div>
    </div>
  )
}
