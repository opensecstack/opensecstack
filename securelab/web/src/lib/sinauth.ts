const SINAUTH_URL      = import.meta.env.VITE_SINAUTH_URL      ?? 'http://localhost:8100'
const SINAUTH_SITE_URL = import.meta.env.VITE_SINAUTH_SITE_URL ?? 'http://localhost:5173'
const CLIENT_ID        = import.meta.env.VITE_SINAUTH_CLIENT_ID ?? 'securelab'

const VERIFIER_KEY = 'sinauth_verifier'
const STATE_KEY    = 'sinauth_state'
const MSG_TYPE     = 'sinauth_callback'

function b64url(buf: Uint8Array): string {
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

async function pkceVerifier(): Promise<string> {
  return b64url(crypto.getRandomValues(new Uint8Array(32)))
}

async function pkceChallenge(verifier: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return b64url(new Uint8Array(hash))
}

export interface SinauthTokens {
  access_token:  string
  refresh_token: string
  expires_in:    number
}

export function decodeJWT(token: string): Record<string, unknown> {
  try {
    return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
  } catch { return {} }
}

export async function loginWithPopup(): Promise<SinauthTokens> {
  const redirectUri = `${window.location.origin}/auth/callback`
  const verifier    = await pkceVerifier()
  const challenge   = await pkceChallenge(verifier)
  const state       = b64url(crypto.getRandomValues(new Uint8Array(16)))

  sessionStorage.setItem(VERIFIER_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)

  const authorizeParams = new URLSearchParams({
    response_type:         'code',
    client_id:             CLIENT_ID,
    redirect_uri:          redirectUri,
    scope:                 'openid profile email',
    state,
    code_challenge:        challenge,
    code_challenge_method: 'S256',
  })

  const w = 480, h = 640
  const left = Math.round(window.screenX + (window.outerWidth  - w) / 2)
  const top  = Math.round(window.screenY + (window.outerHeight - h) / 2)
  const popup = window.open(
    `${SINAUTH_SITE_URL}/oauth/login?returnUrl=${encodeURIComponent(`/oauth/authorize?${authorizeParams}`)}`,
    'sinauth_popup',
    `width=${w},height=${h},left=${left},top=${top},toolbar=0,scrollbars=1,status=0,menubar=0`,
  )
  if (!popup) throw new Error('Popup blocked. Please allow popups for this site.')

  return new Promise<SinauthTokens>((resolve, reject) => {
    let done = false
    const finish = (fn: () => void) => { if (done) return; done = true; clearTimeout(timeout); clearInterval(poll); window.removeEventListener('message', handler); fn() }
    const timeout = setTimeout(() => finish(() => reject(new Error('Login timed out'))), 300_000)

    const handler = async (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return
      if (!event.data || event.data.type !== MSG_TYPE) return
      finish(async () => {
        if (event.data.error) { reject(new Error(event.data.error)); return }
        if (event.data.state !== sessionStorage.getItem(STATE_KEY)) { reject(new Error('State mismatch')); return }
        const verifier = sessionStorage.getItem(VERIFIER_KEY) ?? ''
        sessionStorage.removeItem(VERIFIER_KEY); sessionStorage.removeItem(STATE_KEY)
        try {
          const res = await fetch(`${SINAUTH_URL}/oauth/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ grant_type: 'authorization_code', code: event.data.code, redirect_uri: redirectUri, client_id: CLIENT_ID, code_verifier: verifier }),
          })
          if (!res.ok) throw new Error('Token exchange failed')
          resolve(await res.json() as SinauthTokens)
        } catch (err) { reject(err) }
      })
    }
    window.addEventListener('message', handler)
    const poll = setInterval(() => { if (popup.closed) finish(() => reject(new Error('Popup closed'))) }, 500)
  })
}
