const POPUP_KEY_VERIFIER = 'sinauth_popup_verifier'
const POPUP_KEY_STATE    = 'sinauth_popup_state'
const MESSAGE_TYPE       = 'sinauth_callback'

function base64url(buf: Uint8Array): string {
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

async function generateVerifier(): Promise<string> {
  const arr = new Uint8Array(32)
  crypto.getRandomValues(arr)
  return base64url(arr)
}

async function generateChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return base64url(new Uint8Array(hash))
}

function generateState(): string {
  const arr = new Uint8Array(16)
  crypto.getRandomValues(arr)
  return base64url(arr)
}

export interface PopupUser {
  username: string
  email: string
  display_name?: string
}

export async function loginWithPopup(
  sinauthURL: string,
  clientId: string,
  siteURL?: string,
): Promise<PopupUser> {
  const redirectUri = `${window.location.origin}/auth/callback`
  const verifier    = await generateVerifier()
  const challenge   = await generateChallenge(verifier)
  const state       = generateState()

  sessionStorage.setItem(POPUP_KEY_VERIFIER, verifier)
  sessionStorage.setItem(POPUP_KEY_STATE, state)

  const authorizeParams = new URLSearchParams({
    response_type: 'code', client_id: clientId,
    redirect_uri: redirectUri, scope: 'openid profile email',
    state, code_challenge: challenge, code_challenge_method: 'S256',
  })
  const returnUrl  = `/oauth/authorize?${authorizeParams}`
  const popupBase  = siteURL ?? sinauthURL
  const popupURL   = `${popupBase}/oauth/login?returnUrl=${encodeURIComponent(returnUrl)}`

  const w = 480, h = 640
  const left = Math.round(window.screenX + (window.outerWidth  - w) / 2)
  const top  = Math.round(window.screenY + (window.outerHeight - h) / 2)
  const popup = window.open(popupURL, 'sinauth_popup',
    `width=${w},height=${h},left=${left},top=${top},toolbar=0,scrollbars=1,status=0,menubar=0`)
  if (!popup) throw new Error('Popup was blocked by the browser')

  return new Promise<PopupUser>((resolve, reject) => {
    const timeout = setTimeout(() => {
      window.removeEventListener('message', handler)
      reject(new Error('Login timed out'))
    }, 300_000)

    const handler = async (event: MessageEvent) => {
      if (event.origin !== new URL(redirectUri).origin) return
      if (!event.data || event.data.type !== MESSAGE_TYPE) return
      clearTimeout(timeout)
      window.removeEventListener('message', handler)
      if (event.data.error) { reject(new Error(event.data.error)); return }
      const savedState = sessionStorage.getItem(POPUP_KEY_STATE)
      if (event.data.state !== savedState) { reject(new Error('State mismatch')); return }
      const savedVerifier = sessionStorage.getItem(POPUP_KEY_VERIFIER) ?? ''
      sessionStorage.removeItem(POPUP_KEY_VERIFIER)
      sessionStorage.removeItem(POPUP_KEY_STATE)
      try {
        const res = await fetch(`${sinauthURL}/oauth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code', code: event.data.code,
            redirect_uri: redirectUri, client_id: clientId, code_verifier: savedVerifier,
          }),
        })
        if (!res.ok) throw new Error('Token exchange failed')
        const tokens = await res.json()
        const userRes = await fetch(`${sinauthURL}/oauth/userinfo`, {
          headers: { Authorization: `Bearer ${tokens.access_token}` },
        })
        if (!userRes.ok) throw new Error('Failed to fetch user info')
        resolve(await userRes.json())
      } catch (err) { reject(err) }
    }

    window.addEventListener('message', handler)
    const poll = setInterval(() => {
      if (popup.closed) {
        clearInterval(poll); clearTimeout(timeout)
        window.removeEventListener('message', handler)
        reject(new Error('Popup closed'))
      }
    }, 500)
  })
}
