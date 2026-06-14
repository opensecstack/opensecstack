import type { SinauthClient } from './client.js'
import type { TokenResponse } from './types.js'
import { generatePKCE, buildAuthURL } from './pkce.js'

export interface PopupLoginOptions {
  clientId: string
  redirectUri: string
  scopes?: string[]
  /** Popup window dimensions. Defaults to 480×640. */
  width?: number
  height?: number
}

const POPUP_KEY_VERIFIER = 'sinauth_popup_verifier'
const POPUP_KEY_STATE    = 'sinauth_popup_state'
const MESSAGE_TYPE       = 'sinauth_callback'

function openPopup(url: string, w: number, h: number): Window {
  const left = Math.round(window.screenX + (window.outerWidth - w) / 2)
  const top  = Math.round(window.screenY + (window.outerHeight - h) / 2)
  const popup = window.open(url, 'sinauth_popup',
    `width=${w},height=${h},left=${left},top=${top},toolbar=0,scrollbars=1,status=0,menubar=0`)
  if (!popup) throw new Error('sinauth: popup blocked by browser')
  return popup
}

/**
 * Opens a sinauth login popup and returns tokens after the user authenticates.
 *
 * Usage:
 * ```ts
 * const tokens = await loginWithPopup(client, {
 *   clientId: 'my-app',
 *   redirectUri: 'https://myapp.example.com/auth/callback',
 *   scopes: ['openid', 'profile', 'email'],
 * })
 * ```
 *
 * The redirect_uri page must call `handlePopupCallback()` on load.
 */
export async function loginWithPopup(
  client: SinauthClient,
  options: PopupLoginOptions,
): Promise<TokenResponse> {
  const { clientId, redirectUri, scopes = ['openid', 'profile', 'email'] } = options
  const w = options.width  ?? 480
  const h = options.height ?? 640

  const pkce = await generatePKCE()
  sessionStorage.setItem(POPUP_KEY_VERIFIER, pkce.codeVerifier)
  sessionStorage.setItem(POPUP_KEY_STATE, pkce.state)

  const discovery = await client.getDiscovery()
  const authURL = buildAuthURL({
    authorizationEndpoint: discovery.authorization_endpoint,
    clientID: clientId,
    redirectURI: redirectUri,
    scopes,
    state:         pkce.state,
    codeChallenge: pkce.codeChallenge,
  })

  const popup = openPopup(authURL, w, h)

  return new Promise<TokenResponse>((resolve, reject) => {
    const timeout = setTimeout(() => {
      window.removeEventListener('message', handler)
      reject(new Error('sinauth: popup login timed out'))
    }, 300_000)

    const handler = async (event: MessageEvent) => {
      // Accept messages only from the redirect_uri origin.
      const expectedOrigin = new URL(redirectUri).origin
      if (event.origin !== expectedOrigin) return
      if (!event.data || event.data.type !== MESSAGE_TYPE) return

      clearTimeout(timeout)
      window.removeEventListener('message', handler)

      if (event.data.error) {
        reject(new Error(`sinauth: ${event.data.error}`))
        return
      }

      const savedState = sessionStorage.getItem(POPUP_KEY_STATE)
      if (event.data.state !== savedState) {
        reject(new Error('sinauth: state mismatch — possible CSRF'))
        return
      }

      const verifier = sessionStorage.getItem(POPUP_KEY_VERIFIER) ?? ''
      sessionStorage.removeItem(POPUP_KEY_VERIFIER)
      sessionStorage.removeItem(POPUP_KEY_STATE)

      try {
        const tokens = await client.exchangeCode({
          code:         event.data.code,
          redirectUri,
          clientID:     clientId,
          codeVerifier: verifier,
        })
        resolve(tokens)
      } catch (err) {
        reject(err)
      }
    }

    window.addEventListener('message', handler)

    // Poll for popup being closed by user.
    const pollClosed = setInterval(() => {
      if (popup.closed) {
        clearInterval(pollClosed)
        clearTimeout(timeout)
        window.removeEventListener('message', handler)
        reject(new Error('sinauth: popup closed by user'))
      }
    }, 500)
  })
}

/**
 * Call this on the redirect_uri callback page.
 * It reads `code` + `state` from the URL and sends them to the opener via postMessage,
 * then closes the popup.
 *
 * Usage (in your callback route component or page):
 * ```ts
 * import { handlePopupCallback } from '@opensecstack/sinauth'
 * handlePopupCallback()
 * ```
 */
export function handlePopupCallback(): void {
  const params = new URLSearchParams(window.location.search)
  const code  = params.get('code')
  const state = params.get('state')
  const error = params.get('error')

  if (!window.opener) return

  window.opener.postMessage(
    error
      ? { type: MESSAGE_TYPE, error }
      : { type: MESSAGE_TYPE, code, state },
    window.location.origin,
  )
  window.close()
}
