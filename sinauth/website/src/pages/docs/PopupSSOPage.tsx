import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const installCode = `npm install @opensecstack/sinauth`

const basicPopupCode = `import { SinauthClient, loginWithPopup } from '@opensecstack/sinauth'

const client = new SinauthClient({
  baseUrl:  'https://auth.example.com',
  clientId: 'my-spa',
})

async function handleLogin() {
  const tokens = await loginWithPopup(client, {
    redirectUri: 'https://app.example.com/auth/callback',
    scope: 'openid profile email',
  })

  // Access token is a short-lived RS256 JWT
  console.log(tokens.accessToken)
}`

const reactHookCode = `import { useState, useCallback } from 'react'
import { SinauthClient, loginWithPopup, SinauthPopupError } from '@opensecstack/sinauth'

const client = new SinauthClient({
  baseUrl:  'https://auth.example.com',
  clientId: 'my-spa',
})

export function useAuth() {
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState<string | null>(null)

  const login = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const tokens = await loginWithPopup(client, {
        redirectUri: window.location.origin + '/auth/callback',
        scope: 'openid profile email',
      })
      setAccessToken(tokens.accessToken)
    } catch (err) {
      if (err instanceof SinauthPopupError && err.code === 'popup_closed') {
        // User closed the popup — not an error
      } else {
        setError('Login failed. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }, [])

  const logout = useCallback(() => {
    setAccessToken(null)
  }, [])

  return { accessToken, loading, error, login, logout }
}`

const callbackPageCode = `// src/pages/AuthCallback.tsx
// This page must be registered as the redirect_uri in sinauth.
// The popup SDK handles the token exchange automatically — this page
// just needs to exist and load the SDK.
import { handlePopupCallback } from '@opensecstack/sinauth'

export default function AuthCallback() {
  // Completes the PKCE exchange and posts the tokens back to the opener window.
  // The page closes itself after posting.
  handlePopupCallback()
  return <div>Authenticating...</div>
}`

const popupConfigCode = `// Advanced popup options
const tokens = await loginWithPopup(client, {
  redirectUri: 'https://app.example.com/auth/callback',
  scope: 'openid profile email',

  // Popup window dimensions (default: 480x600)
  popupWidth:  500,
  popupHeight: 650,

  // Time to wait for the user to complete login (default: 300s)
  timeoutMs: 180_000,

  // Pass extra OAuth2 parameters
  extraParams: {
    login_hint: 'user@example.com',
    prompt: 'select_account',
  },
})`

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'setup', label: 'Setup' },
  { id: 'basic', label: 'Basic usage' },
  { id: 'react', label: 'React hook' },
  { id: 'callback', label: 'Callback page' },
  { id: 'options', label: 'Popup options' },
  { id: 'errors', label: 'Error handling' },
]

export default function PopupSSOPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Authentication', 'Popup SSO']}
      toc={toc}
      editPath="PopupSSOPage.tsx"
      prev={{ label: 'PKCE Flow', path: '/docs/pkce' }}
      next={{ label: 'Go SDK', path: '/docs/sdk-go' }}
    >
      <h1>Popup SSO</h1>

      <p>
        Popup SSO lets users authenticate in a small overlay window — like Google or GitHub's
        OAuth flow — without a full-page redirect. The TypeScript SDK handles the PKCE flow,
        popup lifecycle, and cross-window messaging automatically.
      </p>

      <h2 id="overview">Overview</h2>

      <p>
        When <code>loginWithPopup</code> is called, the SDK:
      </p>
      <ol>
        <li>Generates a PKCE verifier/challenge pair</li>
        <li>Opens a centred popup window pointing to sinauth's <code>/oauth/authorize</code></li>
        <li>Waits for sinauth to redirect to your callback page inside the popup</li>
        <li>The callback page calls <code>handlePopupCallback()</code> which exchanges the code for tokens and <code>postMessage</code>s them to the opener</li>
        <li>The popup closes and <code>loginWithPopup</code> resolves with the token set</li>
      </ol>

      <div className="callout-note">
        <strong>Same origin required:</strong> The callback page must be served from the same
        origin as your app. Cross-origin <code>postMessage</code> is not supported.
      </div>

      <h2 id="setup">Setup</h2>

      <CodeBlock code={installCode} language="bash" filename="terminal" />

      <p>
        Register your app in the sinauth admin panel under{' '}
        <strong>Applications → New Application</strong>. Add your callback URL
        (e.g. <code>https://app.example.com/auth/callback</code>) to the allowed redirect URIs.
      </p>

      <h2 id="basic">Basic usage</h2>

      <CodeBlock code={basicPopupCode} language="typescript" filename="login.ts" />

      <h2 id="react">React hook</h2>

      <p>
        Wrap the popup in a custom hook to manage loading and error state cleanly in React
        components:
      </p>

      <CodeBlock code={reactHookCode} language="typescript" filename="useAuth.ts" />

      <h2 id="callback">Callback page</h2>

      <p>
        Create a dedicated callback page at the URL you registered as the <code>redirect_uri</code>.
        This page runs inside the popup and completes the token exchange:
      </p>

      <CodeBlock code={callbackPageCode} language="typescript" filename="AuthCallback.tsx" />

      <div className="callout-warning">
        <strong>Route it:</strong> Make sure your router includes the callback path. In React
        Router: <code>{'<Route path="/auth/callback" element={<AuthCallback />} />'}</code>
      </div>

      <h2 id="options">Popup options</h2>

      <CodeBlock code={popupConfigCode} language="typescript" />

      <h2 id="errors">Error handling</h2>

      <p>
        <code>loginWithPopup</code> throws a <code>SinauthPopupError</code> for all failure
        cases. Check <code>err.code</code> to distinguish them:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Code</th>
              <th>Cause</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>popup_closed</code></td>
              <td>User closed the popup window before completing login</td>
            </tr>
            <tr>
              <td><code>popup_blocked</code></td>
              <td>Browser blocked the popup — call <code>loginWithPopup</code> from a user gesture (click handler)</td>
            </tr>
            <tr>
              <td><code>timeout</code></td>
              <td>Login was not completed within <code>timeoutMs</code></td>
            </tr>
            <tr>
              <td><code>exchange_failed</code></td>
              <td>Token exchange returned an error from sinauth (check <code>err.message</code>)</td>
            </tr>
          </tbody>
        </table>
      </div>
    </DocsLayout>
  )
}
