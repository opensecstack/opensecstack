import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const installCode = `npm install @opensecstack/sinauth
# or
pnpm add @opensecstack/sinauth`

const clientCode = `import { SinauthClient } from '@opensecstack/sinauth'

// Create once — manages JWKS caching internally
export const sinauth = new SinauthClient({
  baseUrl:  'https://auth.example.com',
  clientId: 'my-app',
})`

const serverVerifyCode = `// Next.js API route / Bun / Node.js
import { sinauth } from '@/lib/sinauth'

export async function GET(request: Request) {
  const header = request.headers.get('Authorization') ?? ''
  const token  = header.replace('Bearer ', '')

  const claims = await sinauth.verify(token)
  // Throws SinauthVerifyError if invalid or expired

  return Response.json({
    userId: claims.sub,
    email:  claims.email,
    roles:  claims.roles,
  })
}`

const browserVerifyCode = `// Client-side: decode without verification (for display only — never for access control)
import { decodeJWT } from '@opensecstack/sinauth'

const payload = decodeJWT(accessToken)
console.log(payload.name)   // display name
console.log(payload.email)  // email address

// For access control, always verify server-side or via the Go SDK.`

const popupCode = `import { loginWithPopup } from '@opensecstack/sinauth'
import { sinauth } from '@/lib/sinauth'

// Call from a button click handler (popups must be user-initiated)
async function login() {
  const tokens = await loginWithPopup(sinauth, {
    redirectUri: window.location.origin + '/auth/callback',
    scope: 'openid profile email',
  })

  // tokens.accessToken  — RS256 JWT (15 min default)
  // tokens.refreshToken — rotate on every use
  // tokens.idToken      — OIDC ID token
  // tokens.expiresIn    — seconds until accessToken expires
}`

const refreshCode = `import { sinauth } from '@/lib/sinauth'

async function refreshTokens(refreshToken: string) {
  const tokens = await sinauth.refresh({
    clientId:     'my-app',
    refreshToken,
  })
  // Save tokens.refreshToken — it is rotated on every use
  return tokens
}`

const autoRefreshCode = `const client = new SinauthClient({
  baseUrl:  'https://auth.example.com',
  clientId: 'my-spa',
  autoRefresh: true,       // refresh access token 60s before expiry
  onRefreshFailed: () => {
    // Refresh token expired — send user to login
    window.location.href = '/login'
  },
})`

const claimsCode = `interface SinauthClaims {
  sub:    string    // User ID (UUID)
  email:  string    // Email address
  name:   string    // Display name
  roles:  string[]  // Role names
  groups: string[]  // Group names
  iss:    string    // Issuer
  aud:    string[]  // Audience
  exp:    number    // Expiry (Unix timestamp)
  iat:    number    // Issued at (Unix timestamp)
}`

const toc = [
  { id: 'install', label: 'Installation' },
  { id: 'client', label: 'Create a client' },
  { id: 'server-verify', label: 'Server-side verify' },
  { id: 'browser', label: 'Browser decode' },
  { id: 'popup', label: 'Popup login' },
  { id: 'refresh', label: 'Token refresh' },
  { id: 'auto-refresh', label: 'Auto-refresh' },
  { id: 'claims', label: 'Claims reference' },
]

export default function SDKTSPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'SDKs', 'TypeScript SDK']}
      toc={toc}
      editPath="SDKTSPage.tsx"
      prev={{ label: 'Go SDK', path: '/docs/sdk-go' }}
      next={{ label: 'Auth Endpoints', path: '/docs/api-auth' }}
    >
      <h1>TypeScript SDK</h1>

      <p>
        The sinauth TypeScript SDK runs in browsers (popup login, token decoding) and in server
        runtimes (Node.js, Bun, Deno, edge functions) for JWT verification. It is fully
        tree-shakeable with a single peer dependency on the Web Crypto API.
      </p>

      <h2 id="install">Installation</h2>

      <CodeBlock code={installCode} language="bash" filename="terminal" />

      <h2 id="client">Create a client</h2>

      <p>
        Instantiate <code>SinauthClient</code> once (module-level or singleton) and share it
        across your app. It caches the JWKS with a 5-minute TTL and auto-refreshes when a new key
        ID is encountered.
      </p>

      <CodeBlock code={clientCode} language="typescript" filename="lib/sinauth.ts" />

      <h2 id="server-verify">Server-side verify</h2>

      <p>
        Call <code>client.verify(token)</code> in API route handlers to validate an access token.
        It verifies the signature, expiry, and issuer. Throws <code>SinauthVerifyError</code>{' '}
        with a descriptive <code>code</code> on failure.
      </p>

      <CodeBlock code={serverVerifyCode} language="typescript" filename="app/api/me/route.ts" />

      <h2 id="browser">Browser decode</h2>

      <p>
        For displaying user info in the browser (name, avatar) you can decode the JWT payload
        without verifying it. Never use client-side decoded claims for access-control decisions.
      </p>

      <CodeBlock code={browserVerifyCode} language="typescript" filename="UserMenu.tsx" />

      <h2 id="popup">Popup login</h2>

      <p>
        <code>loginWithPopup</code> drives the full PKCE flow in a popup window. See the{' '}
        <a href="/docs/popup-sso" style={{ color: '#6366f1' }}>Popup SSO guide</a> for setup
        details and error handling.
      </p>

      <CodeBlock code={popupCode} language="typescript" filename="LoginButton.tsx" />

      <h2 id="refresh">Token refresh</h2>

      <p>
        Exchange a refresh token for new tokens. sinauth rotates refresh tokens on every use —
        always persist the new <code>refreshToken</code> returned.
      </p>

      <CodeBlock code={refreshCode} language="typescript" filename="auth.ts" />

      <h2 id="auto-refresh">Auto-refresh</h2>

      <p>
        Enable <code>autoRefresh</code> to have the client silently renew the access token 60
        seconds before it expires. Provide an <code>onRefreshFailed</code> callback to handle
        session expiry.
      </p>

      <CodeBlock code={autoRefreshCode} language="typescript" />

      <h2 id="claims">Claims reference</h2>

      <CodeBlock code={claimsCode} language="typescript" filename="types/sinauth.d.ts" />
    </DocsLayout>
  )
}
