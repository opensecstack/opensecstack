import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const generateVerifierCode = `// Step 1: Generate a code verifier (43-128 random URL-safe chars)
function generateCodeVerifier(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

// Step 2: Derive the code challenge (SHA-256 of the verifier, base64url-encoded)
async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}`

const authRequestCode = `const verifier = generateCodeVerifier()
const challenge = await generateCodeChallenge(verifier)

// Store verifier in sessionStorage — needed for the token exchange
sessionStorage.setItem('pkce_verifier', verifier)

// Build the authorization URL
const params = new URLSearchParams({
  response_type: 'code',
  client_id:     'my-spa',
  redirect_uri:  'https://app.example.com/callback',
  scope:         'openid profile email',
  state:         crypto.randomUUID(),   // CSRF protection
  code_challenge:        challenge,
  code_challenge_method: 'S256',
})

// Redirect the user to sinauth
window.location.href = \`https://auth.example.com/oauth/authorize?\${params}\``

const tokenExchangeCode = `// On the callback page (/callback)
const urlParams = new URLSearchParams(window.location.search)
const code     = urlParams.get('code')!
const verifier = sessionStorage.getItem('pkce_verifier')!

// Exchange the authorization code + verifier for tokens
const response = await fetch('https://auth.example.com/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type:    'authorization_code',
    client_id:     'my-spa',
    redirect_uri:  'https://app.example.com/callback',
    code,
    code_verifier: verifier,
  }),
})

const tokens = await response.json()
// tokens.access_token  — RS256 JWT, short-lived (default 15 min)
// tokens.refresh_token — rotate this on every use
// tokens.id_token      — OIDC ID token (user profile)
// tokens.expires_in    — seconds until access_token expires`

const refreshCode = `// Exchange an expired access token for a new one
const response = await fetch('https://auth.example.com/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type:    'refresh_token',
    client_id:     'my-spa',
    refresh_token: storedRefreshToken,
  }),
})

if (!response.ok) {
  // Refresh token expired or revoked — redirect to login
  window.location.href = '/login'
  return
}

const tokens = await response.json()
// Save the NEW refresh token — sinauth rotates them on every use`

const toc = [
  { id: 'why-pkce', label: 'Why PKCE?' },
  { id: 'flow', label: 'Flow overview' },
  { id: 'step1', label: 'Step 1: Code verifier & challenge' },
  { id: 'step2', label: 'Step 2: Authorization request' },
  { id: 'step3', label: 'Step 3: Token exchange' },
  { id: 'refresh', label: 'Token refresh' },
  { id: 'security', label: 'Security notes' },
]

export default function PKCEPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Authentication', 'PKCE Flow']}
      toc={toc}
      editPath="PKCEPage.tsx"
      prev={{ label: 'Database Setup', path: '/docs/database' }}
      next={{ label: 'Popup SSO', path: '/docs/popup-sso' }}
    >
      <h1>PKCE Flow</h1>

      <p>
        PKCE (Proof Key for Code Exchange, RFC 7636) is the recommended authorization flow for
        public clients — browsers, mobile apps, and desktop apps — that cannot safely store a
        client secret. sinauth requires PKCE for all public clients.
      </p>

      <h2 id="why-pkce">Why PKCE?</h2>

      <p>
        The standard Authorization Code flow requires a <code>client_secret</code> to exchange an
        authorization code for tokens. Public clients cannot keep secrets (any user can inspect
        the app's source code or binary). PKCE solves this by having the client generate a
        one-time cryptographic secret (<em>code verifier</em>) at the start of each login, derive
        a hash of it (<em>code challenge</em>) that is sent to the authorization server, and then
        prove knowledge of the original secret during the token exchange.
      </p>

      <p>
        An attacker who intercepts the authorization code cannot exchange it for tokens without
        also knowing the verifier, which never leaves the client.
      </p>

      <h2 id="flow">Flow overview</h2>

      <ol>
        <li>Client generates a random <code>code_verifier</code></li>
        <li>Client computes <code>code_challenge = BASE64URL(SHA-256(verifier))</code></li>
        <li>Client redirects user to <code>/oauth/authorize</code> with the challenge</li>
        <li>User authenticates; sinauth redirects back with an authorization <code>code</code></li>
        <li>Client sends the <code>code</code> + original <code>code_verifier</code> to <code>/oauth/token</code></li>
        <li>sinauth verifies the verifier against the stored challenge and issues tokens</li>
      </ol>

      <h2 id="step1">Step 1: Code verifier & challenge</h2>

      <p>
        Generate a cryptographically random verifier and derive its SHA-256 challenge using the
        Web Crypto API (available in all modern browsers and Node.js 18+):
      </p>

      <CodeBlock code={generateVerifierCode} language="typescript" filename="pkce.ts" />

      <h2 id="step2">Step 2: Authorization request</h2>

      <p>
        Store the verifier in <code>sessionStorage</code>, then redirect the user to sinauth's
        authorization endpoint. Include the <code>state</code> parameter to prevent CSRF attacks.
      </p>

      <CodeBlock code={authRequestCode} language="typescript" filename="login.ts" />

      <div className="callout-note">
        <strong>state parameter:</strong> Always generate a random <code>state</code> value,
        store it in <code>sessionStorage</code>, and verify it on the callback to confirm the
        response belongs to your request.
      </div>

      <h2 id="step3">Step 3: Token exchange</h2>

      <p>
        On the callback page, read the <code>code</code> from the URL query string and exchange
        it for tokens using the stored verifier:
      </p>

      <CodeBlock code={tokenExchangeCode} language="typescript" filename="callback.ts" />

      <h2 id="refresh">Token refresh</h2>

      <p>
        Access tokens are short-lived (default 15 minutes). Use the refresh token to obtain a new
        access token silently. sinauth rotates refresh tokens on every use — always save the new
        refresh token returned in the response.
      </p>

      <CodeBlock code={refreshCode} language="typescript" filename="refresh.ts" />

      <h2 id="security">Security notes</h2>

      <ul>
        <li>
          <strong>Store tokens in memory, not localStorage.</strong> Memory prevents XSS from
          reading tokens across page loads. Use a <code>httpOnly</code> cookie set by your backend
          if you need persistence.
        </li>
        <li>
          <strong>One verifier per login attempt.</strong> Never reuse a code verifier. Generate a
          fresh one on each authorization request.
        </li>
        <li>
          <strong>Verify the state parameter.</strong> If the returned <code>state</code> does not
          match the value you stored, discard the response — it may be a CSRF attempt.
        </li>
        <li>
          <strong>Short-lived codes.</strong> sinauth invalidates authorization codes after 60
          seconds or on first use, whichever comes first.
        </li>
      </ul>
    </DocsLayout>
  )
}
