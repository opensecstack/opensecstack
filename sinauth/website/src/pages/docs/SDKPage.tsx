import { useState } from 'react'
import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

// Go snippets
const goInstall = `go get github.com/opensecstack/sinauth/sdk/go/sinauth@latest`

const goBasicVerify = `package main

import (
  "fmt"
  "net/http"

  "github.com/opensecstack/sinauth/sdk/go/sinauth"
)

func main() {
  client := sinauth.New("https://auth.example.com")

  http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    if len(token) > 7 {
      token = token[7:] // strip "Bearer "
    }

    claims, err := client.Verify(r.Context(), token)
    if err != nil {
      http.Error(w, "unauthorized", http.StatusUnauthorized)
      return
    }

    fmt.Fprintf(w, "Hello, %s!", claims.Sub)
  })

  http.ListenAndServe(":3000", nil)
}`

const goMiddleware = `// Middleware example with chi router
import "github.com/go-chi/chi/v5"

func AuthMiddleware(client *sinauth.Client) func(http.Handler) http.Handler {
  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      claims, err := client.VerifyRequest(r)
      if err != nil {
        http.Error(w, "unauthorized", 401)
        return
      }
      ctx := sinauth.WithClaims(r.Context(), claims)
      next.ServeHTTP(w, r.WithContext(ctx))
    })
  }
}`

const goRefresh = `// Refresh access token using a refresh token
tokens, err := client.Refresh(ctx, sinauth.RefreshRequest{
  ClientID:     "my-app",
  RefreshToken: oldRefreshToken,
})
if err != nil {
  // refresh token expired or rotated — user must re-authenticate
  return err
}
// tokens.AccessToken, tokens.RefreshToken (rotated)`

// TypeScript snippets
const tsInstall = `npm install @opensecstack/sinauth`

const tsBasicPopup = `import { SinauthClient, loginWithPopup } from '@opensecstack/sinauth'

const client = new SinauthClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'my-spa',
})

// In your React component or event handler:
async function handleLogin() {
  try {
    const tokens = await loginWithPopup(client, {
      redirectUri: 'https://app.example.com/callback',
      scope: 'openid profile email',
    })

    // Store tokens securely (memory or httpOnly cookie via backend)
    console.log('Access token:', tokens.accessToken)
    console.log('Expires in:', tokens.expiresIn, 'seconds')
  } catch (err) {
    if (err instanceof SinauthPopupError) {
      console.error('Login cancelled or failed:', err.code)
    }
  }
}`

const tsServerVerify = `// Server-side verification (Node.js / Bun / Edge Runtime)
import { SinauthClient } from '@opensecstack/sinauth'

const client = new SinauthClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'my-api',
})

// In your API route handler:
export async function GET(request: Request) {
  const authHeader = request.headers.get('Authorization')
  const token = authHeader?.replace('Bearer ', '') ?? ''

  const claims = await client.verify(token)
  // claims.sub — user ID
  // claims.email — email address
  // claims.roles — string[] of role names

  return Response.json({ user: claims.sub })
}`

const tsRefresh = `// Automatic token refresh
const client = new SinauthClient({
  baseUrl: 'https://auth.example.com',
  clientId: 'my-spa',
  autoRefresh: true,   // refresh access token before expiry
  onRefreshFailed: () => {
    // session expired — redirect to login
    window.location.href = '/login'
  },
})`

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'go', label: 'Go SDK' },
  { id: 'go-install', label: 'Installation', level: 3 as const },
  { id: 'go-verify', label: 'Verify tokens', level: 3 as const },
  { id: 'go-middleware', label: 'Middleware', level: 3 as const },
  { id: 'go-refresh', label: 'Token refresh', level: 3 as const },
  { id: 'typescript', label: 'TypeScript SDK' },
  { id: 'ts-install', label: 'Installation', level: 3 as const },
  { id: 'ts-popup', label: 'Popup login', level: 3 as const },
  { id: 'ts-verify', label: 'Server verify', level: 3 as const },
  { id: 'ts-refresh', label: 'Auto refresh', level: 3 as const },
]

export default function SDKPage() {
  const [activeTab, setActiveTab] = useState<'go' | 'typescript'>('go')

  return (
    <DocsLayout
      breadcrumbs={['Docs', 'SDKs', 'Overview']}
      toc={toc}
      editPath="SDKPage.tsx"
      prev={{ label: 'Environment Variables', path: '/docs/config' }}
    >
      <h1>SDK Overview</h1>

      <p>
        sinauth ships native SDKs for Go and TypeScript/Node.js. Both handle JWT verification,
        JWKS caching, token refresh, and the PKCE popup flow. Python and Java SDKs are in active
        development.
      </p>

      <h2 id="overview">Overview</h2>

      <div className="callout-note">
        <strong>JWKS caching:</strong> Both SDKs cache the public key set fetched from{' '}
        <code>/oauth/jwks</code> and refresh it automatically when a new key ID is encountered.
        This means key rotation is zero-downtime and zero-config.
      </div>

      {/* Tab switcher */}
      <div className="sdk-tabs" style={{ marginTop: 32 }}>
        <button
          className={`sdk-tab ${activeTab === 'go' ? 'active' : ''}`}
          onClick={() => setActiveTab('go')}
        >
          Go
        </button>
        <button
          className={`sdk-tab ${activeTab === 'typescript' ? 'active' : ''}`}
          onClick={() => setActiveTab('typescript')}
        >
          TypeScript
        </button>
      </div>

      {/* GO TAB */}
      {activeTab === 'go' && (
        <div>
          <h2 id="go">Go SDK</h2>
          <p>
            The Go SDK is a zero-dependency module. It verifies RS256 JWTs locally after fetching
            the JWKS, with configurable caching and retry behaviour.
          </p>

          <h3 id="go-install">Installation</h3>
          <CodeBlock code={goInstall} language="bash" />

          <h3 id="go-verify">Verify tokens</h3>
          <p>
            Create a <code>Client</code> once at application startup (it manages JWKS caching
            internally) and call <code>Verify</code> per request.
          </p>
          <CodeBlock code={goBasicVerify} language="go" filename="main.go" />

          <h3 id="go-middleware">Middleware</h3>
          <p>
            Use <code>VerifyRequest</code> for convenient HTTP middleware. It reads the{' '}
            <code>Authorization: Bearer …</code> header automatically.
          </p>
          <CodeBlock code={goMiddleware} language="go" filename="middleware.go" />

          <h3 id="go-refresh">Token refresh</h3>
          <p>
            Call <code>Refresh</code> with a refresh token to get new tokens. Refresh tokens are
            rotated on every use — store the new refresh token immediately.
          </p>
          <CodeBlock code={goRefresh} language="go" />
        </div>
      )}

      {/* TYPESCRIPT TAB */}
      {activeTab === 'typescript' && (
        <div>
          <h2 id="typescript">TypeScript SDK</h2>
          <p>
            The TypeScript SDK runs in browsers (via the popup helper) and in Node.js, Bun, Deno,
            and edge runtimes (via the server verify helper). It is tree-shakeable and has a single
            peer dependency on the Web Crypto API.
          </p>

          <h3 id="ts-install">Installation</h3>
          <CodeBlock code={tsInstall} language="bash" />

          <h3 id="ts-popup">Popup login</h3>
          <p>
            <code>loginWithPopup</code> opens a centred popup window, drives the full PKCE
            authorization code flow, exchanges the code for tokens, and resolves with the token
            set. No redirect handling needed in your app.
          </p>
          <CodeBlock code={tsBasicPopup} language="typescript" filename="LoginButton.tsx" />

          <h3 id="ts-verify">Server-side verification</h3>
          <p>
            Call <code>client.verify(token)</code> in your API handlers. The JWKS is fetched once
            and cached with a configurable TTL (default 5 minutes).
          </p>
          <CodeBlock code={tsServerVerify} language="typescript" filename="route.ts" />

          <h3 id="ts-refresh">Automatic token refresh</h3>
          <p>
            Enable <code>autoRefresh</code> in the client options to automatically renew the access
            token before it expires, keeping sessions alive without user interaction.
          </p>
          <CodeBlock code={tsRefresh} language="typescript" />
        </div>
      )}
    </DocsLayout>
  )
}
