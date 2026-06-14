import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const installCode = `go get github.com/opensecstack/sinauth/sdk/go/sinauth@latest`

const basicVerifyCode = `package main

import (
  "fmt"
  "net/http"

  "github.com/opensecstack/sinauth/sdk/go/sinauth"
)

func main() {
  // Create a client once — it manages JWKS caching internally.
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

const middlewareCode = `package middleware

import (
  "net/http"

  "github.com/go-chi/chi/v5"
  "github.com/opensecstack/sinauth/sdk/go/sinauth"
)

// Auth wraps a chi router with sinauth token verification.
func Auth(client *sinauth.Client) func(http.Handler) http.Handler {
  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      claims, err := client.VerifyRequest(r)
      if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
      }
      // Attach claims to the request context for downstream handlers
      ctx := sinauth.WithClaims(r.Context(), claims)
      next.ServeHTTP(w, r.WithContext(ctx))
    })
  }
}

// Usage in router setup:
func NewRouter(client *sinauth.Client) http.Handler {
  r := chi.NewRouter()
  r.Use(middleware.Auth(client))
  r.Get("/me", handleMe)
  return r
}

func handleMe(w http.ResponseWriter, r *http.Request) {
  claims := sinauth.ClaimsFromContext(r.Context())
  w.Write([]byte(claims.Email))
}`

const claimsCode = `// sinauth.Claims fields
type Claims struct {
  Sub    string   \`json:"sub"\`    // User ID (UUID)
  Email  string   \`json:"email"\`  // Email address
  Name   string   \`json:"name"\`   // Display name
  Roles  []string \`json:"roles"\`  // Role names
  Groups []string \`json:"groups"\` // Group names
  Iss    string   \`json:"iss"\`    // Issuer (SINAUTH_SITE_URL)
  Aud    []string \`json:"aud"\`    // Audience (client IDs)
  Exp    int64    \`json:"exp"\`    // Expiry (Unix timestamp)
  Iat    int64    \`json:"iat"\`    // Issued at (Unix timestamp)
}`

const refreshCode = `// Exchange a refresh token for new tokens
tokens, err := client.Refresh(ctx, sinauth.RefreshRequest{
  ClientID:     "my-api",
  RefreshToken: storedRefreshToken,
})
if err != nil {
  // Token expired or revoked — user must re-authenticate
  return err
}

// Save the new refresh token immediately — sinauth rotates on every use
saveTokens(tokens.AccessToken, tokens.RefreshToken)`

const optionsCode = `// Configure the client with options
client := sinauth.New(
  "https://auth.example.com",
  sinauth.WithJWKSCacheTTL(10 * time.Minute),  // default: 5 minutes
  sinauth.WithHTTPClient(customHTTPClient),      // custom HTTP client
  sinauth.WithExpectedAudience("my-api"),        // validate aud claim
)`

const toc = [
  { id: 'install', label: 'Installation' },
  { id: 'create-client', label: 'Create a client' },
  { id: 'verify', label: 'Verify tokens' },
  { id: 'middleware', label: 'Middleware (chi)' },
  { id: 'claims', label: 'Claims reference' },
  { id: 'refresh', label: 'Token refresh' },
  { id: 'options', label: 'Client options' },
]

export default function SDKGoPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'SDKs', 'Go SDK']}
      toc={toc}
      editPath="SDKGoPage.tsx"
      prev={{ label: 'Popup SSO', path: '/docs/popup-sso' }}
      next={{ label: 'TypeScript SDK', path: '/docs/sdk-ts' }}
    >
      <h1>Go SDK</h1>

      <p>
        The sinauth Go SDK verifies RS256 JWTs locally using a cached JWKS, provides HTTP
        middleware for chi and <code>net/http</code>, and handles token refresh. It has zero
        non-standard dependencies.
      </p>

      <h2 id="install">Installation</h2>

      <CodeBlock code={installCode} language="bash" filename="terminal" />

      <div className="callout-note">
        <strong>Go version:</strong> Requires Go 1.21 or later for the{' '}
        <code>slices</code> and <code>maps</code> packages used internally.
      </div>

      <h2 id="create-client">Create a client</h2>

      <p>
        Instantiate a <code>sinauth.Client</code> once at application startup. The client fetches
        the JWKS from <code>{'${baseUrl}/.well-known/jwks.json'}</code> on first use and caches
        it. Key rotation is handled transparently — when the SDK encounters an unknown key ID it
        re-fetches the JWKS automatically.
      </p>

      <CodeBlock code={basicVerifyCode} language="go" filename="main.go" />

      <h2 id="verify">Verify tokens</h2>

      <p>
        Use <code>client.Verify(ctx, rawToken)</code> to validate a JWT string. It checks the
        signature, expiry, issuer, and (optionally) audience. Returns parsed{' '}
        <code>*sinauth.Claims</code> on success, or a descriptive error.
      </p>

      <p>
        For HTTP handlers, <code>client.VerifyRequest(r)</code> reads the{' '}
        <code>Authorization: Bearer …</code> header automatically.
      </p>

      <h2 id="middleware">Middleware (chi)</h2>

      <p>
        Wrap your router with the provided middleware to protect all routes. Verified claims are
        attached to the request context and retrieved with{' '}
        <code>sinauth.ClaimsFromContext(ctx)</code>.
      </p>

      <CodeBlock code={middlewareCode} language="go" filename="middleware/auth.go" />

      <h2 id="claims">Claims reference</h2>

      <p>
        The <code>Claims</code> struct maps the fields sinauth includes in every access token:
      </p>

      <CodeBlock code={claimsCode} language="go" filename="sinauth/claims.go" />

      <h2 id="refresh">Token refresh</h2>

      <p>
        Access tokens expire after 15 minutes by default. Call <code>client.Refresh</code> to
        exchange a refresh token for a new token pair. Refresh tokens are rotated on every use —
        persist the new refresh token immediately.
      </p>

      <CodeBlock code={refreshCode} language="go" />

      <h2 id="options">Client options</h2>

      <p>
        The client accepts functional options to override defaults:
      </p>

      <CodeBlock code={optionsCode} language="go" />
    </DocsLayout>
  )
}
