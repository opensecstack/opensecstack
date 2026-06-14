import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const loginCode = `curl -X POST https://auth.example.com/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "email":    "user@example.com",
    "password": "hunter2",
    "client_id": "my-app"
  }'

# Response
{
  "access_token":  "eyJ...",
  "refresh_token": "rt_...",
  "token_type":    "Bearer",
  "expires_in":    900
}`

const authorizeCode = `# Redirect the user's browser to:
GET https://auth.example.com/oauth/authorize
  ?response_type=code
  &client_id=my-spa
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
  &scope=openid+profile+email
  &state=abc123
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256`

const tokenCode = `# Exchange authorization code for tokens (PKCE)
curl -X POST https://auth.example.com/oauth/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "client_id=my-spa" \\
  -d "redirect_uri=https://app.example.com/callback" \\
  -d "code=AUTH_CODE_HERE" \\
  -d "code_verifier=VERIFIER_HERE"

# Refresh token grant
curl -X POST https://auth.example.com/oauth/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=refresh_token" \\
  -d "client_id=my-spa" \\
  -d "refresh_token=rt_..."`

const registerCode = `curl -X POST https://auth.example.com/api/v1/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "email":    "newuser@example.com",
    "password": "s3cur3p@ss",
    "name":     "Jane Doe"
  }'`

const forgotPasswordCode = `# Request a reset link
curl -X POST https://auth.example.com/api/v1/auth/forgot-password \\
  -H "Content-Type: application/json" \\
  -d '{"email": "user@example.com"}'

# Submit new password using the token from email
curl -X POST https://auth.example.com/api/v1/auth/reset-password \\
  -H "Content-Type: application/json" \\
  -d '{
    "token":    "RESET_TOKEN_FROM_EMAIL",
    "password": "newP@ssw0rd"
  }'`

const userinfoCode = `curl https://auth.example.com/oauth/userinfo \\
  -H "Authorization: Bearer ACCESS_TOKEN"

# Response (OIDC standard)
{
  "sub":   "user-uuid",
  "email": "user@example.com",
  "name":  "Jane Doe",
  "email_verified": true
}`

const toc = [
  { id: 'base-url', label: 'Base URL' },
  { id: 'login', label: 'POST /auth/login' },
  { id: 'register', label: 'POST /auth/register' },
  { id: 'authorize', label: 'GET /oauth/authorize' },
  { id: 'token', label: 'POST /oauth/token' },
  { id: 'userinfo', label: 'GET /oauth/userinfo' },
  { id: 'password-reset', label: 'Password reset' },
  { id: 'discovery', label: 'OIDC discovery' },
]

export default function APIAuthPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'API Reference', 'Auth Endpoints']}
      toc={toc}
      editPath="APIAuthPage.tsx"
      prev={{ label: 'TypeScript SDK', path: '/docs/sdk-ts' }}
      next={{ label: 'Admin Endpoints', path: '/docs/api-admin' }}
    >
      <h1>Auth Endpoints</h1>

      <p>
        The auth API covers authentication, OIDC/OAuth2 protocol endpoints, user registration,
        and password management. These endpoints are public (no admin token required).
      </p>

      <h2 id="base-url">Base URL</h2>

      <p>
        All paths are relative to <code>SINAUTH_SITE_URL</code>. Application-specific auth
        endpoints are under <code>/api/v1/auth/</code>; OAuth2/OIDC protocol endpoints are at
        the root path as required by the specs.
      </p>

      <h2 id="login">POST /api/v1/auth/login</h2>

      <p>
        Direct email/password login. Returns a token pair. Use this for machine-to-machine
        clients or native apps where a redirect flow is impractical.
      </p>

      <CodeBlock code={loginCode} language="bash" filename="terminal" />

      <div className="callout-note">
        <strong>Rate limited:</strong> This endpoint is rate-limited to{' '}
        <code>SINAUTH_RATE_LIMIT_AUTH</code> attempts per minute per IP (default: 10).
        Exceeding the limit returns HTTP 429.
      </div>

      <h2 id="register">POST /api/v1/auth/register</h2>

      <p>
        Create a new user account. sinauth sends a verification email if{' '}
        <code>SINAUTH_SMTP_*</code> environment variables are configured.
      </p>

      <CodeBlock code={registerCode} language="bash" filename="terminal" />

      <h2 id="authorize">GET /oauth/authorize</h2>

      <p>
        The OAuth2 Authorization Endpoint (RFC 6749 §3.1). Redirect the user's browser here to
        start the PKCE flow. See the{' '}
        <a href="/docs/pkce" style={{ color: '#6366f1' }}>PKCE guide</a> for the full parameter
        reference.
      </p>

      <CodeBlock code={authorizeCode} language="bash" filename="terminal" />

      <h2 id="token">POST /oauth/token</h2>

      <p>
        The OAuth2 Token Endpoint (RFC 6749 §3.2). Supports{' '}
        <code>authorization_code</code> and <code>refresh_token</code> grant types.
      </p>

      <CodeBlock code={tokenCode} language="bash" filename="terminal" />

      <h2 id="userinfo">GET /oauth/userinfo</h2>

      <p>
        Returns the authenticated user's profile claims (OIDC Core §5.3). Requires a valid
        access token with the <code>openid</code> scope.
      </p>

      <CodeBlock code={userinfoCode} language="bash" filename="terminal" />

      <h2 id="password-reset">Password reset</h2>

      <p>
        Two-step flow: request a reset link by email, then submit the new password using the
        token from the link.
      </p>

      <CodeBlock code={forgotPasswordCode} language="bash" filename="terminal" />

      <h2 id="discovery">OIDC discovery</h2>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Path</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>/.well-known/openid-configuration</code></td>
              <td>OIDC Discovery document — all endpoint URLs and supported features</td>
            </tr>
            <tr>
              <td><code>/.well-known/jwks.json</code></td>
              <td>JSON Web Key Set — public key(s) for verifying RS256 JWTs</td>
            </tr>
          </tbody>
        </table>
      </div>
    </DocsLayout>
  )
}
