import DocsLayout from './DocsLayout'

interface EnvVar {
  name: string
  default?: string
  description: string
  required?: boolean
}

const coreVars: EnvVar[] = [
  {
    name: 'DATABASE_URL',
    description: 'PostgreSQL connection string. Accepts the standard postgres:// scheme.',
    required: true,
  },
  {
    name: 'SINAUTH_SITE_URL',
    description: 'The public-facing base URL of your sinauth instance. Used in OIDC discovery and email links.',
    required: true,
  },
  {
    name: 'SINAUTH_JWT_PRIVATE_KEY_PATH',
    default: '/keys/private.pem',
    description: 'Filesystem path to the RS256 private key PEM file. Used to sign JWTs.',
    required: true,
  },
  {
    name: 'SINAUTH_JWT_PUBLIC_KEY_PATH',
    default: '/keys/public.pem',
    description: 'Filesystem path to the RS256 public key PEM file. Served at /oauth/jwks.',
    required: true,
  },
  {
    name: 'SINAUTH_JWT_EXPIRY',
    default: '15m',
    description: 'Access token lifetime. Accepts Go duration strings: 15m, 1h, 24h.',
  },
  {
    name: 'SINAUTH_REFRESH_EXPIRY',
    default: '30d',
    description: 'Refresh token lifetime. Refresh tokens are rotated on each use.',
  },
  {
    name: 'SINAUTH_ADMIN_PASSWORD',
    description: 'Bootstrap password for the built-in admin account. Required on first run. Stored hashed after boot.',
    required: true,
  },
  {
    name: 'SINAUTH_BCRYPT_COST',
    default: '12',
    description: 'bcrypt cost factor for password hashing. Higher = slower brute-force, higher CPU usage. Range: 10–14.',
  },
]

const socialVars: EnvVar[] = [
  {
    name: 'GOOGLE_CLIENT_ID',
    description: 'Google OAuth2 app client ID. Create at console.cloud.google.com.',
  },
  {
    name: 'GOOGLE_CLIENT_SECRET',
    description: 'Google OAuth2 app client secret.',
  },
  {
    name: 'GITHUB_CLIENT_ID',
    description: 'GitHub OAuth2 app client ID. Create at github.com/settings/applications.',
  },
  {
    name: 'GITHUB_CLIENT_SECRET',
    description: 'GitHub OAuth2 app client secret.',
  },
]

const rateLimitVars: EnvVar[] = [
  {
    name: 'SINAUTH_RATE_LIMIT_AUTH',
    default: '10',
    description: 'Maximum authentication attempts (login, token exchange) per minute per IP address.',
  },
  {
    name: 'SINAUTH_RATE_LIMIT_GLOBAL',
    default: '200',
    description: 'Maximum total API requests per minute per IP address across all endpoints.',
  },
  {
    name: 'SINAUTH_RATE_LIMIT_REGISTER',
    default: '5',
    description: 'Maximum account registration attempts per hour per IP address.',
  },
]

const toc = [
  { id: 'core', label: 'Core settings' },
  { id: 'social', label: 'Social SSO' },
  { id: 'rate-limiting', label: 'Rate limiting' },
  { id: 'notes', label: 'Configuration notes' },
]

function VarTable({ vars }: { vars: EnvVar[] }) {
  return (
    <div className="docs-table-wrapper">
      <table className="docs-table">
        <thead>
          <tr>
            <th>Variable</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {vars.map(v => (
            <tr key={v.name}>
              <td>
                <code>{v.name}</code>
                {v.required && (
                  <span
                    style={{
                      marginLeft: 6,
                      fontSize: '0.65rem',
                      background: 'rgba(99,102,241,0.15)',
                      color: '#6366f1',
                      padding: '1px 6px',
                      borderRadius: 4,
                      fontWeight: 600,
                      verticalAlign: 'middle',
                    }}
                  >
                    required
                  </span>
                )}
              </td>
              <td>
                {v.default ? <code>{v.default}</code> : <span style={{ color: '#3d4a5c' }}>—</span>}
              </td>
              <td>{v.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function ConfigPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Configuration', 'Environment Variables']}
      toc={toc}
      editPath="ConfigPage.tsx"
      prev={{ label: 'Installation', path: '/docs/installation' }}
      next={{ label: 'Database Setup', path: '/docs/database' }}
    >
      <h1>Environment Variables</h1>

      <p>
        sinauth is configured entirely through environment variables. This makes it straightforward
        to deploy on Kubernetes, Docker Compose, or any twelve-factor platform. Sensitive values
        should be supplied through a secret manager or encrypted environment rather than baked into
        images.
      </p>

      <div className="callout-note">
        <strong>Tip:</strong> Copy <code>.env.example</code> from the repository root for a
        pre-populated template with comments. Run <code>docker compose --env-file .env up</code>{' '}
        to inject it automatically.
      </div>

      <h2 id="core">Core settings</h2>

      <p>
        These variables control the fundamental behaviour of sinauth — database connectivity, JWT
        signing, and the admin account.
      </p>

      <VarTable vars={coreVars} />

      <h2 id="social">Social SSO</h2>

      <p>
        Social providers are enabled by supplying credentials. If both a <code>CLIENT_ID</code>{' '}
        and <code>CLIENT_SECRET</code> are set for a provider, the corresponding sign-in button
        appears automatically on the login page.
      </p>

      <div className="callout-note">
        <strong>Callback URLs:</strong> Register{' '}
        <code>{'${SINAUTH_SITE_URL}'}/oauth/callback/google</code> and{' '}
        <code>{'${SINAUTH_SITE_URL}'}/oauth/callback/github</code> in the respective developer
        consoles.
      </div>

      <VarTable vars={socialVars} />

      <h2 id="rate-limiting">Rate limiting</h2>

      <p>
        sinauth ships with built-in IP-based rate limiting using a token-bucket algorithm. These
        limits protect against credential stuffing and enumeration attacks without requiring an
        external WAF.
      </p>

      <VarTable vars={rateLimitVars} />

      <h2 id="notes">Configuration notes</h2>

      <h3>Duration format</h3>
      <p>
        Any variable accepting a duration (e.g. <code>SINAUTH_JWT_EXPIRY</code>) uses Go's
        duration notation: <code>30s</code>, <code>15m</code>, <code>1h</code>, <code>24h</code>,
        <code>7d</code>. Days (<code>d</code>) are supported as a sinauth extension.
      </p>

      <h3>Secrets management</h3>
      <p>
        For production deployments, never store credentials in plaintext files. Use Docker secrets,
        Kubernetes Secrets, HashiCorp Vault, or your cloud provider's secret manager. sinauth reads
        from environment at startup — any injection mechanism that sets environment variables will
        work.
      </p>

      <h3>Reload behaviour</h3>
      <p>
        sinauth reads configuration once at startup. To apply environment changes, restart the
        process. In Docker: <code>docker compose restart sinauth</code>. In Kubernetes: roll the
        deployment.
      </p>
    </DocsLayout>
  )
}
