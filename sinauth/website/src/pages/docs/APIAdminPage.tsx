import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const authHeaderCode = `# All admin endpoints require an admin JWT in the Authorization header.
# Obtain one by logging in as the admin user:
TOKEN=$(curl -s -X POST https://auth.example.com/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"admin@example.com","password":"changeme","client_id":"admin-ui"}' \\
  | jq -r .access_token)

# Use it on subsequent requests:
curl https://auth.example.com/api/v1/admin/users \\
  -H "Authorization: Bearer $TOKEN"`

const listUsersCode = `# List users (paginated)
curl "https://auth.example.com/api/v1/admin/users?page=1&per_page=20" \\
  -H "Authorization: Bearer $TOKEN"

# Search by email
curl "https://auth.example.com/api/v1/admin/users?q=jane" \\
  -H "Authorization: Bearer $TOKEN"

# Response
{
  "data": [
    {
      "id":         "uuid",
      "email":      "jane@example.com",
      "name":       "Jane Doe",
      "roles":      ["viewer"],
      "created_at": "2026-01-15T10:00:00Z",
      "last_login": "2026-05-20T08:32:11Z"
    }
  ],
  "total": 142,
  "page":  1,
  "per_page": 20
}`

const createUserCode = `curl -X POST https://auth.example.com/api/v1/admin/users \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "email":    "newuser@example.com",
    "name":     "New User",
    "password": "TempP@ss!",
    "roles":    ["viewer"],
    "groups":   ["team-alpha"]
  }'`

const clientsCode = `# List registered OAuth2 clients
curl https://auth.example.com/api/v1/admin/clients \\
  -H "Authorization: Bearer $TOKEN"

# Create a new client
curl -X POST https://auth.example.com/api/v1/admin/clients \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "client_id":   "my-spa",
    "name":        "My SPA",
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types":   ["authorization_code"],
    "pkce_required": true,
    "token_endpoint_auth_method": "none"
  }'

# Revoke all tokens for a client
curl -X DELETE https://auth.example.com/api/v1/admin/clients/my-spa/tokens \\
  -H "Authorization: Bearer $TOKEN"`

const sessionsCode = `# List active sessions
curl https://auth.example.com/api/v1/admin/sessions \\
  -H "Authorization: Bearer $TOKEN"

# Revoke a specific session by ID
curl -X DELETE https://auth.example.com/api/v1/admin/sessions/SESSION_ID \\
  -H "Authorization: Bearer $TOKEN"

# Revoke all sessions for a user
curl -X DELETE "https://auth.example.com/api/v1/admin/users/USER_ID/sessions" \\
  -H "Authorization: Bearer $TOKEN"`

const auditCode = `# Fetch audit log (most recent first)
curl "https://auth.example.com/api/v1/admin/audit?limit=50&offset=0" \\
  -H "Authorization: Bearer $TOKEN"

# Filter by user and action
curl "https://auth.example.com/api/v1/admin/audit?user_id=UUID&action=login.failed" \\
  -H "Authorization: Bearer $TOKEN"

# Each entry includes:
# {
#   "id":         "uuid",
#   "timestamp":  "2026-05-22T09:14:00Z",
#   "user_id":    "uuid",
#   "action":     "login.success",
#   "ip":         "192.168.1.1",
#   "user_agent": "Mozilla/5.0 ...",
#   "chain_hash": "sha256+sha512+blake3 of previous entry"
# }`

const toc = [
  { id: 'auth', label: 'Authentication' },
  { id: 'users', label: 'Users' },
  { id: 'clients', label: 'OAuth2 clients' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'audit', label: 'Audit log' },
  { id: 'endpoints', label: 'Endpoint index' },
]

export default function APIAdminPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'API Reference', 'Admin Endpoints']}
      toc={toc}
      editPath="APIAdminPage.tsx"
      prev={{ label: 'Auth Endpoints', path: '/docs/api-auth' }}
    >
      <h1>Admin Endpoints</h1>

      <p>
        The admin API provides programmatic access to user management, OAuth2 client registration,
        session control, and the audit log. All admin endpoints require a valid admin JWT.
      </p>

      <h2 id="auth">Authentication</h2>

      <p>
        Obtain an admin token by authenticating with the built-in admin account or any user that
        has the <code>admin</code> role. Pass it as a Bearer token on every request.
      </p>

      <CodeBlock code={authHeaderCode} language="bash" filename="terminal" />

      <div className="callout-warning">
        <strong>Admin role required:</strong> Requests to <code>/api/v1/admin/*</code> from a
        token without the <code>admin</code> role return HTTP 403.
      </div>

      <h2 id="users">Users</h2>

      <p>
        Create, update, and query user accounts. Passwords are hashed with bcrypt cost-12 before
        storage.
      </p>

      <CodeBlock code={listUsersCode} language="bash" filename="terminal" />
      <CodeBlock code={createUserCode} language="bash" filename="terminal" />

      <h2 id="clients">OAuth2 clients</h2>

      <p>
        Manage registered client applications. Public clients (SPAs, mobile) use{' '}
        <code>token_endpoint_auth_method: "none"</code> with PKCE. Confidential clients
        (server-side apps) use a <code>client_secret</code>.
      </p>

      <CodeBlock code={clientsCode} language="bash" filename="terminal" />

      <h2 id="sessions">Sessions</h2>

      <p>
        Inspect and revoke active refresh token sessions. Revoking a session invalidates the
        refresh token immediately; the short-lived access token remains valid until it expires
        (max 15 minutes).
      </p>

      <CodeBlock code={sessionsCode} language="bash" filename="terminal" />

      <h2 id="audit">Audit log</h2>

      <p>
        sinauth records every authentication event in a tamper-evident WORM chain. Each entry
        links to the previous one via a triple hash (SHA-256 + SHA-512 + BLAKE3). Audit log
        entries cannot be modified or deleted through the API.
      </p>

      <CodeBlock code={auditCode} language="bash" filename="terminal" />

      <h2 id="endpoints">Endpoint index</h2>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {[
              ['GET',    '/api/v1/admin/users',                     'List users'],
              ['POST',   '/api/v1/admin/users',                     'Create user'],
              ['GET',    '/api/v1/admin/users/:id',                 'Get user by ID'],
              ['PATCH',  '/api/v1/admin/users/:id',                 'Update user'],
              ['DELETE', '/api/v1/admin/users/:id',                 'Delete user'],
              ['DELETE', '/api/v1/admin/users/:id/sessions',        'Revoke all sessions for user'],
              ['GET',    '/api/v1/admin/clients',                   'List OAuth2 clients'],
              ['POST',   '/api/v1/admin/clients',                   'Register client'],
              ['GET',    '/api/v1/admin/clients/:id',               'Get client'],
              ['PATCH',  '/api/v1/admin/clients/:id',               'Update client'],
              ['DELETE', '/api/v1/admin/clients/:id',               'Delete client'],
              ['DELETE', '/api/v1/admin/clients/:id/tokens',        'Revoke all tokens for client'],
              ['GET',    '/api/v1/admin/groups',                    'List groups'],
              ['POST',   '/api/v1/admin/groups',                    'Create group'],
              ['GET',    '/api/v1/admin/sessions',                  'List active sessions'],
              ['DELETE', '/api/v1/admin/sessions/:id',              'Revoke session'],
              ['GET',    '/api/v1/admin/audit',                     'Query audit log'],
              ['GET',    '/api/v1/admin/providers',                 'List identity providers'],
              ['POST',   '/api/v1/admin/providers',                 'Add identity provider (SAML/LDAP)'],
            ].map(([method, path, desc]) => (
              <tr key={path + method}>
                <td>
                  <code style={{
                    color: method === 'GET' ? '#22d3ee'
                         : method === 'POST' ? '#4ade80'
                         : method === 'PATCH' ? '#fb923c'
                         : '#f87171',
                  }}>{method}</code>
                </td>
                <td><code>{path}</code></td>
                <td>{desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DocsLayout>
  )
}
