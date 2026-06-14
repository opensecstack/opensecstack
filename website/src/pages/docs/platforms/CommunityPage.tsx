import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'key-features', label: 'Key features' },
  { id: 'architecture', label: 'Architecture' },
  { id: 'ports-endpoints', label: 'Ports & endpoints' },
  { id: 'integration', label: 'Integration' },
  { id: 'full-documentation', label: 'Full documentation' },
]

export default function CommunityPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'SIN Community']}
      toc={toc}
      editPath="platforms/CommunityPage.tsx"
      prev={{ label: 'VertGuard', path: '/docs/platforms/vertguard' }}
      next={{ label: 'Identity (sinauth)', path: '/docs/identity' }}
    >
      <h1>SIN Community</h1>
      <p>
        <strong>SIN Community</strong> is the developer knowledge hub of the opensecstack
        ecosystem — a publishing platform for post-mortems, detection recipes, NIS2 guides,
        and CSAF advisory write-ups. Posts are tagged, full-text searchable via Meilisearch,
        and optionally anchored into the CITADEL WORM chain for tamper evidence.
      </p>
      <p>
        The platform is inspired by dev.to. It runs at{' '}
        <strong>sin.to</strong> and is self-hostable. License:{' '}
        <strong>AGPL-3.0-or-later</strong>.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        SIN Community is a three-tier application: a Go API backed by PostgreSQL 16 and
        Meilisearch, and a React + TypeScript + Vite frontend. It supports threaded
        comments, post reactions, tag-based discovery, push notifications (Web Push via
        VAPID), TOTP two-factor authentication, and personal API keys.
      </p>
      <p>
        Authentication is flexible by design. Because SIN Community is a public hub,
        it keeps its own native account system (email/password with bcrypt and a
        server-side pepper) alongside sinauth SSO and direct GitHub/Google OAuth. In a
        fully integrated opensecstack deployment the native path can be disabled entirely,
        making sinauth the only login — matching the SSO-only posture of the other
        platforms.
      </p>

      <h2 id="key-features">Key features</h2>
      <ul>
        <li>
          <strong>Posts, comments, and reactions</strong> — Markdown posts with threaded
          comments (unlimited depth via <code>parent_id</code> self-reference) and
          per-kind reactions enforced as unique at the database level.
        </li>
        <li>
          <strong>Tags and spaces</strong> — posts are organised by tags; spaces provide
          a higher-level grouping for topic communities within the hub.
        </li>
        <li>
          <strong>Full-text search (Meilisearch)</strong> — post titles, bodies, tags,
          and author usernames are indexed in Meilisearch v1.10 for fast, typo-tolerant
          search.
        </li>
        <li>
          <strong>Notifications</strong> — in-app and Web Push notifications (VAPID) for
          mentions, replies, and follows.
        </li>
        <li>
          <strong>TOTP two-factor authentication</strong> — time-based OTP for native
          accounts; sinauth accounts inherit MFA from the identity provider.
        </li>
        <li>
          <strong>API keys</strong> — personal API keys for programmatic access;
          useful for posting from CI/CD pipelines.
        </li>
        <li>
          <a href="/docs/identity"><strong>sinauth SSO</strong></a> — "Continue with SIN" button on the Login and
          Register pages uses OAuth 2.0 / OIDC (authorization code + PKCE via
          the server-side flow). A first sinauth login auto-provisions a Community
          account; an existing account is linked by verified email. sinauth also provides
          centralised TOTP MFA and social login (Google, GitHub).
        </li>
        <li>
          <strong>Native accounts + social OAuth</strong> — email/password registration
          with email verification and password reset; direct GitHub and Google OAuth as
          alternatives. Set <code>COMMUNITY_NATIVE_AUTH=false</code> to disable the
          native path in a sinauth-integrated deployment.
        </li>
        <li>
          <strong>Invite-only mode</strong> — set <code>COMMUNITY_INVITE_ONLY=true</code>{' '}
          to restrict registration to invited users; optionally combine with
          <code> COMMUNITY_ALLOWED_EMAIL_DOMAINS</code> to limit to specific domains.
        </li>
        <li>
          <a href="/docs/governance"><strong>CITADEL tamper evidence</strong></a> — <code>community.post.published</code>{' '}
          events are emitted to CITADEL on publish, recording an immutable anchor for each
          published post.
        </li>
        <li>
          <strong>Four-role RBAC</strong> — <code>viewer</code>, <code>author</code>,{' '}
          <code>moderator</code>, <code>admin</code>.
        </li>
      </ul>

      <h2 id="architecture">Architecture</h2>
      <p>
        The Go API uses raw SQL via <code>pgx/v5</code> (no ORM) and serves HTTP on{' '}
        <code>:8090</code>. Session tokens are HMAC-signed JWTs (HS256). The
        authentication methods that are active at runtime are advertised at{' '}
        <code>GET /api/v1/auth/methods</code>, which the frontend reads to decide which
        login buttons to render.
      </p>
      <p>
        Meilisearch is the search backend. Posts are indexed on publish (title, body up to
        5 000 characters, tags, author username). The <code>MEILISEARCH_URL</code> and{' '}
        <code>MEILISEARCH_KEY</code> environment variables wire the client; leave{' '}
        <code>MEILISEARCH_URL</code> at the default (<code>http://localhost:7700</code>)
        for local development.
      </p>
      <p>
        The CITADEL integration is opt-in: leave <code>COMMUNITY_CITADEL_API_URL</code>{' '}
        empty to disable it entirely. In development, <code>COMMUNITY_CITADEL_DRY_RUN=true</code>{' '}
        (default) logs calls without sending them.
      </p>
      <p>
        In production the multi-stage Docker image bundles the Go binary and the compiled
        React SPA into a single container, with nginx serving the frontend and proxying API
        requests.
      </p>

      <h2 id="ports-endpoints">Ports &amp; endpoints</h2>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>Port</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Go API</td>
              <td><code>8090</code></td>
              <td><code>COMMUNITY_HTTP_ADDR</code></td>
            </tr>
            <tr>
              <td>React frontend (dev)</td>
              <td><code>5173</code></td>
              <td>Vite dev server; nginx in production</td>
            </tr>
            <tr>
              <td>Meilisearch</td>
              <td><code>7700</code></td>
              <td><code>MEILISEARCH_URL</code></td>
            </tr>
            <tr>
              <td>PostgreSQL 16</td>
              <td><code>5435</code></td>
              <td>Host-side dev port (<code>COMMUNITY_DB_URL</code>)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>Selected API endpoints (full reference at <code>api/openapi.yaml</code>):</p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/auth/methods</code></td>
              <td>Lists active login methods (drives frontend buttons)</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/auth/sinauth</code></td>
              <td>Initiates sinauth OAuth flow (server-side)</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/auth/register</code></td>
              <td>Native email/password registration</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/auth/login</code></td>
              <td>Native email/password login; issues session JWT</td>
            </tr>
            <tr>
              <td><code>GET</code> <code>POST</code></td>
              <td><code>/api/v1/posts</code></td>
              <td>List and create posts</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/posts/{'{id}'}/publish</code></td>
              <td>Publish post; emits CITADEL evidence event</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/search</code></td>
              <td>Full-text search via Meilisearch</td>
            </tr>
            <tr>
              <td><code>GET</code> <code>POST</code></td>
              <td><code>/api/v1/posts/{'{id}'}/comments</code></td>
              <td>Threaded comments</td>
            </tr>
            <tr>
              <td><code>/api/v1/notifications</code></td>
              <td><code>GET</code></td>
              <td>In-app notification feed</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="integration">Integration</h2>
      <p>
        Minimum required environment variables:
      </p>

      <CodeBlock
        language="bash"
        filename=".env"
        code={`COMMUNITY_DB_URL=postgres://community:community@postgres:5432/community
COMMUNITY_JWT_SECRET=<32+ random bytes>
COMMUNITY_PASSWORD_PEPPER=<32+ random bytes>
MEILISEARCH_KEY=<master key>

# sinauth SSO (optional — enable "Continue with SIN" button)
SINAUTH_CLIENT_ID=<client id registered in sinauth>
SINAUTH_URL=https://auth.sin.to
SINAUTH_CALLBACK_URL=https://sin.to/api/v1/auth/sinauth/callback

# CITADEL tamper evidence (optional)
COMMUNITY_CITADEL_API_URL=https://citadel.internal
COMMUNITY_CITADEL_DRY_RUN=false`}
      />

      <p>To run the full development stack:</p>

      <CodeBlock
        language="bash"
        code={`git clone https://github.com/opensecstack/opensecstack
cd opensecstack/community
cp .env.example .env          # edit secrets before proceeding
cp web/.env.example web/.env  # set VITE_VAPID_PUBLIC_KEY
docker compose -f docker-compose.dev.yml up
# API:         http://localhost:8090
# Frontend:    http://localhost:5173
# Meilisearch: http://localhost:7700
# Login:       admin / admin  (change immediately)`}
      />

      <p>
        SIN Community integrates with one other opensecstack platform by default:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Platform</th>
              <th>Direction</th>
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>CITADEL</strong></td>
              <td>Push on publish</td>
              <td><code>community.post.published</code> events; opt-in via <code>COMMUNITY_CITADEL_API_URL</code></td>
            </tr>
            <tr>
              <td><strong>sinauth</strong></td>
              <td>OAuth callback</td>
              <td>SSO login and account provisioning; opt-in via <code>SINAUTH_CLIENT_ID</code></td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        The complete SIN Community documentation — operator guides, content guidelines,
        badge system, and API reference — is available in the repository:
      </p>
      <p>
        <a
          href="https://github.com/opensecstack/opensecstack/tree/main/community/docs"
          target="_blank"
          rel="noopener noreferrer"
        >
          github.com/opensecstack/opensecstack/tree/main/community/docs
        </a>
      </p>
    </DocsLayout>
  )
}
