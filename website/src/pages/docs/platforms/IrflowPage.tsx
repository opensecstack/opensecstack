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

export default function IrflowPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'IRFlow']}
      toc={toc}
      editPath="platforms/IrflowPage.tsx"
      prev={{ label: 'NIS2 Compass', path: '/docs/platforms/nis2compass' }}
      next={{ label: 'ThreatFlow', path: '/docs/platforms/threatflow' }}
    >
      <h1>IRFlow</h1>
      <p>
        <strong>IRFlow</strong> is the incident response workflow engine for the opensecstack
        ecosystem. It manages the full incident lifecycle — from detection through containment,
        eradication, recovery, and closure — while enforcing <strong>CITADEL MARSHAL</strong>{' '}
        governance and tracking <strong>NIS2 Article 23</strong> notification deadlines at every
        step.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        IRFlow is a Go service (v1.0.0) licensed under <strong>AGPL-3.0</strong>. It listens on
        port <strong>8083</strong> and exposes a JWT-protected REST API alongside public
        HMAC-SHA256 signed webhook endpoints for receiving events from APIGuard, CITADEL, and
        ThreatFlow. PostgreSQL 16 is the single source of truth; the service is stateless and can
        run behind a load balancer with multiple replicas.
      </p>

      <h2 id="key-features">Key features</h2>
      <ul>
        <li>
          <strong>Guarded incident state machine</strong> — incidents follow a strict lifecycle:{' '}
          <code>open → investigating → contained → eradicating → recovering → closed</code>. The
          API enforces all transitions.
        </li>
        <li>
          <strong>CITADEL MARSHAL governance</strong> — every privileged action is evaluated
          through the 5-gate MARSHAL engine. A <code>REFUSE</code> or <code>HARD_STOP</code>{' '}
          outcome prevents local persistence and returns HTTP 403. CITADEL is never bypassed even
          when unreachable.
        </li>
        <li>
          <strong>CITADEL WORM anchoring</strong> — incident creation is anchored in the
          tamper-evident audit chain; the returned <code>worm_entry_id</code> is persisted on the
          incident record.
        </li>
        <li>
          <strong>NIS2 Article 23 notifications</strong> — regulatory-significant incidents
          (P1/P2/P3) trigger an asynchronous notification to the NIS2 Compass Article 21(2)(b)
          Incident Handling control. The async design ensures a slow Compass API can never block
          the incident creation path.
        </li>
        <li>
          <strong>Graph-based playbook executor</strong> — playbooks are defined as graphs with{' '}
          <code>OnSuccess</code> / <code>OnFailure</code> branching, per-step timeouts, and a
          cycle guard (max 100 steps per execution).
        </li>
        <li>
          <strong>HMAC-signed webhook ingestion</strong> — inbound events from APIGuard, CITADEL,
          and ThreatFlow are verified with HMAC-SHA256 and a ±5-minute replay protection window.
        </li>
        <li>
          <strong>IOC enrichment</strong> — incidents can have indicators of compromise (IOCs)
          attached and cross-referenced with ThreatFlow intelligence.
        </li>
        <li>
          <strong>JWT + RBAC</strong> — HS256 bearer tokens with five canonical roles:{' '}
          <code>admin</code>, <code>operator</code>, <code>verifier</code>, <code>viewer</code>,
          and <code>service</code>.
        </li>
        <li>
          <strong>Observability</strong> — Prometheus metrics at <code>/metrics</code>; structured
          JSON audit log with <code>request_id</code> propagation; the audit middleware fires{' '}
          <em>before</em> authentication so rejected requests are also logged.
        </li>
      </ul>

      <h2 id="architecture">Architecture</h2>
      <p>
        IRFlow has three concentric responsibility layers:
      </p>
      <ol>
        <li>
          <strong>Transport</strong> — a chi HTTP router with a middleware stack providing request
          IDs, audit logging, Prometheus metrics, JWT authentication, and HMAC verification for
          webhook routes.
        </li>
        <li>
          <strong>Domain services</strong> — <code>incident.Service</code> encodes lifecycle rules,
          Separation of Duties checks, and NIS2 notification thresholds.{' '}
          <code>playbook.Service</code> drives the graph-traversal executor.
        </li>
        <li>
          <strong>Persistence + governance</strong> — <code>PGStore</code> adapters backed by
          PostgreSQL 16 (pgxpool); <code>CitadelClient</code> for MARSHAL evaluation and WORM
          emission; <code>NIS2Client</code> for Article 23 notifications. All boundary crossings
          are HMAC-signed.
        </li>
      </ol>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Package</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            <tr><td><code>cmd/irflow</code></td><td>CLI: <code>serve</code>, <code>migrate</code>, <code>version</code>, <code>auth issue</code></td></tr>
            <tr><td><code>internal/api</code></td><td>chi router, middleware stack, HTTP handlers</td></tr>
            <tr><td><code>internal/auth</code></td><td>JWT verification, RBAC guards, audit logging</td></tr>
            <tr><td><code>internal/incident</code></td><td>Domain types, Service, governance interfaces, Stats</td></tr>
            <tr><td><code>internal/playbook</code></td><td>Domain types, Service, Executor (graph traversal)</td></tr>
            <tr><td><code>internal/governance</code></td><td>CitadelClient (MARSHAL + WORM), NIS2Client</td></tr>
            <tr><td><code>internal/db</code></td><td>pgxpool, PGStore (incidents), PGPlaybookStore</td></tr>
            <tr><td><code>internal/webhook</code></td><td>HMAC-SHA256 verifier and typed inbound payloads</td></tr>
          </tbody>
        </table>
      </div>

      <p>
        The service layer depends on interfaces defined next to its own domain types — not on
        concrete <code>db</code> or <code>governance</code> packages — so unit tests run against
        in-memory mocks and integration tests run against live PostgreSQL without changing any
        service code.
      </p>

      <h2 id="ports-endpoints">Ports &amp; endpoints</h2>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>Default port</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>IRFlow API</td>
              <td><code>8083</code></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Path</th>
              <th>Auth</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>GET</td><td><code>/health</code></td><td>public</td><td>Liveness check</td></tr>
            <tr><td>GET</td><td><code>/health/detail</code></td><td>public</td><td>Liveness + DB ping + version info</td></tr>
            <tr><td>GET</td><td><code>/metrics</code></td><td>public</td><td>Prometheus scrape endpoint</td></tr>
            <tr><td>POST</td><td><code>/api/v1/webhooks/apiguard</code></td><td>HMAC</td><td>Inbound APIGuard scan events</td></tr>
            <tr><td>POST</td><td><code>/api/v1/webhooks/citadel</code></td><td>HMAC</td><td>Inbound CITADEL governance events</td></tr>
            <tr><td>POST</td><td><code>/api/v1/webhooks/threatflow</code></td><td>HMAC</td><td>Inbound ThreatFlow IOC events</td></tr>
            <tr><td>GET / POST</td><td><code>/api/v1/incidents</code></td><td>JWT</td><td>List / create incidents</td></tr>
            <tr><td>GET / PATCH / DELETE</td><td><code>/api/v1/incidents/{'{id}'}</code></td><td>JWT</td><td>Fetch / update / delete incident</td></tr>
            <tr><td>POST / GET</td><td><code>/api/v1/incidents/{'{id}'}/actions</code></td><td>JWT</td><td>Submit / list governed actions</td></tr>
            <tr><td>GET</td><td><code>/api/v1/incidents/{'{id}'}/timeline</code></td><td>JWT</td><td>Chronological incident timeline</td></tr>
            <tr><td>POST / GET</td><td><code>/api/v1/incidents/{'{id}'}/iocs</code></td><td>JWT</td><td>Attach / list IOCs</td></tr>
            <tr><td>GET / POST</td><td><code>/api/v1/playbooks</code></td><td>JWT</td><td>List / create playbooks</td></tr>
            <tr><td>POST</td><td><code>/api/v1/playbooks/{'{id}'}/execute</code></td><td>JWT</td><td>Async execution; returns 202 + Execution</td></tr>
            <tr><td>GET</td><td><code>/api/v1/stats</code></td><td>JWT</td><td>Dashboard aggregation</td></tr>
          </tbody>
        </table>
      </div>

      <CodeBlock
        language="bash"
        filename="Quick start"
        code={`# Build and run
make build
./bin/irflow migrate
./bin/irflow serve

# Or with Docker
docker build -t irflow .
docker run -p 8083:8083 --env-file .env irflow

# Issue a dev JWT (local testing only)
export IRFLOW_AUTH_SECRET=local-secret
./bin/irflow auth issue --user alice --role operator --ttl 1h

# Hit a protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8083/api/v1/incidents`}
      />

      <h2 id="integration">Integration</h2>

      <h3>sinauth (identity)</h3>
      <p>
        IRFlow authenticates operators via <a href="/docs/identity"><strong>sinauth</strong></a> SSO — the SIN identity
        provider (OAuth 2.0 / OIDC, authorization code + PKCE). Access tokens are RS256-signed
        JWTs issued by <code>https://auth.sin.to</code> and validated against the sinauth JWKS
        endpoint at <code>https://auth.sin.to/.well-known/jwks.json</code>. See the{' '}
        <a href="https://github.com/opensecstack/opensecstack/tree/main/sinauth/docs/integration/irflow.md" target="_blank" rel="noopener noreferrer">
          sinauth integration guide
        </a>{' '}
        for token validation setup, RBAC mapping, and MFA configuration.
      </p>

      <h3>CITADEL (governance)</h3>
      <p>
        IRFlow integrates with <a href="/docs/governance">CITADEL</a> at two points. Every privileged action is evaluated by
        CITADEL <a href="/docs/citadel/marshal">MARSHAL</a> via a dual-control Kerkese call; a <code>REFUSE</code> or{' '}
        <code>HARD_STOP</code> outcome returns HTTP 403 and the action is never persisted locally.
        Incident creation is anchored in the CITADEL <a href="/docs/citadel/worm">WORM</a> audit chain. Set{' '}
        <code>IRFLOW_CITADEL_API_URL</code> and <code>IRFLOW_CITADEL_KEY_SECRET</code> in
        production — omitting these leaves IRFlow in dev mode where governance is not enforced.
      </p>

      <h3>NIS2 Compass (compliance)</h3>
      <p>
        When an incident with severity P1, P2, or P3 is created, IRFlow fires an asynchronous
        notification to <a href="/docs/platforms/nis2compass">NIS2 Compass</a> (<code>IRFLOW_NIS2_API_URL</code>) to update the Article
        21(2)(b) Incident Handling control. The notification has a 30-second per-attempt timeout;
        failures are logged and <code>nis2_notified_at</code> is only persisted on success.
      </p>

      <h3>APIGuard (API security)</h3>
      <p>
        IRFlow accepts HMAC-signed webhook events from <a href="/docs/platforms/apiguard">APIGuard</a> at{' '}
        <code>POST /api/v1/webhooks/apiguard</code>. Critical or high findings from APIGuard can
        automatically open new incidents or enrich existing ones. Configure the shared secret
        with <code>IRFLOW_WEBHOOK_APIGUARD_SECRET</code>.
      </p>

      <h3>ThreatFlow (threat intelligence)</h3>
      <p>
        IRFlow accepts HMAC-signed events from <a href="/docs/platforms/threatflow">ThreatFlow</a> at{' '}
        <code>POST /api/v1/webhooks/threatflow</code>. ThreatFlow also receives incident artefacts
        from IRFlow for retroactive IOC matching, and pushes STIX 2.1 IOC bundles back for
        incident enrichment. Configure the shared secret with{' '}
        <code>IRFLOW_WEBHOOK_THREATFLOW_SECRET</code>.
      </p>

      <div className="callout-note">
        <strong>Note:</strong> Minimum production configuration requires{' '}
        <code>IRFLOW_DB_PASSWORD</code>, <code>IRFLOW_AUTH_SECRET</code>,{' '}
        <code>IRFLOW_CITADEL_API_URL</code>, <code>IRFLOW_CITADEL_KEY_SECRET</code>,{' '}
        <code>IRFLOW_NIS2_API_URL</code>, <code>IRFLOW_NIS2_API_KEY</code>,{' '}
        <code>IRFLOW_NIS2_ASSESSMENT_ID</code>, and one webhook secret per integrated source.
        An empty <code>IRFLOW_AUTH_SECRET</code> enables dev mode — never use in production.
      </div>

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        The complete IRFlow documentation lives in the{' '}
        <a
          href="https://github.com/opensecstack/opensecstack/tree/main/irflow/docs"
          target="_blank"
          rel="noopener noreferrer"
        >
          irflow/docs
        </a>{' '}
        folder on GitHub. Key references:
      </p>
      <ul>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/irflow/docs/api.md" target="_blank" rel="noopener noreferrer">
            docs/api.md
          </a>{' '}
          — complete REST API reference with examples and Prometheus metrics catalogue
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/irflow/docs/architecture.md" target="_blank" rel="noopener noreferrer">
            docs/architecture.md
          </a>{' '}
          — component map, package layout, request lifecycle, and design decisions
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/irflow/CHANGELOG.md" target="_blank" rel="noopener noreferrer">
            CHANGELOG.md
          </a>{' '}
          — release history
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/irflow/SECURITY.md" target="_blank" rel="noopener noreferrer">
            SECURITY.md
          </a>{' '}
          — vulnerability reporting and threat model
        </li>
      </ul>
    </DocsLayout>
  )
}
