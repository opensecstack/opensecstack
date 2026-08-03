import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'key-features', label: 'Key features' },
  { id: 'architecture', label: 'Architecture' },
  { id: 'ports-endpoints', label: 'Ports & endpoints' },
  { id: 'integration', label: 'Integration' },
  { id: 'full-documentation', label: 'Full documentation' },
]

export default function Nis2CompassPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'NIS2 Compass']}
      toc={toc}
      editPath="platforms/Nis2CompassPage.tsx"
      prev={{ label: 'APIGuard', path: '/docs/platforms/apiguard' }}
      next={{ label: 'IRFlow', path: '/docs/platforms/irflow' }}
    >
      <Helmet>
        <title>NIS2 Compass — Compliance Management | opensecstack Docs</title>
        <meta
          name="description"
          content="NIS2 Compass helps organisations subject to the EU NIS2 Directive manage Article 21(2) security measures, compliance evidence, and Article 23 incident notification."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/platforms/nis2compass" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/platforms/nis2compass" />
        <meta property="og:title" content="NIS2 Compass — Compliance Management | opensecstack Docs" />
        <meta
          property="og:description"
          content="NIS2 Compass helps organisations subject to the EU NIS2 Directive manage Article 21(2) security measures, compliance evidence, and Article 23 incident notification."
        />
      </Helmet>
      <h1>NIS2 Compass</h1>
      <p>
        <strong>NIS2 Compass</strong> is the compliance management platform in the opensecstack
        ecosystem. It helps organisations subject to the EU NIS2 Directive (Directive 2022/2555)
        assess, track, and demonstrate adherence to the ten cybersecurity risk-management measures
        defined in <strong>Article 21(2)</strong>, and supports the incident notification obligations
        in Article 23.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        NIS2 Compass exposes a REST API on <strong>port 8090</strong>, backed by a Python/Flask
        application, PostgreSQL 16 as the primary data store, and Redis 7 for caching and session
        state. Schema migrations are managed by Alembic and applied automatically at container
        startup. An audit subsystem implements the CITADEL WORM append-only log pattern, producing
        tamper-evident evidence chains suitable for regulatory inspection.
      </p>
      <p>
        The platform is licensed under <strong>Apache-2.0</strong> and is self-hosted with no
        external SaaS dependency.
      </p>

      <h2 id="key-features">Key features</h2>
      <ul>
        <li>
          <strong>Ten-control template library</strong> — a canonical reference of all ten NIS2
          Article 21(2) measures (a)–(j), seeded into every deployment.
        </li>
        <li>
          <strong>Structured assessment workflow</strong> — assessments progress through a guarded
          state machine: <code>draft → in_progress → under_review → completed → archived</code>.
          Each transition is enforced by the API.
        </li>
        <li>
          <strong>Per-control evidence tracking</strong> — each control stores compliance status,
          JSONB evidence references, risk score, gap description, remediation plan, and reviewer
          notes.
        </li>
        <li>
          <strong>Content-addressed artefact storage</strong> — evidence files are hashed with
          SHA-256 on upload; duplicate detection and integrity verification are built-in.
        </li>
        <li>
          <strong>CITADEL WORM audit chain</strong> — every write appends a cryptographically
          linked row to <code>audit_log</code>. A PostgreSQL trigger blocks any UPDATE or DELETE,
          making the chain tamper-evident at the database layer.
        </li>
        <li>
          <strong>NIST CSF category mapping</strong> — each NIS2 Article 21(2) control is mapped
          to a NIST Cybersecurity Framework function (identify, protect, detect, respond, recover)
          for cross-framework reporting.
        </li>
        <li>
          <strong>IRFlow Article 23 notifications</strong> — IRFlow notifies NIS2 Compass
          asynchronously when a regulatory-significant incident (P1/P2/P3) is created, updating
          the Article 21(2)(b) Incident Handling control with evidence.
        </li>
      </ul>

      <h2 id="architecture">Architecture</h2>
      <p>
        The platform consists of five components, started in a defined dependency order enforced
        by Docker Compose <code>depends_on</code> conditions:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Component</th>
              <th>Technology</th>
              <th>Responsibility</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>REST API</td>
              <td>Python / Flask</td>
              <td>Assessment CRUD, control status updates, artefact upload, audit writes</td>
            </tr>
            <tr>
              <td>Database</td>
              <td>PostgreSQL 16</td>
              <td>Primary data store — organisations, assessments, controls, artefacts, audit_log</td>
            </tr>
            <tr>
              <td>Cache / Sessions</td>
              <td>Redis 7</td>
              <td>Rate limiting, session state, background job queuing</td>
            </tr>
            <tr>
              <td>Migration runner</td>
              <td>Alembic</td>
              <td>Schema versioning, applied automatically on startup</td>
            </tr>
            <tr>
              <td>Seed scripts</td>
              <td>Python / psycopg2</td>
              <td>Control template library and sample data (development only)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        The database schema uses six core tables. The <code>audit_log</code> table is immutable:
        a PostgreSQL trigger raises an exception on any UPDATE or DELETE attempt, regardless of
        the caller's privileges. Each audit row records a SHA-256 chain hash over its own fields
        plus the preceding row's hash, forming a linked structure where any retroactive alteration
        produces a detectable break.
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
              <td>NIS2 Compass API</td>
              <td><code>8090</code></td>
            </tr>
            <tr>
              <td>Dashboard UI</td>
              <td><code>3001</code></td>
            </tr>
            <tr>
              <td>pgAdmin (dev only)</td>
              <td><code>5051</code></td>
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
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>GET</td><td><code>/health</code></td><td>Liveness check — returns <code>&#123;"status": "ok"&#125;</code></td></tr>
            <tr><td>GET</td><td><code>/api/v1/controls</code></td><td>List all Article 21(2) control templates</td></tr>
            <tr><td>GET</td><td><code>/api/v1/organisations</code></td><td>List organisations</td></tr>
            <tr><td>POST</td><td><code>/api/v1/organisations</code></td><td>Register a new organisation</td></tr>
            <tr><td>GET</td><td><code>/api/v1/organisations/{'{id}'}/assessments</code></td><td>List assessments for an organisation</td></tr>
            <tr><td>POST</td><td><code>/api/v1/organisations/{'{id}'}/assessments</code></td><td>Create a new assessment</td></tr>
            <tr><td>GET</td><td><code>/api/v1/assessments/{'{id}'}/controls</code></td><td>List controls for an assessment</td></tr>
            <tr><td>PATCH</td><td><code>/api/v1/assessments/{'{id}'}/controls/{'{ref}'}</code></td><td>Update control status and evidence</td></tr>
          </tbody>
        </table>
      </div>

      <p>
        The full OpenAPI specification is available at{' '}
        <code>http://localhost:8090/docs</code> when the API is running.
      </p>

      <CodeBlock
        language="bash"
        filename="Quick start"
        code={`# Start the development stack
git clone https://github.com/opensecstack/opensecstack.git
cd opensecstack/nis2compass
docker compose -f docker-compose.dev.yml up --build

# Verify the API is up
curl http://localhost:8090/health
# {"status": "ok"}`}
      />

      <h2 id="integration">Integration</h2>

      <h3>sinauth (identity)</h3>
      <p>
        NIS2 Compass authenticates users via <a href="/docs/identity"><strong>sinauth</strong></a> SSO using OpenID Connect
        (authorization code + PKCE). RS256-signed tokens are validated against the sinauth JWKS
        endpoint via <code>app/sinauth.py</code>. The web dashboard uses <code>sinauth.ts</code>{' '}
        for popup-based login and handles the OIDC callback. See the{' '}
        <a href="https://github.com/opensecstack/opensecstack/tree/main/sinauth/docs/integration/nis2compass.md" target="_blank" rel="noopener noreferrer">
          sinauth integration guide
        </a>{' '}
        for setup details.
      </p>

      <h3>CITADEL (governance)</h3>
      <p>
        Every write operation appends a row to the <a href="/docs/citadel/worm">WORM</a> <code>audit_log</code> table. The chain
        hash construction uses SHA-256 over the row's fields plus the preceding row's hash,
        producing a tamper-evident ledger. Immutability is enforced at both the application layer
        and the database layer via a PostgreSQL trigger. This satisfies the evidentiary requirements
        of <a href="/docs/nis2">NIS2</a> Article 21 and Article 23 audits.
      </p>

      <h3>IRFlow (incident response)</h3>
      <p>
        <a href="/docs/platforms/irflow">IRFlow</a> notifies NIS2 Compass asynchronously via{' '}
        <code>IRFLOW_NIS2_API_URL</code> when a regulatory-significant incident (P1, P2, or P3)
        is created. The notification updates the Article 21(2)(b) Incident Handling control with
        incident evidence. The async design means a slow NIS2 Compass API can never block the
        incident creation path in IRFlow.
      </p>

      <h3>APIGuard (API security)</h3>
      <p>
        <a href="/docs/platforms/apiguard">APIGuard</a> scan findings are mapped to NIS2 Article 21 measures and can be submitted as
        control evidence. See{' '}
        <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/nis2-mapping.md" target="_blank" rel="noopener noreferrer">
          apiguard/docs/nis2-mapping.md
        </a>{' '}
        for the full mapping.
      </p>

      <h3>ThreatFlow (threat intelligence)</h3>
      <p>
        <a href="/docs/platforms/threatflow">ThreatFlow</a> forwards supply chain IOCs to NIS2 Compass as evidence artefacts for the
        Article 21(2)(d) supply chain security control, in STIX 2.1 format.
      </p>

      <div className="callout-note">
        <strong>Note:</strong> Production deployments require five mandatory environment variables:
        <code> POSTGRES_PASSWORD</code>, <code>NIS2_DB_PASSWORD</code>,{' '}
        <code>REDIS_PASSWORD</code>, <code>NIS2_SECRET_KEY</code>, and{' '}
        <code>NIS2_JWT_SECRET</code>. The Compose file will refuse to start if any are absent.
      </div>

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        The complete NIS2 Compass documentation lives in the{' '}
        <a
          href="https://github.com/opensecstack/opensecstack/tree/main/nis2compass/docs"
          target="_blank"
          rel="noopener noreferrer"
        >
          nis2compass/docs
        </a>{' '}
        folder on GitHub. Key references:
      </p>
      <ul>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/nis2compass/docs/quick-start.md" target="_blank" rel="noopener noreferrer">
            quick-start.md
          </a>{' '}
          — zero-to-first-assessment guide
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/nis2compass/docs/architecture.md" target="_blank" rel="noopener noreferrer">
            architecture.md
          </a>{' '}
          — Flask API, PostgreSQL, Redis, Alembic, and CITADEL WORM design
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/nis2compass/docs/api-reference.md" target="_blank" rel="noopener noreferrer">
            api-reference.md
          </a>{' '}
          — full REST API reference
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/nis2compass/docs/nis2-controls-reference.md" target="_blank" rel="noopener noreferrer">
            nis2-controls-reference.md
          </a>{' '}
          — canonical reference for all ten Article 21(2) measures
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/nis2compass/docs/assessment-workflow.md" target="_blank" rel="noopener noreferrer">
            assessment-workflow.md
          </a>{' '}
          — step-by-step compliance assessment walkthrough
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/nis2compass/docs/configuration.md" target="_blank" rel="noopener noreferrer">
            configuration.md
          </a>{' '}
          — environment variable reference for all runtime configuration
        </li>
      </ul>
    </DocsLayout>
  )
}
