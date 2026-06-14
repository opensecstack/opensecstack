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

export default function ApiGuardPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'APIGuard']}
      toc={toc}
      editPath="platforms/ApiGuardPage.tsx"
      prev={{ label: 'Platforms Overview', path: '/docs/platforms' }}
      next={{ label: 'NIS2 Compass', path: '/docs/platforms/nis2compass' }}
    >
      <h1>APIGuard</h1>
      <p>
        <strong>APIGuard</strong> is the API security testing platform in the opensecstack
        ecosystem. Point it at any OpenAPI, Swagger, or GraphQL schema, and it runs a full{' '}
        <strong>OWASP API Top 10</strong> security assessment against your live API endpoints,
        producing CVSS 3.1-scored findings in HTML, PDF, JSON, or SARIF format.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        APIGuard is licensed under <strong>Apache-2.0</strong> and is built for both local
        developer use and CI/CD pipeline automation. It ships as a single Go binary and a React
        dashboard backed by PostgreSQL. No telemetry, no SaaS requirement.
      </p>
      <p>
        The platform covers all ten OWASP API Security Top 10 (2023) categories — from Broken
        Object Level Authorization (A1) to Unsafe Consumption of APIs (A10) — and maps every
        finding to NIS2 Article 21 security measures for compliance evidence.
      </p>

      <h2 id="key-features">Key features</h2>
      <ul>
        <li>
          <strong>Full OWASP API Top 10 coverage</strong> — all ten categories (A1–A10) implemented
          and enabled by default (A6 and A10 require additional configuration).
        </li>
        <li>
          <strong>Multi-format schema support</strong> — parses OpenAPI 3.x, Swagger 2.x, and
          GraphQL schemas via a Rust-based parser that never panics on malformed input.
        </li>
        <li>
          <strong>CVSS 3.1 scoring</strong> — every finding receives a deterministic CVSS 3.1
          score computed by a dedicated Rust scorer.
        </li>
        <li>
          <strong>Multiple output formats</strong> — HTML and PDF for human review (Python + Jinja2),
          JSON and SARIF for machine consumption and GitHub Advanced Security upload.
        </li>
        <li>
          <strong>Flexible authentication</strong> — supports Bearer token, JWT, OAuth2
          (client_credentials / authorization_code), API key, and HTTP Basic auth for the target API.
        </li>
        <li>
          <strong>CI/CD integration</strong> — ships a GitHub Action (<code>opensecstack/apiguard-action@v1</code>)
          and supports GitLab CI and Jenkins natively.
        </li>
        <li>
          <strong>Scan history dashboard</strong> — React UI on port 3000 shows scan trends,
          finding regressions, and API inventory.
        </li>
        <li>
          <strong>NIS2 Directive mapping</strong> — findings are mapped to NIS2 Article 21
          measures to produce compliance evidence artefacts.
        </li>
      </ul>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>OWASP ID</th>
              <th>Vulnerability</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>A1</td><td>Broken Object Level Authorization (BOLA)</td><td>Implemented</td></tr>
            <tr><td>A2</td><td>Broken Authentication</td><td>Implemented</td></tr>
            <tr><td>A3</td><td>Broken Object Property Level Authorization</td><td>Implemented</td></tr>
            <tr><td>A4</td><td>Unrestricted Resource Consumption</td><td>Implemented</td></tr>
            <tr><td>A5</td><td>Broken Function Level Authorization</td><td>Implemented</td></tr>
            <tr><td>A6</td><td>Unrestricted Access to Sensitive Flows</td><td>Implemented</td></tr>
            <tr><td>A7</td><td>Server Side Request Forgery (SSRF)</td><td>Implemented</td></tr>
            <tr><td>A8</td><td>Security Misconfiguration</td><td>Implemented</td></tr>
            <tr><td>A9</td><td>Improper Inventory Management</td><td>Implemented</td></tr>
            <tr><td>A10</td><td>Unsafe Consumption of APIs</td><td>Implemented</td></tr>
          </tbody>
        </table>
      </div>

      <h2 id="architecture">Architecture</h2>
      <p>
        APIGuard is a ten-layer pipeline. Each layer has a single responsibility and a defined
        input/output contract — no layer knows the internals of another, making every layer
        independently testable and replaceable.
      </p>
      <p>
        <strong>Rust</strong> handles all untrusted input and high-throughput analysis: the schema
        parser (L1), test generator (L2), response analyser (L5), and CVSS scorer (L6). Memory
        safety eliminates buffer-overflow vulnerabilities when processing schemas from arbitrary
        sources. <strong>Go</strong> handles concurrent HTTP execution (L3), auth token lifecycle
        management (L4), report generation for machine formats (L7), persistence (L8), and the CLI
        (L10). The React dashboard (L9) is SELECT-only against PostgreSQL via row-level security.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Layer</th>
              <th>Language</th>
              <th>Responsibility</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>L1 Schema Parser</td><td>Rust</td><td>Parse OpenAPI/Swagger/GraphQL safely into the APIGuard IR</td></tr>
            <tr><td>L2 Test Generator</td><td>Rust + Go</td><td>Generate test case specs per endpoint per OWASP module</td></tr>
            <tr><td>L3 OWASP Modules</td><td>Rust + Go</td><td>Concurrent HTTP execution and response analysis for A1–A10</td></tr>
            <tr><td>L4 Auth Handler</td><td>Go</td><td>Token lifecycle, refresh, multi-step auth flows</td></tr>
            <tr><td>L5 Response Analyser</td><td>Rust</td><td>Pattern matching, timing analysis, vulnerability detection</td></tr>
            <tr><td>L6 CVSS Scorer</td><td>Rust</td><td>Deterministic CVSS 3.1 scoring per finding</td></tr>
            <tr><td>L7 Report Generator</td><td>Python + Go</td><td>HTML/PDF (Jinja2) and JSON/SARIF output</td></tr>
            <tr><td>L8 Persistence</td><td>PostgreSQL</td><td>Scan history, finding trends, regression detection</td></tr>
            <tr><td>L9 Dashboard</td><td>React</td><td>Interactive scan history, inventory, team management UI</td></tr>
            <tr><td>L10 CLI</td><td>Go</td><td>Single binary for CI/CD and local use</td></tr>
          </tbody>
        </table>
      </div>

      <h2 id="ports-endpoints">Ports &amp; endpoints</h2>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>Default port</th>
              <th>Env var</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>APIGuard API server</td>
              <td><code>8080</code></td>
              <td><code>APIGUARD_PORT</code></td>
            </tr>
            <tr>
              <td>React dashboard UI</td>
              <td><code>3000</code></td>
              <td><code>APIGUARD_DASHBOARD_PORT</code></td>
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
            <tr><td>GET</td><td><code>/api/v1/health</code></td><td>public</td><td>Liveness check</td></tr>
            <tr><td>POST</td><td><code>/api/v1/scans</code></td><td>JWT</td><td>Start a new scan</td></tr>
            <tr><td>GET</td><td><code>/api/v1/scans</code></td><td>JWT</td><td>List scan history</td></tr>
            <tr><td>GET</td><td><code>/api/v1/scans/{'{id}'}</code></td><td>JWT</td><td>Fetch a single scan result</td></tr>
            <tr><td>GET</td><td><code>/api/v1/scans/{'{id}'}/report</code></td><td>JWT</td><td>Download report (format via query param)</td></tr>
            <tr><td>POST</td><td><code>/api/v1/auth/logout</code></td><td>JWT</td><td>Add token to access-token denylist</td></tr>
          </tbody>
        </table>
      </div>

      <p>
        The full REST API reference is at <code>http://localhost:8080/api/v1/docs</code> when
        the server is running. See{' '}
        <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/api.md" target="_blank" rel="noopener noreferrer">
          docs/api.md
        </a>{' '}
        for the complete endpoint catalogue.
      </p>

      <h2 id="integration">Integration</h2>

      <h3>sinauth (identity)</h3>
      <p>
        APIGuard delegates all user authentication to <a href="/docs/identity"><strong>sinauth</strong></a> via OpenID Connect
        (authorization code + PKCE). ID and access tokens are RS256-signed and validated against
        the sinauth JWKS endpoint (<code>https://auth.sin.to/.well-known/jwks.json</code>). The
        web dashboard uses <code>sinauth.ts</code> for popup-based login and an{' '}
        <code>AuthCallback</code> page. A <code>POST /api/v1/auth/logout</code> endpoint maintains
        an access-token denylist for explicit revocation.
      </p>

      <h3>CITADEL (governance)</h3>
      <p>
        APIGuard emits scan lifecycle events — <code>scan_started</code>,{' '}
        <code>scan_completed</code>, <code>finding_critical</code>, and{' '}
        <code>finding_high</code> — to the <a href="/docs/governance">CITADEL</a> <a href="/docs/citadel/worm">WORM</a> audit chain via a one-way outbound
        webhook. CITADEL cannot write back to APIGuard scan data. Configure with{' '}
        <code>CITADEL_WEBHOOK_URL</code> and <code>CITADEL_API_KEY</code>.
      </p>

      <h3>IRFlow (incident response)</h3>
      <p>
        APIGuard sends HMAC-SHA256 signed webhook events to <a href="/docs/platforms/irflow">IRFlow</a> when critical or high findings
        are detected, allowing IRFlow to automatically open or update security incidents. IRFlow
        listens on <code>POST /api/v1/webhooks/apiguard</code> with replay protection (±5 min
        window).
      </p>

      <h3>ThreatFlow (threat intelligence)</h3>
      <p>
        APIGuard sends scan target URLs and discovered API endpoints to <a href="/docs/platforms/threatflow">ThreatFlow</a> for IOC
        matching. ThreatFlow in turn enriches APIGuard scans with known-malicious URL and IP
        indicators from its STIX 2.1 bundle store.
      </p>

      <h3>NIS2 Compass (compliance)</h3>
      <p>
        APIGuard findings are mapped to <a href="/docs/nis2">NIS2</a> Article 21 security measures. See{' '}
        <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/nis2-mapping.md" target="_blank" rel="noopener noreferrer">
          docs/nis2-mapping.md
        </a>{' '}
        for the full compliance evidence mapping.
      </p>

      <div className="callout-note">
        <strong>Note:</strong> All inter-platform communication uses HMAC-SHA256 signed payloads
        over the typed <code>opensecstack/sdk</code> contracts. See{' '}
        <a href="/docs/contracts">SDK &amp; Contracts</a> for the event schemas.
      </div>

      <h3>Quick start</h3>
      <CodeBlock
        language="bash"
        filename=".github/workflows/api-security.yml (excerpt)"
        code={`# Run a scan locally
apiguard scan \\
  --spec ./api/openapi.yaml \\
  --target http://localhost:8080 \\
  --format html \\
  --output report.html

# Or use the GitHub Action
- uses: opensecstack/apiguard-action@v1
  with:
    spec: ./api/openapi.yaml
    target: \${{ secrets.API_TARGET_URL }}
    fail-on: HIGH
    format: sarif
    output: apiguard-results.sarif`}
      />

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        The complete APIGuard documentation lives in the{' '}
        <a
          href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs"
          target="_blank"
          rel="noopener noreferrer"
        >
          apiguard/docs
        </a>{' '}
        folder on GitHub. Key references:
      </p>
      <ul>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/quick-start.md" target="_blank" rel="noopener noreferrer">
            quick-start.md
          </a>{' '}
          — from zero to first scan in 5 minutes
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/architecture.md" target="_blank" rel="noopener noreferrer">
            architecture.md
          </a>{' '}
          — layered pipeline design and component responsibilities
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/api.md" target="_blank" rel="noopener noreferrer">
            api.md
          </a>{' '}
          — full REST API reference
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/configuration.md" target="_blank" rel="noopener noreferrer">
            configuration.md
          </a>{' '}
          — all CLI flags, environment variables, and config file options
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/owasp-coverage.md" target="_blank" rel="noopener noreferrer">
            owasp-coverage.md
          </a>{' '}
          — detection methods, confidence levels, known false positives
        </li>
        <li>
          <a href="https://github.com/opensecstack/opensecstack/tree/main/apiguard/docs/cicd-integration.md" target="_blank" rel="noopener noreferrer">
            cicd-integration.md
          </a>{' '}
          — GitHub Actions, GitLab CI, and Jenkins examples
        </li>
      </ul>
    </DocsLayout>
  )
}
