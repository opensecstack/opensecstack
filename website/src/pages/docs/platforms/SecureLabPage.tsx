import DocsLayout from '../DocsLayout'
import CodeBlock from '../../../components/CodeBlock'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'key-features', label: 'Key features' },
  { id: 'architecture', label: 'Architecture' },
  { id: 'ports-and-endpoints', label: 'Ports & endpoints' },
  { id: 'integration', label: 'Integration' },
  { id: 'full-documentation', label: 'Full documentation' },
]

export default function SecureLabPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'SecureLab']}
      toc={toc}
      editPath="platforms/SecureLabPage.tsx"
      prev={{ label: 'CyberPath', path: '/docs/platforms/cyberpath' }}
      next={{ label: 'OpenCSIRT', path: '/docs/platforms/opencsirt' }}
    >
      <h1>SecureLab</h1>
      <p>
        <strong>SecureLab</strong> is the attack simulation and detection validation platform
        in the opensecstack (SIN) ecosystem. It answers the question that detection stacks
        cannot answer themselves: <em>do your deployed defences actually fire when the
        technique is executed?</em> Scenarios are mapped to MITRE ATT&amp;CK, run inside
        isolated Docker networks, and every run emits immutable evidence to CITADEL.
      </p>

      <div className="callout-note">
        <strong>Safety notice:</strong> SecureLab contains offensive tooling. It must only be
        used against explicitly authorised test environments in an isolated network segment.
        Running attack scenarios against unauthorised systems is illegal and unethical. Read{' '}
        <code>docs/safety-controls.md</code> before executing any scenario.
      </div>

      <h2 id="overview">Overview</h2>
      <p>
        Detection rules degrade silently. Log pipelines change, field names are renamed, and
        a rule that matched in 2025 can fail with zero alert in 2027 without anyone noticing.
        SecureLab closes this gap with three complementary capabilities:
      </p>
      <ul>
        <li>
          <strong>Continuous detection validation.</strong> After each scenario run the
          detection validator polls OpenScrub, APIGuard, and ThreatFlow for expected alert
          events within a configurable window, returning a per-step{' '}
          <code>detected / not_detected / inconclusive</code> verdict.
        </li>
        <li>
          <strong>ATT&amp;CK coverage measurement.</strong> The MITRE ATT&amp;CK mapper
          builds a coverage matrix from executed scenarios — coverage is measured by
          execution outcome, not by rule existence.
        </li>
        <li>
          <strong>Immutable audit trail.</strong> Every live run emits a{' '}
          <code>securelab.run_completed</code> event (HMAC-SHA256 signed) to CITADEL, providing
          an externally verifiable record of all simulation activity including timed-out and
          blocked runs.
        </li>
      </ul>
      <p>
        SecureLab is licensed under <strong>Apache 2.0</strong>. Offensive tooling embedded
        in the platform does not grant authorisation to test systems you do not own or have
        explicit written permission to test.
      </p>

      <h2 id="key-features">Key features</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Module</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Scenario Engine</td>
              <td>
                Author, version, and execute multi-step YAML attack scenarios; content-hashed
                on write so every execution references an immutable scenario version
              </td>
            </tr>
            <tr>
              <td>Attack Library</td>
              <td>
                15 built-in attack primitives tagged with MITRE ATT&amp;CK technique IDs,
                tactics, and target platforms; extensible via YAML
              </td>
            </tr>
            <tr>
              <td>MITRE ATT&amp;CK Mapper</td>
              <td>
                Maps scenarios to techniques and sub-techniques; generates a coverage heatmap
                and gap analysis from execution history
              </td>
            </tr>
            <tr>
              <td>Detection Validator</td>
              <td>
                Polls <a href="/docs/platforms/openscrub">OpenScrub</a> (<code>/api/v1/alerts</code>), <a href="/docs/platforms/apiguard">APIGuard</a> (
                <code>/api/v1/anomalies</code>), and <a href="/docs/platforms/threatflow">ThreatFlow</a> (
                <code>/api/v1/ioc-matches</code>) read-only over HMAC-signed requests;
                returns per-step verdicts within a configurable detection window
              </td>
            </tr>
            <tr>
              <td>Payload Fuzzer</td>
              <td>
                Rust payload-generation crate (called via PyO3 / subprocess) generating
                encoding variants, byte mutations, and fuzzing campaigns to stress-test
                detection rule boundaries
              </td>
            </tr>
            <tr>
              <td>CITADEL Evidence Emitter</td>
              <td>
                Async <code>securelab.run_completed</code> events to <a href="/docs/governance">CITADEL</a> <a href="/docs/citadel/worm">WORM</a>; dry-run
                executions do not emit; circuit breaker marks runs <code>evidence_pending</code>{' '}
                if emission fails
              </td>
            </tr>
            <tr>
              <td>IRFlow Integration</td>
              <td>
                Pushes execution results and ATT&amp;CK coverage gaps to <a href="/docs/platforms/irflow">IRFlow</a> via{' '}
                <code>POST /api/v1/securelab/results</code> for incident-response correlation
              </td>
            </tr>
            <tr>
              <td>Safety controls</td>
              <td>
                Target URL blocklist, <code>--internal</code> Docker networks, per-attack-type
                rate caps, hard 30-minute scenario timeouts, admin-only environment creation,
                append-only audit log (Postgres row-level security), and pre-execution audit
                record creation — all non-bypassable at the platform level
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="architecture">Architecture</h2>
      <p>
        The v1.0.0 backend is written in <strong>Go</strong> (chi router, pgx, zap) and runs
        on <code>:8080</code>. The scenario engine and detection monitor run inside the same
        process; async scenario execution uses background goroutines with Redis-backed task
        state. The Rust <code>payload-gen</code> crate is compiled as a standalone library and
        invoked from Go via subprocess or shared-library binding.
      </p>
      <p>
        Test target environments are provisioned on Docker bridge networks with{' '}
        <code>internal: true</code> — target containers have no outbound internet access and
        cannot reach any host outside the isolated test network. This cannot be overridden via
        the SecureLab API.
      </p>
      <p>
        The platform enforces a strict security boundary: the API port (<code>8080</code>) and
        dashboard port (<code>3000</code>) must not be reachable from the public internet.
        Outbound from the Celery worker or detection monitor to integration endpoints must be
        allow-listed by IP and port at the firewall level.
      </p>
      <p>
        The <code>audit_log</code> table is INSERT-only at the database level (Postgres
        row-level security with <code>USING (false)</code> on UPDATE/DELETE for the API service
        role). Every scenario run is recorded <em>before execution begins</em>, so blocked and
        timed-out runs also have a complete audit trail.
      </p>
      <p>
        <code>executions.evidence_hash</code> stores a BLAKE3 hash of the canonical evidence
        body submitted to CITADEL, enabling independent audit verification.
      </p>

      <h2 id="ports-and-endpoints">Ports &amp; endpoints</h2>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>8080</code></td>
              <td>SecureLab REST API (Go — v1.0.0)</td>
            </tr>
            <tr>
              <td><code>3000</code></td>
              <td>React operator dashboard (nginx in production)</td>
            </tr>
            <tr>
              <td><code>8087</code></td>
              <td>SecureLab REST API (Python/FastAPI — scaffold reference)</td>
            </tr>
            <tr>
              <td><code>3007</code></td>
              <td>React operator dashboard (scaffold reference)</td>
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
              <th>Purpose</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/health</code></td>
              <td>Liveness + DB ping</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/scenarios</code></td>
              <td>List scenarios with ATT&amp;CK mapping</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/scenarios</code></td>
              <td>Create scenario (YAML body, content-hashed on write)</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/scenarios/{'{id}'}/execute</code></td>
              <td>Execute scenario — <code>dry_run: true</code> for plan-only</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/executions/{'{exec_id}'}</code></td>
              <td>Execution status and result</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/executions/{'{exec_id}'}/detections</code></td>
              <td>Per-step detection verdicts</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/coverage</code></td>
              <td>ATT&amp;CK technique coverage matrix</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/coverage/{'{technique_id}'}</code></td>
              <td>Coverage detail for one technique</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/attack-library</code></td>
              <td>List all attack primitives</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="integration">Integration</h2>
      <p>
        SecureLab authenticates dashboard users via <a href="/docs/identity"><strong>sinauth</strong></a> SSO using the
        OAuth 2.0 <code>authorization_code + PKCE (S256)</code> flow. The API validates
        RS256-signed tokens against the sinauth JWKS endpoint at{' '}
        <code>https://auth.sin.to/.well-known/jwks.json</code>.
      </p>
      <p>Minimum required environment variables:</p>
      <CodeBlock
        language="bash"
        filename=".env"
        code={`SECURELAB_DB_URL=postgres://securelab:securelab@postgres:5432/securelab
SECURELAB_REDIS_URL=redis://redis:6379/0
SECURELAB_CITADEL_API_URL=https://citadel.internal
SECURELAB_CITADEL_KEY_SECRET=<hmac secret>
SECURELAB_OPENSCRUB_API_URL=https://openscrub.internal
SECURELAB_APIGUARD_API_URL=https://apiguard.internal
SECURELAB_THREATFLOW_API_URL=https://threatflow.internal
SECURELAB_IRFLOW_API_URL=https://irflow.internal
SECURELAB_ISOLATION_MODE=strict
SECURELAB_CITADEL_DRY_RUN=false`}
      />
      <p>Quick start with Docker Compose:</p>
      <CodeBlock
        language="bash"
        code={`git clone https://github.com/opensecstack/opensecstack
cd opensecstack/securelab

cp .env.example .env
docker compose up -d

# Health check
curl http://localhost:8080/api/v1/health

# List available scenarios
curl -H "Authorization: Bearer $TOKEN" \\
     http://localhost:8080/api/v1/scenarios

# Dry-run a scenario (no payloads sent — plan only)
curl -X POST http://localhost:8080/api/v1/scenarios/api-bola-basic/execute \\
     -H "Authorization: Bearer $TOKEN" \\
     -H "Content-Type: application/json" \\
     -d '{"dry_run": true}'`}
      />
      <p>
        A YAML scenario maps each step to an attack primitive from the library with MITRE
        ATT&amp;CK technique IDs:
      </p>
      <CodeBlock
        language="yaml"
        filename="scenarios/api/bola-basic.yaml"
        code={`name: bola-basic
description: "BOLA via sequential integer ID enumeration on REST objects"
mitre_technique_ids: ["T1078"]
tags: [api, owasp-a1, bola]
severity: high
timeout: 3m
steps:
  - kind: bola
    params:
      endpoint: /api/v1/users/{id}
      id_range: [1, 100]
      auth_token_param: low_privilege_jwt`}
      />

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        The complete SecureLab reference — scenario specification, attack library, detection
        validation guide, safety controls, MITRE ATT&amp;CK mapping, CITADEL integration,
        and operator handbook — is in the repository:
      </p>
      <p>
        <a
          href="https://github.com/opensecstack/opensecstack/tree/main/securelab/docs"
          target="_blank"
          rel="noopener noreferrer"
        >
          github.com/opensecstack/opensecstack/tree/main/securelab/docs
        </a>
      </p>
    </DocsLayout>
  )
}
