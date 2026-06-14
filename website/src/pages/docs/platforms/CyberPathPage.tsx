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

export default function CyberPathPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Platforms', 'CyberPath']}
      toc={toc}
      editPath="platforms/CyberPathPage.tsx"
      prev={{ label: 'OpenScrub', path: '/docs/platforms/openscrub' }}
      next={{ label: 'SecureLab', path: '/docs/platforms/securelab' }}
    >
      <h1>CyberPath</h1>
      <p>
        <strong>CyberPath</strong> is the security training and certification platform in the
        opensecstack (SIN) ecosystem. It delivers hands-on, lab-based cybersecurity training
        with cryptographically signed completion evidence anchored in the CITADEL WORM ledger —
        satisfying the immutable-record requirements that NIS2 Article 21(2)(g) auditors
        increasingly expect.
      </p>
      <p>
        CyberPath ships at <strong>v1.0.0</strong> (2026-05-09) under the Apache 2.0 licence.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        NIS2 Article 21(2)(g) requires essential and important entities to provide
        cybersecurity training to staff with documented evidence of completion. Existing
        learning management systems treat completion as a mutable database row. CyberPath
        treats it as immutable, signed, audit-grade evidence:
      </p>
      <ul>
        <li>
          Every lesson completion references the exact content revision the learner saw
          (Module 8 content versioning — append-only snapshots).
        </li>
        <li>
          Every completion emits a <code>cyberpath.completion</code> event, HMAC-SHA256
          signed, to the CITADEL WORM ledger via an async circuit-breaker queue.
        </li>
        <li>
          Each track-level certificate carries an Ed25519 signature over a canonical
          certification body, with the signing key held in a KMS-backed secret store.
        </li>
        <li>
          NIS2 Compass can query{' '}
          <code>GET /api/v1/cyberpath/coverage/{'{user_id}'}</code> to verify which
          Article 21 measures a user has produced training evidence for.
        </li>
      </ul>

      <div className="callout-note">
        <strong>NIS2 Article 21(2)(g):</strong> The CITADEL-anchored completion record lets
        auditors verify not just "did training happen?" but "which learner completed which
        lesson revision, with what score, at what time — and is that record tamper-evident?"
      </div>

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
              <td>Learning Path Engine</td>
              <td>
                Track / module / lesson sequencing with prerequisites and per-learner progress
                tracking
              </td>
            </tr>
            <tr>
              <td>Quiz &amp; Assessment Engine</td>
              <td>
                Knowledge-check assessments with randomised question banks and configurable
                pass thresholds
              </td>
            </tr>
            <tr>
              <td>Docker-based labs</td>
              <td>
                Per-session Docker containers with a browser terminal (xterm.js + WebSocket
                relay) for hands-on exercises requiring a full Linux environment
              </td>
            </tr>
            <tr>
              <td>Wasm sandbox labs</td>
              <td>
                Lower-overhead labs hosted by a Rust wasmtime runtime; pre-built lab images
                with SHA-256 checksums, per-session isolation, no host filesystem access, and
                resource caps via wasmtime fuel + memory limits
              </td>
            </tr>
            <tr>
              <td>Certification issuance</td>
              <td>
                Per-track certificates with Ed25519 signatures; key rotation procedure
                documented in <code>docs/operator-handbook.md</code>
              </td>
            </tr>
            <tr>
              <td>CITADEL evidence emitter</td>
              <td>
                Async <code>cyberpath.completion</code> event emission to CITADEL WORM;
                bounded queue + circuit breaker + 10 s drain on shutdown
              </td>
            </tr>
            <tr>
              <td>NIS2 Compass coverage API</td>
              <td>
                <code>/api/v1/cyberpath/coverage/{'{user_id}'}</code> — Article 21 measure
                coverage by user; <code>/api/v1/cyberpath/recommend?gap=art21_g</code> for
                gap-driven track recommendations
              </td>
            </tr>
            <tr>
              <td>Content versioning</td>
              <td>
                Immutable, append-only content snapshots; every completion record references
                the exact <code>content_version_id</code> the learner saw
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="architecture">Architecture</h2>
      <p>
        The platform consists of three main runtime components and three outbound integration
        targets.
      </p>
      <p>
        The <strong>Go API</strong> (chi router, pgx, zerolog, viper) runs on{' '}
        <code>:8086</code> and owns all business logic: path sequencing, quiz scoring, lab
        session management, certificate issuance, and CITADEL event emission. It uses the same
        stack as VertGuard and APIGuard for ecosystem consistency.
      </p>
      <p>
        The <strong>lab runtime</strong> sits behind the API over a WebSocket relay. For
        exercises that need a full Linux userspace the API spins up a per-session Docker
        container. For lighter exercises the Rust wasmtime host loads a pre-registered lab
        image, providing faster spinup (seconds vs. minutes) with strong isolation — no host
        filesystem access, bounded fuel and memory.
      </p>
      <p>
        The <strong>React + Vite frontend</strong> (<code>:3006</code>) provides the learner
        dashboard, lesson runner, quiz UI, and the xterm.js browser terminal for lab sessions.
        The UI is bilingual (Albanian + English).
      </p>
      <p>Outbound integrations:</p>
      <ul>
        <li>
          <a href="/docs/governance"><strong>CITADEL</strong></a> — receives <code>cyberpath.completion</code> events
          asynchronously after every lesson completion.
        </li>
        <li>
          <a href="/docs/platforms/nis2compass"><strong>NIS2 Compass</strong></a> — calls CyberPath synchronously to query coverage
          and fetch gap-driven track recommendations.
        </li>
        <li>
          <a href="/docs/platforms/irflow"><strong>IRFlow</strong></a> — pushes incident signals inbound to CyberPath; CyberPath
          maps incident type to a recommended training track.
        </li>
      </ul>
      <p>
        The <code>completions.evidence_hash</code> column stores a BLAKE3 hash of the
        canonical evidence body submitted to CITADEL, enabling independent audit verification
        without re-fetching from the ledger.
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
              <td><code>8086</code></td>
              <td>CyberPath REST API (Go)</td>
            </tr>
            <tr>
              <td><code>3006</code></td>
              <td>React learner dashboard (Vite / nginx)</td>
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
              <td><code>/api/v1/tracks</code></td>
              <td>List learning tracks</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/tracks/{'{id}'}</code></td>
              <td>Track detail</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/enrollments</code></td>
              <td>Enroll the caller in a track</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/lessons/{'{id}'}/complete</code></td>
              <td>Record lesson completion (emits CITADEL event)</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/quizzes/{'{id}'}/submit</code></td>
              <td>Submit quiz answers, receive score</td>
            </tr>
            <tr>
              <td><code>POST</code></td>
              <td><code>/api/v1/labs/{'{id}'}/start</code></td>
              <td>Start a sandbox lab session (Docker or wasmtime)</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/cyberpath/coverage/{'{user_id}'}</code></td>
              <td>NIS2 Article 21 measure coverage by user</td>
            </tr>
            <tr>
              <td><code>GET</code></td>
              <td><code>/api/v1/cyberpath/recommend</code></td>
              <td>Gap-driven track recommendation (<code>?gap=art21_g</code>)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="integration">Integration</h2>
      <p>
        CyberPath authenticates users via <a href="/docs/identity"><strong>sinauth</strong></a> SSO using the OAuth 2.0{' '}
        <code>authorization_code + PKCE (S256)</code> flow. The API validates RS256-signed
        tokens against the sinauth JWKS endpoint at{' '}
        <code>https://auth.sin.to/.well-known/jwks.json</code>.
      </p>
      <p>Minimum required environment variables:</p>
      <CodeBlock
        language="bash"
        filename=".env"
        code={`CYBERPATH_DB_URL=postgres://cyberpath:cyberpath@postgres:5432/cyberpath
CYBERPATH_HTTP_ADDR=:8086
CYBERPATH_CITADEL_API_URL=https://citadel.internal
CYBERPATH_CITADEL_KEY_SECRET=<hmac secret>
CYBERPATH_CITADEL_PROJECT_ID=<project id>
CYBERPATH_NIS2COMPASS_API_URL=https://nis2.internal
CYBERPATH_IRFLOW_API_URL=https://irflow.internal
CYBERPATH_IRFLOW_KEY_SECRET=<hmac secret>
CYBERPATH_LAB_RUNTIME=wasmtime
CYBERPATH_CERT_SIGNING_KEY=<KMS reference>`}
      />
      <p>Quick start with Docker Compose:</p>
      <CodeBlock
        language="bash"
        code={`git clone https://github.com/opensecstack/opensecstack
cd opensecstack/cyberpath

cp .env.example .env
docker compose up -d

# Health check
curl http://localhost:8086/api/v1/health

# List available learning tracks
curl http://localhost:8086/api/v1/tracks`}
      />

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        The complete CyberPath reference — module list, CITADEL integration schema, NIS2
        Compass integration, architecture, and operator handbook — is in the repository:
      </p>
      <p>
        <a
          href="https://github.com/opensecstack/opensecstack/tree/main/cyberpath/docs"
          target="_blank"
          rel="noopener noreferrer"
        >
          github.com/opensecstack/opensecstack/tree/main/cyberpath/docs
        </a>
      </p>
    </DocsLayout>
  )
}
