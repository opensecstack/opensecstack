import DocsLayout from './DocsLayout'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'three-layers', label: 'Three layers' },
  { id: 'language-per-layer', label: 'Language per layer' },
  { id: 'data-persistence', label: 'Data persistence' },
  { id: 'data-flow', label: 'Data flow example' },
  { id: 'time-dimension-segmentation', label: 'Time Dimension Segmentation' },
]

export default function ArchitecturePage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Architecture', 'Overview']}
      toc={toc}
      editPath="ArchitecturePage.tsx"
      prev={{ label: 'Local Development', path: '/docs/local-dev' }}
      next={{ label: 'SDK & Contracts', path: '/docs/contracts' }}
    >
      <Helmet>
        <title>Architecture Overview | opensecstack Docs</title>
        <meta
          name="description"
          content="How opensecstack's three layers fit together: the 11 security platforms, the typed opensecstack/sdk contract layer, and the sinauth identity and CITADEL governance cross-cutting layers."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/architecture" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/architecture" />
        <meta property="og:title" content="Architecture Overview | opensecstack Docs" />
        <meta
          property="og:description"
          content="How opensecstack's three layers fit together: the 11 security platforms, the typed opensecstack/sdk contract layer, and the sinauth identity and CITADEL governance cross-cutting layers."
        />
      </Helmet>
      <h1>Architecture Overview</h1>
      <p>
        opensecstack is structured as three concentric layers: the <strong>11 security
        platforms</strong> that do the work, the <strong>opensecstack/sdk</strong> that
        connects them through typed contracts, and two cross-cutting infrastructure layers —
        <strong> sinauth</strong> for identity and <strong>CITADEL</strong> for cryptographic
        governance. Every privileged action across the stack passes through CITADEL; every
        user and operator authenticates through sinauth.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        The platforms cover the full security lifecycle: API security testing, NIS2
        compliance, incident response, threat intelligence, DDoS mitigation, security
        training, attack simulation, CSIRT operations, AI-attack defence, and a developer
        knowledge hub. They communicate exclusively through the SDK — never through
        ad-hoc HTTP calls or shared database tables.
      </p>
      <p>
        All platforms share a single PostgreSQL 16 persistence model, a single sinauth
        identity provider (single sign-on), and a single CITADEL governance engine
        (append-only WORM audit chain). There is no vendor lock-in and no required SaaS
        dependency.
      </p>

      <h2 id="three-layers">Three layers</h2>

      <h3>Platform layer — the 11 security platforms</h3>
      <p>
        Each platform has a defined scope and emits typed SDK events when significant things
        happen (scan completed, incident opened, compliance control updated, and so on). A
        full list with stacks and licences is on the <a href="/docs/platforms">Platforms
        Overview</a> page.
      </p>

      <h3>SDK contract layer</h3>
      <p>
        The <code>opensecstack/sdk</code> provides typed clients in <a href="/docs/sdk/go">Go</a>, <a href="/docs/sdk/python">Python</a>, <a href="/docs/sdk/typescript">TypeScript</a>,
        and <a href="/docs/sdk/rust">Rust</a>. All inter-platform communication uses the typed event schemas defined in
        the SDK. This means a consumer of a <code>ScanResult</code> never needs to know
        which version of APIGuard produced it — the contract absorbs the change. See
        <a href="/docs/contracts"> SDK &amp; Contracts</a> for the full event schema table
        and usage examples.
      </p>

      <h3>Cross-cutting layers</h3>
      <p>
        Beneath the platforms and SDK sit the two layers every platform depends on:
      </p>
      <ul>
        <li>
          <strong>sinauth</strong> — the identity layer. An OAuth 2.0 / OpenID Connect
          authorization server: RS256-signed ID and access tokens, JWKS endpoint at
          <code> https://auth.sin.to/.well-known/jwks.json</code>, authorization-code +
          PKCE (S256) flow, TOTP MFA, and social login (Google, GitHub). Every platform
          validates sinauth-issued tokens against the JWKS endpoint instead of maintaining
          its own user credentials. See <a href="/docs/identity">Identity (sinauth)</a>.
        </li>
        <li>
          <strong>CITADEL</strong> — the governance layer. Every privileged action is
          evaluated by the <a href="/docs/citadel/marshal">MARSHAL</a> 5-gate engine (Authority → Scope → Determinism →
          Evidence → Schema) and the outcome — EXECUTE, REFUSE, or HARD STOP — is written
          into an append-only <a href="/docs/citadel/worm">WORM</a> audit chain with TripleHash integrity (SHA-256 +
          SHA-512 + BLAKE3) and Ed25519-signed chain anchors every 100 entries. See
          <a href="/docs/governance"> Governance (CITADEL)</a>.
        </li>
      </ul>

      <h2 id="language-per-layer">Language per layer</h2>
      <p>
        opensecstack uses the right language for each concern rather than a single runtime.
        This is formalised in ADR-001 (Rust for parsing) and ADR-002 (Go for HTTP/orchestration).
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Concern</th>
              <th>Language</th>
              <th>Rationale</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>HTTP services, orchestration, CLI</td>
              <td><strong>Go</strong></td>
              <td>Goroutines for concurrency, single-binary deployment, mature ecosystem</td>
            </tr>
            <tr>
              <td>Parsing untrusted input, crypto, regex-heavy analysis</td>
              <td><strong>Rust</strong></td>
              <td>Memory safety for security-critical code; performance for high-throughput paths</td>
            </tr>
            <tr>
              <td>ML inference, data science, report templates</td>
              <td><strong>Python</strong></td>
              <td>HuggingFace ecosystem, pandas, Jinja2, scikit-learn</td>
            </tr>
            <tr>
              <td>Dashboards and UIs</td>
              <td><strong>React + TypeScript</strong></td>
              <td>Component ecosystem, type safety, developer familiarity</td>
            </tr>
            <tr>
              <td>Kernel-level packet processing</td>
              <td><strong>C + Rust/Aya</strong></td>
              <td>XDP/eBPF requires C or Rust/Aya for kernel programs</td>
            </tr>
            <tr>
              <td>Data persistence</td>
              <td><strong>PostgreSQL 16+</strong></td>
              <td>JSONB for flexible storage, row-level security, WORM tables for CITADEL</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="data-persistence">Data persistence</h2>
      <p>
        Every platform uses <strong>PostgreSQL 16+</strong> as its primary store. CITADEL
        uses append-only WORM tables enforced at the database level — rows can be inserted
        but never updated or deleted, which provides the tamper-resistance the audit chain
        requires. Flexible event payloads are stored as JSONB columns, and row-level
        security isolates multi-tenant data where applicable.
      </p>

      <h2 id="data-flow">Data flow example</h2>
      <p>
        A typical integration — from an API security scan to a NIS2 compliance evidence
        record — looks like this:
      </p>
      <ol>
        <li>A developer pushes an OpenAPI spec to the CI pipeline.</li>
        <li><a href="/docs/platforms/apiguard">APIGuard</a> scans it and produces a <code>ScanResult</code> with findings and CVSS scores.</li>
        <li>APIGuard emits a <code>scan_completed</code> event to the CITADEL WORM log.</li>
        <li>APIGuard exports a NIS2 evidence bundle.</li>
        <li><a href="/docs/platforms/nis2compass">NIS2 Compass</a> receives the bundle and attaches it to the Art. 21(2)(e) control.</li>
        <li>NIS2 Compass emits a <code>control_updated</code> event to the CITADEL WORM log.</li>
        <li>An <a href="/docs/citadel/evidence">auditor</a> verifies the unbroken chain in CITADEL.</li>
      </ol>
      <p>
        Parallel flows include: APIGuard CRITICAL findings auto-creating incidents in
        <a href="/docs/platforms/irflow">IRFlow</a>; <a href="/docs/platforms/threatflow">ThreatFlow</a> IOC bundles triggering automatic IP blocks in <a href="/docs/platforms/openscrub">OpenScrub</a>; and
        <a href="/docs/platforms/cyberpath">CyberPath</a> training completions providing NIS2 Art. 21(2)(g) evidence records.
        The full data-flow map is in <code>ECOSYSTEM.md</code> in the repository.
      </p>

      <h2 id="time-dimension-segmentation">Time Dimension Segmentation</h2>
      <p>
        All platforms classify operations by latency tier (<a href="/docs/tds">Time Dimension Segmentation</a>,
        ADR-009) to ensure the runtime profile matches the operation's urgency:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Tier</th>
              <th>Bound</th>
              <th>Examples</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Second hand</td>
              <td>&lt; 300 ms</td>
              <td>MARSHAL evaluation, status polls, per-request analysis</td>
            </tr>
            <tr>
              <td>Minute hand</td>
              <td>300 ms – 30 s</td>
              <td>Report generation, standard scans, <a href="/docs/citadel/augur-vigil">VIGIL</a>_REALTIME</td>
            </tr>
            <tr>
              <td>Hour hand</td>
              <td>&gt; 30 s</td>
              <td>VIGIL_DEEP, large-spec scans, batch exports</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="callout-note">
        <strong>Note:</strong> For the full repository layout, port assignments, and
        network segmentation see <code>docs/deployment-topology.md</code> in the
        repository. For the security maturity tiers (Standard / Elevated / High Assurance)
        see <a href="/docs/security">Security</a>.
      </div>
    </DocsLayout>
  )
}
