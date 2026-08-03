import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'
import { Helmet } from 'react-helmet-async'

const toc = [
  { id: 'the-sdk', label: 'The SDK' },
  { id: 'event-contracts', label: 'Event contracts' },
  { id: 'go-sdk-example', label: 'Go SDK example' },
  { id: 'webhooks', label: 'Signed webhooks' },
  { id: 'contract-versioning', label: 'Contract versioning' },
]

export default function ContractsPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Architecture', 'SDK & Contracts']}
      toc={toc}
      editPath="ContractsPage.tsx"
      prev={{ label: 'Overview', path: '/docs/architecture' }}
      next={{ label: 'Time Dimension Segmentation', path: '/docs/tds' }}
    >
      <Helmet>
        <title>SDK &amp; Contracts | opensecstack Docs</title>
        <meta
          name="description"
          content="How opensecstack platforms communicate through the typed opensecstack/sdk event contracts available in Go, Python, TypeScript, and Rust, including signed webhooks and contract versioning."
        />
        <link rel="canonical" href="https://opensecstack.github.io/opensecstack/docs/contracts" />
        <meta property="og:url" content="https://opensecstack.github.io/opensecstack/docs/contracts" />
        <meta property="og:title" content="SDK & Contracts | opensecstack Docs" />
        <meta
          property="og:description"
          content="How opensecstack platforms communicate through the typed opensecstack/sdk event contracts available in Go, Python, TypeScript, and Rust, including signed webhooks and contract versioning."
        />
      </Helmet>
      <h1>SDK &amp; Contracts</h1>
      <p>
        All inter-platform communication in opensecstack uses the <strong>opensecstack/sdk</strong> —
        a set of typed clients and event schemas available in Go, Python, TypeScript, and Rust.
        Platforms never exchange ad-hoc payloads; every message conforms to a versioned
        contract defined in the SDK. This means a consumer can trust the shape of data
        regardless of which platform version produced it.
      </p>

      <h2 id="the-sdk">The SDK</h2>
      <p>
        The <code>opensecstack/sdk</code> (Apache 2.0, v1.0.0) ships four language clients
        that are byte-compatible with each other:
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Language</th>
              <th>Import / install</th>
              <th>Runtime requirement</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><a href="/docs/sdk/go">Go</a></td>
              <td><code>github.com/opensecstack/sdk/go/opensecstack</code></td>
              <td>Go 1.21+. Zero external dependencies.</td>
            </tr>
            <tr>
              <td><a href="/docs/sdk/python">Python</a></td>
              <td><code>pip install opensecstack-sdk</code></td>
              <td>Python 3.10+</td>
            </tr>
            <tr>
              <td><a href="/docs/sdk/typescript">TypeScript</a></td>
              <td><code>@opensecstack/sdk</code></td>
              <td>Node.js 18+ or browser. Zero external runtime dependencies.</td>
            </tr>
            <tr>
              <td><a href="/docs/sdk/rust">Rust</a></td>
              <td><code>opensecstack</code> crate</td>
              <td>Rust 1.75+. Async-first with tokio + reqwest.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        The SDK also includes a shared <strong>Argon2id + pepper password hashing</strong>{' '}
        module with byte-compatible PHC encoding across Go (<code>sdk/go/password</code>)
        and Python (<code>sdk/python-password</code>).
      </p>

      <h2 id="event-contracts">Event contracts</h2>
      <p>
        The table below lists every typed contract the SDK defines, together with which
        platform produces it and which platforms consume it.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Contract</th>
              <th>Format / version</th>
              <th>Producers</th>
              <th>Consumers</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Scan Result</strong></td>
              <td>JSON v1</td>
              <td><a href="/docs/platforms/apiguard">APIGuard</a></td>
              <td><a href="/docs/platforms/irflow">IRFlow</a>, <a href="/docs/platforms/threatflow">ThreatFlow</a>, <a href="/docs/platforms/nis2compass">NIS2 Compass</a></td>
            </tr>
            <tr>
              <td><strong>IOC Bundle</strong></td>
              <td>STIX 2.1 v1</td>
              <td>ThreatFlow</td>
              <td><a href="/docs/platforms/openscrub">OpenScrub</a>, IRFlow, <a href="/docs/platforms/opencsirt">OpenCSIRT</a></td>
            </tr>
            <tr>
              <td><strong>Incident Record</strong></td>
              <td>JSON v1</td>
              <td>IRFlow</td>
              <td>NIS2 Compass, OpenCSIRT, <a href="/docs/governance">CITADEL</a></td>
            </tr>
            <tr>
              <td><strong>Compliance Evidence</strong></td>
              <td>JSON v1</td>
              <td>NIS2 Compass</td>
              <td>CITADEL</td>
            </tr>
            <tr>
              <td><strong>CITADEL Kerkese</strong></td>
              <td>JSON v2.0</td>
              <td>Any platform</td>
              <td>CITADEL MARSHAL (governance input)</td>
            </tr>
            <tr>
              <td><strong>Training Record</strong></td>
              <td>JSON v1</td>
              <td><a href="/docs/platforms/cyberpath">CyberPath</a></td>
              <td>NIS2 Compass, CITADEL</td>
            </tr>
            <tr>
              <td><strong>Advisory</strong></td>
              <td>CSAF 2.0 v1</td>
              <td>OpenCSIRT</td>
              <td>ThreatFlow</td>
            </tr>
            <tr>
              <td><strong>Simulation Result</strong></td>
              <td>JSON v1</td>
              <td><a href="/docs/platforms/securelab">SecureLab</a></td>
              <td>IRFlow, OpenScrub, ThreatFlow, <a href="/docs/platforms/vertguard">VertGuard</a></td>
            </tr>
            <tr>
              <td><strong>AI-Attack Detection</strong></td>
              <td>JSON v1</td>
              <td>VertGuard</td>
              <td>CITADEL, IRFlow, ThreatFlow, OpenCSIRT</td>
            </tr>
            <tr>
              <td><strong>Content Provenance</strong></td>
              <td>C2PA + JSON v1.3</td>
              <td>VertGuard Module 1</td>
              <td>CITADEL (as WORM evidence)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="callout-note">
        <strong>Note:</strong> The <strong>Identity</strong> contract (OpenID Connect 1.0,
        RS256) is handled separately by sinauth — it is not an SDK event schema but an
        OIDC token flow. See <a href="/docs/identity">Identity (sinauth)</a> for details.
      </div>

      <h2 id="go-sdk-example">Go SDK example</h2>
      <p>
        The following snippet shows the typical integration flow from an APIGuard scan to
        the CITADEL WORM log using the Go client. The same pattern is available in Python,
        TypeScript, and Rust.
      </p>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`import "github.com/opensecstack/sdk/go/opensecstack"

// Create a client for the APIGuard platform
client := opensecstack.NewAPIGuardClient("https://apiguard.example.com", "your-api-key")

// Kick off a scan against a published OpenAPI spec
scan, _ := client.CreateScan(ctx, "https://api.example.com/openapi.json")

// Retrieve only critical findings once the scan completes
findings, _ := client.GetFindings(ctx, scan.ID, opensecstack.GetFindingsOptions{
    Severity: "critical",
})

// Emit the scan result to the CITADEL WORM audit chain
entry := &opensecstack.AuditEntry{
    Source:    "apiguard",
    EventType: "scan_completed",
    ProjectID: "your-project-id",
    TsUTC:     scan.CompletedAt,
    Payload: map[string]any{
        "scan_id":          scan.ID,
        "findings_summary": findings,
    },
}
citadel.EmitWORM(ctx, entry)`}
      />

      <h2 id="webhooks">Signed webhooks</h2>
      <p>
        When a platform emits an event to another platform over HTTP, the request is signed
        with <strong>HMAC-SHA256</strong> using a per-source secret. The receiving platform
        must verify the signature before processing the payload. A <strong>±5-minute
        replay window</strong> is enforced on the timestamp in every request to prevent
        replay attacks. See <a href="/docs/webhooks">Webhooks &amp; Events</a> for the
        full specification.
      </p>
      <p>
        IRFlow defines the canonical wire format for signed webhooks; all other platforms
        follow the same specification. See <code>irflow/docs/webhook-spec.md</code> in the
        repository for the full header schema and verification algorithm.
      </p>

      <h2 id="contract-versioning">Contract versioning</h2>
      <p>
        Contracts are versioned by SDK package version. Minor version increments are
        backward-compatible additions; breaking changes increment the minor SDK version and
        are announced in <code>sdk/docs/migration.md</code> with a step-by-step upgrade
        guide. Consumers should pin to a minimum SDK version and upgrade when producers
        in their deployment do.
      </p>
    </DocsLayout>
  )
}
