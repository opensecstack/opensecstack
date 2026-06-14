import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'submitting-a-kerkese', label: 'Submitting a governed action (Kerkese)' },
  { id: 'marshal-verdicts', label: 'MARSHAL verdicts' },
  { id: 'worm-chain', label: 'Forwarding evidence to the WORM chain' },
  { id: 'transport', label: 'Transport & authentication' },
  { id: 'env-vars', label: 'Environment variables' },
  { id: 'dry-run', label: 'Dry-run mode' },
  { id: 'platform-examples', label: 'Platform examples' },
  { id: 'disabled-mode', label: 'Disabled mode (local dev)' },
]

export default function CitadelIntegrationPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Architecture', 'CITADEL Integration']}
      toc={toc}
      editPath="CitadelIntegrationPage.tsx"
      prev={{ label: 'Time Dimension Segmentation', path: '/docs/tds' }}
      next={{ label: 'Webhooks & Events', path: '/docs/webhooks' }}
    >
      <h1>CITADEL Integration</h1>
      <p>
        <strong>CITADEL</strong> is the governance and audit layer shared by every opensecstack
        platform. It provides two services that platforms plug into:
      </p>
      <ul>
        <li>
          <strong><a href="/docs/citadel/marshal">MARSHAL</a></strong> — the deterministic 5-gate decision engine. Before any
          high-impact operation executes, the platform submits a <em>Kerkese</em> (governed action
          request) and waits for one of three verdicts: <code>EXECUTE</code>,{' '}
          <code>REFUSE</code>, or <code>HARD_STOP</code>.
        </li>
        <li>
          <strong><a href="/docs/citadel/worm">WORM chain</a></strong> — the append-only, immutable audit ledger. Every
          significant state change is emitted as an evidence packet, triple-hashed (BLAKE3 +
          SHA-256 + SHA-512), Ed25519-anchored, and permanently recorded.
        </li>
      </ul>
      <p>
        For the governance engine internals (gate logic, SoD enforcement, AUGUR, VIGIL) see{' '}
        <a href="/docs/governance">Governance (CITADEL)</a>.
      </p>

      <h2 id="overview">Overview</h2>
      <p>The integration flow for any platform is always the same five steps:</p>
      <ol>
        <li>Platform detects a high-impact operation is about to run.</li>
        <li>
          Platform submits a Kerkese JSON payload to CITADEL MARSHAL via{' '}
          <code>POST /api/v1/marshal/evaluate</code>.
        </li>
        <li>MARSHAL evaluates 5 gates and returns a verdict (<code>EXECUTE</code> / <code>REFUSE</code> / <code>HARD_STOP</code>).</li>
        <li>Platform acts on the verdict: proceed, log rejection, or halt and alert.</li>
        <li>
          Platform emits evidence packets to the WORM chain via{' '}
          <code>POST /api/v1/ingest</code> (or via the Connector SDK).
        </li>
      </ol>
      <p>
        All outcomes — including REFUSE and HARD_STOP — are written to{' '}
        <code>citadel.log</code> by CITADEL automatically. The platform does not need to log
        MARSHAL verdicts itself.
      </p>

      <h2 id="submitting-a-kerkese">Submitting a governed action (Kerkese)</h2>
      <p>
        A <strong>Kerkese</strong> is the standardised JSON request format that represents a
        proposed governed action. It carries the action type, the actor identity, supporting
        evidence, and the SoD (Separation of Duties) assignment.
      </p>
      <CodeBlock
        language="bash"
        code={`POST {CITADEL_API_URL}/api/v1/marshal/evaluate
Content-Type: application/json
Authorization: Bearer <jwt>      # or HMAC headers for connector auth`}
      />
      <p>Example Kerkese payload (<a href="/docs/platforms/threatflow">ThreatFlow</a> bulk IOC ingestion):</p>
      <CodeBlock
        language="typescript"
        code={`{
  "kerkese_version": "1.0",
  "project_id": "threatflow",
  "execution_id": "poll-otx-2026-03-31",
  "action": {
    "type": "bulk_ioc_ingest",
    "label": "Ingest 247 IOCs from alienvault-otx feed"
  },
  "actor": {
    "user_id": 0,
    "role": "group_sig_operator"
  },
  "evidence": {
    "feed_name": "alienvault-otx",
    "ioc_count": 247,
    "confidence_base": 70
  },
  "sod": {
    "operator_user_id": 0,
    "verifier_user_id": 0
  },
  "dry_run": false
}`}
      />
      <p>Required fields in every Kerkese:</p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Field</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>kerkese_version</code></td>
              <td>Schema version — currently <code>"1.0"</code></td>
            </tr>
            <tr>
              <td><code>project_id</code></td>
              <td>
                Must string-exact match a whitelisted project in CITADEL (Gate 2). Platforms use
                their own service name (e.g. <code>"threatflow"</code>, <code>"opencsirt"</code>).
              </td>
            </tr>
            <tr>
              <td><code>execution_id</code></td>
              <td>Unique identifier for this specific request invocation</td>
            </tr>
            <tr>
              <td><code>action.type</code></td>
              <td>Operation identifier checked against MARSHAL's authority rules (Gate 1)</td>
            </tr>
            <tr>
              <td><code>actor.role</code></td>
              <td>
                Must be <code>group_sig_operator</code> or <code>group_sig_verifier</code>; SoD
                requires operator ≠ verifier
              </td>
            </tr>
            <tr>
              <td><code>evidence</code></td>
              <td>Operation-specific evidence evaluated at Gate 4</td>
            </tr>
            <tr>
              <td><code>sod</code></td>
              <td>
                Separation of duties assignment. If <code>operator_user_id === verifier_user_id</code>,
                MARSHAL returns HARD_STOP immediately
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="marshal-verdicts">MARSHAL verdicts</h2>
      <p>
        MARSHAL always returns exactly one of three outcomes. There are no partial verdicts, no
        warnings, and no heuristics — the result is deterministic.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Verdict</th>
              <th>Meaning</th>
              <th>Required platform action</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>EXECUTE</code></td>
              <td>All 5 gates passed. The operation is authorised.</td>
              <td>Proceed with the operation.</td>
            </tr>
            <tr>
              <td><code>REFUSE</code></td>
              <td>
                One or more gates failed (insufficient authority, out of scope, incomplete
                evidence, schema validation failure).
              </td>
              <td>
                Do not execute the operation. Log the refusal in the platform's own audit trail.
                Surface the MARSHAL reason to the operator.
              </td>
            </tr>
            <tr>
              <td><code>HARD_STOP</code></td>
              <td>
                A critical violation was detected: SoD breach (same user as operator and
                verifier), scope spoofing, or contradictory evidence. CITADEL automatically
                creates an incident.
              </td>
              <td>
                Immediately halt the operation and any related processes. Raise a VIGIL RED alert.
                Do not retry without manual review.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>The MARSHAL response envelope carries the verdict and per-gate status:</p>
      <CodeBlock
        language="typescript"
        code={`{
  "meta": {
    "schema_version": "2.0",
    "project_id": "threatflow",
    "execution_id": "poll-otx-2026-03-31",
    "ts_utc": "2026-05-23T10:00:00Z"
  },
  "decision": {
    "outcome": "EXECUTE",          // EXECUTE | REFUSE | HARD_STOP
    "severity": "INFO",            // INFO | WARNING | CRITICAL
    "gates": [
      { "gate": 1, "name": "authority",    "status": "PASS", "reason": "" },
      { "gate": 2, "name": "scope",        "status": "PASS", "reason": "" },
      { "gate": 3, "name": "determinism",  "status": "PASS", "reason": "" },
      { "gate": 4, "name": "evidence",     "status": "PASS", "reason": "" },
      { "gate": 5, "name": "schema",       "status": "PASS", "reason": "" }
    ],
    "reasons": []
  }
}`}
      />
      <div className="callout-note">
        <strong>Rule:</strong> When <code>outcome=EXECUTE</code>, the <code>required_evidence</code>{' '}
        array in the response is always empty. If it is non-empty, treat the response as a{' '}
        <code>REFUSE</code> regardless of the stated outcome.
      </div>

      <h2 id="worm-chain">Forwarding evidence to the WORM chain</h2>
      <p>
        After an operation completes, the platform emits one or more evidence packets to the CITADEL
        WORM chain. Packets are append-only — once written, they cannot be modified or deleted.
        CITADEL computes the TripleHash and Ed25519 chain anchor automatically on ingest.
      </p>
      <p>
        The recommended approach is the <strong>Connector SDK</strong> (<code>citadel-connector</code>{' '}
        Python package), which handles canonical JSON serialisation, triple-hash computation,
        Ed25519 signing, and retry logic with persistent queueing.
      </p>
      <CodeBlock
        language="bash"
        code={`pip install "citadel-connector>=1.0.0,<1.1.0"`}
      />
      <CodeBlock
        language="typescript"
        code={`from citadel_connector import CitadelConnector

connector = CitadelConnector(
    endpoint="https://citadel.internal.example.org",
    api_key="svc-<your-service-api-key>",
    service_name="my-platform",
    dry_run=False,
    timeout_seconds=10,
    retry_max_attempts=5,
    retry_backoff_factor=2.0,
    persistent_queue_path="/var/lib/my-platform/citadel-queue"
)

result = connector.emit(
    event_type="incident.created",
    payload={
        "incident_id": "INC-2026-0412",
        "severity": "HIGH",
        "affected_system": "web-proxy-01",
        "detected_at": "2026-05-10T14:23:00Z"
    }
)
# result.packet_id  — UUID assigned to the emitted packet
# result.chain_id   — WORM chain this packet was written to
# result.block_seq  — block sequence number`}
      />
      <p>
        Platforms that use languages other than Python send packets directly over HTTPS. The wire
        format is the same JSON event body with HMAC-SHA256 authentication headers.
      </p>

      <h2 id="transport">Transport &amp; authentication</h2>
      <p>
        All platforms authenticate to CITADEL as connectors using HMAC-SHA256 request signing.
        The exact header names vary slightly per platform (each prefixes with its own service
        name), but the signing scheme is uniform — the same scheme used for{' '}
        <a href="/docs/webhooks">Webhooks &amp; Events</a> between platforms:
      </p>
      <CodeBlock
        language="bash"
        code={`POST {CITADEL_API_URL}/api/v1/evidence
Content-Type: application/json
X-Source:     <platform-name>
X-Signature:  HMAC-SHA256(<CITADEL_HMAC_SECRET>, body)
X-Timestamp:  <unix epoch seconds>`}
      />
      <p>
        CITADEL enforces a ±5-minute replay window on the <code>X-Timestamp</code> header.
        Events carry a stable UUIDv4 <code>id</code> field; CITADEL ingest is idempotent on{' '}
        <code>(source, id)</code> so at-least-once delivery from the platform outbox is safe.
      </p>

      <h2 id="env-vars">Environment variables</h2>
      <p>
        Each platform uses a prefixed variant of the same three variables. The table below
        shows the canonical names; substitute the platform prefix (e.g.{' '}
        <code>THREATFLOW_</code>, <code>OPENCSIRT_</code>, <code>OPENSCRUB_</code>) for your
        platform.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Variable pattern</th>
              <th>Required</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>*_CITADEL_API_URL</code></td>
              <td>Yes (in production)</td>
              <td>
                Base URL of the CITADEL API, e.g.{' '}
                <code>https://citadel.internal:8099</code>. When empty, all CITADEL calls are
                no-ops (development mode).
              </td>
            </tr>
            <tr>
              <td><code>*_CITADEL_API_KEY</code> or <code>*_CITADEL_HMAC_SECRET</code></td>
              <td>Yes (in production)</td>
              <td>
                Service API key or HMAC shared secret issued by the CITADEL administrator for
                this platform.
              </td>
            </tr>
            <tr>
              <td><code>*_CITADEL_DRY_RUN</code></td>
              <td>No</td>
              <td>
                Set to <code>true</code> to enable dry-run mode — packets are validated but not
                written to the chain, and MARSHAL evaluations return simulated verdicts. Default:{' '}
                <code>false</code>.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>Example configuration for OpenCSIRT:</p>
      <CodeBlock
        language="yaml"
        filename=".env"
        code={`OPENCSIRT_CITADEL_API_URL=https://citadel.internal:8099
OPENCSIRT_CITADEL_HMAC_SECRET=<secret-from-citadel-admin>
OPENCSIRT_CITADEL_DRY_RUN=false   # set true for staging`}
      />

      <h2 id="dry-run">Dry-run mode</h2>
      <p>
        Dry-run mode is the recommended configuration for local development, integration tests,
        and CI pipelines. In dry-run mode:
      </p>
      <ul>
        <li>
          Evidence packets are sent to <code>/api/v1/ingest/validate</code> instead of{' '}
          <code>/api/v1/ingest</code>. CITADEL validates the schema, triple-hash, and signature
          but does not write anything to the chain.
        </li>
        <li>
          MARSHAL evaluations hit <code>/api/v1/marshal/evaluate</code> with{' '}
          <code>"dry_run": true</code> in the Kerkese payload. The response is a simulated
          verdict; no log entry is created in <code>citadel.log</code>.
        </li>
        <li>VIGIL does not receive the packets. ARBITER rule evaluation is not triggered.</li>
      </ul>
      <p>Enable dry-run via the SDK flag or the environment variable override:</p>
      <CodeBlock
        language="bash"
        code={`# Environment variable — affects all connectors in the process
export CITADEL_DRY_RUN=true`}
      />
      <p>A successful dry-run validation response looks like:</p>
      <CodeBlock
        language="typescript"
        code={`{
  "dry_run": true,
  "packet_id": "<uuid-that-would-have-been-assigned>",
  "validation": "PASSED",
  "triple_hash_verified": true,
  "signature_verified": true,
  "estimated_chain_id": "<chain-id-that-would-receive-this-packet>",
  "warnings": []
}`}
      />
      <div className="callout-note">
        <strong>CI recommendation:</strong> Create a dedicated API key scoped to{' '}
        <code>dry_run_only</code> for CI pipelines. This prevents accidental writes to the live
        chain even if <code>CITADEL_DRY_RUN</code> is accidentally omitted.
        <br />
        <code>citadel-cli apikey create --service-name my-service-ci --scope dry_run_only --expiry 365d</code>
      </div>

      <h2 id="platform-examples">Platform examples</h2>
      <p>
        The following table summarises how the opensecstack platforms use CITADEL. Every platform
        that emits to WORM follows the same wire pattern.
      </p>
      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Platform</th>
              <th>MARSHAL-gated operations</th>
              <th>WORM event types</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>ThreatFlow</td>
              <td>Bulk IOC ingestion (&gt;100), feed source addition, STIX export, confidence override</td>
              <td>
                <code>threatflow.ioc.ingested</code>, <code>threatflow.ioc.revoked</code>,{' '}
                <code>threatflow.bundle.imported</code>, <code>threatflow.bundle.exported</code>,{' '}
                <code>threatflow.sighting.created</code>
              </td>
            </tr>
            <tr>
              <td><a href="/docs/platforms/openscrub">OpenScrub</a></td>
              <td>—</td>
              <td>
                <code>openscrub.mitigation</code> (per drop window),{' '}
                <code>openscrub.rule_change</code> (per rule insert/withdraw/expire)
              </td>
            </tr>
            <tr>
              <td><a href="/docs/platforms/opencsirt">OpenCSIRT</a></td>
              <td>—</td>
              <td>
                <code>opencsirt.incident_opened</code>,{' '}
                <code>opencsirt.incident_closed</code>,{' '}
                <code>opencsirt.advisory_published</code>,{' '}
                <code>opencsirt.escalation_sent</code>
              </td>
            </tr>
            <tr>
              <td><a href="/docs/platforms/apiguard">APIGuard</a></td>
              <td>Scan requested (Gate 1 authority + Gate 2 scope)</td>
              <td>Scan completed + findings linked to <code>citadel.evidence</code></td>
            </tr>
            <tr>
              <td><a href="/docs/platforms/irflow">IRFlow</a></td>
              <td>—</td>
              <td>Incident created → <code>citadel.incident</code> auto-created</td>
            </tr>
            <tr>
              <td><a href="/docs/platforms/nis2compass">NIS2 Compass</a></td>
              <td>—</td>
              <td>Assessment evidence → <code>citadel.evidence</code></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        Any HARD_STOP verdict — regardless of the originating platform — causes CITADEL to
        automatically create an incident entry and trigger a notification cascade.
      </p>

      <h2 id="disabled-mode">Disabled mode (local dev)</h2>
      <p>
        When a platform's <code>CITADEL_API_URL</code> variable is empty, all CITADEL calls
        become no-ops:
      </p>
      <ul>
        <li>WORM events are silently discarded (not queued, not written).</li>
        <li>MARSHAL evaluations return an implicit <code>EXECUTE</code> without network I/O.</li>
        <li>Platform operations proceed without governance checks.</li>
      </ul>
      <div className="callout-note">
        <strong>Warning:</strong> Disabled mode is intended for local development and testing only.
        Never deploy to a production or staging environment without a valid{' '}
        <code>CITADEL_API_URL</code>. Use dry-run mode for staging to keep governance checks
        active without writing to the live chain.
      </div>
    </DocsLayout>
  )
}
