import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const toc = [
  { id: 'overview', label: 'Overview' },
  { id: 'wire-format', label: 'Wire format & signing' },
  { id: 'replay-protection', label: 'Replay protection' },
  { id: 'per-source-secrets', label: 'Per-source secrets' },
  { id: 'signed-example', label: 'Signed-webhook example' },
  { id: 'event-types', label: 'Event & contract types' },
  { id: 'error-responses', label: 'Error responses' },
  { id: 'retry-policy', label: 'Retry & dead-letter (ThreatFlow)' },
]

export default function WebhooksPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'Architecture', 'Webhooks & Events']}
      toc={toc}
      editPath="WebhooksPage.tsx"
      prev={{ label: 'CITADEL Integration', path: '/docs/citadel-integration' }}
      next={{ label: 'Overview', path: '/docs/platforms' }}
    >
      <h1>Webhooks &amp; Events</h1>
      <p>
        Platforms in the opensecstack ecosystem communicate through signed, replay-protected
        webhooks rather than ad-hoc HTTP calls. Every webhook uses the same{' '}
        <strong>HMAC-SHA256 signing scheme</strong>, a <strong>±5-minute replay window</strong>,
        and <strong>per-source shared secrets</strong>. This page is the cross-platform
        reference — consult the individual platform docs for endpoint-specific details.
      </p>

      <h2 id="overview">Overview</h2>
      <p>
        Two platforms act as primary webhook <em>receivers</em> in the ecosystem:
      </p>
      <ul>
        <li>
          <strong><a href="/docs/platforms/irflow">IRFlow</a></strong> — receives events from APIGuard,{' '}
          <a href="/docs/citadel-integration">CITADEL</a>, and ThreatFlow to
          create or enrich incidents automatically.
        </li>
        <li>
          <strong><a href="/docs/platforms/threatflow">ThreatFlow</a></strong> — receives events from APIGuard, CITADEL, and generic
          external sources; pushes outbound events to IRFlow, NIS2Compass, and OpenCSIRT.
        </li>
      </ul>
      <p>
        All webhook endpoints share one signing scheme that differs only in the header names and
        per-source secret used. No JWT is required — authentication is entirely via HMAC.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Platform</th>
              <th>Endpoint</th>
              <th>Source</th>
              <th>Typical trigger</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>IRFlow</td>
              <td><code>POST /api/v1/webhooks/apiguard</code></td>
              <td>APIGuard</td>
              <td>Finding crosses severity threshold or scan completes</td>
            </tr>
            <tr>
              <td>IRFlow</td>
              <td><code>POST /api/v1/webhooks/citadel</code></td>
              <td>CITADEL</td>
              <td>HARD_STOP decisions, WORM anchor events</td>
            </tr>
            <tr>
              <td>IRFlow</td>
              <td><code>POST /api/v1/webhooks/threatflow</code></td>
              <td>ThreatFlow</td>
              <td>IOC bundle published, correlation match</td>
            </tr>
            <tr>
              <td>ThreatFlow</td>
              <td><code>POST /api/v1/webhooks/apiguard</code></td>
              <td>APIGuard</td>
              <td>Scan completed, critical finding</td>
            </tr>
            <tr>
              <td>ThreatFlow</td>
              <td><code>POST /api/v1/webhooks/citadel</code></td>
              <td>CITADEL</td>
              <td>MARSHAL decision, AUGUR advisory, VIGIL alert</td>
            </tr>
            <tr>
              <td>ThreatFlow</td>
              <td><code>POST /api/v1/webhooks/generic</code></td>
              <td>Third-party</td>
              <td>Custom IOC report from external scanner</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="wire-format">Wire format &amp; signing</h2>
      <p>
        Every signed webhook request carries two mandatory headers. The canonical signing
        input is the Unix timestamp, a literal dot, and the raw request body — exactly as
        received on the wire, with no re-serialisation or whitespace normalisation.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Header (IRFlow)</th>
              <th>Header (ThreatFlow)</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>X-Irflow-Timestamp</code></td>
              <td><code>X-ThreatFlow-Timestamp</code></td>
              <td>Unix seconds at signing time (UTC)</td>
            </tr>
            <tr>
              <td><code>X-Irflow-Signature</code></td>
              <td><code>X-ThreatFlow-Signature</code></td>
              <td><code>sha256=&lt;hex&gt;</code> — HMAC-SHA256 over the canonical input</td>
            </tr>
            <tr>
              <td><code>X-Irflow-Event-Id</code> (optional)</td>
              <td><code>X-ThreatFlow-Delivery</code></td>
              <td>UUID for sender-side deduplication and idempotency</td>
            </tr>
            <tr>
              <td>—</td>
              <td><code>X-ThreatFlow-Event</code></td>
              <td>Event type string (e.g. <code>apiguard.scan.completed</code>)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>The canonical signing formula used by both platforms is:</p>
      <CodeBlock
        language="bash"
        code={`signed_payload = timestamp + "." + raw_body
signature      = hex(HMAC-SHA256(per_source_secret, signed_payload))
header_value   = "sha256=" + signature`}
      />

      <div className="callout-note">
        <strong>Constant-time comparison:</strong> Always use a constant-time byte-comparison
        function (e.g. <code>hmac.Equal</code> in Go, <code>hmac.compare_digest</code> in
        Python, <code>timingSafeEqual</code> in Node.js) when verifying the
        signature — standard string equality leaks timing information.
      </div>

      <h2 id="replay-protection">Replay protection</h2>
      <p>
        Both IRFlow and ThreatFlow reject requests whose timestamp falls outside a{' '}
        <strong>±5-minute window</strong> of the server's current time. IRFlow exposes the
        tolerance via the environment variable{' '}
        <code>IRFLOW_WEBHOOK_CLOCK_SKEW_TOLERANCE</code> (default <code>5m</code>); ThreatFlow
        hard-codes <code>maxTimestampSkew = 300</code> seconds.
      </p>
      <p>
        The ±5-minute window balances capture-replay risk against real-world NTP drift between
        peers. A tighter window (e.g. 30 s) is possible but requires well-synchronised clocks
        across all sender platforms. Requests outside the window return <strong>401</strong>{' '}
        with a structured JSON error body.
      </p>
      <p>
        ThreatFlow also issues a unique <code>X-ThreatFlow-Delivery</code> header (UUID v4) per
        delivery. Receivers should use this ID to deduplicate retried deliveries. IRFlow logs
        the optional <code>X-Irflow-Event-Id</code> for the same purpose; v1.1 will persist and
        reject duplicate IDs.
      </p>

      <h2 id="per-source-secrets">Per-source secrets</h2>
      <p>
        Each source platform has its own shared secret. <strong>Never reuse a secret across
        sources.</strong> Secrets are configured on the <em>receiver</em> side. If a per-source
        secret is not set, the corresponding endpoint returns <strong>503</strong> until
        configured — this is fail-closed by design.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Receiver</th>
              <th>Environment variable</th>
              <th>Covers</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>IRFlow</td>
              <td><code>IRFLOW_WEBHOOK_APIGUARD_SECRET</code></td>
              <td>APIGuard endpoint verifier</td>
            </tr>
            <tr>
              <td>IRFlow</td>
              <td><code>IRFLOW_WEBHOOK_CITADEL_SECRET</code></td>
              <td>CITADEL endpoint verifier</td>
            </tr>
            <tr>
              <td>IRFlow</td>
              <td><code>IRFLOW_WEBHOOK_THREATFLOW_SECRET</code></td>
              <td>ThreatFlow endpoint verifier</td>
            </tr>
            <tr>
              <td>ThreatFlow</td>
              <td><code>THREATFLOW_APIGUARD_WEBHOOK_SECRET</code></td>
              <td>Inbound APIGuard events</td>
            </tr>
            <tr>
              <td>ThreatFlow</td>
              <td><code>THREATFLOW_CITADEL_KEY_SECRET</code></td>
              <td>Inbound CITADEL events</td>
            </tr>
            <tr>
              <td>ThreatFlow</td>
              <td><code>THREATFLOW_IRFLOW_WEBHOOK_SECRET</code></td>
              <td>Outbound deliveries to IRFlow</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="callout-warning">
        <strong>Legacy variable:</strong> <code>IRFLOW_WEBHOOK_SECRET</code> exists as a legacy
        fallback and will be removed in IRFlow v1.1. Do not use it for new deployments.
      </div>

      <h2 id="signed-example">Signed-webhook example</h2>
      <p>
        The following shows a complete IRFlow inbound webhook from ThreatFlow — a correlation
        match payload with the signing headers already populated. The same shape applies to
        APIGuard and CITADEL payloads with their respective event types.
      </p>
      <CodeBlock
        language="bash"
        filename="signed-webhook-request.sh"
        code={`# Signed webhook from ThreatFlow -> IRFlow
# Headers
X-Irflow-Timestamp: 1745056462
X-Irflow-Signature: sha256=3a7f1c84e2d09b56f8ac4210edb3f70a92651cc8fa2e47d13b09e5a7c682b41f
X-Irflow-Event-Id: tf-bundle-0000042
Content-Type: application/json

# Body
{
  "event_id":   "tf-bundle-0000042",
  "event_type": "threatflow.bundle.published",
  "bundle_id":  "tf_bundle_789",
  "incident_id": "inc_123",
  "iocs": [
    {"type": "ipv4",   "value": "203.0.113.5",       "confidence": 0.92},
    {"type": "sha256", "value": "abc123...",          "confidence": 0.81},
    {"type": "domain", "value": "malicious.example", "confidence": 0.77}
  ],
  "occurred_at": "2026-04-19T10:14:22Z"
}

# Signature computation (pseudo-code):
# signed_payload = "1745056462" + "." + raw_body_bytes
# signature      = hex(HMAC-SHA256(IRFLOW_WEBHOOK_THREATFLOW_SECRET, signed_payload))
# header         = "sha256=" + signature`}
      />

      <p>
        The <a href="/docs/contracts">SDK</a> ships pre-built sender clients that handle signing automatically — prefer those
        over rolling your own implementation.
      </p>

      <h2 id="event-types">Event &amp; contract types</h2>
      <p>
        The SDK defines a typed <code>Event</code> envelope that all platforms share. The
        common fields are <code>event_id</code>, <code>event_type</code>, <code>source</code>,{' '}
        <code>ts_utc</code>, and an optional <code>project_id</code>, with a{' '}
        <code>payload</code> map carrying event-specific data.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Event type</th>
              <th>Source</th>
              <th>Consumer(s)</th>
              <th>IRFlow action</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>apiguard.scan.completed</code></td>
              <td>APIGuard</td>
              <td>IRFlow, ThreatFlow</td>
              <td>Log; attach to nearest open incident for project</td>
            </tr>
            <tr>
              <td><code>apiguard.finding.critical</code></td>
              <td>APIGuard</td>
              <td>IRFlow, ThreatFlow</td>
              <td>Auto-create P1 incident</td>
            </tr>
            <tr>
              <td><code>apiguard.finding.*</code> (high)</td>
              <td>APIGuard</td>
              <td>IRFlow</td>
              <td>Auto-create P2 incident</td>
            </tr>
            <tr>
              <td><code>citadel.marshal.hard_stop</code></td>
              <td>CITADEL</td>
              <td>IRFlow, ThreatFlow</td>
              <td>Always creates P1 incident; triggers project freeze playbook</td>
            </tr>
            <tr>
              <td><code>citadel.marshal.decision</code></td>
              <td>CITADEL</td>
              <td>ThreatFlow</td>
              <td>MARSHAL governance decision delivered</td>
            </tr>
            <tr>
              <td><code>citadel.augur.advisory</code></td>
              <td>CITADEL</td>
              <td>ThreatFlow</td>
              <td>May block ingestion pipeline</td>
            </tr>
            <tr>
              <td><code>citadel.vigil.alert</code></td>
              <td>CITADEL</td>
              <td>ThreatFlow</td>
              <td>VIGIL monitoring alert</td>
            </tr>
            <tr>
              <td><code>citadel.hard_stop</code></td>
              <td>CITADEL</td>
              <td>SDK / custom</td>
              <td>WORM-logged; <code>irflow_incident_id</code> in payload</td>
            </tr>
            <tr>
              <td><code>citadel.vigil_red</code></td>
              <td>CITADEL</td>
              <td>SDK / custom</td>
              <td>VIGIL transitioned to RED state</td>
            </tr>
            <tr>
              <td><code>threatflow.bundle.published</code></td>
              <td>ThreatFlow</td>
              <td>IRFlow</td>
              <td>Attach IOCs to open incident if <code>incident_id</code> present</td>
            </tr>
            <tr>
              <td><code>threatflow.correlation.match</code></td>
              <td>ThreatFlow</td>
              <td>IRFlow</td>
              <td>IOC matched to active finding or incident</td>
            </tr>
            <tr>
              <td><code>threatflow.ioc.ingested</code></td>
              <td>ThreatFlow</td>
              <td>IRFlow</td>
              <td>New IOC persisted to store</td>
            </tr>
            <tr>
              <td><code>threatflow.ioc.revoked</code></td>
              <td>ThreatFlow</td>
              <td>IRFlow</td>
              <td>IOC expired or manually revoked</td>
            </tr>
            <tr>
              <td><code>threatflow.bundle.exported</code></td>
              <td>ThreatFlow</td>
              <td>NIS2Compass, OpenCSIRT</td>
              <td>STIX bundle exported for downstream compliance use</td>
            </tr>
            <tr>
              <td><code>nis2compass.control.updated</code></td>
              <td>NIS2Compass</td>
              <td>SDK / custom</td>
              <td>Control status changed in an assessment</td>
            </tr>
            <tr>
              <td><code>nis2compass.assessment.completed</code></td>
              <td>NIS2Compass</td>
              <td>SDK / custom</td>
              <td>All controls reached terminal status</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="callout-note">
        <strong>SDK event router:</strong> The SDK ships a typed event router
        (<code>webhook.NewRouter</code> in Go) that dispatches by <code>event_type</code> and
        handles signature verification before routing. Custom integrations should use the router
        rather than parsing the envelope manually.
      </div>

      <h2 id="error-responses">Error responses</h2>
      <p>
        Both platforms return structured JSON errors:{' '}
        <code>{'{"error": "human-readable description"}'}</code>.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Meaning</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>200 / 202</td>
              <td>Accepted — processed synchronously or queued</td>
            </tr>
            <tr>
              <td>400</td>
              <td>Payload failed JSON decode or schema validation</td>
            </tr>
            <tr>
              <td>401</td>
              <td>Signature missing, timestamp outside skew, or HMAC mismatch</td>
            </tr>
            <tr>
              <td>413</td>
              <td>
                Body exceeds <code>IRFLOW_WEBHOOK_MAX_BODY_SIZE</code> (default 1 MiB) or
                ThreatFlow body limit
              </td>
            </tr>
            <tr>
              <td>429</td>
              <td>
                Rate limit exceeded (ThreatFlow: 100 inbound requests/min per source IP)
              </td>
            </tr>
            <tr>
              <td>503</td>
              <td>Per-source secret not configured — endpoint disabled (fail-closed)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2 id="retry-policy">Retry &amp; dead-letter (ThreatFlow)</h2>
      <p>
        When an <em>outbound</em> delivery from ThreatFlow fails, it retries with exponential
        backoff. After all attempts are exhausted, the delivery moves to a dead-letter queue for
        manual inspection and replay.
      </p>

      <div className="docs-table-wrapper">
        <table className="docs-table">
          <thead>
            <tr>
              <th>Attempt</th>
              <th>Delay</th>
              <th>Total elapsed</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>1 (initial)</td>
              <td>0 s</td>
              <td>0 s</td>
            </tr>
            <tr>
              <td>2 (first retry)</td>
              <td>30 s</td>
              <td>30 s</td>
            </tr>
            <tr>
              <td>3 (second retry)</td>
              <td>60 s</td>
              <td>90 s</td>
            </tr>
            <tr>
              <td>4 (third retry)</td>
              <td>120 s</td>
              <td>210 s</td>
            </tr>
          </tbody>
        </table>
      </div>

      <p>
        <code>401</code>, <code>403</code>, and <code>404</code> responses are
        non-retryable — retrying will not change the outcome. Network errors, timeouts, and
        5xx responses are retried. Dead-letter items are retained for 30 days (configurable)
        and can be replayed via the ThreatFlow admin API.
      </p>

      <div className="callout-note">
        <strong>Event delivery guarantees:</strong> Webhook delivery is best-effort. Always
        poll the source platform's REST API as a fallback for critical alerting paths — do not
        rely solely on webhooks.
      </div>
    </DocsLayout>
  )
}
