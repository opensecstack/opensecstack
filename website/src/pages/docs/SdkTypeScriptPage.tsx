import DocsLayout from './DocsLayout'
import CodeBlock from '../../components/CodeBlock'

const toc = [
  { id: 'installation', label: 'Installation' },
  { id: 'client-construction', label: 'Client construction' },
  { id: 'running-a-scan', label: 'Running a scan' },
  { id: 'nis2-compass-client', label: 'NIS2 Compass client' },
  { id: 'citadel-client', label: 'CITADEL client' },
  { id: 'webhook-router', label: 'Webhook router' },
  { id: 'error-handling', label: 'Error handling' },
  { id: 'full-documentation', label: 'Full documentation' },
]

export default function SdkTypeScriptPage() {
  return (
    <DocsLayout
      breadcrumbs={['Docs', 'SDK', 'TypeScript']}
      toc={toc}
      editPath="SdkTypeScriptPage.tsx"
      prev={{ label: 'Python', path: '/docs/sdk/python' }}
      next={{ label: 'Rust', path: '/docs/sdk/rust' }}
    >
      <h1>TypeScript SDK</h1>
      <p>
        The TypeScript client provides typed clients for <strong><a href="/docs/platforms/apiguard">APIGuard</a></strong>,{' '}
        <strong><a href="/docs/platforms/nis2compass">NIS2 Compass</a></strong>, and <strong><a href="/docs/governance">CITADEL</a></strong>, plus a{' '}
        <strong><a href="/docs/webhooks">webhook router</a></strong> with HMAC-SHA256 signature verification. It requires{' '}
        <strong>Node.js 18+</strong> or a modern browser, and has{' '}
        <strong>zero external runtime dependencies</strong>. See <a href="/docs/contracts">SDK &amp; Contracts</a> for the full integration contract reference.
      </p>

      <h2 id="installation">Installation</h2>
      <p>
        Install the package from npm:
      </p>
      <CodeBlock
        language="bash"
        code={`npm install @opensecstack/sdk`}
      />

      <h2 id="client-construction">Client construction</h2>
      <p>
        Each platform client takes a configuration object with <code>baseURL</code> and{' '}
        <code>apiKey</code>. Optional parameters control request timeouts, retry count, and
        exponential back-off base. All client methods return <code>Promise</code>s and are
        designed to be used with <code>async</code>/<code>await</code>.
      </p>
      <CodeBlock
        language="typescript"
        filename="clients.ts"
        code={`import { APIGuardClient, NIS2CompassClient, CITADELClient } from "@opensecstack/sdk";

// APIGuard
const apiguard = new APIGuardClient({
  baseURL: "https://apiguard.internal",
  apiKey: "ag_key_...",
  timeout: 30_000,    // ms, optional — default 30 s
  maxRetries: 3,      // optional
  retryWaitBase: 500, // ms, optional
});

// NIS2 Compass
const nis2 = new NIS2CompassClient({
  baseURL: "https://nis2compass.internal",
  apiKey: "nis2_key_...",
});

// CITADEL (HMAC-SHA256 signed)
const citadel = new CITADELClient({
  baseURL: "https://citadel.internal",
  keyID: "key-001",
  sharedSecret: "hmac-secret-...",
});`}
      />

      <h2 id="running-a-scan">Running a scan</h2>
      <p>
        Start an APIGuard scan, wait for it to complete, then retrieve and triage findings.
        Use <code>createScanFull</code> to specify custom modules, target URL, or
        authentication.
      </p>
      <CodeBlock
        language="typescript"
        filename="scan.ts"
        code={`// Simple scan from spec URL
const scan = await apiguard.createScan("https://example.com/openapi.json");
console.log(\`Scan ID: \${scan.id}, status: \${scan.status}\`);

// Full options — modules, target, bearer auth
const scan2 = await apiguard.createScanFull({
  spec_url: "https://example.com/openapi.json",
  target: "https://api.example.com",
  modules: ["auth", "injection"],
  auth_type: "bearer",
  auth_token: "tok_...",
});

// Poll until complete
const completed = await apiguard.getScan(scan.id);

// Retrieve critical findings (paginated)
const findings = await apiguard.getFindings(scan.id, {
  severity: "critical",
  page: 1,
  per_page: 50,
});

// Triage a finding
await apiguard.patchFinding(findings[0].id, {
  status: "false_positive",
  note: "Not applicable in our deployment",
});

// Download a SARIF report
const report = await apiguard.getReport(scan.id, "sarif");`}
      />

      <h2 id="nis2-compass-client">NIS2 Compass client</h2>
      <p>
        Create an organisation and assessment, update a NIS2 Article 21 control, and upload
        evidence artifacts. Controls are addressed by their <code>measure_ref</code>{' '}
        (letters <code>a</code> through <code>j</code> per Article 21(2)).
      </p>
      <CodeBlock
        language="typescript"
        filename="nis2.ts"
        code={`// Create organisation
const org = await nis2.createOrganisation({
  name: "Acme Corp",
  industry: "energy",
  country: "DE",
});

// Create assessment
const assessment = await nis2.createAssessment(org.id, {
  title: "Q1 2026 NIS2 Assessment",
  framework_version: "2.0",
});

// List controls that have not been started yet
const controls = await nis2.listControls(assessment.id, {
  status: "not_started",
});

// Mark control 'a' as implemented with notes
await nis2.patchControl(assessment.id, controls[0].measure_ref, {
  status: "implemented",
  notes: "Deployed firewall rules per NIS2 Article 21(2)(a)",
  risk_score: 2.5,
});

// Upload evidence artifact
const artifact = await nis2.uploadArtifact(
  assessment.id,
  file,
  "evidence",
  { control_id: controls[0].measure_ref, description: "Firewall config evidence", filename: "evidence.pdf" },
);

// Generate PDF compliance report
const pdf = await nis2.generateReport(assessment.id);`}
      />

      <h2 id="citadel-client">CITADEL client</h2>
      <p>
        Send security events to the <a href="/docs/citadel/worm">WORM</a> audit chain and verify chain integrity locally.
        The CITADEL client also exposes AUGUR advisories for threat intelligence lookups.
      </p>
      <CodeBlock
        language="typescript"
        filename="citadel.ts"
        code={`// Send an event (fire-and-forget)
citadel.sendEvent({
  event_type: "apiguard.scan.completed",
  source: "apiguard",
  actor_id: "system",
  actor_type: "system",
  resource_type: "scan",
  resource_id: scan.id,
  severity: "info",
  payload: { findings_count: 5 },
});

// Query events from the WORM chain
const events = await citadel.getEvents({
  source: "apiguard",
  since: "2026-03-01T00:00:00Z",
  limit: 100,
});

// Verify TripleHash chain integrity (throws if chain is broken)
citadel.verifyChain(events);

// Fetch active AUGUR advisories
const active = await citadel.getActiveAdvisories();`}
      />

      <h2 id="webhook-router">Webhook router</h2>
      <p>
        The <code>WebhookRouter</code> verifies incoming HMAC-SHA256 signatures, enforces
        the ±5-minute replay window, and dispatches typed events to registered handlers.
        It integrates with any Node.js HTTP server.
      </p>
      <CodeBlock
        language="typescript"
        filename="webhook.ts"
        code={`import { WebhookRouter, EventAPIScanCompleted } from "@opensecstack/sdk";
import http from "node:http";

const router = new WebhookRouter("my-shared-secret");

router
  .on(EventAPIScanCompleted, (event) => {
    console.log("Scan completed:", event.id, event.payload);
  })
  .on("*", (event) => {
    console.log("Unhandled event:", event.event_type);
  });

// Mount on a plain Node.js HTTP server
http.createServer((req, res) => router.handleHttp(req, res)).listen(3000);`}
      />
      <p>
        For standalone signature verification (useful in Express / Koa middleware):
      </p>
      <CodeBlock
        language="typescript"
        filename="verify.ts"
        code={`import { verifySignature, InvalidSignatureError } from "@opensecstack/sdk";

try {
  verifySignature(rawBody, req.headers["x-citadel-signature"] as string, secret);
} catch (err) {
  if (err instanceof InvalidSignatureError) {
    res.status(400).send("Bad signature");
  }
}`}
      />

      <h2 id="error-handling">Error handling</h2>
      <p>
        All client methods throw instances of <code>OpenSecStackError</code> or its
        subclasses. Catch <code>RateLimitError</code> to implement back-off; its{' '}
        <code>retryAfter</code> property gives the wait time in seconds.
      </p>
      <CodeBlock
        language="typescript"
        filename="errors.ts"
        code={`import { OpenSecStackError, RateLimitError } from "@opensecstack/sdk";

try {
  await apiguard.getScan("nonexistent-id");
} catch (err) {
  if (err instanceof RateLimitError) {
    console.log(\`Rate limited — retry after \${err.retryAfter}s\`);
  } else if (err instanceof OpenSecStackError) {
    console.log(\`API error \${err.statusCode}: \${err.message}\`);
    if (err.code) console.log(\`Error code: \${err.code}\`);
  }
}`}
      />

      <h2 id="full-documentation">Full documentation</h2>
      <p>
        Other SDK language clients: <a href="/docs/sdk/go">Go SDK</a>,{' '}
        <a href="/docs/sdk/python">Python SDK</a>,{' '}
        <a href="/docs/sdk/rust">Rust SDK</a>.
      </p>
      <p>
        The complete TypeScript client reference — including all method signatures, option
        types, and configuration defaults — is available in the SDK repository:
      </p>
      <p>
        <a href="https://github.com/opensecstack/opensecstack/tree/main/sdk" target="_blank" rel="noopener noreferrer">
          https://github.com/opensecstack/opensecstack/tree/main/sdk
        </a>
      </p>
    </DocsLayout>
  )
}
