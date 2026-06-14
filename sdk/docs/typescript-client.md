# SDK TypeScript Client

The TypeScript SDK provides typed clients for APIGuard, NIS2 Compass, and CITADEL, plus a webhook router with HMAC-SHA256 signature verification.

---

## Installation

```bash
npm install @opensecstack/sdk
```

Requires Node.js 18+.

---

## APIGuard Client

### Creating a client

```typescript
import { APIGuardClient } from "@opensecstack/sdk";

const client = new APIGuardClient({
  baseURL: "https://apiguard.internal",
  apiKey: "ag_key_...",
  timeout: 30_000,       // optional, default 30s
  maxRetries: 3,         // optional
  retryWaitBase: 500,    // optional, ms
});
```

### Running a scan

```typescript
const scan = await client.createScan("https://example.com/openapi.json");
console.log(`Scan ID: ${scan.id}, status: ${scan.status}`);

// Full options
const scan2 = await client.createScanFull({
  spec_url: "https://example.com/openapi.json",
  target: "https://api.example.com",
  modules: ["auth", "injection"],
  auth_type: "bearer",
  auth_token: "tok_...",
});

// Poll until complete
const completed = await client.getScan(scan.id);

// List scans with pagination
const scans = await client.listScans({ page: 1, per_page: 10 });
```

### Findings

```typescript
const findings = await client.getFindings(scan.id, {
  severity: "critical",
  page: 1,
  per_page: 50,
});

const finding = await client.getFinding(findings[0].id);

await client.patchFinding(finding.id, {
  status: "false_positive",
  note: "Not applicable in our deployment",
});

// List findings across all scans
const allFindings = await client.listFindings({ scan_id: scan.id });
```

### Reports

```typescript
// Get full report as ArrayBuffer
const report = await client.getReport(scan.id, "sarif");

// Stream report
const stream = await client.getReportStream(scan.id, "html");
```

### Specs and audit

```typescript
// Upload a spec file
const spec = await client.uploadSpec(file, "openapi.yaml");

// Audit log
const entries = await client.getAuditLog(50, 1);

// Token refresh
const tokens = await client.refreshToken("rt_...");
```

---

## NIS2 Compass Client

### Creating a client

```typescript
import { NIS2CompassClient } from "@opensecstack/sdk";

const nis2 = new NIS2CompassClient({
  baseURL: "https://nis2compass.internal",
  apiKey: "nis2_key_...",
});
```

### Organisations

```typescript
const org = await nis2.createOrganisation({
  name: "Acme Corp",
  industry: "energy",
  country: "DE",
});

const orgs = await nis2.getOrganisations({ page: 1, per_page: 10 });
const single = await nis2.getOrganisation(org.id);
await nis2.patchOrganisation(org.id, { size: "large" });
await nis2.deleteOrganisation(org.id);
```

### Assessments

```typescript
const assessment = await nis2.createAssessment(org.id, {
  title: "Q1 2026 NIS2 Assessment",
  framework_version: "2.0",
});

const assessments = await nis2.getAssessments(org.id, { status: "in_progress" });
await nis2.patchAssessment(assessment.id, { status: "completed" });
await nis2.deleteAssessment(assessment.id);
```

### Controls

```typescript
const controls = await nis2.listControls(assessment.id, {
  status: "not_started",
  nist_category: "PR",
});

const control = await nis2.getControl(assessment.id, controls[0].measure_ref);

await nis2.patchControl(assessment.id, control.measure_ref, {
  status: "implemented",
  notes: "Deployed firewall rules per NIS2 Article 21(2)(a)",
  risk_score: 2.5,
});
```

### Artifacts

```typescript
const artifacts = await nis2.listArtifacts(assessment.id);

const uploaded = await nis2.uploadArtifact(
  assessment.id,
  file,
  "evidence",
  { control_id: control.measure_ref, description: "Firewall configuration evidence", filename: "evidence.pdf" },
);

const artifact = await nis2.getArtifact(uploaded.id);
const blob = await nis2.downloadArtifact(uploaded.id);
await nis2.deleteArtifact(uploaded.id);
```

### API keys, reports, audit, health

```typescript
const keys = await nis2.listAPIKeys();
const key = await nis2.createAPIKey({ label: "CI/CD" });
await nis2.revokeAPIKey(key.id);

const report = await nis2.generateReport(assessment.id);
const auditLog = await nis2.getAuditLog(50, 1);
const entry = await nis2.getAuditEntry(auditLog[0].id);

const health = await nis2.getHealth();
const detail = await nis2.getHealthDetail();
```

---

## CITADEL Client

### Creating a client

```typescript
import { CITADELClient } from "@opensecstack/sdk";

const citadel = new CITADELClient({
  baseURL: "https://citadel.internal",
  keyID: "key-001",
  sharedSecret: "hmac-secret-...",
});
```

### Events

```typescript
citadel.sendEvent({
  event_type: "apiguard.scan.completed",
  source: "apiguard",
  actor_id: "system",
  actor_type: "system",
  resource_type: "scan",
  resource_id: "scan-001",
  severity: "info",
  payload: { findings_count: 5 },
});

const events = await citadel.getEvents({
  source: "apiguard",
  since: "2026-03-01T00:00:00Z",
  limit: 100,
});

const event = await citadel.getEvent("evt-001");
```

### Chain verification

```typescript
const events = await citadel.getEvents({ limit: 1000 });
citadel.verifyChain(events); // throws if chain is broken
```

### AUGUR advisories

```typescript
const advisory = await citadel.createAdvisory({
  title: "CVE-2026-XXXX in libfoo",
  description: "Remote code execution via crafted input",
  severity: "critical",
  cve: "CVE-2026-XXXX",
  affects: [{ component: "libfoo", version_min: "1.0.0", version_max: "1.2.3" }],
});

const advisories = await citadel.listAdvisories({ status: "published", severity: "critical" });
const single = await citadel.getAdvisory(advisory.id);
const updated = await citadel.patchAdvisory(advisory.id, { status: "published" });
await citadel.deleteAdvisory(advisory.id);

const active = await citadel.getActiveAdvisories();
```

---

## Webhook Router

### Basic usage

```typescript
import { WebhookRouter, EventAPIScanCompleted } from "@opensecstack/sdk";

const router = new WebhookRouter("my-shared-secret");

router
  .on(EventAPIScanCompleted, (event) => {
    console.log("Scan completed:", event.id, event.payload);
  })
  .on("*", (event) => {
    console.log("Unhandled event:", event.event_type);
  });
```

### Node.js HTTP server

```typescript
import http from "node:http";

http.createServer((req, res) => router.handleHttp(req, res)).listen(3000);
```

### Direct invocation (Express / Koa / test)

```typescript
// When you already have the raw body and signature header:
const event = await router.handle(rawBodyBuffer, signatureHeader);
```

### Signature verification standalone

```typescript
import { verifySignature, InvalidSignatureError } from "@opensecstack/sdk";

try {
  verifySignature(rawBody, req.headers["x-citadel-signature"], secret);
} catch (err) {
  if (err instanceof InvalidSignatureError) {
    res.status(400).send("Bad signature");
  }
}
```

---

## Error Handling

```typescript
import { OpenSecStackError, RateLimitError } from "@opensecstack/sdk";

try {
  await client.getScan("nonexistent");
} catch (err) {
  if (err instanceof RateLimitError) {
    console.log(`Rate limited — retry after ${err.retryAfter}s`);
  } else if (err instanceof OpenSecStackError) {
    console.log(`API error ${err.statusCode}: ${err.message}`);
    if (err.code) console.log(`Error code: ${err.code}`);
  }
}
```

---

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `baseURL` | (required) | Root URL of the API instance |
| `apiKey` | (required for APIGuard/NIS2) | Bearer token for authentication |
| `keyID` | (required for CITADEL) | HMAC key identifier |
| `sharedSecret` | (required for CITADEL) | HMAC-SHA256 shared secret |
| `timeout` | `30000` | Request timeout in milliseconds |
| `maxRetries` | `3` | Maximum retry attempts for 5xx / 429 errors |
| `retryWaitBase` | `500` | Base wait in ms for exponential backoff |

---

## Development

```bash
cd sdk/typescript
npm install
npm test          # run tests (vitest)
npm run build     # build with tsup
npm run typecheck # tsc --noEmit
npm run lint      # eslint
```
