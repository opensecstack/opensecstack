# @opensecstack/sdk

Official TypeScript SDK for **OpenSecStack** -- providing typed clients for APIGuard, NIS2Compass, and CITADEL.

## Installation

```bash
npm install @opensecstack/sdk
```

## Requirements

- Node.js >= 18

## Quick Start

### APIGuard -- API Security Scanner

```typescript
import { APIGuardClient } from "@opensecstack/sdk";

const apiguard = new APIGuardClient({
  baseURL: "http://localhost:8080",
  apiKey: "your-api-key",
});

// Start a scan from a spec URL
const scan = await apiguard.createScan("https://example.com/openapi.yaml");

// Or use createScanFull for additional options
const scanFull = await apiguard.createScanFull({
  spec_url: "https://example.com/openapi.yaml",
  target: "https://api.example.com",
  modules: ["auth", "injection", "bola"],
});

// Poll scan status
const status = await apiguard.getScan(scan.id);
console.log(`Scan ${status.id}: ${status.status}`);

// Retrieve findings
const findings = await apiguard.getFindings(scan.id, {
  severity: "critical",
  page: 1,
  per_page: 25,
});

for (const finding of findings) {
  console.log(`[${finding.severity}] ${finding.title} -- ${finding.endpoint_method} ${finding.endpoint_path}`);
}

// Triage a finding
await apiguard.patchFinding(findings[0].id, {
  status: "confirmed",
  note: "Verified in staging environment",
});
```

### NIS2Compass -- NIS2 Compliance Management

```typescript
import { NIS2CompassClient } from "@opensecstack/sdk";

const nis2 = new NIS2CompassClient({
  baseURL: "http://localhost:8081",
  apiKey: "your-api-key",
});

// Create an organisation
const org = await nis2.createOrganisation({
  name: "Acme Corp",
  industry: "energy",
  country: "DE",
  size: "large",
  entity_type: "essential",
});

// Start an assessment
const assessment = await nis2.createAssessment(org.id, {
  title: "Q1 2026 NIS2 Assessment",
  scope: "All critical infrastructure",
  assessor: "security-team@acme.com",
  due_date: "2026-03-31",
});

// List controls for the assessment
const controls = await nis2.listControls(assessment.id, {
  status: "not_assessed",
});

for (const control of controls) {
  console.log(`[${control.measure_ref}] ${control.title} -- ${control.status}`);
}

// Update a control with evidence
await nis2.patchControl(assessment.id, controls[0].measure_ref, {
  status: "partially_met",
  notes: "MFA deployed for admin accounts, rollout pending for all users",
  risk_score: 3,
  remediation_plan: "Complete MFA rollout by end of Q2",
  remediation_owner: "iam-team@acme.com",
});
```

### CITADEL -- Security Event Aggregation

```typescript
import { CITADELClient } from "@opensecstack/sdk";

const citadel = new CITADELClient({
  baseURL: "http://localhost:8082",
  keyID: "your-key-id",
  sharedSecret: "your-shared-secret",
});

// Query recent security events
const events = await citadel.getEvents({
  source: "apiguard",
  since: "2026-03-01T00:00:00Z",
  limit: 50,
});

for (const event of events) {
  console.log(`[${event.severity}] ${event.event_type} from ${event.source} at ${event.timestamp}`);
}

// Get a single event by ID
const event = await citadel.getEvent("evt_abc123");
console.log(event.payload);
```

## Error Handling

All clients throw typed errors that can be caught and inspected:

```typescript
import { OpenSecStackError, RateLimitError } from "@opensecstack/sdk";

try {
  await apiguard.getScan("nonexistent-id");
} catch (err) {
  if (err instanceof RateLimitError) {
    console.log(`Rate limited. Retry after ${err.retryAfter}s`);
  } else if (err instanceof OpenSecStackError) {
    console.log(`API error ${err.statusCode}: ${err.message}`);
  }
}
```

## Configuration

Each client accepts the following common options:

| Option         | Type     | Default  | Description                          |
| -------------- | -------- | -------- | ------------------------------------ |
| `baseURL`      | `string` | required | Base URL of the service              |
| `timeout`      | `number` | `30000`  | Request timeout in milliseconds      |
| `maxRetries`   | `number` | `3`      | Maximum number of retry attempts     |
| `retryWaitBase`| `number` | `500`    | Base wait time (ms) between retries  |

Authentication differs per client:

- **APIGuardClient** and **NIS2CompassClient** use `apiKey: string` (sent as a Bearer token).
- **CITADELClient** uses `keyID: string` and `sharedSecret: string` (HMAC-signed requests).

Retries use exponential backoff and are applied to 5xx errors and 429 rate-limit responses automatically.

## Development

```bash
# Install dependencies
npm install

# Type-check
npm run typecheck

# Run tests
npm test

# Build
npm run build
```

## License

Apache-2.0
