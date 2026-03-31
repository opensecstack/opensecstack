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
  token: "your-api-token",
});

// Upload an OpenAPI spec and start a scan
const scan = await apiguard.createScan({
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

for (const finding of findings.data) {
  console.log(`[${finding.severity}] ${finding.title} -- ${finding.endpoint_method} ${finding.endpoint_path}`);
}

// Triage a finding
await apiguard.patchFinding(finding.id, {
  status: "confirmed",
  note: "Verified in staging environment",
});
```

### NIS2Compass -- NIS2 Compliance Management

```typescript
import { NIS2CompassClient } from "@opensecstack/sdk";

const nis2 = new NIS2CompassClient({
  baseURL: "http://localhost:8081",
  token: "your-api-token",
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
const controls = await nis2.listControls(org.id, assessment.id, {
  status: "not_assessed",
});

for (const control of controls) {
  console.log(`[${control.measure_ref}] ${control.title} -- ${control.status}`);
}

// Update a control with evidence
await nis2.patchControl(org.id, assessment.id, control.id, {
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
  token: "your-api-token",
});

// Query recent security events
const events = await citadel.getEvents({
  source: "apiguard",
  since: "2026-03-01T00:00:00Z",
  limit: 50,
});

for (const event of events.data) {
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
| `token`        | `string` | --       | Bearer token for authentication      |
| `timeout`      | `number` | `30000`  | Request timeout in milliseconds      |
| `maxRetries`   | `number` | `3`      | Maximum number of retry attempts     |
| `retryWaitBase`| `number` | `500`    | Base wait time (ms) between retries  |

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
