# OpenScrub Validation

This guide explains how to use SecureLab to validate OpenScrub PII detection and anomaly alerting.

## Overview

OpenScrub detects PII in API traffic and alerts on anomalous data access patterns. SecureLab exercises the API scenarios most likely to trigger OpenScrub alerts — BOLA (bulk object enumeration), data exfiltration, and mass assignment — and then validates that OpenScrub generated the expected alerts.

## Prerequisites

1. OpenScrub deployed and ingesting traffic from the test environment.
2. `SECURELAB_OPENSCRUB_URL` and `SECURELAB_OPENSCRUB_API_KEY` configured.
3. Test environment running (`docker compose -f docker-compose.test.yml up`).

## Recommended scenarios

| Scenario | Expected OpenScrub Alert |
|---|---|
| `api/bola-basic` | Anomalous access pattern: sequential ID enumeration on user objects |
| `api/bola-uuid` | Bulk access to user objects from a single token |
| `api/mass-assignment-role` | Privilege field write attempt flagged as anomaly |
| `scenarios/combined/apt-simulation` | Data exfiltration pattern: bulk user data access |
| `scenarios/combined/full-kill-chain` | Exfiltration alert on export endpoint |

## Running the validation

```bash
# Run BOLA basic scenario against the test environment
curl -X POST http://localhost:8080/api/v1/runs \
  -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "scenario": "api/bola-basic",
    "environment_id": "env_test_01",
    "detection_platforms": ["openscrub"]
  }'
```

## Reading the coverage report

After the run completes, fetch the detection report:

```bash
GET /api/v1/runs/{run_id}/report
```

The report includes:
- `detection_rate`: percentage of steps that triggered an OpenScrub alert.
- `gaps`: steps where no alert was received within the detection window.
- `latency_p95_ms`: 95th percentile detection latency.

## Common gaps and remediation

| Gap | Likely cause | Remediation |
|---|---|---|
| BOLA not detected | OpenScrub's sequential access rule threshold too high | Lower the threshold or enable per-token rate tracking |
| Exfil not detected | Export endpoint not in OpenScrub's monitored path list | Add the export endpoint to the monitored API paths |
| Mass assignment not detected | Field-level anomaly detection not enabled | Enable field-level write anomaly rules in OpenScrub config |
