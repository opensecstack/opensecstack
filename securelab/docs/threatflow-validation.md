# ThreatFlow Validation

This guide explains how to use SecureLab to validate ThreatFlow IOC detection against simulated attack traffic.

## Overview

ThreatFlow matches network and application traffic against an IOC database. SecureLab generates traffic patterns that should match known IOC categories — port scans, DoS signatures, SSRF to known internal ranges, and brute force patterns — and verifies that ThreatFlow generates the expected alerts.

## Prerequisites

1. ThreatFlow deployed and ingesting traffic from the test environment.
2. `SECURELAB_THREATFLOW_URL` and `SECURELAB_THREATFLOW_API_KEY` configured.
3. Test environment running.

## Recommended scenarios

| Scenario | IOC Category | Expected ThreatFlow Alert |
|---|---|---|
| `recon/port-scan` | Network reconnaissance | Port scan IOC match on source IP |
| `network/syn-flood-100kpps` | DoS — SYN flood | DoS signature IOC match |
| `network/udp-amplification` | DoS — volumetric | UDP flood IOC match |
| `api/ssrf-metadata` | Cloud metadata SSRF | IOC match on `169.254.169.254` target |
| `api/jwt-brute` | Brute force | Source IP flagged as brute force IOC |
| `combined/apt-simulation` | Multi-technique | Multiple IOC matches across recon, auth, exfil categories |

## Running the validation

```bash
curl -X POST http://localhost:8080/api/v1/runs \
  -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "scenario": "recon/port-scan",
    "environment_id": "env_test_01",
    "detection_platforms": ["threatflow"]
  }'
```

## How SecureLab polls ThreatFlow

SecureLab queries `GET /api/v1/ioc-matches` with:
- `tag`: the MITRE ATT&CK technique ID from the scenario step
- `since`: the step start timestamp
- `source_env`: the environment ID (to avoid false positives from other sources)

A match is confirmed when ThreatFlow returns at least one IOC match event within the detection window.

## Common gaps and remediation

| Gap | Likely cause | Remediation |
|---|---|---|
| Port scan not detected | ThreatFlow reconnaissance rules disabled | Enable network recon IOC rules |
| SYN flood not detected | DoS detection threshold too high | Lower the PPS threshold in ThreatFlow DoS rules |
| SSRF metadata not detected | `169.254.169.254` not in ThreatFlow blocklist | Add AWS/GCP/Azure metadata IP ranges to the blocklist |
| Brute force not detected | Authentication traffic not being ingested | Ensure ThreatFlow is receiving API gateway logs |
