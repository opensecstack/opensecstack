# Detection Validation

SecureLab validates that your detection platforms (OpenScrub, APIGuard, ThreatFlow) actually alert when the corresponding attack occurs. This document explains how the validation pipeline works.

## Overview

After each scenario step executes, the detection monitor opens a configurable detection window (default: 60 seconds). During this window it polls the configured detection platforms for alerts that match the attack that just ran. At the end of the window, it records a verdict for each expected detection.

## Verdicts

| Verdict | Meaning |
|---|---|
| `detected` | Alert was found within the detection window. |
| `not_detected` | Window elapsed with no matching alert. This is a detection gap. |
| `inconclusive` | Platform was unreachable or returned an error during the window. |
| `not_configured` | No detection platform is configured for this attack type. |

## Detection monitor flow

```
Attack step executes
        |
        v
Detection window opens (default: 60s)
        |
        v
Poll loop starts (default: every 5s)
  |
  +-- GET OpenScrub /api/v1/alerts?technique={mitre_id}&since={step_start}
  +-- GET APIGuard /api/v1/events?attack_kind={kind}&since={step_start}
  +-- GET ThreatFlow /api/v1/ioc-matches?tag={mitre_id}&since={step_start}
        |
        v
Verifier matches alerts to the current step:
  - technique ID matches
  - timestamp is within the window
  - target environment ID matches (to avoid false positives from other runs)
        |
        v
Verdict recorded in run result
        |
        v
Window closes
```

## Latency measurement

For each `detected` verdict, SecureLab records the detection latency: the time from when the attack step started to when the first matching alert appeared. This is reported in the run result as `detection_latency_ms`.

High detection latency (e.g. >30s) is flagged as a warning even if the verdict is `detected`, since slow detections may miss real attacks.

## Gap reporting

At the end of a scenario run, SecureLab generates a coverage report:

- **Detection rate**: percentage of steps with `detected` verdict.
- **Gap list**: all steps with `not_detected` verdict, with MITRE technique IDs.
- **Latency distribution**: p50/p95/p99 detection latency across all detected steps.

The report is available via `GET /api/v1/runs/{run_id}/report` and is also emitted to CITADEL as part of the `securelab.run_completed` event.

## Configuring detection platforms

Each platform is configured via environment variables:

```bash
SECURELAB_OPENSCRUB_URL=https://openscrub.internal
SECURELAB_OPENSCRUB_API_KEY=...

SECURELAB_APIGUARD_URL=https://apiguard.internal
SECURELAB_APIGUARD_API_KEY=...

SECURELAB_THREATFLOW_URL=https://threatflow.internal
SECURELAB_THREATFLOW_API_KEY=...
```

Detection validation is optional. If no platform is configured, SecureLab records `not_configured` verdicts but still executes scenarios and records attack results.

## Detection window configuration

```bash
# How long to wait for detection alerts after each step (default: 60s)
SECURELAB_DETECTION_WINDOW=60s
```

Increase this value if your detection platforms have higher ingestion latency (e.g. batch processing, async log pipelines).

## Per-platform details

- **OpenScrub**: SecureLab queries the `/api/v1/alerts` endpoint. Alert matching uses `technique_id` and `source_env` fields.
- **APIGuard**: SecureLab queries the `/api/v1/events` endpoint. Matching uses `attack_kind` and `environment_id`.
- **ThreatFlow**: SecureLab queries the `/api/v1/ioc-matches` endpoint. Matching uses ATT&CK technique tags.

For per-platform integration guides see:
- [docs/openscrub-validation.md](openscrub-validation.md)
- [docs/apiguard-validation.md](apiguard-validation.md)
- [docs/threatflow-validation.md](threatflow-validation.md)
