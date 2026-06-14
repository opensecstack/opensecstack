---
name: Detection gap report
about: Report a false negative — an attack that was not detected by a platform
title: "[Detection Gap] <attack_kind> not detected by <platform>"
labels: detection-gap, false-negative
assignees: ""
---

## Detection gap details

**Attack kind**: <!-- e.g. bola, jwt_none, ssrf -->

**MITRE technique**: <!-- e.g. T1078, T1552.005 -->

**Platform that missed the detection**: <!-- OpenScrub / APIGuard / ThreatFlow -->

**Scenario name**: <!-- e.g. api/bola-basic -->

## Expected alert

<!-- What alert or event should have been generated? Include the expected alert type, severity, and any relevant fields. -->

## Actual result

<!-- What actually happened? No alert? Wrong alert? Alert outside detection window? -->

## SecureLab run ID

<!-- Paste the run ID from the SecureLab dashboard or API response, if available. -->

`run_id: `

## Platform version

<!-- Version of the detection platform that missed the detection. -->

**OpenScrub / APIGuard / ThreatFlow version**:

## Reproduction steps

1. Start test environment: `docker compose -f docker-compose.test.yml up`
2. Run scenario:
   ```bash
   curl -X POST http://localhost:8080/api/v1/runs \
     -H "Authorization: Bearer <jwt>" \
     -d '{"scenario": "<scenario_name>", "environment_id": "<env_id>"}'
   ```
3. Observe detection result in run report.

## Detection platform configuration

<!-- Paste the relevant detection platform configuration (sanitized of credentials). What rules are enabled? What is the detection threshold? -->

## Additional context

<!-- Any other context. Did this work in a previous version? Was there a recent configuration change? -->
