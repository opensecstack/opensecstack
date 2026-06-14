# SecureLab Operator Handbook

> **Audience:** authorised operators running SecureLab in a deployed
> environment — red-team leads, SOC managers, and detection engineers
> with write access to the SecureLab API.
>
> **Prerequisite:** You must have completed the access control
> onboarding for your deployment (MFA enrolled, operator role granted,
> target scope approved by your security manager) before following any
> procedure in this handbook.

## Daily operations checklist

Run this before executing any scenario:

- [ ] Confirm SecureLab is healthy: `curl http://<host>:8087/api/v1/health`
- [ ] Confirm Celery worker is running and connected to Redis
- [ ] Confirm CITADEL emitter is not circuit-broken (check Prometheus
      `securelab_citadel_circuit_breaker_state == 0`)
- [ ] Confirm target simulation systems are in a known clean state
      (no prior scenario artefacts left from previous runs)
- [ ] Review the execution queue — no executions in `running` state
      from a previous operator session
- [ ] Confirm your execution has been approved per your deployment's
      change management procedure

## Running a scenario safely

### Step 1 — Select the scenario

```bash
# List scenarios filtered to your target tactic
curl http://localhost:8087/api/v1/scenarios?tactic=execution \
     -H "Authorization: Bearer <token>"
```

Review the scenario detail — pay particular attention to:
- `target_scope`: confirm the target CIDR matches your authorised scope
- `destructive` steps: plan your cleanup before you run
- `expected_detections`: know what a pass looks like before you fire

### Step 2 — Always dry-run first

```bash
curl -X POST http://localhost:8087/api/v1/scenarios/T1059.001-powershell-encoded/execute \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "dry_run": true,
       "target_scope": ["192.168.100.0/24"],
       "notes": "Dry-run pre-check — operator: alice — approved by: bob"
     }'
```

Review the execution plan in the response. Verify that:
- All step targets are within the approved scope
- No destructive steps are present that you have not planned rollbacks for
- The detection sources are all configured and reachable

### Step 3 — Execute live

```bash
curl -X POST http://localhost:8087/api/v1/scenarios/T1059.001-powershell-encoded/execute \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "dry_run": false,
       "target_scope": ["192.168.100.0/24"],
       "notes": "Live execution — operator: alice — CR-2027-1101 approved by: bob"
     }'
```

Note the `execution_id` from the response.

### Step 4 — Monitor execution

```bash
# Poll for completion
curl http://localhost:8087/api/v1/executions/<exec_id> \
     -H "Authorization: Bearer <token>"
```

Or watch in the dashboard execution console.

### Step 5 — Review detection results (v1.0.0+)

```bash
curl http://localhost:8087/api/v1/executions/<exec_id>/detections \
     -H "Authorization: Bearer <token>"
```

For each step:
- `detected`: the detection platform fired within the detection window. Pass.
- `not_detected`: no event received within the window. **This is a finding.**
  Document the gap and open a detection engineering ticket.
- `inconclusive`: detection platform was unreachable or returned an error.
  The execution was real; the validation was not. Re-run when the platform
  is healthy.
- `timeout`: detection window elapsed with no event. Equivalent to
  `not_detected` for coverage purposes.

### Step 6 — Verify CITADEL emission

```bash
# Check the execution record for citadel_emitted: true
curl http://localhost:8087/api/v1/executions/<exec_id> \
     -H "Authorization: Bearer <token>" | jq '.data.citadel_emitted'
```

If `citadel_emitted` is `false` and `evidence_status` is `pending`:
see [Resolving evidence_pending](#resolving-evidence_pending) below.

### Step 7 — Cleanup destructive steps

For any execution with destructive steps, run cleanup immediately
after the execution completes — do not leave artefacts on target
systems. If the scenario's rollback was automatic (triggered by the
engine), verify the rollback succeeded:

```bash
curl http://localhost:8087/api/v1/executions/<exec_id> \
     -H "Authorization: Bearer <token>" | jq '.data.steps[].rollback_status'
```

If any step shows `rollback_status: failed`, clean up manually and
document the action in the notes field via the execution update
endpoint.

## Interpreting detection verdicts

| Verdict | Meaning | Action |
|---|---|---|
| `detected` | Detection platform fired within the window. | No action. Record as validated coverage. |
| `not_detected` | No detection event within the window. | **Finding.** Open detection engineering ticket with scenario ID, step index, and execution ID. |
| `inconclusive` | Detection platform error during polling. | Re-run when platform is healthy. Do not count as validated. |
| `timeout` | Detection window elapsed without event. | Treat as `not_detected`. May indicate platform performance issue — check detection platform health first. |
| `not_applicable` | This source was not expected to detect this step (documented in scenario). | No action. |
| `partial` | Mixed verdicts across detection sources. | Review per-source breakdown. At least one source detected; identify which source is missing. |

## Coverage monitoring

The ATT&CK coverage dashboard shows current validated coverage.
Coverage degrades when:

1. A previously `validated` technique produces `not_detected` in a
   subsequent execution (detection regression).
2. The ATT&CK matrix is updated with new techniques (new gaps appear).

### Scheduling regular re-validation

Re-run scenarios on a schedule to detect coverage drift. Recommended
cadences by risk:

| Scenario type | Re-validation cadence |
|---|---|
| High-priority techniques (T1566, T1190, T1078) | Weekly |
| Standard technique coverage | Monthly |
| Full coverage sweep | Quarterly |

The operator handbook recommends running all scenarios in dry-run
mode after any detection platform update to verify scope compatibility
before live re-execution.

## Audit trail

Every action in SecureLab — login, scenario create/update/delete,
execution request, detection verdict, CITADEL emission — is recorded
in the `audit_log` table. The audit log is INSERT-only at the database
level.

### Querying the audit log

```bash
# Last 50 audit entries
curl "http://localhost:8087/api/v1/audit?limit=50" \
     -H "Authorization: Bearer <token>"

# Entries for a specific operator
curl "http://localhost:8087/api/v1/audit?operator_id=<id>" \
     -H "Authorization: Bearer <token>"

# Entries for a specific execution
curl "http://localhost:8087/api/v1/audit?resource_type=execution&resource_id=<exec_id>" \
     -H "Authorization: Bearer <token>"
```

### Audit log retention

The audit log is retained for the lifetime of the deployment. Do
not truncate the `audit_log` table. If storage is a concern, archive
old entries to cold storage (maintaining the append-only guarantee)
rather than deleting them.

## Resolving `evidence_pending`

When a live execution completes but CITADEL emission fails (circuit
breaker open, CITADEL unreachable), the execution is marked
`evidence_status: pending`. The evidence is not lost — it is in the
SecureLab database — but the WORM seal is missing.

Resolution procedure:

1. Check CITADEL health. If CITADEL is down, wait for it to recover.
2. Check the `securelab_citadel_circuit_breaker_state` Prometheus
   metric. If the circuit is open, check CITADEL connectivity from
   the SecureLab host.
3. Once CITADEL is reachable, trigger a manual re-emit:
   ```bash
   curl -X POST http://localhost:8087/api/v1/executions/<exec_id>/re-emit-citadel \
        -H "Authorization: Bearer <token>"
   ```
4. Verify `citadel_emitted: true` after re-emit.

If CITADEL remains unavailable for an extended period, document the
gap and the reason in the execution notes. The CITADEL team can
accept late emissions with a documented explanation.

## Prometheus metrics reference

| Metric | Type | Description |
|---|---|---|
| `securelab_executions_total` | Counter | Total executions by mode (dry_run, live) and status |
| `securelab_executions_running` | Gauge | Currently running live executions |
| `securelab_detection_verdict_total` | Counter | Detection verdicts by source and verdict type |
| `securelab_citadel_queue_depth` | Gauge | Current CITADEL emission queue depth |
| `securelab_citadel_emit_total` | Counter | CITADEL emissions by status (success, failure) |
| `securelab_citadel_circuit_breaker_state` | Gauge | 0 = closed (healthy), 1 = open (failing) |
| `securelab_coverage_pct` | Gauge | Current ATT&CK coverage percentage (validated) |
| `securelab_api_request_duration_seconds` | Histogram | API request latency by endpoint |

All metrics are available at `http://<host>:8087/metrics`. Restrict
this endpoint to your monitoring stack via firewall; it is
unauthenticated by convention.

## Incident response — unauthorised access

If you suspect an unauthorised actor has accessed the SecureLab API
or dashboard:

1. **Immediately revoke all active operator tokens:**
   ```bash
   curl -X POST http://localhost:8087/api/v1/auth/revoke-all \
        -H "Authorization: Bearer <admin-token>"
   ```
2. **Rotate all HMAC keys** (`SECURELAB_CITADEL_KEY_SECRET`,
   integration keys) — restart the stack after rotation.
3. **Review the audit log** for the time window of suspected access.
4. **Notify your security team** and escalate via your IR procedure.
5. **Preserve the audit log** — do not restart or clear Postgres
   before the IR team has reviewed it.
6. **Report to CITADEL** any simulation events that may have been
   triggered under the unauthorised session — these must be marked
   as potentially tainted in the CITADEL ledger.

An unauthorised access event must be treated as a critical security
incident. Escalate to your CISO and, if applicable, to IRFlow.

## Related

- [SECURITY.md](../SECURITY.md) — threat model and access control
- [docs/deployment.md](deployment.md) — isolation architecture
- [docs/configuration.md](configuration.md) — env vars
- [docs/citadel-integration.md](citadel-integration.md) — CITADEL emission
- [docs/mitre-attack-coverage.md](mitre-attack-coverage.md) — coverage model
