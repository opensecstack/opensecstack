# IRFlow Operator Handbook

The day-to-day runbook for the team operating IRFlow in production.
Read this alongside [troubleshooting.md](./troubleshooting.md) — the
handbook covers planned operations, the troubleshooting guide covers
unplanned ones.

## Starting a shift

1. **Check health.** `curl -f https://irflow.internal/health/detail`
   returns `{"status":"ok","db":"ok","version":"..."}` — if not, see
   troubleshooting.
2. **Scan the incident queue.** `GET /api/v1/incidents?status=open` —
   acknowledge any P1/P2 without an assignee.
3. **Review overnight alerts.** Grafana dashboard for
   `irflow_governance_calls_total{result="failure"}` — any sustained
   CITADEL or NIS2 failure is a carry-over ticket.
4. **Verify CITADEL chain.** Weekly: `GET /citadel/api/v1/worm/verify`
   over the last 7 days must return `{"valid": true}`.

## Incident lifecycle

IRFlow enforces a state machine:

```
open → investigating → contained → eradicating → recovering → closed
                   │
                   └──► reopened (from closed, rare)
```

| Transition | When |
|---|---|
| `open → investigating` | Triage started — an operator has picked it up |
| `investigating → contained` | Bleed stopped — attacker no longer progressing |
| `contained → eradicating` | Clean-up underway (malware removal, credential rotation) |
| `eradicating → recovering` | Restoration of normal operations |
| `recovering → closed` | All action items complete, post-mortem scheduled |

The service layer rejects invalid transitions (`closed → open`
without explicit reopen, skipping `contained`, etc.) — don't try to
force them via direct SQL.

## Submitting a governed action

Every containment / export / restore action needs:

1. **An operator** (you).
2. **A verifier** (peer with `verifier` or `admin` role).
3. **An open incident**.

```
POST /api/v1/incidents/inc_123/actions
Content-Type: application/json
Authorization: Bearer <operator JWT>

{
  "type":        "CONTAIN",
  "target":      "endpoint-42",
  "verifier_id": 77,
  "payload":     { "method": "isolate_network" }
}
```

Response:

- `201 Created` — action accepted and passed MARSHAL.
- `403 ErrMarshalRefused` — read the returned `reasons[]`, correct,
  resubmit.
- `403 ErrMarshalHardStop` — **stop**. This is a policy violation;
  open a new incident if needed.

## Running a playbook

```
POST /api/v1/playbooks/pb_critical_finding/execute
{ "incident_id": "inc_123" }
```

Returns `202 Accepted` + an `Execution` in `pending`. Poll
`GET /api/v1/executions/{id}` every 10 s until `status` is terminal
(`completed`, `failed`, `cancelled`).

Executions older than 1 hour auto-cancel via the enclosing
execution-level timeout — no stuck-forever state.

## Playbook lifecycle management

| Command | Use |
|---|---|
| Author YAML | See [playbook-authoring.md](./playbook-authoring.md) |
| Upload | `POST /api/v1/playbooks` with parsed JSON |
| Activate | `PATCH /api/v1/playbooks/{id}` with `{"status":"active"}` |
| Retire | Set `status: "archived"` — doesn't delete, preserves audit |

Never delete a playbook that has been executed — the `playbook_executions`
table references it, and the audit chain expects the definition to be
retrievable forever.

## Rotating credentials

### JWT signing secret (`IRFLOW_AUTH_SECRET`)

1. Generate a new secret: `openssl rand -base64 32`.
2. Store as the new version in your secret manager.
3. Roll deployment — old tokens become invalid immediately (8-hour
   default TTL limits blast radius).
4. Anyone with a live session needs to re-authenticate.

**Window of pain**: 0-8 hours (the TTL). Plan for a low-traffic
window, or issue fresh tokens proactively.

### Webhook secrets (`IRFLOW_WEBHOOK_*_SECRET`)

1. Coordinate with the sender owner — the rotation is shared.
2. Current (v1.0.0) approach: **maintenance window** required —
   overlapping-secret support is a v1.1 feature.
3. Update both sides, roll both, verify a test webhook arrives
   successfully.

### DB password

1. Use PostgreSQL's `ALTER USER irflow PASSWORD '...'`.
2. Update `IRFLOW_DB_PASSWORD` in the secret manager.
3. Roll deployment — the new pods pick up the new password; pre-existing
   connections in the pool die on the next acquire cycle.

## Scaling

IRFlow is stateless — the DB is the shared state. To scale:

```bash
kubectl scale deployment/irflow --replicas=5
```

Concerns:

- **DB connections.** Each replica opens its own pool
  (`IRFLOW_DB_POOL_MAX_CONNS` per replica, default 25). Ensure
  `replicas × max_conns ≤ Postgres max_connections - 10`.
- **CITADEL load.** Each IRFlow replica is an independent caller.
  More replicas means more `Evaluate` calls; keep CITADEL's own
  scaling in sync.
- **Playbook executions.** In v1.0.0, executions run on the replica
  that received the `execute` request. A replica crash mid-execution
  leaves a stuck `running` state — v1.2's distributed job queue fixes
  this. Today's workaround: cap long playbooks to < 1 h and rely on
  the auto-cancel.

## Backup and restore

Daily `pg_dump` is sufficient. Point-in-time recovery adds forensic
replay.

Critical tables for backup:

- `incidents` — primary records
- `incident_actions` — governed action log
- `ioc_enrichments`
- `timeline_entries`
- `playbooks` + `playbook_executions`

Restore procedure:

1. Provision a fresh DB from the backup.
2. Start IRFlow pointing at it with `IRFLOW_DB_HOST=restored`.
3. Verify `GET /health/detail` reports the expected incident count.
4. Cross-check CITADEL `worm_entry_id`s on a sample of recent actions
   — any mismatch signals the DB and WORM chain have diverged and
   needs manual reconciliation.

## Upgrading

Every tagged version (`1.x.y`) is backwards-compatible with the
previous tag.

1. Pull the new image: `docker pull ghcr.io/opensecstack/irflow:1.1.0`.
2. Run the migration job first — it is idempotent, safe to run
   against an up-to-date DB.
3. Roll the Deployment forward — rolling update, replicas are
   stateless.
4. Watch `/health/detail` on each pod; `version` reflects the new tag.
5. If any replica reports the old version 5 min after rollout, that
   pod is stuck — `kubectl delete pod <name>` to force recycle.

For `1.x → 2.0`, read the release notes — coordination may be
required (e.g. single-writer transitions).

## Reporting

Useful endpoints for management reports:

| Endpoint | Use |
|---|---|
| `GET /api/v1/incidents?status=closed&closed_after=...` | Resolved incident count |
| `GET /api/v1/incidents/{id}/timeline` | Per-incident MTTD / MTTR |
| Metric `irflow_incidents_created_total{severity}` | Volume trend |
| Metric `irflow_governance_calls_total{result}` | Governance reliability |

## Escalation matrix

| Symptom | Page |
|---|---|
| DB unavailable for > 5 min | DBA on-call + IRFlow owner |
| CITADEL `verify` returns `valid: false` | CITADEL owner (tier 1 incident) |
| NIS2 notification success rate < 90% for 24h | Compliance team |
| Sustained 5xx > 1% | IRFlow owner |

## Related

- [Deployment](./deployment.md)
- [Troubleshooting](./troubleshooting.md)
- [Playbook authoring](./playbook-authoring.md)
- [NIS2 mapping](./nis2-mapping.md)
