# OpenCSIRT Operator Handbook

Day-to-day operational guide for OpenCSIRT v1.0.0. For incident
disclosure see [SECURITY.md](../SECURITY.md). For deployment and
topology see [deployment.md](deployment.md). For architecture see
[architecture.md](architecture.md). For symptom-driven debugging see
[troubleshooting.md](troubleshooting.md).

## Deployment topology

OpenCSIRT deploys as three stateless services plus Postgres:

| Tier | Workload | Replicas | Network |
|---|---|---|---|
| Control | `opencsirt-api` (Go) | N, behind LB, **Deployment** | HTTP `:8088` |
| Control | `opencsirt-advisory` (Python) | M, behind ClusterIP, **Deployment** | HTTP `:8089` |
| Control | `opencsirt-web` (nginx + SPA) | M, behind LB, **Deployment** | HTTP `:80` (`:3088` on Compose) |
| Data | `postgres` 16 | 1 primary (+ replica) | TCP 5432, cluster-internal |

The Go API talks to the Python advisory subsystem over the cluster
network at `OPENCSIRT_ADVISORY_SERVICE_URL` (default
`http://localhost:8089` in dev, `http://opencsirt-advisory:8089` in
production). The advisory subsystem holds no state; killing it does
not lose data — drafts in flight retry on the next request.

Sizing: the Go API is CPU-bound on JSON marshalling and JWT
verification; scale horizontally on CPU. The advisory subsystem is
CPU-bound on CSAF schema validation; one replica per ~50 advisories
per minute is comfortable. Postgres sizing follows the constituency
count and incident retention policy (see Capacity below).

## Morning routine (5 minutes)

```bash
# 1. API health (db + advisory_service must both be true)
curl -sf https://opencsirt.internal/api/v1/health | jq .

# 2. CITADEL outbox depth (should be near 0)
curl -sf -H "Authorization: Bearer $READONLY_TOKEN" \
  https://opencsirt.internal/api/v1/metrics \
  | grep '^opencsirt_citadel_queue_depth'

# 3. Last 24 h advisories published
curl -sf -H "Authorization: Bearer $READONLY_TOKEN" \
  https://opencsirt.internal/api/v1/metrics \
  | grep '^opencsirt_advisories_published_total'

# 4. ThreatFlow IOC ingest cadence
curl -sf -H "Authorization: Bearer $READONLY_TOKEN" \
  https://opencsirt.internal/api/v1/metrics \
  | grep '^opencsirt_iocs_ingested_total'

# 5. Alert queue — Grafana / Alertmanager for overnight pages
```

Healthy state:

- `db: true`, `advisory_service: true` on every API replica.
- `opencsirt_citadel_queue_depth` ≤ 10 sustained.
- `opencsirt_citadel_events_total{outcome="error"}` flat for the last
  24 h.
- `opencsirt_iocs_ingested_total` advances on the configured
  `OPENCSIRT_THREATFLOW_INTERVAL` cadence.
- No incident with `status = 'open'` older than the local CSIRT's
  triage SLA (typically 1 h).

## Daily monitoring

The metrics that matter — exposed at
[`/api/v1/metrics`](api.md#metrics) (JWT-gated) and grounded in
[`internal/metrics/metrics.go`](../internal/metrics/metrics.go):

| Metric | Healthy | Action threshold |
|---|---|---|
| `opencsirt_incidents_created_total{source,severity}` | advances during business hours | Sudden spike of `severity="critical"` → P1 (real or false-positive flood) |
| `opencsirt_incidents_closed_total{severity}` | tracks incidents_created on a lag | Closure ratio < 0.5 over a week → triage backlog |
| `opencsirt_advisories_published_total{tlp}` | advances per drafting cadence | Flat for > 7 days while incidents climb → publication bottleneck |
| `opencsirt_escalations_sent_total` | rare, but advances on cross-CSIRT calls | Spike → coordinated incident; check peer roster |
| `opencsirt_citadel_events_total{outcome="error"}` | 0 | > 1% of total over 30 m → P1 (evidence chain breaking) |
| `opencsirt_citadel_queue_depth` | ≤ 10 | > 100 sustained → P1 (CITADEL unreachable or HMAC mismatch) |
| `opencsirt_iocs_ingested_total{source}` | advances each pull | Flat for 2× `OPENCSIRT_THREATFLOW_INTERVAL` → ThreatFlow puller stuck |

Specific alerts to wire in:

- **citadel-queue-depth-high** —
  `opencsirt_citadel_queue_depth > 100` for > 5 m. Operationally:
  CITADEL is unreachable, the HMAC secret is mismatched after
  rotation, or the dryRun flag is misconfigured. Page on-call. See
  [troubleshooting.md § "CITADEL events stuck pending"](troubleshooting.md).
- **advisory-service-down** — `advisory_service: false` in
  `/api/v1/health` for > 2 m. New advisory drafts are blocked
  (NoopClient fallback). Incident triage continues; advisories
  block. P2.
- **ioc-ingest-stalled** — `opencsirt_iocs_ingested_total{source="threatflow"}`
  flat for > 5 min while `OPENCSIRT_THREATFLOW_INTERVAL` is
  ≤ 5 min. ThreatFlow URL/token misconfigured, ThreatFlow down, or
  the puller goroutine crashed. P3.
- **citadel-emit-error-rate** —
  `rate(opencsirt_citadel_events_total{outcome="error"}[30m])`
  > 1% of total. Evidence is being lost. Page on-call. Check clock
  drift, HMAC mismatch (rotation), CITADEL ingress reachability.
- **incident-triage-backlog** — `incidents` rows with
  `status = 'open' AND opened_at < now() - interval '1 hour'` > 10.
  Triage SLA at risk. P3.

## Upgrade procedure

API and dashboard upgrades are rolling Deployments. The advisory
subsystem is also rolling; in-flight requests retry against the next
replica. Postgres migrations run by the Go API on boot, so the
migration ordering is:

1. **Snapshot Postgres** — `pg_dump` before any migration boundary.
2. **Roll the API Deployment** — new pods run `migrate up` on start;
   the OpenAPI handler returns 503 until the migration completes.
3. **Roll the advisory Deployment** — independent of the API.
4. **Roll the web Deployment** — independent of the API.

Rollback: previous image tags + `helm rollback`. Migrations are
version-pinned; a rollback that crosses a migration boundary needs
`make migrate-down` against the Postgres before the API replicas
come back up.

## CSIRT-specific playbooks

### Abuse mailbox triage flow

The `abuse_mailbox` source feeds the incidents board via a downstream
SMTP-to-API bridge (separate from this repo). Operationally:

1. **Sort the queue** in the dashboard by `severity` desc,
   `opened_at` asc. Anything with `severity = 'critical'` jumps to
   the top.
2. **Confirm the constituency.** Bridge messages without a known
   reporter domain land with `constituency_id = NULL`. Either
   register the constituency now or close the incident as
   `out_of_scope`.
3. **Triage transition.** Move `open → triaged` once you have a
   working theory; update `metadata.triaged_by`. This state change
   is tracked internally but does not emit a CITADEL event.
4. **Cross-reference IRFlow.** Search the IRFlow case board for
   IOCs that match — if a case exists, set
   `metadata.irflow_case_id` so the timeline links cleanly.
5. **Decide: contain or close.** `contained` = mitigation in place
   on the constituent's side; `closed` = no further action. Moving
   to `closed` emits `opencsirt.incident_closed` to CITADEL; the
   `contained` transition is tracked internally only.

> **Note:** only `opened` and `closed` transitions currently emit
> CITADEL events; intermediate state changes (`triaged`, `contained`)
> are tracked internally but not forwarded.

### Advisory drafting checklist

Before you click *Publish* on an advisory:

- [ ] **Constituency or vulnerability identified** — every advisory
      maps to either a specific constituency segment or a CVE pulled
      via VertGuard. Generic "be careful" advisories are out of scope.
- [ ] **TLP set correctly.** TLP:CLEAR/GREEN are readable by
      `external_peer` role; TLP:AMBER is internal + named peers;
      TLP:RED is internal only. Re-read the
      [TLP 2.0 spec](https://www.first.org/tlp/) if unsure.
- [ ] **CSAF document validated.** The Python subsystem returns the
      CSAF doc and the validation outcome; if the doc has open errors,
      the publish endpoint returns 422.
- [ ] **csirt_lead role.** Only `csirt_lead` and `admin` may publish.
      `operator` may draft.
- [ ] **Peer fan-out.** TLP:CLEAR/GREEN advisories also queue an
      escalation event for federated peers; verify the peer roster
      reflects current trust.

### Peer escalation runbook

When a coordinated incident requires reaching another CSIRT:

1. **Open an incident** with `source = 'peer_csirt'` (if reaching
   out) or wait for inbound peer push.
2. **Confirm the peer record.** `peer_csirts` row must exist with a
   recent `last_handshake_at`. If stale (> 30 days), re-run the
   handshake before sending sensitive payloads
   ([peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md)).
3. **Send the escalation.** The API helper fires
   `opencsirt.escalation_sent` with the target peer id. The recipient
   CSIRT receives a TLP-tagged advisory pointer; the actual incident
   body stays in OpenCSIRT.
4. **Record the response.** Update `metadata.peer_response` on the
   incident with whatever the peer reports back.

### NIS2 Article 23 deadline calculation

NIS2 Article 23 requires significant-incident notification within:

- **Early warning:** 24 h from awareness.
- **Incident notification:** 72 h from awareness.
- **Final report:** 1 month after the incident notification.

OpenCSIRT does not enforce these deadlines — they are jurisdictional
— but the dashboard surfaces a `nis2_deadline` chip on each incident
where the constituency has `nis2_status IN ('essential', 'important')`.
The chip is computed as `opened_at + 24 h` (early warning) and
`opened_at + 72 h` (notification). When `OPENCSIRT_NIS2COMPASS_API_URL`
is configured, the API auto-pushes a draft notification to NIS2
Compass at the 24 h mark; the operator confirms or amends.

Operationally:

- Watch the *Incidents* board filter `NIS2 due`. Anything in red is
  past the 24 h chip.
- The 72 h chip is the hard deadline for most jurisdictions; treat
  red here as a P1 escalation to `csirt_lead`.

## Incident-response correlation with IRFlow

OpenCSIRT and IRFlow are intentionally separate platforms:

- **IRFlow** owns the per-incident workflow engine — the playbook
  steps, the case-management screens, the per-action audit trail.
- **OpenCSIRT** owns the coordination layer — constituency mapping,
  advisory authoring, peer escalation, NIS2 reporting.

When IRFlow opens a case it POSTs to
`/api/v1/integrations/irflow/incident` with an HMAC-SHA256 signed
body. OpenCSIRT creates an incident with `source = 'irflow'` and
`metadata.irflow_case_id` set. From then on:

- IRFlow continues to drive the playbook.
- OpenCSIRT decides whether the incident becomes an advisory.
- Both write to CITADEL; the WORM ledger is the join key.

When investigating a multi-platform incident:

1. Pull the `irflow_case_id` from the OpenCSIRT incident metadata.
2. Query CITADEL for events tagged with that case id; both
   `irflow.*` and `opencsirt.*` show up.
3. The CITADEL timeline is the auditor-facing record of record.

## Capacity planning

OpenCSIRT is small-scale by design — a national CSIRT serves
hundreds to low thousands of constituencies, not millions. The
sizing constraints in v1.0.0:

- **Constituencies**: 10 000 rows is comfortable on a single Postgres
  primary. Beyond that, partition by sector or country.
- **Incidents**: ~10 000 incidents per quarter is the design
  ceiling for an unsharded Postgres. Higher rates indicate either an
  abuse-mailbox flood (rate-limit upstream) or an under-tuned
  bridge.
- **Advisories**: ~500 advisories per quarter for a national
  CSIRT, ~50 per quarter for a sector CSIRT. The Python subsystem
  comfortably handles 100×.
- **Peers**: low-hundreds of peer CSIRTs is the practical ceiling.
- **CITADEL outbox**: 10 ops/sec sustained on a single API replica
  before queue depth grows. For higher throughput, scale API
  replicas — the watcher is per-replica, racing on row-level locks.

## Routine ops

### Rotating `OPENCSIRT_JWT_SECRET`

The auth package supports multiple secrets internally for verify;
the env loader currently takes a single secret. Rotation procedure:

1. Mint a new secret (`openssl rand -base64 32`).
2. Set the new value in the deployment env.
3. Roll the API. Existing tokens become invalid; users must re-login.
4. The token TTL (`OPENCSIRT_TOKEN_TTL`, default 12 h) bounds the
   disruption window; for graceful overlap pre-flight a coordinated
   re-login.

### Rotating `OPENCSIRT_CITADEL_HMAC_SECRETS`

Comma-separated list (`primary,next,previous`) supports overlap
windows:

1. Provision the new secret on CITADEL with an overlap window.
2. Append the new secret as the **second** entry in
   `OPENCSIRT_CITADEL_HMAC_SECRETS` (e.g. `old,new`). Roll the API.
3. Promote the new secret to first slot (e.g. `new,old`). Roll the
   API.
4. After CITADEL's overlap expires, drop the old entry.

A mismatched HMAC secret manifests as
`opencsirt_citadel_events_total{outcome="error"}` with `bad_signature`
in API logs.

### `OPENCSIRT_TEST_DB_URL`

Used exclusively by the `make test-postgres` target to run the Go
integration test suite against a real Postgres instance. It is never
read at runtime; the application uses `OPENCSIRT_DB_URL` instead.

| Field | Detail |
|---|---|
| **Purpose** | DSN for the Postgres database targeted by integration tests |
| **Example** | `postgres://opencsirt:opencsirt@localhost:5432/opencsirt_test?sslmode=disable` |
| **Make targets** | `test-postgres` |
| **Behaviour when unset** | `make test-postgres` exits with an error message; `make test` (unit tests) is unaffected |

The test database should be a separate instance from the development
database (`OPENCSIRT_DB_URL`) so that integration tests can truncate
tables freely without disrupting a running dev stack.

### Postgres backups

Standard `pg_dump` / restore. Migrations live in [`migrations/`](../migrations/),
applied by the API on boot. The `incidents`, `advisories`, and
`audit_log` tables are the critical surfaces; lose them and you lose
provenance for every active incident.

## Related

- [architecture.md](architecture.md)
- [deployment.md](deployment.md)
- [configuration.md](configuration.md)
- [api.md](api.md)
- [troubleshooting.md](troubleshooting.md)
- [peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md)
- [citadel-integration.md](citadel-integration.md)
- [irflow-integration.md](irflow-integration.md)
- [threatflow-integration.md](threatflow-integration.md)
- [nis2-integration.md](nis2-integration.md)
- [vertguard-integration.md](vertguard-integration.md)
- [faq.md](faq.md)
- See the [monorepo SECURITY.md](https://github.com/opensecstack/opensecstack/blob/main/SECURITY.md) for ecosystem-wide disclosure policy
- [ROADMAP.md](../ROADMAP.md)
