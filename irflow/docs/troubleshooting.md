# IRFlow Troubleshooting

Common failure modes and the fastest path to a fix. Entries are
grouped by the symptom the operator sees first; each one names the
real root cause and the exact next step.

For broader context on what should happen in a healthy deployment,
see [deployment.md](./deployment.md).

## Startup

### `config: IRFLOW_DB_PASSWORD is required`

**Meaning:** the config validator refused to start the process because
production requires an explicit DB password.

**Fix:** set `IRFLOW_DB_PASSWORD` in the env (via secret manager, not
in the compose file). If you're running locally with the shipped
docker-compose, the password is in `docker-compose.yml`.

### `auth: secret is empty — DEV MODE enabled`

**Meaning:** `IRFLOW_AUTH_SECRET` is blank. IRFlow is running with
authentication disabled; every request is authorised as
`(dev, admin)`.

**Fix:** generate a 32-byte secret (`openssl rand -base64 32`), store
it in your secret manager, set `IRFLOW_AUTH_SECRET`, and restart.

### Migration job fails with `schema_migrations already exists`

**Meaning:** benign if the table contents match. If the table
contents *don't* match, the migration runner refuses to replay.

**Fix:** compare `schema_migrations.version` against
`migrations/NNN_*.sql` filenames. If they match, the error is harmless
and you can ignore; if they don't, your DB was partially migrated in
the past — restore from the previous backup and retry.

### `worm entry id mismatch` on startup self-check

**Meaning:** CITADEL self-check could not find a WORM entry for the
last decision IRFlow recorded. Signals a CITADEL outage or a chain
rewind.

**Fix:** do not continue. Investigate the CITADEL side first — see
[../../citadel/docs/worm-log.md](../../citadel/docs/worm-log.md).

## Webhooks

### `401 webhook: signature does not match`

**Meaning:** the sender's HMAC-SHA256 signature does not match what
IRFlow computed with the configured secret.

**Fix:**

1. Verify `IRFLOW_WEBHOOK_<SOURCE>_SECRET` matches the sender's shared
   secret exactly (no trailing newline, no base64 confusion).
2. Check the sender is signing `timestamp + "." + raw_body`, not just
   the body.
3. Confirm the sender is using the *exact bytes* on the wire — a
   re-serialised JSON (different whitespace) will invalidate the
   signature even if the content is semantically identical.

### `401 webhook: X-Irflow-Timestamp outside allowed clock skew`

**Meaning:** the timestamp is more than ±5 minutes from server time.

**Fix:** sync clocks. NTP should keep both sides within a few seconds.
If a legitimate sender cannot sync, raise
`IRFLOW_WEBHOOK_CLOCK_SKEW_TOLERANCE` — but the cost is increased
capture-replay exposure.

### `503 Service Unavailable` on a webhook endpoint

**Meaning:** the per-source secret for this endpoint is not
configured. The endpoint fails closed.

**Fix:** set `IRFLOW_WEBHOOK_<SOURCE>_SECRET` and restart.

### Webhook accepts but nothing happens

**Meaning:** payload was valid and signature verified, but the
handler decided it required no action (e.g. a `threatflow.bundle.published`
whose `incident_id` matched no open incident).

**Fix:** check structured logs with `request_id`; the handler logs its
"no-op" decision. If the behaviour is wrong, open a GitHub issue —
this is not an error condition, just unexpected triage.

## CITADEL integration

### `403 ErrMarshalRefused`

**Meaning:** MARSHAL Gate 1, 2, or 4 rejected the Kerkese. Auditable,
recoverable.

**Fix:** inspect the returned `reasons[]` in the response body.
Typical culprits: AuthZ rejection (role isn't permitted this action
type), AUGUR rule_01 triggered during an off-hours operation, Gate 1
role mismatch.

### `403 ErrMarshalHardStop`

**Meaning:** Gate 3 (NDS) or Gate 4 rule_03 flagged the operation.
Not recoverable — retrying doesn't help.

**Fix:** stop. A HARD_STOP is a policy flag, not a transient error.
Open an incident. If the flag is a false positive, the fix is in the
policy, not in the retry.

### `502 Bad Gateway` on action submission

**Meaning:** IRFlow could not reach CITADEL.

**Fix:** `curl $IRFLOW_CITADEL_API_URL/api/v1/health`. If it fails,
CITADEL is down — follow its own runbooks. If it succeeds, the HMAC
secret mismatch between IRFlow and CITADEL is the next thing to
verify.

### CITADEL calls seem slow

**Meaning:** p95 latency on the outbound `marshal_calls` series has
risen.

**Fix:** check CITADEL's `citadel_worm_append_seconds` — Gate 5
dominates latency and is disk-bound on PostgreSQL. A slow DB on the
CITADEL side is almost always the cause; raise the DB I/O profile or
migrate to provisioned IOPS.

## NIS2 notification

### `governance_calls_total{target="nis2",result="failure"}` sustained > 0

**Meaning:** NIS2 Compass is rejecting or failing notifications.

**Fix:** check the alert payload in logs for the exact HTTP status
from Compass. Common causes:

- **401**: `IRFLOW_NIS2_API_KEY` is stale — rotate, restart.
- **404**: `IRFLOW_NIS2_ASSESSMENT_ID` doesn't exist — correct the ID.
- **5xx**: Compass is down — this is the assessment owner's runbook,
  not IRFlow's.

Incidents continue to be created successfully; only the Article 23
notification is missing. Log these and re-notify manually from
Compass UI until the root cause is fixed.

## Performance

### High `irflow_http_request_duration_seconds` at p95

**Candidates in order of frequency:**

1. **DB pool exhaustion**: check `irflow_db_pool_connections{state="acquired"}`
   vs `state="max"`. > 80% for 10 min is an alert condition.
2. **CITADEL round-trip dominates**: see above — Gate 5 WORM append is
   disk-bound.
3. **Large webhook bodies**: if p95 is on webhook endpoints
   specifically, `IRFLOW_WEBHOOK_MAX_BODY_SIZE` may be too lenient
   relative to DB capacity. Senders should paginate large IOC bundles.

### OOM on startup after scaling replicas

**Meaning:** the pxx pool config × replicas exceeds DB max
connections.

**Fix:** reduce `IRFLOW_DB_POOL_MAX_CONNS` per replica (default 25)
so `replicas × max_conns ≤ Postgres max_connections - 10`. The `-10`
reserves room for migrations and incidental psql sessions.

## Integration tests

### `TRUNCATE incident_actions` errors intermittently

**Fix:** add `-p 1` to `go test`. Always. See [testing.md § The -p 1 flag](./testing.md#integration-tests).

### `IRFLOW_TEST_DB_URL not set — skipping`

**Meaning:** expected in environments without Docker. Not a failure.

### Real DB test fails with `too many connections`

**Meaning:** prior test runs left stale connections. The Go test
runtime is tidy but pxx pools can leak on panic.

**Fix:** `make compose-test-down && make compose-test-up` — the
cleanest reset.

## When to escalate

- WORM chain divergence or any `Valid: false` from
  `GET /api/v1/worm/verify` on CITADEL — incident, not troubleshooting.
- An action that should have been REFUSED but returned EXECUTE —
  governance breach, file a SECURITY report per [../SECURITY.md](../SECURITY.md).
- Persistent 5xx rate > 1% for 15 min — page on-call, don't bisect
  in the ticket queue.

## Related

- [Deployment](./deployment.md) — reference for the healthy state you're diffing against
- [Operator handbook](./operator-handbook.md) — day-to-day runbooks
- [Architecture](./architecture.md) — understanding the layers the symptoms live in
