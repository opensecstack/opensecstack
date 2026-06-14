# VertGuard Troubleshooting Guide

A symptom-first index for the issues operators see most often. Every
entry follows the same shape:

> **Symptom** → **Likely cause** → **Diagnosis command** → **Fix**

If your problem is not listed here, capture the output of `vertguard
diagnose` (described at the bottom) and check the `troubleshooting`
channel in the opensecstack community Slack.

---

## Startup failures

### `database: failed to connect: FATAL: password authentication failed`

The configured DB user does not exist or the password is wrong.

```bash
# Verify connectivity outside VertGuard
psql "$VERTGUARD_DB_URL" -c "select 1;"
```

If `psql` also fails, fix the credentials. If `psql` succeeds but
VertGuard does not, the application is reading a different env var or
config path — check `vertguard config print`.

### `migrate: pq: relation "schema_migrations" already exists`

Harmless if you ran a manual `psql -f migrations/001_initial.sql` once.
Recover by running `vertguard migrate up` — it is idempotent and will
either pick up where the manual run left off or report `0 pending`.

### Server boots but `/health/ready` returns 503

Either CITADEL, the database, or Redis is unreachable. Inspect the body:

```bash
curl -s http://localhost:8093/health/ready | jq .
```

Each dependency has a boolean and a `last_error`. Fix the one that is
`false`.

---

## Scan-path symptoms

### Every scan returns `CLEAN` regardless of input

1. Confirm the rule corpus is loaded:

   ```bash
   curl -s http://localhost:8093/api/v1/threats/iocs?source=internal | jq '. | length'
   ```

   If 0, the threat-feed sync has not run. Trigger it manually:

   ```bash
   vertguard threatfeed sync --source mitre-atlas
   ```

2. Verify the detector is enabled in `config.yaml`:

   ```yaml
   prompt:
     detector: rule          # or 'ml' or 'hybrid'
     enabled: true
   ```

3. If using ML, confirm the model loaded successfully:

   ```bash
   curl -s http://localhost:8093/api/v1/ml/status | jq .
   ```

### `BLOCKED` rate spikes after a deploy

Probably a model regression. Roll back via the registry:

```bash
vertguard ml rollback prompt
```

Then file a ticket against the model card with the new
false-positive corpus — see [false-positive-handling.md](false-positive-handling.md).

### Scan latency p99 > 200 ms

Common causes, in order of likelihood:

1. **Database write bottleneck.** Check `pg_stat_activity` for waits on
   `prompt_scans` or `phishing_scans`. Tune `max_open_conns` per
   [performance.md](performance.md).

2. **CITADEL WORM emission running synchronously.** Confirm the env
   variable `VERTGUARD_CITADEL_ASYNC=true` is set (the default).

3. **GC pressure from the ML detector.** If `BenchmarkPromptDetector_ML`
   shows > 100 allocs/op, regenerate the model with the optimised
   tokenizer (`make ml-rebuild`).

---

## Auth & authz

### `401 unauthorized` after a successful login

The token expired, was revoked, or VertGuard restarted with a new JWT
secret.

```bash
# Confirm the token signature is still valid
vertguard auth inspect "$TOKEN"

# Was the JTI revoked?
psql "$VERTGUARD_DB_URL" -c \
  "SELECT * FROM token_denylist WHERE kind='jti' AND value='<JTI>';"

# Did the JWT secret rotate?
vertguard config print | grep jwt_secret_id
```

Re-issue with `vertguard auth token <api_key>` once you've identified
the cause.

### `403 forbidden: requires operator`

The caller's role is below the endpoint's required role. Roles are
hierarchical (`viewer < analyst < operator < admin`).

```bash
vertguard auth inspect "$TOKEN" --json | jq .role
```

If the role is wrong, an admin can rotate it via the `api_keys`
endpoint or by re-issuing the key.

---

## Outbound webhooks

### Subscribers stuck in `retrying` state

The destination is returning 5xx or timing out. Inspect:

```bash
curl -s http://localhost:8093/api/v1/webhooks/$ID/deliveries?limit=20 | jq .
```

Each delivery row carries `last_status` (HTTP code) and `last_error`.
Common causes:

- TLS / hostname mismatch — fix the URL or the cert
- IP allow-listing — the destination blocks traffic from VertGuard
- HMAC mismatch — secret was rotated on one side only

If the destination is permanently broken, disable the subscriber:

```bash
curl -X PATCH http://localhost:8093/api/v1/webhooks/$ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"active": false}'
```

### `webhook queue saturated` log lines

The async dispatcher is dropping events because the bounded queue
filled up. Either:

- Reduce subscriber count or filters (so fewer events match)
- Bump the queue size in `config.yaml` (`webhooks.queue_size`)
- Investigate why deliveries are slow — see the previous symptom

---

## CITADEL & WORM

### `worm chain break detected — expected prev_hash X, got Y`

Either CITADEL was restored from a backup that overlapped with
VertGuard's emission stream, or another VertGuard replica is sharing the
same connector key. Both must each have **their own** key — share a key
between replicas and their `prev_hash` cursors will collide.

Fix:

1. Generate a new connector key per replica.
2. Re-issue WORM events from the gap range
   (`vertguard worm replay --from <ts> --to <ts>`).

### CITADEL evaluation always returns `EXECUTE` even for known-bad actions

`VERTGUARD_CITADEL_API_URL` is empty → the connector is in no-op mode.
Configure it pointing at the live CITADEL service. If the URL is set
but evaluation still bypasses, check the fail-mode:

```yaml
citadel:
  fail_mode: closed   # production default
  fail_mode: open     # DEV ONLY — never deploy
```

---

## Database health

### `prompt_scans` is growing 5 GB per day

You have either a runaway client or duplicate scans. Identify the
culprit:

```sql
SELECT classification, count(*) AS n
FROM prompt_scans
WHERE created_at > now() - interval '1 day'
GROUP BY classification
ORDER BY n DESC;

-- Top sources
SELECT input_hash, count(*) AS reps
FROM prompt_scans
WHERE created_at > now() - interval '1 hour'
GROUP BY input_hash
ORDER BY reps DESC
LIMIT 10;
```

If the same `input_hash` is hit thousands of times per hour, a client
is likely retrying without backoff. Address client-side first; only
deduplicate server-side as a stop-gap.

### `pg_stat_activity` shows long-running `idle in transaction`

VertGuard never holds open transactions on the request path; this is
either an operator running a manual query or a backup tool. Identify:

```sql
SELECT pid, query, state_change FROM pg_stat_activity
WHERE state = 'idle in transaction';
```

`pg_terminate_backend(pid)` if you can confirm it is safe to kill.

---

## ML / model issues

### Model loads but inference returns identical confidences

The model is in a degenerate state — usually a tokenizer mismatch
between training and serving. Run:

```bash
vertguard ml smoke prompt
```

Output flags whether the tokenizer hash matches the model card. If not,
re-export the model with the matching tokenizer.

### Out-of-memory on startup with the ML detector enabled

The model exceeds the container's memory request. Either:

- Bump `resources.limits.memory` to the value listed in
  [performance.md](performance.md)
- Switch to the quantised model variant (`prompt.model: prompt-int8`)
- Switch to the rule-only detector (`prompt.detector: rule`) and rely
  on a separate ML replica behind an inference service

---

## Quick diagnose dump

For any "I don't know what's wrong" moment, run:

```bash
vertguard diagnose > diagnose.txt
```

The dump includes:

- Effective config (with secrets redacted)
- Recent log lines (last 500)
- Database health (`SELECT version()`, applied migrations, table sizes)
- CITADEL connectivity (ping + chain anchor)
- Redis connectivity
- ML model load status + last-N inference latencies
- Goroutine count + heap profile

Attach this to any ticket in the opensecstack tracker.

---

## See Also

- [operator-runbook.md](operator-runbook.md) — incident-response procedures
- [operator-handbook.md](operator-handbook.md) — day-to-day operations
- [false-positive-handling.md](false-positive-handling.md) — model corpus management
- [performance.md](performance.md) — latency / throughput baselines
- [faq.md](faq.md) — conceptual questions before they become incidents
