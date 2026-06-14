# CyberPath Troubleshooting Guide

A symptom-first index for the issues operators see most often. Every
entry follows the same shape:

> **Symptom** → **Likely cause** → **Diagnosis command** → **Fix**

If the issue isn't listed here, capture `cyberpath-cli diagnose` and
attach it to a ticket in the opensecstack tracker.

---

## Startup failures

### `database: failed to connect: FATAL: password authentication failed`

The configured DB user does not exist or the password is wrong.

```bash
# Verify connectivity outside CyberPath
psql "$CYBERPATH_DB_URL" -c "select 1;"
```

If `psql` also fails, fix the credentials. If `psql` succeeds but
CyberPath does not, the application is reading a different env var
or config path — check `cyberpath-cli config print` and confirm
which file Viper picked up.

### `migrate: relation "schema_migrations" already exists`

Harmless if a manual `psql -f migrations/001_initial.sql` ran once.
Recover with:

```bash
cyberpath-cli migrate up    # idempotent; reports "0 pending" if all applied
```

### `/readyz` returns 503 with `db: ok` but `citadel: unreachable`

CITADEL is configured but unreachable. CyberPath continues to serve
learner traffic; completion events buffer to the local WAL. Verify:

```bash
curl -sf "$CYBERPATH_CITADEL_API_URL/healthz"
```

If CITADEL is down for the long term, set
`CYBERPATH_CITADEL_API_URL=` and restart — the loud WARN is fine in
maintenance windows; do not deploy this configuration permanently.

---

## Auth & JWT 401s

### `401 unauthorized` on every authenticated call after a working session

The JWT expired, the secret rotated, or the issuer is wrong.

```bash
# Decode the token (no verification)
echo "$TOKEN" | cut -d. -f2 | base64 -d | jq .
# Check exp, iss, role

# Confirm the issuer matches what CyberPath expects
cyberpath-cli config print | grep auth_issuer
```

Re-issue with `POST /api/v1/auth/refresh` (using the refresh token)
or log in again. If `iss` mismatches, the token was issued by a
different CyberPath instance — confirm tenant/cluster.

### `401 unauthorized` immediately after deploying a new release

`CYBERPATH_AUTH_SECRET` changed. All existing access tokens are
invalid; refresh tokens issued before the rotation are also
invalid. Force re-login at the UI; this is the intended behaviour
of secret rotation.

### `403 forbidden: requires admin`

The caller's role is below the endpoint's required role.

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d | jq .role
```

Roles in CyberPath: `learner < instructor < admin`. The `service`
role is for ecosystem callouts (NIS2 Compass) and is not
hierarchical.

---

## Lab sandbox

### `503 runtime_unavailable` from `POST /api/v1/labs/{id}/start`

The configured lab runtime can't be reached.

**Docker runtime** — Docker socket not mounted:

```bash
docker compose exec api ls -l /var/run/docker.sock
# Expect: srw-rw---- ... /var/run/docker.sock
```

If missing, the `docker-compose.yml` needs the volume mount:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

**Wasm runtime (v1.0.0+)** — wasmtime module not loaded:

```bash
curl -sf http://localhost:8086/readyz | jq '.modules.lab'
# Expect: "active (wasmtime)"
```

If `inactive`, the wasmtime side-car failed to start. Check:

```bash
kubectl -n cyberpath logs -l app.kubernetes.io/component=sandbox
# Look for: "wasmtime engine ready, fuel=5000000000"
```

### Lab session OOM-killed within seconds

The lab image needs more memory than `CYBERPATH_SANDBOX_MEMORY_MIB`.

```bash
# Per-session metrics
curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/labs/$LAB_ID/status | jq .resource_metrics
```

Bump `SANDBOX_MEMORY_MIB` for the runtime, or pin the specific lab
to a larger limit via `labs/<lab>.yaml`:

```yaml
limits:
  memory_mib: 1024
  cpu_quota:  "1.5"
```

### Lab WebSocket disconnects after 60 seconds

The ingress / reverse proxy is timing out long-lived connections.

For nginx:

```
proxy-read-timeout: 3600
proxy-send-timeout: 3600
proxy-buffering:    off
```

For Caddy: `flush_interval -1` on the `reverse_proxy` to the lab
WebSocket route.

### `403 sandbox_network_blocked` inside the lab

The lab tried to reach a host outside its NetworkPolicy. By default
labs run with `network: none`. If the lab legitimately needs egress,
override per-lab:

```yaml
network: egress-only
egress_allowed:
  - cve.mitre.org:443
  - api.osv.dev:443
```

CyberPath renders an additional NetworkPolicy and the egress is
audit-logged.

---

## CITADEL evidence emission

### Sustained `cyberpath_citadel_queue_depth > 800`

CITADEL is unreachable or slow, and the local queue is filling.

```bash
# Direct CITADEL probe
curl -sf -m 3 "$CYBERPATH_CITADEL_API_URL/healthz"

# CyberPath circuit breaker state
curl -sf http://localhost:8086/metrics | grep cyberpath_citadel_breaker_state
# 0 = closed (healthy), 1 = open, 2 = half-open
```

If CITADEL is up but slow, raise `CYBERPATH_CITADEL_QUEUE_MAX`
temporarily and investigate the CITADEL side. If CITADEL is down,
the on-disk WAL drains automatically once the breaker closes; no
intervention is needed unless the WAL disk fills.

### `worm chain submission timed out` in logs

Per-event timeout exceeded. Increase the per-event budget if the
target deployment is on a high-latency link:

```bash
CYBERPATH_CITADEL_REQUEST_TIMEOUT=10s
```

If timeouts persist, the event will retry up to 5 times then go to
the WAL — the learner-visible completion is unaffected.

### Events show `citadel_emitted: queued` forever

The async drainer goroutine is wedged. Trigger a forced flush:

```bash
cyberpath-cli citadel flush --max-events 10000
```

If the flush also hangs, capture a goroutine dump:

```bash
curl -sf http://localhost:8086/debug/pprof/goroutine?debug=2 > goroutines.txt
```

and file a ticket with the dump attached.

---

## NIS2 Compass

### `GET /api/v1/coverage/{user_id}` returns 401 when called from NIS2 Compass

The NIS2 Compass service token is not accepted. Either it's expired,
the issuer is wrong, or it was minted with the wrong role.

```bash
# Inspect the token Compass is sending
echo "$NIS2_TOKEN" | cut -d. -f2 | base64 -d | jq .
# Expect: role=service, iss=<your auth issuer>, exp in future
```

Verify both sides agree on `CYBERPATH_AUTH_ISSUER`.

### NIS2 Compass times out calling CyberPath

CyberPath is reachable from your shell but not from NIS2 Compass.
The egress path is blocked.

```bash
# From within Compass's namespace
kubectl -n nis2compass exec deploy/nis2compass -- \
  curl -sf -m 3 http://cyberpath.cyberpath.svc.cluster.local:8086/healthz
```

If this fails, check CyberPath's NetworkPolicy
`networkPolicy.ingress.fromNamespaces` includes `nis2compass`.

### Coverage response missing recently completed track

Two cases:

1. CITADEL emission is queued but not yet acked — the response is
   sourced from the local DB, so it will be present. Check
   `cyberpath-cli completions show <id>`.
2. The track's `nis2_measures` field in `track.yaml` is empty.
   Coverage is derived from this field. Verify and re-import:

```bash
cyberpath-cli track import /content/tracks/<slug>/track.yaml
```

---

## Content version mismatch

### `track import` says `content_version mismatch`

A lesson markdown file changed but `track.yaml`'s semver wasn't
bumped. CyberPath refuses to silently ship a content drift because
already-issued completions reference the previous `content_version_id`.

```bash
# Identify the offending lesson
cyberpath-cli content diff /content/tracks/<slug>/

# Either revert the markdown
git checkout content/tracks/<slug>/lessons/<file>.sq.md

# Or bump track.yaml: version: 1.4.0 → 1.5.0
```

The mismatch counter `cyberpath_content_version_mismatch_total`
should never increment in production. A non-zero rate means a
deployer is editing content in place; investigate immediately.

### Learner saw a lesson that no longer exists

The learner has an in-flight `progress` row referencing a
`content_version_id` that's still in the DB, but the current track
revision has dropped or replaced the lesson. This is fine — the
learner sees the version they started against until they complete
or abandon. Force-abandon if needed:

```bash
cyberpath-cli progress reset <user_id> <track_id>
```

---

## i18n

### Learner UI shows raw `{key}` strings instead of translated text

A translation key is missing in one of the locales.

```bash
# Validate every track has both .sq.md and .en.md
cyberpath-cli content validate --strict-bilingual
```

CI should fail on this; if it slipped through, set
`CYBERPATH_I18N_MISSING_KEY_BEHAVIOUR=fallback` to fall back to the
default locale (default behaviour) and file a content ticket.

### `Accept-Language: sq` returns English content

The track was imported without a `.sq.md` file and CyberPath is
falling back. Confirm:

```bash
cyberpath-cli content show <track_slug> --locale sq
```

Author the missing translation and re-import.

---

## Database health

### `completions` table growing unexpectedly fast

Each lesson should produce one completion row per `(user_id,
content_version_id)`. Idempotency should prevent duplicates.

```sql
SELECT user_id, lesson_id, content_version_id, count(*)
FROM completions
WHERE created_at > now() - interval '1 day'
GROUP BY 1,2,3
HAVING count(*) > 1
ORDER BY 4 DESC;
```

If this returns rows, the idempotency key isn't being enforced —
file a bug; the unique constraint should prevent it at the DB
level.

### `pg_stat_activity` shows long-running `idle in transaction`

CyberPath does not hold open transactions on the request path. This
is an operator running a manual query or a backup tool. Identify:

```sql
SELECT pid, query, state_change FROM pg_stat_activity
WHERE state = 'idle in transaction';
```

`pg_terminate_backend(pid)` if you can confirm it is safe.

---

## Quick diagnose dump

For any "I don't know what's wrong" moment:

```bash
cyberpath-cli diagnose > diagnose.txt
```

Includes effective config (secrets redacted), recent log lines,
DB health (`SELECT version()`, applied migrations, table sizes),
CITADEL connectivity + queue depth, lab runtime status, content
inventory + hashes, goroutine count.

Attach to any ticket in the opensecstack tracker.

---

## See also

- [quick-start.md](quick-start.md)
- [configuration.md](configuration.md)
- [deployment.md](deployment.md)
- [deployment-helm.md](deployment-helm.md)
- [citadel-integration.md](citadel-integration.md)
- [nis2-integration.md](nis2-integration.md)
- [faq.md](faq.md)
