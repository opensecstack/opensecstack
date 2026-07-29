# CITADEL Troubleshooting

Common failure modes and the fastest path to a fix. Entries are
grouped by the symptom an operator sees first; each one names the
real root cause and the exact next step.

For day-to-day operations (healthy-state reference), see
[operator-runbook.md](./operator-runbook.md). For incident-scale
response (P1 chain break, key compromise), see
[sop-012-incident.md](./sop-012-incident.md).

## Startup

### `WARNING: CITADEL_DB_URL is not set`

**Meaning:** config-time warning. CITADEL will start the HTTP server
but every request that touches the DB will fail.

**Fix:** set `CITADEL_DB_URL` and restart. See
[configuration.md § Database](./configuration.md#database) for the
connection-string format.

### `WARNING: CITADEL_CITADEL_MASTER_KEY is not set — WORM anchor signing is disabled`

**Meaning:** the Ed25519 anchor key is missing. The WORM chain is
still **tamper-evident** (TripleHash + chain_hash linking) but not
**tamper-resistant** — an attacker able to rewrite chain_hashes won't
be stopped by a signature check.

**Fix:** generate an Ed25519 keypair, store the private key in a
secret manager, set `CITADEL_CITADEL_MASTER_KEY`, restart. Never
accept this warning in production.

### `pq: password authentication failed for user "citadel"`

**Meaning:** `CITADEL_DB_URL` has wrong credentials, or Postgres user
was not created.

**Fix:** verify the DB password in the secret manager. If running
via shipped `docker-compose.yml`, check the compose file's
`POSTGRES_PASSWORD` matches the URL.

### `pq: SSL is not enabled on the server`

**Meaning:** connection string has `sslmode=require` but Postgres
rejects it (typical for local docker).

**Fix:** for docker-compose / local dev, use `sslmode=disable`. For
production, configure Postgres to require SSL and use a certificate
signed by a CA you trust.

### CITADEL starts but `/api/v1/health` returns 503 `{"status":"degraded","db":"fail"}`

**Meaning:** DB connection succeeded at startup but is failing now —
Postgres restarted, network dropped, DNS resolution broke.

**Fix:** check Postgres logs. `kubectl get pods -l app=citadel-db`
(or equivalent). CITADEL's readiness probe will remove the pod from
the Service until DB recovers.

### Container exits immediately with "failed to apply migrations"

**Meaning:** a previous run applied partial migrations, or someone
ran `psql` manually against the DB.

**Fix:** inspect `schema_migrations` — compare `version` values
against `migrations/NNN_*.sql` filenames. If mismatched, restore DB
from the last known-good backup and re-apply cleanly.

## MARSHAL evaluation

### All Kerkeses return `REFUSE`/`WARN` with `AUTH_FAIL: actor_token invalid or expired`

**Meaning:** Gate 1 rejects because `ActorToken` failed verification
against sinauth's JWKS (`internal/auth.SinauthVerifier`) — expired
token, wrong issuer, or `CitadelConfig.SinauthIssuerURL` pointing at
the wrong sinauth instance. CITADEL has no local session table to
inspect; the check is a live call to sinauth. See
[ADR-005](../adrs/005-sinauth-identity-bridge.md).

**Fix:** confirm `CITADEL_SINAUTH_ISSUER_URL` points at the correct,
reachable sinauth instance and that the caller is forwarding a fresh
bearer token as `ActorToken`/`VerifierToken`. `NewServer` fails fast
at startup if the sinauth issuer is unreachable — check startup logs
first. Whether this REFUSEs or only WARNs depends on `EnforceIdentity`
(default `false`) — see
[ADR-006](../adrs/006-split-enforce-identity-and-signatures.md).

### Kerkeses return `HARD_STOP: NDS_SAME_GROUP` for legitimate pairs

**Meaning:** operator and verifier role groups — derived from the
producer-asserted `Actor.Role`/`Verifier.Role` on the Kerkese, not
looked up from any table — resolve to `role_group = "unknown"` or
both sit in the same group.

**Fix:** check the caller's role-group mapping for the `role` values
each side is submitting. The role groups need to be configured
distinct. A startup WARN logs when role groups are empty.

### Kerkeses return `HARD_STOP: AUGUR_rule_03` for every DATA_EXPORT

**Meaning:** callers are submitting `DATA_EXPORT` without
`action.incident_id`. This is **working as designed** — rule_03
exists to block exactly this.

**Fix:** callers must populate `action.incident_id` with the
investigation's ID. If you don't have an incident ID, create one in
IRFlow first — the WORM chain then traces "export → incident →
investigation justification".

### All decisions are `outcome=EXECUTE` even when they should REFUSE

**Meaning:** you may be running in dry-run mode.

**Fix:** check `CITADEL_DRY_RUN` — must be `false` or unset in
production. Also check inbound Kerkeses for `"dry_run": true` —
those are server-honoured. If `CITADEL_DRY_RUN_ALLOWED=false` (v1.1+),
dry-run Kerkeses are rejected with 400.

## WORM chain

### `/api/v1/worm/verify` returns `{"valid": false, "break_at": "..."}`

**Meaning:** the chain is broken. This is a **P1 incident**.

**Fix:** **do not continue debugging.** Stop ingress, freeze the
chain (`CITADEL_WORM_READONLY=true`), follow
[SOP-012A](./sop-012-incident.md#sop-012a--worm-chain-verification-failure).

### WORM append latency spikes > 100 ms

**Meaning:** Gate 5 is disk-bound on PostgreSQL. A sustained spike
means the DB is struggling.

**Candidates in order of frequency:**

1. **Backup running mid-day.** Schedule backups at low-traffic
   windows; `pg_dump` can significantly increase I/O contention.
2. **Autovacuum on `worm_entries`.** Tune
   `autovacuum_vacuum_scale_factor` lower (more frequent, smaller
   vacuums) for the WORM table specifically.
3. **Disk saturation.** IOPS at ceiling; upgrade provisioned IOPS or
   move to NVMe.
4. **Connection exhaustion.** `SELECT count(*) FROM pg_stat_activity
   WHERE datname = 'citadel'` — if near `max_connections`, raise the
   Postgres limit or reduce CITADEL pool size.

### `LOCK TABLE worm_entries` waits > 1 s

**Meaning:** multiple writers competing for the chain lock.

**Root cause:** someone is running a long-running `SELECT` against
`worm_entries` that holds an incompatible lock. Chain verification
over a large range is the usual culprit.

**Fix:** narrow verify ranges (chunk by day) — see
[known-limitations.md § No streaming chain verification](./known-limitations.md#no-streaming-chain-verification).

### `sequence_num` gaps

```sql
WITH expected AS (SELECT generate_series(1, max(sequence_num)) AS seq
                  FROM worm_entries)
SELECT seq FROM expected
EXCEPT SELECT sequence_num FROM worm_entries;
```

**Meaning:** missing entries. In a healthy chain this query returns
empty. Non-empty = tampering or DB corruption.

**Fix:** P1 incident. Follow
[SOP-012A](./sop-012-incident.md#sop-012a--worm-chain-verification-failure).

## Anchor signatures

### Anchors stopped producing

```
SELECT count(*), max(ts_utc) FROM chain_anchors;
# last anchor timestamp > expected interval ago
```

**Meaning:** either the anchor key is missing / malformed or the
anchor interval is wrong.

**Fix:**

1. Startup logs for `anchor signing is disabled` warn.
2. Verify `CITADEL_CITADEL_MASTER_KEY` is loaded. In-process
   debug endpoint (v1.1) will expose this; for now, check env.
3. Verify `CITADEL_CITADEL_ANCHOR_INTERVAL` — if set to 0, no
   anchors.

### Anchor signature fails to verify on exported bundle

**Meaning:** the pubkey you're verifying against doesn't match the
key that signed the anchor, OR the signature is forged.

**Fix:** check the anchor's `pubkey_id` — must match a registered
pubkey in your auditor's registry. If mismatched, the anchor was
signed by a key you haven't been told about — contact the deployer.
If matched and verification still fails, the bundle may have been
tampered with — reject.

## Performance

### `/api/v1/marshal/evaluate` p95 > 20 ms

**Meaning:** the evaluation round-trip is slow. In-memory gate work
is ~5 µs; the rest is Gate 5 WORM append against Postgres.

**Fix:** see "WORM append latency spikes" above. The MARSHAL-side
improvement opportunities are v1.1 (anchor batch-sign) and v2.0
(sharded chains).

### Memory growth on CITADEL replica

**Meaning:** (probable cause) chain verification endpoint buffering
a large response.

**Fix:** operators / callers should chunk verify ranges. A future
v1.1 streaming verifier removes this cause.

## Connectivity

### Platform callers (IRFlow, APIGuard, etc.) get 401 / signature mismatch

**Meaning:** the caller's HMAC secret doesn't match what CITADEL
knows.

**Fix:** check the caller's `*_CITADEL_KEY_SECRET` env var matches
the secret recorded on CITADEL's side. Since v1.0.0 does not support
overlapping secrets, rotation requires a coordinated cut-over.

### Ingress returns 502

**Meaning:** ingress can't reach CITADEL.

**Fix:**

- `kubectl get pods -l app=citadel` — are pods up?
- `kubectl logs -l app=citadel --tail=50` — is CITADEL running?
- Service selector matches Deployment labels?
- NetworkPolicy blocking?

### DB reachable from ingress but not from CITADEL pod

**Meaning:** egress NetworkPolicy misconfiguration.

**Fix:** your cluster's `NetworkPolicy` must allow egress from
`citadel` pods to the Postgres Service.

## Operational

### `rate_limit_counters` table filling up

**Meaning:** similar — the GC worker for old counters isn't running.

**Fix:**

```sql
DELETE FROM rate_limit_counters
 WHERE window_start < now() - interval '10 minutes';
```

This is safe any time — AUGUR rule_02 tolerates missing counters (it
falls through as "zero prior actions").

## When to escalate

- **WORM chain `valid: false`** → P1 incident, [SOP-012A](./sop-012-incident.md#sop-012a--worm-chain-verification-failure).
- **Anchor key compromise suspected** → P1, [SOP-012B](./sop-012-incident.md#sop-012b--anchor-key-compromise).
- **CITADEL unavailable > 2 min** → P1, [SOP-012C](./sop-012-incident.md#sop-012c--citadel-unavailable).
- **MARSHAL divergence between replicas** → P2, [SOP-012D](./sop-012-incident.md#sop-012d--marshal-decision-divergence).

For anything that can't be diagnosed with this page in < 30 min,
page the CITADEL on-call — do not bisect in the ticket queue.

## Related

- [Deployment](./deployment.md) — healthy-state reference to diff against
- [Configuration](./configuration.md) — knob reference
- [Operator runbook](./operator-runbook.md) — daily / weekly / monthly ops
- [SOP-012](./sop-012-incident.md) — incident-scale response
- [Known limitations](./known-limitations.md) — what CITADEL doesn't yet do (many "issues" are documented limitations, not bugs)
