## VertGuard Operator Incident-Response Runbook

You have been paged. You have not used VertGuard before. Read sections 1 and 2.
Jump to the playbook in section 3 that matches your alert. Sections 4-6 are
reference.

VertGuard is a Go HTTP service (`:8091` default), backed by Postgres,
emitting WORM evidence to CITADEL and AI-IOCs to ThreatFlow. It scans prompts
and emails for injection / phishing patterns and serves MITRE ATLAS technique
data. It is stateless apart from the DB: kill any pod, the next one picks up.

## 1. Quick reference card

| Check | Where | Healthy looks like |
|---|---|---|
| Pod status | `kubectl get pod -n vertguard` | `Running 1/1`, restarts stable |
| Liveness | `kubectl exec -n vertguard deploy/vertguard -- wget -qO- http://localhost:8091/api/v1/health` | HTTP 200, `"status":"ok"` |
| Readiness (same endpoint) | as above | HTTP 200 (503 means DB down) |
| DB health | `/api/v1/health` `db` field | `"db":"ok"` |
| WORM queue depth | `vertguard_citadel_queue_depth` | < 100 (buffer default 1000) |
| WORM emit failures | `rate(vertguard_worm_emit_total{result="fail"}[5m])` | 0 |
| ATLAS staleness | `vertguard_threatfeed_staleness_seconds{source="atlas"}` | < 86400 (24h sync interval) |
| Rate-limit pressure | `rate(vertguard_rate_limited_total[5m])` | < 0.1/s |
| Audit denies | `rate(vertguard_audit_events_total{outcome="denied"}[5m])` | < 0.5/s steady-state |
| HTTP 5xx | `rate(vertguard_http_requests_total{status=~"5.."}[5m])` | 0 |
| Recent panics | `kubectl logs -n vertguard deploy/vertguard --tail=2000 \| grep panic_recovered` | empty |
| ML breaker (if `ml.enabled`) | `vertguard_ml_calls_total{result="breaker_open"}` | 0 |
| ML p95 latency (if `ml.enabled`) | `histogram_quantile(0.95, sum by (le) (rate(vertguard_ml_latency_seconds_bucket[5m])))` | < 0.080 |

Default routes (see `internal/api/server.go`):

```
GET  /api/v1/health                       (unauth)
GET  /metrics                             (unauth, Prometheus)
POST /api/v1/prompt/scan                  (write)
POST /api/v1/phishing/scan                (write)
GET  /api/v1/threatfeed/iocs              (read)
POST /api/v1/threatfeed/atlas             (read)
GET  /api/v1/threatfeed/atlas/coverage    (read)
POST /api/v1/admin/patterns/reload        (admin, 501)
POST /api/v1/admin/atlas/sync             (admin, 501)
GET  /api/v1/admin/audit                  (admin)
POST /api/v1/webhooks/subscribers         (admin)
```

Note: there is no separate `/livez` / `/readyz`. `/api/v1/health` is the
single probe endpoint and returns 503 when the DB ping fails. Configure your
liveness and readiness probes against it.

## 2. Triage decision tree

```
PAGE RECEIVED
    |
    v
[1] kubectl get pod -n vertguard
    |
    +--- Pod not Running / CrashLoopBackOff -------> 3.1
    +--- Pod Running 1/1 but probes failing
    |       |
    |       v
    |   [2] curl /api/v1/health
    |       |
    |       +--- HTTP 503, "db":"fail" -----------> 3.2
    |       +--- HTTP 200 but degraded -----------> check Modules in body
    |
    +--- Pod Running, alert is metric-driven
            |
            v
        [3] Which metric fired?
            |
            +--- vertguard_citadel_queue_depth high
            |    or worm_emit_total{result="fail"} ----> 3.3
            +--- threatfeed_staleness_seconds > 24h ----> 3.4
            +--- rate_limited_total spiking ------------> 3.5
            +--- audit_events_total{outcome="denied"} --> 3.6
            +--- http_requests_total{status=~"5.."} ----> 3.7 (likely panic)
            +--- prompt/phishing FP complaints ---------> 3.8
            +--- Postgres disk > 80% -------------------> 3.9
            +--- vertguard_ml_calls_total{result=fail|breaker_open}
            |    or scan p95 > 80ms ---------------------> 3.10
```

If none of the above match: pull `kubectl logs --tail=200 -n vertguard
deploy/vertguard`, search for `level":"error"` and `level":"warn"`, attach to
the incident channel, escalate per section 5.

## 3. Playbooks

### 3.1 Pod CrashLoopBackOff at startup

If you see pods stuck in `CrashLoopBackOff` immediately after a deploy or
restart, do this.

Symptom: `kubectl get pod -n vertguard` shows `CrashLoopBackOff`, restart
count climbing. No `/metrics` reachable.

Likely causes (in descending order):
- Missing/invalid env var (`VERTGUARD_AUTH_SECRET`, DB credentials)
- DB unreachable AND code path requires it (rare — main.go tolerates this,
  see `cmd/server/main.go` lines 64-74; pod stays up with stub pinger)
- Bad image / wrong tag
- Listen port clash (`VERTGUARD_SERVER_PORT` already bound)

Verify:
```
kubectl describe pod -n vertguard <pod>
kubectl logs -n vertguard <pod> --previous --tail=200
kubectl logs -n vertguard <pod> --previous | grep -E '"level":"(fatal|error)"|^WARNING'
```

Look at the `WARNING:` lines emitted by `config.WarnIfInsecure` (logged at
INFO level with prefix `WARNING:`). They are not fatal, but they tell you
which env vars are unset:

| Warning | Meaning | Action |
|---|---|---|
| `VERTGUARD_AUTH_SECRET is empty` | JWT verification disabled | set the secret; never run prod without it |
| `VERTGUARD_AUTH_DEV_MODE is true` | auth bypass | flip to false in prod values.yaml |
| `VERTGUARD_DB_SSL_MODE is 'disable'` | unencrypted DB | set to `require` or `verify-full` |
| `VERTGUARD_CITADEL_API_URL is empty` | no WORM logging | set CITADEL URL or accept standalone |
| `VERTGUARD_THREATFLOW_API_URL is empty` | no IOC push | set ThreatFlow URL or accept standalone |

A true fatal (`config load failed`) prints once at the top of the previous
log buffer — fix the env var it names, redeploy.

Mitigation:
```
kubectl rollout undo deployment/vertguard -n vertguard
```
or if you know the bad env var:
```
kubectl set env deployment/vertguard -n vertguard VERTGUARD_AUTH_SECRET=<value>
```

Post-mortem: capture `kubectl describe pod`, `--previous` logs, the values
diff that caused the regression. File a config-validation bug if a startup
check would have caught it.

### 3.2 DB connection lost

If you see `vertguard_citadel_queue_depth` growing AND `/api/v1/health`
returns 503 with `"db":"fail"`, the Postgres link is gone.

Symptom: 503 on health endpoint, `"db":"fail"` in response body. Audit DB
sink errors in logs (`audit sink failed`). Scans still serve (the prompt /
phishing path tolerates a nil store) but persistence is off.

Likely causes:
- Postgres pod down / OOMKilled
- Network policy regression
- Credential rotation gone wrong
- Cert expiry on `ssl_mode=verify-full`

Verify:
```
kubectl get pod -n <db-namespace> -l app=postgres
kubectl exec -n vertguard deploy/vertguard -- \
    sh -c 'wget -qO- http://localhost:8091/api/v1/health'
kubectl logs -n vertguard deploy/vertguard --tail=200 | grep -i 'db\|postgres\|pgx'
```

From inside the pod:
```
kubectl exec -n vertguard deploy/vertguard -- \
    sh -c 'apk add --no-cache postgresql-client && \
    psql "postgres://$VERTGUARD_DB_USER:$VERTGUARD_DB_PASSWORD@$VERTGUARD_DB_HOST:$VERTGUARD_DB_PORT/$VERTGUARD_DB_NAME?sslmode=$VERTGUARD_DB_SSL_MODE" -c "select 1"'
```

Mitigation, two paths:

1. DB transient (under 15 min): leave pods running. Scans return 200 from
   memory, audit goes to logger sink only, CITADEL queue absorbs WORM
   emits. No action.
2. DB lost long-term and WORM queue depth approaching `cfg.Citadel.AsyncBuffer`
   (default 1000): scale to zero to stop accepting traffic that won't be
   audited.
   ```
   kubectl scale deploy/vertguard -n vertguard --replicas=0
   ```
   Bring DB back, then scale up.

Emergency keep-pods-up fallback: setting `VERTGUARD_DB_PASSWORD=""` (and
`VERTGUARD_DB_HOST=""`) makes `cmd/server/main.go` skip DB init entirely —
pods serve scans without persistence. Only do this if you accept losing
audit history for the duration. Revert the change to re-enable DB.

Post-mortem: confirm Postgres backups, RPO; verify the `audit_events` table
did not lose rows during the gap (logger sink JSONL is the recovery
artefact).

### 3.3 CITADEL upstream unreachable

If you see `vertguard_worm_emit_total{result="fail"}` rising and
`vertguard_citadel_queue_depth` near `cfg.Citadel.AsyncBuffer`, CITADEL is
not accepting our evidence.

Symptom: `vertguard_citadel_calls_total{target="worm_emit",result="fail"}`
counter rising. Logs contain `WORM emit failed` warnings. Queue depth
climbs because the drain goroutine retries with backoff (100ms, 500ms, 2s
per attempt, 3 attempts). When the buffer fills, new emits are dropped
(`vertguard_worm_emit_total{result="dropped_buffer_full"}`).

Likely causes:
- CITADEL down or upgrading
- HMAC secret rotated on CITADEL but not on VertGuard
- Network policy / mTLS regression
- 4xx terminal failure (see `internal/citadel/client.go` `do`): no retry,
  hard fail — usually means schema mismatch

Verify:
```
kubectl exec -n vertguard deploy/vertguard -- \
    wget -qO- "$VERTGUARD_CITADEL_BASE_URL/api/v1/health" || echo "DOWN"

kubectl logs -n vertguard deploy/vertguard --tail=500 | \
    grep -E 'citadel|WORM emit'
```

Check the metric breakdown:
```
curl -s http://<pod>:8091/metrics | grep vertguard_worm_emit_total
curl -s http://<pod>:8091/metrics | grep vertguard_citadel_queue_depth
```

Mitigation:

1. If CITADEL outage is short and queue has headroom: do nothing. The
   client retries with exponential backoff and drains automatically.
2. If queue is filling and CITADEL is expected down for hours: set
   `VERTGUARD_CITADEL_DRY_RUN=true`. The client logs each emit but does not
   call CITADEL (`internal/citadel/client.go` `EmitWORM`). Audit logger
   sink still records. CITADEL backfill becomes a manual reconcile job.
   ```
   kubectl set env deployment/vertguard -n vertguard VERTGUARD_CITADEL_DRY_RUN=true
   ```
3. If you need more buffer to ride out a known maintenance: bump
   `VERTGUARD_CITADEL_ASYNC_BUFFER` (default 1000) and roll the deployment.
   The buffer is in-memory — pod restarts lose its contents.

Post-mortem: count dropped emissions, reconcile from VertGuard's
`audit_events` table (which has the same evidence content) into CITADEL
manually if compliance requires it.

### 3.4 ATLAS sync stuck

If you see `vertguard_threatfeed_staleness_seconds{source="atlas"}` over
86400 (24h), the ATLAS YAML fetch is failing.

Symptom: staleness gauge grows linearly. Logs contain `atlas periodic sync
failed` warnings. The fallback `Initial()` set keeps serving, so requests
do not 5xx — but coverage drifts from upstream.

Likely cause: GitHub raw fetch failing
(`https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml`).
Egress block, DNS, GitHub outage, or schema drift (parser sees zero
techniques and refuses to swap, see `internal/threatfeed/atlas/sync.go`).

Verify reachability from inside the pod:
```
kubectl exec -n vertguard deploy/vertguard -- \
    wget -qO- https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml | head -20
```

Inspect last sync attempt:
```
kubectl logs -n vertguard deploy/vertguard --tail=2000 | grep atlas_sync
```

Mitigation:

1. Manually trigger a sync:
   ```
   curl -sS -X POST -H "Authorization: Bearer $ADMIN_JWT" \
        https://vertguard.example.com/api/v1/admin/atlas/sync
   ```
   Today this returns 501 (handler stubbed in
   `handlers.AdminAtlasSyncTODO`). When that lands, prefer it.
2. If 501: force a startup sync by rolling the pods.
   ```
   kubectl rollout restart deployment/vertguard -n vertguard
   ```
   New pods seed from `Initial()` and run the periodic loop on schedule.
3. If egress is blocked, mirror the YAML internally and override
   `threatfeed.atlas_source_url` (when wired through config — currently
   only `internal/threatfeed/atlas/sync.go` `SyncerConfig.SourceURL`,
   change at deploy time).

Post-mortem: alert threshold review (24h is generous; 6h for a Tier 0
deployment), and add a synthetic check that GET-fetches the upstream YAML
from the cluster every hour.

### 3.5 Sudden traffic spike — 429 storm

If you see `vertguard_rate_limited_total` spiking, a client is over their
quota or the limit is too tight for current load.

Symptom: 429s in `vertguard_http_requests_total{status="429"}`,
`vertguard_rate_limited_total` counter rising. Limit is keyed per JWT
subject (see `internal/api/server.go`: rate-limit middleware runs after
auth so the key is the authenticated identity, not the source IP).

Verify the offender. Use access logs:
```
kubectl logs -n vertguard deploy/vertguard --tail=10000 | \
    grep '"status":429' | jq -r '.request_id' | head -50
```
Cross-reference `request_id` against the audit table to find the actor:
```
SELECT actor, count(*) FROM audit_events
 WHERE ts > now() - interval '1 hour' AND status_code = 429
 GROUP BY actor ORDER BY 2 DESC LIMIT 10;
```

Mitigation:

1. If the spike is legitimate (release event, customer ramp): bump the
   limit and roll.
   ```
   kubectl set env deployment/vertguard -n vertguard \
       VERTGUARD_SERVER_RATE_LIMIT_RPS=200 \
       VERTGUARD_SERVER_RATE_LIMIT_BURST=400
   ```
2. If the spike is abusive: drop the offender's quota to zero with a
   per-subject override. The global limit stays untouched, so legitimate
   traffic from other actors keeps flowing.
   ```
   curl -sS -X POST https://vertguard.internal/api/v1/admin/ratelimit/overrides \
       -H "Authorization: Bearer $ADMIN_JWT" \
       -H "Content-Type: application/json" \
       -d '{"kind":"sub","value":"<offender-sub>","rps":0,"burst":0,"reason":"<incident-id>"}'
   ```
   The handler refreshes the limiter snapshot synchronously, so the new
   quota applies on the next bucket creation for that key. Other admin
   pods pick it up within one refresh tick (default 30s).

   LIMITATION: a bucket already in memory for that subject keeps its
   construction-time rate until the janitor evicts it (IdleTTL = 10m by
   default). For sub-second cut-over, ALSO revoke the JWT via
   `/api/v1/admin/denylist` so the request is rejected at auth time
   rather than at rate-limit time.

   For a known high-throughput internal job, run the same call with a
   loosened quota (e.g. `"rps":500,"burst":1000`).

   List + remove:
   ```
   curl -sS -H "Authorization: Bearer $ADMIN_JWT" \
       https://vertguard.internal/api/v1/admin/ratelimit/overrides
   curl -sS -X DELETE -H "Authorization: Bearer $ADMIN_JWT" \
       https://vertguard.internal/api/v1/admin/ratelimit/overrides/sub/<offender-sub>
   ```
3. If the credential itself is compromised: also revoke the JWT via
   `/api/v1/admin/denylist` and at the issuer so the token can't be
   reused from another network path.
4. If you need to disable rate limiting entirely (incident war-room only):
   `VERTGUARD_SERVER_RATE_LIMIT_ENABLED=false`. Re-enable as soon as the
   spike subsides.

Post-mortem: capacity model the new RPS, document a quota policy per
tenant, audit `vertguard_ratelimit_overrides_active` and
`vertguard_ratelimit_override_hits_total` for ongoing override exposure.

### 3.6 Auth failures spike

If you see `vertguard_audit_events_total{outcome="denied"}` rising, JWT
validation is rejecting requests.

Symptom: spike in `outcome="denied"` audit events, often paired with HTTP
401 in the access log.

Likely causes:
- Token issuer / VertGuard clock skew (HS256 `exp`/`nbf` validation)
- JWT signing secret rotated on the issuer but not on VertGuard
- Bad `VERTGUARD_AUTH_ISSUER` (issuer claim mismatch)
- A client shipped expired or malformed tokens

Verify VertGuard's clock against NTP:
```
kubectl exec -n vertguard deploy/vertguard -- date -u
date -u
```
Drift over a few seconds will reject tokens whose `exp` is near now.

Decode a sample failing token (see one-liner in section 4):
```
echo "<jwt>" | jq -R 'split(".") | .[1] | @base64d | fromjson'
```
Confirm `iss` matches `VERTGUARD_AUTH_ISSUER` and `exp` is in the future.

Mitigation:
1. Clock skew: fix node time sync (kubelet → NTP). Roll affected pods.
2. Rotated secret — tokens minted before the rotation are now 401-ing:
   use **dual-secret rotation** instead of in-place replacement. Set
   `VERTGUARD_AUTH_SECRET_PREVIOUS=<old-secret>` (or
   `VERTGUARD_AUTH_SECRET_NEXT=<new-secret>` if the issuer rolled first)
   and redeploy. The verifier accepts both slots until the TTL window
   passes; observe `vertguard_jwt_secret_used_total{slot}` to confirm
   in-flight tokens validate against the expected slot. Clear the extra
   env var on the next deploy. See `docs/secrets-management.md` for the
   full flow.
3. Bad issuer: `kubectl set env ... VERTGUARD_AUTH_ISSUER=<value>`.

Do not enable `VERTGUARD_AUTH_DEV_MODE=true` in production to "unblock"
clients. Dev mode bypasses verification entirely; the WARNING in startup
logs exists for a reason.

Post-mortem: alert on `rate(vertguard_audit_events_total{outcome="denied"}[5m]) > 1`
in normal traffic; document JWT lifecycle owner.

### 3.7 Panic recovery alerts

If you see `panic_recovered` lines in the logs, the chi `Recoverer`
middleware caught a panic and returned 500. The pod survives. Each panic
is a code bug.

Symptom: log line containing `panic_recovered`, often paired with
`vertguard_http_requests_total{status="500"}` increment.

Verify:
```
kubectl logs -n vertguard deploy/vertguard --tail=5000 | \
    grep -A 30 panic_recovered
```
Capture the `request_id`, the path, the stack trace.

Correlate against audit:
```
SELECT * FROM audit_events WHERE request_id = '<id>';
```

Mitigation:
1. Capture artefacts (logs, request body if present, request_id, audit row).
2. Open a ticket against engineering with the stack and a reproducer.
3. If the panic is high-rate and tied to a specific endpoint, revert the
   most recent deploy (`kubectl rollout undo deployment/vertguard`).

Do not remove `middleware.Recoverer` from `internal/api/server.go`. Without
it the goroutine dies and the connection drops uncleanly. With it, you get
a 500 plus a structured log line — the better failure mode.

Post-mortem: every panic is a P2 bug minimum. Fix in code, add a
regression test. Track via `rate(vertguard_http_requests_total{status="500"}[5m])`.

### 3.8 Phishing or Prompt false-positive flood

If users complain that benign content is being blocked, the rule corpus
needs review.

Symptom: support tickets / Slack complaints. Metrics:
`vertguard_prompt_scans_total{classification="block"}` or
`vertguard_phishing_scans_total{classification="block"}` higher than
baseline. Per-pattern breakdown via
`vertguard_pattern_matches_total{pattern_id=...,category=...}` and
`vertguard_phishing_indicator_matches_total{indicator_id=...}`.

Likely causes: regex pattern is too broad. There is no model — these are
deterministic regex libraries (`internal/prompt/library.go`,
`internal/phishing/library.go`). False positives require pattern review,
not retraining.

Verify the offending pattern_id from metrics:
```
curl -s http://<pod>:8091/metrics | \
    grep vertguard_pattern_matches_total | sort -t= -k3 -n -r | head
```

Mitigation:
1. Read `docs/false-positive-handling.md` and `docs/module-3-prompt-injection.md`
   TUNING section — the documented escape hatches.
2. Lower the global block threshold (`VERTGUARD_PROMPT_BLOCK_THRESHOLD`
   default ~0.8): the pattern still matches but does not auto-block. The
   caller's `context` field can downgrade severity per-request — e.g.
   `context=internal_dev_tool` allows known-noisy ops.
3. For a single bad pattern: edit `internal/prompt/library.go` /
   `internal/phishing/library.go`, ship a patch release. There is no
   runtime hot-reload today: `POST /api/v1/admin/patterns/reload` returns
   501 (`handlers.AdminPatternsReloadTODO`). Roll the deployment to pick
   up the new corpus.

Post-mortem: keep an FP corpus in the repo (one input per FP). Every new
pattern PR runs against it.

### 3.9 Disk pressure on Postgres

If Postgres disk usage is climbing, `audit_events` is the usual culprit —
it grows monotonically.

Symptom: pgsql node disk > 80% used. `audit_events` row count and on-disk
size dominate.

Verify:
```
psql -c "SELECT pg_size_pretty(pg_total_relation_size('audit_events'));"
psql -c "SELECT count(*) FROM audit_events;"
psql -c "SELECT min(ts), max(ts) FROM audit_events;"
```

Mitigation, in order of preference:

1. Add a nightly retention cron. Sample SQL (adjust window per your legal
   retention policy):
   ```sql
   DELETE FROM audit_events WHERE ts < now() - interval '365 days';
   VACUUM (VERBOSE, ANALYZE) audit_events;
   ```
2. Move cold rows to object storage (`COPY ... TO PROGRAM 'gzip > ...'`
   to S3 / MinIO, then DELETE).
3. As a last resort, expand the PV. Buys time, not a fix.

Caveat: if the deployment is under legal hold, NIS2 obligations, or an
active forensic investigation, deleting audit rows can be a regulatory
violation. Confirm with compliance before running the DELETE. The CITADEL
mirror (when configured) is the secondary record.

Post-mortem: codify retention in the Helm values
(`docs/deployment-helm.md`), automate the cron in a sidecar Job.

### 3.10 ML service degraded

If the ML inference subchart is enabled (`ml.enabled=true`) and the Go
side reports breaker-open / fail / latency drift, the scan pipeline is
running but with reduced recall on the BLOCKED class.

Symptom (any one):

- `rate(vertguard_ml_calls_total{result="fail"}[5m])` rising above 0.05/s
- `vertguard_ml_calls_total{result="breaker_open"}` non-zero
- `histogram_quantile(0.95, sum by (le) (rate(vertguard_ml_latency_seconds_bucket[5m])))` > 0.080
- ML pod `Ready` but readiness probe flapping

Verify:
```
# Pod status
kubectl get pod -n vertguard -l app.kubernetes.io/name=vertguard-ml

# gRPC health from inside the cluster
kubectl --namespace vertguard run -it --rm grpchealth \
    --image=ghcr.io/grpc-ecosystem/grpc-health-probe:v0.4.25 --restart=Never -- \
    -addr=vertguard-ml.vertguard.svc:50051

# Recent breaker / fail counts
kubectl exec -n vertguard deploy/vertguard -- \
    wget -qO- http://localhost:8091/metrics | \
    grep -E '^vertguard_ml_(calls_total|latency_seconds|breaker_state)'

# Python-side inference latency + active model
kubectl exec -n vertguard deploy/vertguard-ml -- \
    wget -qO- http://localhost:9100/metrics | \
    grep -E '^vertguard_ml_(inference_seconds|model_loaded_at|score_distribution)'

# Logs
kubectl logs -n vertguard deploy/vertguard-ml --tail=500
```

Mitigation, immediate (operator action ≤ 2 min):

1. Flip the Go side to regex-only. Either:
   ```bash
   kubectl set env -n vertguard deploy/vertguard VERTGUARD_ML_ENABLED=false
   kubectl rollout status -n vertguard deploy/vertguard --timeout=2m
   ```
   or, via Helm:
   ```bash
   helm upgrade vertguard ./deploy/helm/vertguard -n vertguard \
       -f values.production.yaml --set ml.enabled=false
   ```
2. Expect a recall hit on the BLOCKED class — historical baseline against
   `internal/prompt/corpus/` is **55–65% recall** without ML, vs 90%+ with.
   Communicate this on the status page if the outage exceeds 30 min.
3. Audit pipeline is unaffected: `vertguard_audit_events_total` continues
   to record the regex-only verdict.

Post-mortem checklist:

- [ ] Dump pod logs for both `vertguard` and `vertguard-ml` covering the
      incident window. Attach to the postmortem.
- [ ] Pull the deployed model card (`kubectl exec -n vertguard
      deploy/vertguard-ml -- cat /var/lib/vertguard/models/model_card.yaml`)
      and record `model.version`, `training.code_version`,
      `training.dataset_hash`.
- [ ] Re-eval the deployed model against last week's `audit_events`
      (export the `input_hash` + verdict columns) to detect regression
      vs the model card's stated metrics. Threshold: any ship-gate
      metric regressing > 2 pp ⇒ rollback.
- [ ] Decide rollback:
      - Registry-backed: edit `latest.txt` to the previous version
        (see [`ml-model-registry.md`](ml-model-registry.md) §Rollback).
      - PVC-backed: `helm rollback vertguard <previous-rev>`.
- [ ] Re-enable ML once the rollback is healthy:
      ```bash
      kubectl set env -n vertguard deploy/vertguard VERTGUARD_ML_ENABLED=true
      ```
- [ ] File VG-XXXX, link the model card hash, the eval delta, and the
      mitigation timeline.

References: [`ml-architecture.md`](ml-architecture.md) §Failure modes,
[`ml-training-guide.md`](ml-training-guide.md) §Adversarial / red-team.

## 4. Useful one-liners

```bash
# Tail logs by request_id
kubectl logs -n vertguard deploy/vertguard --tail=100000 | \
    jq -c 'select(.request_id == "<REQ_ID>")'

# Top-10 most-rate-limited subjects in the last hour (requires audit DB)
psql -c "SELECT actor, count(*) AS hits
         FROM audit_events
         WHERE ts > now() - interval '1 hour' AND status_code = 429
         GROUP BY actor ORDER BY hits DESC LIMIT 10;"

# Decode a JWT to inspect claims (no signature check)
echo "$JWT" | jq -R 'split(".") | .[1] | @base64d | fromjson'

# Force-rotate pods
kubectl rollout restart deployment/vertguard -n vertguard
kubectl rollout status deployment/vertguard -n vertguard --timeout=5m

# Snapshot Prometheus metrics for outage timeline
kubectl exec -n vertguard deploy/vertguard -- \
    wget -qO- http://localhost:8091/metrics > vg-metrics-$(date -u +%Y%m%dT%H%M%SZ).txt

# Audit actions in the last 30 minutes
psql -c "SELECT ts, actor, action, outcome, status_code, request_id
         FROM audit_events
         WHERE ts > now() - interval '30 minutes'
         ORDER BY ts DESC LIMIT 200;"

# All denied auth events grouped by actor in the last hour
psql -c "SELECT actor, role, count(*)
         FROM audit_events
         WHERE ts > now() - interval '1 hour' AND outcome = 'denied'
         GROUP BY actor, role ORDER BY 3 DESC;"

# Live tail with structured filtering (errors only)
kubectl logs -n vertguard -f deploy/vertguard | \
    jq -c 'select(.level == "error" or .level == "warn")'

# Metrics quick-look from inside cluster
kubectl run -it --rm curl --image=curlimages/curl --restart=Never -- \
    sh -c 'curl -s http://vertguard.vertguard.svc:8091/metrics | grep -E "^vertguard_"'
```

## 5. Escalation matrix

Severity definitions:

| Sev | Definition | Response |
|---|---|---|
| P0 | Total outage, all pods down OR audit pipeline broken (no logger sink, no DB sink) | Page primary + secondary on-call immediately, open incident channel, status page within 15 min |
| P1 | Partial outage: scans returning 5xx, CITADEL or DB down, FP rate > 10x baseline | Page primary on-call, incident channel within 30 min, status page if customer-visible |
| P2 | Degraded: ATLAS staleness, individual panic, single-tenant rate-limit pain | Ticket, fix in business hours |
| P3 | Cosmetic, doc, single FP report | Ticket, normal queue |

On-call rotation: `https://oncall.example.com/team/vertguard` (replace
with your PagerDuty/Opsgenie URL).

Engineering escalation:
- Module 3 (Prompt) — engineering owner per `CODEOWNERS`
- Module 4 (Threat Feed / ATLAS) — same
- CITADEL integration — CITADEL team on-call
- Postgres / infrastructure — platform on-call

Status-page template (P1):

```
[INVESTIGATING] VertGuard — elevated error rate
We are investigating elevated 5xx error rates on VertGuard scan endpoints
starting at <UTC>. Scans may be slower or fail. Audit logging is unaffected.
Next update in 30 minutes.
```

Status-page template (P0):

```
[IDENTIFIED] VertGuard — service unavailable
VertGuard is currently unavailable. Cause: <one line>. Mitigation in
progress. Next update in 15 minutes.
```

Post-incident:
- File a postmortem within 5 business days
- Link logs, metrics snapshot, audit query results
- Action items must have an owner and due date

## 6. Cross-links

- Deployment topology and Helm values: [`deployment-helm.md`](deployment-helm.md)
- All env vars and defaults: [`configuration.md`](configuration.md)
- Operator handbook (steady-state ops): [`operator-handbook.md`](operator-handbook.md)
- CITADEL integration internals: [`citadel-integration.md`](citadel-integration.md)
- ThreatFlow integration: [`threatflow-integration.md`](threatflow-integration.md)
- ATLAS technique mapping: [`mitre-atlas-mapping.md`](mitre-atlas-mapping.md)
- False-positive triage: [`false-positive-handling.md`](false-positive-handling.md)
- Module deep-dives: [`module-3-prompt-injection.md`](module-3-prompt-injection.md), [`module-2-ai-phishing.md`](module-2-ai-phishing.md), [`module-4-ai-threat-feed.md`](module-4-ai-threat-feed.md)
- ML inference: [`ml-architecture.md`](ml-architecture.md), [`ml-training-guide.md`](ml-training-guide.md), [`ml-model-registry.md`](ml-model-registry.md)
- Compliance posture: [`nis2-ai-act-mapping.md`](nis2-ai-act-mapping.md), [`nis3-readiness.md`](nis3-readiness.md)
