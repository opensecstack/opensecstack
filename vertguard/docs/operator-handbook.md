# VertGuard Operator Handbook

Day-to-day operational guide for VertGuard. For incident response, see
[../SECURITY.md](../SECURITY.md). For deployment, see
[../../docs/deployment-topology.md](../../docs/deployment-topology.md).
For configuration, see [configuration.md](configuration.md).

## Morning routine (5 minutes)

```bash
# 1. Health
curl -sf https://vertguard.internal:8091/api/v1/health | jq .

# 2. Integrations
curl -sf https://vertguard.internal:8091/api/v1/health | jq '.integrations'
# Expect: { "citadel": "connected", "threatflow": "connected" }

# 3. Detection rate (last 24h)
curl -sf https://vertguard.internal:8091/metrics | grep 'vertguard_prompt_scans_total'

# 4. Alert queue
# Check your Grafana / alert channel for any overnight VertGuard alerts
```

Healthy state:

- All modules report `active` (or `inactive` for Phase 4.2/4.3 as expected)
- CITADEL + ThreatFlow integrations `connected`
- `vertguard_prompt_blocked_total` rate in normal range (deployment-specific baseline)
- No sustained 5xx on scan endpoints

## Weekly

### Pattern library review

Every Monday:

```bash
# Show current pattern version
curl -sf https://vertguard.internal:8091/api/v1/admin/patterns/status | jq .

# Check for upstream pattern library updates
vertguard patterns check-updates
```

If a new pattern library is available:

1. Review changes in GitHub (`rust/prompt-patterns/CHANGELOG.md`)
2. Test in staging for 24-48 hours (FP rate must hold)
3. Promote to production with `vertguard patterns apply`

### MITRE ATLAS sync verification

```bash
curl -sf https://vertguard.internal:8091/api/v1/admin/atlas/status | jq .
```

Expected: `atlas_version` not older than 2 weeks; `last_sync` within
last 7 days.

### False-positive rate check

```bash
# Check the FP test corpus is clean on current patterns
make test-fp

# If failing, this is urgent — a real deployment is FP-spiking
```

## Monthly

### Threat feed source health

Review `vertguard_threatfeed_staleness_seconds{source}` — any source
with staleness > 2× its refresh interval is stuck.

### Model accuracy (Phase 4.2+)

```bash
# Run scheduled benchmark suite
make test-ml-accuracy

# Results posted to /var/log/vertguard/ml-accuracy-*.json
```

If any model's accuracy has drifted > 5 percentage points from the
registry baseline, pin the older model version and investigate.

### CODEOWNERS + pubkey registry review

Per [../.github/CODEOWNERS](../.github/CODEOWNERS):

- Confirm security-sensitive paths still reviewed by security-team
- Verify the trust-store still matches the expected certificates
- Run `vertguard c2pa truststore verify` to confirm signature chain is valid

## Quarterly

### Pattern-library quarterly refresh

VertGuard's pattern library ships quarterly (Q1, Q2, Q3, Q4). Major
updates here usually coincide with:

- OWASP LLM Top 10 revisions
- MITRE ATLAS releases
- New generation-model fingerprints (Phase 4.2+)

Refresh procedure:

1. Review `rust/prompt-patterns/CHANGELOG.md` for the quarterly release
2. Staging deploy + 7-day soak
3. Review FP rate vs baseline — must not exceed +1 percentage point
4. Production rollout during maintenance window

### NIS2 / AI Act evidence export

Quarterly audit requirement — even if no audit is active:

```bash
vertguard evidence export \
  --from 2026-01-01 \
  --to 2026-03-31 \
  --format audit-bundle \
  --output /secure/vertguard-evidence-2026-Q1.tar.gz

# Verify integrity
vertguard evidence verify /secure/vertguard-evidence-2026-Q1.tar.gz
```

Store signed in your compliance vault per NIS2 Article 21 + AI Act
Article 12 retention obligations.

## Common operations

### Rotating CITADEL HMAC secret

1. Generate new secret: `openssl rand -base64 48`
2. Add to secret manager as `vertguard-citadel-key-secret-vN`
3. Update CITADEL's acceptance list (accept both old + new during
   overlap — Phase 2 of ecosystem PQ roadmap)
4. Update `VERTGUARD_CITADEL_KEY_SECRET` in VertGuard config
5. Roll VertGuard deployment (rolling update, no downtime)
6. After 48 hours, retire old secret from CITADEL

In v1.0.0, overlapping-secret support is not yet in place — so
rotation requires a short maintenance window until v1.1.

### Adding a custom pattern

1. Author pattern YAML in `/etc/vertguard/custom-patterns.yaml`
2. Write matching FP test case in `tests/fp/custom_test.go`
3. Run `make test-fp` to confirm no regression
4. Hot-reload via `POST /api/v1/admin/patterns/reload`

### Suppressing a pattern causing FPs

Not recommended — fix the pattern instead. But if urgent:

```bash
# /etc/vertguard/pattern-exclusions.yaml
suppressions:
  - pattern_id: LLM01.jailbreak.storytelling.v2
    reason:     "FP spike in creative-writing internal tool"
    approved_by: "secops"
    expires:    "2026-06-01"   # max 30 days; force review
```

Hot-reload. File a GitHub issue to fix the root pattern within the
30-day window.

### Responding to a BLOCKED classification appeal

Users may appeal a BLOCKED classification via the ecosystem appeal
flow. Your job:

1. Retrieve the WORM entry: `curl citadel/api/v1/worm/{worm_entry_id}`
2. Review the input hash, matched patterns, context
3. If legitimate appeal: file the appeal as an `appeal.media_auth` or
   `appeal.prompt_scan` WORM event via CITADEL
4. Notify the user of outcome via your deployment's ticketing system

## Scaling operations

VertGuard Go tier is stateless; add replicas behind the load balancer.

### When to add replicas

- `vertguard_prompt_scan_latency_seconds{q=0.95}` > 50 ms sustained
- `vertguard_http_request_in_flight` > 500 sustained
- ML inference queue depth > 100 (Phase 4.2+)

### GPU planning (Phase 4.2+)

One GPU per VertGuard pod. For real-time video analysis (Phase 4.3):
one GPU per 3-5 concurrent video calls. Plan capacity accordingly.

### DB connection pool

`VERTGUARD_DB_MAX_OPEN_CONNS × replicas ≤ Postgres max_connections − 10`

## Alerting

Suggested alerts:

| Condition | Severity | Rationale |
|---|:-:|---|
| `/health` down 2+ min | **P1** | Service unreachable |
| `vertguard_prompt_blocked_total` rate spike > 5× baseline, 15 min | **P2** | Potential targeted attack campaign |
| `vertguard_threatfeed_push_total{result="failure"}` rate > 0, 10 min | **P2** | ThreatFlow integration broken |
| `vertguard_citadel_queue_depth > 1000` sustained | **P2** | CITADEL unreachable; evidence backlog growing |
| `vertguard_ml_inference_seconds{q=0.95}` > 1s, 30 min | **P3** | ML performance degradation |
| `vertguard_threatfeed_staleness_seconds > 48h` any source | **P3** | Source collection broken |
| `vertguard_model_accuracy < baseline − 5%` | **P3** | Model drift; possibly new attack class |

## Backup and DR

VertGuard is stateless except for:

- PostgreSQL DB (back up daily; critical tables listed in `migrations/`)
- Pattern registry (version-controlled; redeployable)
- Model registry (downloadable; only SHA-256 manifest needs backup)
- Trust store (small; keep in deployment secret manager)

**Nothing in VertGuard's own filesystem is load-bearing long-term.**
All evidence lives in CITADEL's WORM chain; all IOCs in ThreatFlow.
Rebuilding VertGuard from scratch is a ~30-minute operation given
the Postgres backup.

## Upgrade

Standard rolling deploy. Migrations run as a one-shot job before the
rollout:

```bash
# Preview
kubectl apply --dry-run=client -f deploy/k8s/vertguard-0.2.yaml

# Apply migrations
kubectl create job vertguard-migrate-0.2.0 --from=cronjob/vertguard-migrate

# Wait for migration complete, then roll the Deployment
kubectl set image deployment/vertguard vertguard=ghcr.io/opensecstack/vertguard:0.2.0
kubectl rollout status deployment/vertguard
```

Cross-major version upgrades (v1 → v2) require the migration guide in
`docs/migrations/v1-to-v2.md` (written at the v2 release, not before).

## Escalation matrix

| Symptom | Page |
|---|---|
| WORM integrity break (any detection returns `worm_entry_id: null` unexpectedly) | CITADEL on-call + security lead |
| Persistent false-positive spike affecting production | Pattern-library maintainer + secops |
| Model accuracy drop (Phase 4.2+) suggesting new attack class | VertGuard team + research partners |
| Pattern registry hot-reload fails | VertGuard on-call |

## Related

- [quick-start.md](quick-start.md)
- [configuration.md](configuration.md)
- [api.md](api.md)
- [false-positive-handling.md](false-positive-handling.md)
- [../SECURITY.md](../SECURITY.md)
- [../../citadel/docs/sop-012-incident.md](../../citadel/docs/sop-012-incident.md) — ecosystem incident SOP
