# OpenScrub Operator Handbook

Day-to-day operational guide for OpenScrub v1.0.0. For incident
disclosure see [../SECURITY.md](../SECURITY.md). For the kernel
attack surface see [security/threat-model.md](security/threat-model.md). For
deployment and topology see [deployment.md](deployment.md). For
architecture see [architecture.md](architecture.md).

## Deployment topology

OpenScrub deploys in two tiers:

| Tier | Workload | Replicas | Capabilities | Network |
|---|---|---|---|---|
| Edge | `openscrub-loader` (Rust + Aya) | 1 per edge node, **DaemonSet** | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE` | `hostNetwork`, no listeners |
| Control | `openscrub-api` (Go) | N, behind LB, **Deployment** | none | HTTP `:8087`, metrics `:9091` |
| Control | `openscrub-web` (nginx + SPA) | M, behind LB, **Deployment** | none | HTTP `:80` (`:3087` on Compose) |
| Data | `postgres` 16 | 1 primary (+ replica) | none | TCP 5432, cluster-internal |

Edge nodes are labelled
`openscrub.opensecstack.org/edge=true` so the loader DaemonSet only
schedules where XDP attach is wanted. The API is stateless — scale
it horizontally on CPU. The loader is **not** a control-plane peer:
the API talks to it over the per-node Unix socket (default
`/run/openscrub/dataplane.sock`, configured via
`OPENSCRUB_DATAPLANE_SOCKET`).

See [architecture.md](architecture.md) for the full diagram.

## Morning routine (5 minutes)

```bash
# 1. API health (db_ping + dataplane_attached must both be true)
curl -sf https://openscrub.internal/api/v1/health | jq .

# 2. Loader DaemonSet — every edge node must have a Ready pod
kubectl -n openscrub get ds openscrub-loader

# 3. Active rule count (sanity-check against last night's number)
curl -sf https://openscrub.internal:9091/metrics \
  | grep '^openscrub_rules_total'

# 4. CITADEL emit health (no sustained errors)
curl -sf https://openscrub.internal:9091/metrics \
  | grep '^openscrub_citadel_emit_total'

# 5. Alert queue — check Grafana / Alertmanager for overnight pages
```

Healthy state:

- All API replicas return `status: "ok"` with `db_ping: true` and
  `dataplane_attached: true`.
- Every edge node has exactly one loader pod in `Ready`.
- `openscrub_citadel_emit_total{outcome="error"}` flat for the last
  24 h (or empty if CITADEL is unconfigured).
- `openscrub_ioc_pulls_total{outcome="ok"}` advancing on the
  configured `OPENSCRUB_THREATFLOW_INTERVAL` cadence (default 60 s
  in code, 15 min in production deployments).
- No rule-TTL-sweeper backlog —
  `openscrub_rules_expired_total` advances within seconds of TTL.

## Daily monitoring

The metrics that matter, exposed at
[`/api/v1/metrics`](api.md#metrics) and the loader's `:9091`:

| Metric | Healthy | Action threshold |
|---|---|---|
| `openscrub_rules_total{type=…}` | deployment baseline | Sudden drop > 50% → P2 (sweeper or reconciler bug) |
| `openscrub_rules_added_total{source="threatflow"}` | advances each pull | Flat for 2× pull interval → ThreatFlow puller stuck |
| `openscrub_rules_expired_total` | advances near real-time | Lag > 60 s vs. TTL → sweeper failing → P2 |
| `openscrub_dataplane_op_total{outcome!="ok"}` | 0 | Any non-zero rate → loader-API disagreement → P2 |
| `openscrub_citadel_emit_total{outcome="error"}` | 0 | > 1% of total over 30 m → P1 (evidence chain breaking) |
| `openscrub_ioc_pulls_total{outcome="error"}` | 0 | 3 consecutive failures → P3 |
| Dataplane attached (per node) | 1 | 0 on any edge node → P1 |
| Ratelimit map fill | < 80k entries | ≥ 100k (cap) → P1 (see incident playbooks) |
| API p95 packet-event latency | < 150 ms | > 500 ms over 30 m → P3 |

Specific alerts to wire in:

- **rule-ttl-sweeper-stalled** — `openscrub_rules_expired_total`
  flat for > 5 m while `openscrub_rules_total` continues to grow.
  Operationally this means stale rules accumulate in the BPF map;
  eventually the map fills.
- **citadel-emit-failing** —
  `openscrub_citadel_emit_total{outcome="error"}` rate > 1% over
  30 m. Evidence is being lost. Page on-call. Check clock drift,
  HMAC mismatch (rotation), CITADEL ingress reachability.
- **ratelimit-map-full** — `ratelimit` BPF map at 100 000 entries
  (the compile-time cap). New ratelimit entries get rejected by the
  loader and the API surfaces a `503 dataplane_full`. See incident
  playbook below.
- **dataplane-detached** — `dataplane_attached: false` on any node.
  XDP is no longer filtering on that node; traffic is passing.
- **threatflow-pull-stuck** — `openscrub_ioc_pulls_total` not
  advancing for 2× `OPENSCRUB_THREATFLOW_INTERVAL`.

Per-cause drop visibility: dashboards should split
`openscrub_dataplane_op_total` by `op` label
(`add`, `remove`, `lookup`) to keep reconciler bugs visible.

## Upgrade procedure

API and dashboard upgrades are rolling; the loader needs a touch
more care because in-place pod replacement detaches the XDP program
for 1–3 seconds (see [deployment.md § Upgrades](deployment.md)).

Rolling production upgrade, edge node by edge node:

1. **Cordon & drain** one edge node:
   `kubectl cordon <node>; kubectl drain <node> --ignore-daemonsets`.
2. **Drain rules to standby**: traffic for that node's blocklist
   ranges shifts to peer nodes via your load balancer / BGP. Confirm
   `openscrub_rules_total` on peers is unchanged (rules are
   per-node, replayed from Postgres on loader start).
3. **Swap the loader image** by updating the DaemonSet image tag.
   The new pod attaches XDP, replays rule state from Postgres on
   start, and the gap window is the time between detach and the new
   loader's `attach()` returning — typically 1–3 s.
4. **Verify** on the upgraded node:
   `kubectl exec <new-pod> -- ls /sys/fs/bpf/openscrub` (maps
   pinned), and `curl <api>:8087/api/v1/health` shows
   `dataplane_attached: true`.
5. **Uncordon** and move to the next node.
6. After the loader fleet is upgraded, roll the API Deployment
   (standard rolling update — replicas are stateless).

Rollback: previous loader image + helm rollback. Rules in Postgres
are forward-compatible (the schema is migration-controlled); a
rollback that crosses a migration boundary needs `migrate down` on
the Postgres side first.

## Incident-response playbooks

### Runaway block (false-positive flood)

Symptom: paging users / customers report mass connection failures;
`openscrub_rules_total{type="blocklist"}` jumped sharply in a short
window — typically a bad ThreatFlow pull or a misconfigured operator
rule covering too much.

1. **Pause IOC ingestion** to stop the bleed:

   ```bash
   # Disable the puller for the duration of the incident
   kubectl -n openscrub set env deployment/openscrub-api \
     OPENSCRUB_THREATFLOW_API_URL=
   kubectl -n openscrub rollout restart deployment/openscrub-api
   ```

2. **Identify the offending rules**. The Postgres `rules` table
   carries `created_at` and `source`:

   ```sql
   SELECT id, type, cidr, source, created_at
   FROM rules
   WHERE created_at > now() - interval '5 minutes'
   ORDER BY created_at DESC;
   ```

   Every `openscrub.rule_change` event is submitted to CITADEL's WORM
   chain (append-only), but **CITADEL v1.0.0 has no query/list
   endpoint** for reading entries back by source or event type — only
   `POST /api/v1/worm/emit` (write) and `GET /api/v1/worm/verify`
   (integrity check, not content) exist. So the Postgres `rules` table
   above is the fastest way to identify the offending rules during an
   incident. To confirm the CITADEL WORM chain segment covering the
   incident window is intact (not to read event content):

   ```bash
   curl -sf "https://citadel.internal/api/v1/worm/verify?from=$(date -u -d '5 min ago' --iso-8601=seconds)&to=$(date -u --iso-8601=seconds)" \
     | jq '{valid, entries_verified}'
   ```

   Reading the actual event payloads for a postmortem requires direct
   read access to CITADEL's WORM table today — see
   [citadel-integration.md § Verification path](citadel-integration.md#verification-path-auditor-side).
   Also note: only `rule_change` events that were successfully
   delivered (or already retried at the time of the incident) will be
   there — unlike `mitigation` events, `rule_change` emission is not
   backed by a durable outbox, so an event lost to a process restart
   or a full in-memory retry buffer will not appear (same doc,
   § Delivery semantics).

3. **Withdraw in bulk** via the API (one DELETE per id):

   ```bash
   for id in $(psql -At -c "SELECT id FROM rules WHERE created_at > now() - interval '5 minutes' AND source='threatflow';"); do
     curl -sf -X DELETE -H "Authorization: Bearer $TOKEN" \
       "https://openscrub.internal/api/v1/rules/$id?reason=runaway-block-rollback"
   done
   ```

   The loader removes each map entry as the DELETE lands. Watch
   `openscrub_rules_total` drop in real-time.

4. **Postmortem-ready facts** are intended to already be in the
   CITADEL WORM log — every rule add and withdraw *should* have a
   signed, timestamped `rule_change` event — but per the caveat above,
   confirm delivery rather than assuming it: `rule_change` emission has
   no durable outbox, so cross-check against the Postgres `rules` /
   `audit_log` tables (which are always authoritative, independent of
   CITADEL reachability) before relying solely on CITADEL for the
   incident timeline.

5. **Re-enable ThreatFlow** only after confirming the upstream feed
   is clean (or after pinning the puller to an older feed snapshot
   if your ThreatFlow deployment supports it).

### Loader detach on a single node

`dataplane_attached: false` on one node, others healthy.

1. Check loader pod logs:
   `kubectl -n openscrub logs ds/openscrub-loader --previous`.
2. Common causes: NIC driver doesn't support `drv` mode (set
   `OPENSCRUB_XDP_MODE=skb`); `/sys/fs/bpf` not mounted; kernel
   below 5.15 floor.
3. Existing pinned maps in `/sys/fs/bpf/openscrub` survive pod
   restart — `kubectl delete pod` the loader and it reattaches and
   re-uses the maps without dropping any rule.

### Ratelimit map full

`openscrub_dataplane_op_total{op="add",outcome="full"}` advancing.

1. The map cap is compile-time (100 000 entries, see
   [`ebpf/openscrub.bpf.c`](../ebpf/openscrub.bpf.c)). Raising it
   requires a loader rebuild + DaemonSet roll.
2. Short-term: aggressively lower TTL on `ratelimit` rules so the
   sweeper reclaims slots faster.
3. Mid-term: consolidate single-IP rules into wider CIDR blocklist
   rules where appropriate.
4. Long-term: an ADR-tracked map-cap bump.

### CITADEL emit failing

Evidence events failing to deliver. Operationally, mitigation still
happens — but the audit chain breaks if this persists.

1. Check clock skew on every API replica
   (`chronyc tracking` / `timedatectl status`). CITADEL rejects
   events outside its replay window.
2. Verify the HMAC secret matches what's provisioned on CITADEL —
   rotation flow is in [citadel-integration.md](citadel-integration.md).
3. Inspect the CITADEL outbox via the API process logs (each retry
   logs the cause: `replay_window_violation`, `bad_signature`,
   `503`).
4. Outbox is durable in Postgres; events emit when CITADEL recovers.

## Capacity planning

See [`docs/architecture.md` § Capacity](architecture.md) for sizing
formulas and benchmark numbers (per-pps overhead, LPM-trie scale,
ratelimit map sizing). Headline figures:

- Per-edge-node throughput target: **line rate at 64-byte packets**
  on `mlx5` / `i40e` / `bnxt` in `drv` mode.
- Blocklist scale: ~1 M LPM prefixes per node (kernel default; raise
  via `bpf_jit_limit` and the LPM-trie `max_entries`).
- Ratelimit scale: 100 k single-source entries per node (compile-
  time cap; see incident playbook above).

For sites that exceed these, scale horizontally — more edge nodes,
ECMP / BGP balanced upstream. OpenScrub is **not** a substitute for
upstream BGP-based scrubbing past NIC capacity (see
[../README.md](../README.md)).

## Log correlation with IRFlow

Every mitigation event carries a stable `rule_id` and (when CITADEL
is wired) an evidence-event id. IRFlow's incident timeline pulls
both:

- **From CITADEL** — IRFlow subscribes to
  `openscrub.mitigation` and `openscrub.rule_change` events and
  attaches them to the incident timeline by source IP and time
  window.
- **From the API** —
  `GET /api/v1/mitigations?limit=…` returns the live feed; IRFlow
  polls this for sites that don't run CITADEL.

When investigating an IRFlow incident:

1. Pull the source IPs from the IRFlow incident.
2. Cross-reference against the OpenScrub `mitigations` table:
   `SELECT * FROM mitigations WHERE src_ip = $1 ORDER BY ts DESC`.
3. Each mitigation row links to its `rule_id` and CITADEL
   `evidence_id` — paste the latter into the IRFlow incident
   evidence panel.

The reverse direction (an OpenScrub-noticed flood that isn't yet an
IRFlow incident) auto-creates an IRFlow incident if
`OPENSCRUB_IRFLOW_*` is configured — see the integration doc
shipping in a follow-up.

## Routine cleanups

### Expired rules

The TTL sweeper runs in the API process and reconciles every 1 s.
Expired rules are deleted from Postgres, the loader is told to
remove the BPF map entry, and a `rule_expired` row is appended to
the audit log. Monitor:

```bash
curl -sf https://openscrub.internal:9091/metrics \
  | grep '^openscrub_rules_expired_total'
```

If the counter stalls while TTLs continue to elapse, the sweeper is
stuck — restart the API replicas; the BPF maps stay attached so
there is no traffic gap.

### Stale audit-log rows

The `audit_log` table is append-only and **does not** auto-prune —
audit retention is a compliance decision, not an operational one.
NIS2 prescribes record retention; check your local DPA's
interpretation. Plan storage accordingly.

### Postgres backups

Standard `pg_dump` / restore. Migrations run by the API on boot
(see [`internal/db/migrations/`](../internal/db/migrations/)).
Rules and audit_log are the critical tables; lose them and you lose
provenance for every active block.

## Routine ops

### Rotating `OPENSCRUB_JWT_SECRET`

Comma-separated list (`primary,next,previous`) supports overlap
windows — see [`internal/config/config.go`](../internal/config/config.go)
(`splitCSV`):

1. Add the new secret as `next` in the deployment env.
2. Roll the API.
3. Promote `next` to `primary` (and the old `primary` to
   `previous`) in the next deploy.
4. After 24 h, drop `previous`.

### Rotating `OPENSCRUB_CITADEL_HMAC_SECRET`

Single-valued, no overlap. Coordinate with the CITADEL operator:

1. Provision the new secret on CITADEL with an overlap window
   (CITADEL accepts both old and new for N hours).
2. Update `OPENSCRUB_CITADEL_HMAC_SECRET`; roll the API.
3. After CITADEL's overlap expires, the rotation is complete.

A mismatched HMAC secret manifests as
`openscrub_citadel_emit_total{outcome="error"}` with `bad_signature`
in API logs.

### Forcing a ThreatFlow pull cycle

The puller has no manual-trigger HTTP endpoint in v1.0.0 — to force an
out-of-cycle fetch, restart the API container (the first tick fires
immediately on boot):

```bash
docker compose restart openscrub
```

A scheduled `POST /api/v1/iocs/pull` admin endpoint is on the roadmap.

## Related

- [architecture.md](architecture.md)
- [deployment.md](deployment.md)
- [configuration.md](configuration.md)
- [api.md](api.md)
- [troubleshooting.md](troubleshooting.md)
- [security/threat-model.md](security/threat-model.md)
- [threatflow-integration.md](threatflow-integration.md)
- [citadel-integration.md](citadel-integration.md)
- [faq.md](faq.md)
- [../SECURITY.md](../SECURITY.md)
- [../ROADMAP.md](../ROADMAP.md)
