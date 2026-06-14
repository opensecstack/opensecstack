# OpenScrub Quick Start

Get OpenScrub v1.0.0 dropping packets locally in about five minutes:
clone, build, compose up, log in to the dashboard, install a
blocklist rule, confirm the drop counter moves.

For the full configuration reference, see
[configuration.md](configuration.md). For production deployment, see
[deployment.md](deployment.md). For the operations runbook, see
[operator-handbook.md](operator-handbook.md).

## What you'll get

- OpenScrub Go API on `:8087` with `/api/v1/health` reporting
  `dataplane_attached: true` against a loopback NIC
- React dashboard on `:3087`
- PostgreSQL 16 on `127.0.0.1:5432`
- Prometheus on `127.0.0.1:9090` scraping `:9091`
- An `openscrub-loader` container running with explicit Linux
  capabilities (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE`) —
  not `privileged: true`, so seccomp and AppArmor stay engaged —
  with the XDP program attached in `skb` (generic) mode (or `drv`
  mode if you point `OPENSCRUB_IFACE` at a real NIC with
  driver-XDP support)
- One operator-created `/24` blocklist rule and a non-zero
  `openscrub_dataplane_op_total{op="add",outcome="ok"}`

## Prerequisites

- **Linux kernel ≥ 5.15** (the loader refuses older kernels — see
  [troubleshooting.md § "kernel too old"](troubleshooting.md))
- **Docker + Docker Compose** for the local stack
- **clang 14+** and **libbpf-dev** if you intend to recompile the
  BPF object yourself; the prebuilt `opensecstack/openscrub-loader`
  image already contains it
- **Rust 1.75+** and **Go 1.24+** if you want to build from source
- `curl` and `jq` for the smoke test

> macOS / Windows / Docker Desktop: the API and dashboard come up,
> but XDP attach is non-functional on those kernels. The loader logs
> a WARN and the data plane stays detached. Use a Linux VM or a
> remote Linux host to exercise the drop path.

## Clone and build

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/openscrub

cp .env.example .env
# Required:
#   OPENSCRUB_DB_PASSWORD     (any non-empty string)
#   OPENSCRUB_JWT_SECRET      (>=32 bytes — `openssl rand -base64 32`)
#   OPENSCRUB_IFACE           (e.g. eth0; lo works for the smoke test)
# Optional in dev:
#   OPENSCRUB_THREATFLOW_*    (leave empty to disable IOC pull)
#   OPENSCRUB_CITADEL_*       (leave empty to disable evidence emission)
```

Build everything (eBPF object + Rust loader + Go API + web):

```bash
make build
```

Or pull the published v1.0.0 images and skip the build:

```bash
docker compose -f deploy/docker-compose.yml pull
```

## Bring up the stack

```bash
make compose-up
# equivalent to: docker compose -f deploy/docker-compose.yml up -d
```

Wait ~20 seconds for Postgres migrations and the loader's XDP attach,
then verify:

```bash
curl -sf http://localhost:8087/api/v1/health | jq .
# {
#   "status":             "ok",
#   "version":            "1.0.0",
#   "db_ping":            true,
#   "dataplane_attached": true
# }
```

If `dataplane_attached` is `false`, jump to
[troubleshooting.md § "loader: degraded"](troubleshooting.md).

## Open the dashboard

Browse to `http://localhost:3087`. The dashboard ships bilingual
(shqip / English); the toggle is top-right. The default locale is
controlled by `VITE_DEFAULT_LOCALE` at build time
([configuration.md](configuration.md)).

## Mint an operator JWT

OpenScrub's auth is JWT (HS256) signed with `OPENSCRUB_JWT_SECRET`.
The `migrations/0001_init.up.sql` schema does **not** seed any user
accounts — there is no built-in `operator/operator` login. For the
dev stack, mint a token directly against the configured secret:

```bash
# Same secret you set in .env
SECRET="$OPENSCRUB_JWT_SECRET"

HEADER=$(printf '{"alg":"HS256","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(printf '{"sub":"operator","iss":"openscrub","exp":%d}' $(( $(date +%s) + 3600 )) \
  | base64 -w0 | tr '+/' '-_' | tr -d '=')
SIG=$(printf '%s.%s' "$HEADER" "$PAYLOAD" \
  | openssl dgst -sha256 -hmac "$SECRET" -binary \
  | base64 -w0 | tr '+/' '-_' | tr -d '=')
TOKEN="$HEADER.$PAYLOAD.$SIG"

echo "$TOKEN" | cut -c1-40   # sanity check
```

The token is valid for one hour. Pass it as
`Authorization: Bearer $TOKEN` for every mutating call.

> Production deployments wire auth through the ecosystem SDK — see
> [deployment.md](deployment.md) and [../SECURITY.md](../SECURITY.md).

## Add a blocklist rule

Block traffic from `203.0.113.0/24` for one hour:

```bash
curl -sf -X POST http://localhost:8087/api/v1/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type":        "blocklist",
    "cidr":        "203.0.113.0/24",
    "ttl_seconds": 3600,
    "source":      "operator"
  }' | jq .
```

Expected `201`:

```json
{
  "id":          "01J0…",
  "type":        "blocklist",
  "cidr":        "203.0.113.0/24",
  "ttl_seconds": 3600,
  "source":      "operator",
  "created_at":  "2026-05-09T10:23:00Z",
  "expires_at":  "2026-05-09T11:23:00Z"
}
```

The API persisted the rule, sent it to the loader over the dataplane
socket, and the loader wrote it into the `blocklist_v4` LPM-trie BPF
map. The dashboard's *Rules* tab updates immediately.

## Confirm the drop

Send traffic from a source inside the blocked range. From any host
that can route to the OpenScrub interface (use `lo` and `127.0.0.1`
for local smoke; for a real NIC test, source-spoof from a VM):

```bash
sudo hping3 -c 100 -i u1000 -S -s 1024 -p 80 \
  --spoof 203.0.113.42 <openscrub-iface-addr>
```

Then check the metric counter:

```bash
curl -sf http://localhost:9091/metrics | grep openscrub_dataplane_op_total
# openscrub_dataplane_op_total{op="add",outcome="ok"} 1
```

And the live mitigation feed:

```bash
curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:8087/api/v1/mitigations?limit=5 | jq .
```

Each item carries the rule id, source IP, packet count, and (if
`OPENSCRUB_CITADEL_API_URL` is set) a CITADEL evidence-event id.

## Withdraw the rule

```bash
RULE_ID=01J0…   # from the create response

curl -sf -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8087/api/v1/rules/$RULE_ID?reason=quick-start-cleanup"
# 204 No Content
```

The loader removes the BPF map entry. A `rule_withdrawn` row hits the
audit log; if CITADEL is configured, an `openscrub.rule_change` event
is queued.

## Bring it down

```bash
make compose-down
# equivalent to: docker compose -f deploy/docker-compose.yml down -v
```

This drops the Postgres volume too. To preserve state, omit `-v`.

## Troubleshooting

If something didn't work:

- `dataplane_attached: false` — check loader logs:
  `docker logs deploy_openscrub-loader_1`. Most likely the kernel is
  too old, the NIC doesn't support driver XDP (set
  `OPENSCRUB_XDP_MODE=skb`), or `/sys/fs/bpf` isn't mounted in the
  loader container.
- `401 invalid_credentials` on login — `OPENSCRUB_JWT_SECRET` was
  rotated since the API last started. Restart the API container.
- Drops not showing in `/api/v1/mitigations` — the source IP isn't
  matched by any rule, or the traffic is L7 (OpenScrub is L3/L4
  only — see [faq.md](faq.md)).

Full symptom-driven guide: [troubleshooting.md](troubleshooting.md).

## Next steps

- Configure for your environment: [configuration.md](configuration.md)
- Deploy on Kubernetes via Helm: [deployment.md](deployment.md)
- Wire ThreatFlow IOC pull:
  [threatflow-integration.md](threatflow-integration.md)
- Wire CITADEL evidence:
  [citadel-integration.md](citadel-integration.md)
- Operator runbook: [operator-handbook.md](operator-handbook.md)
- Architecture: [architecture.md](architecture.md)
- Threat model: [security/threat-model.md](security/threat-model.md)

## See also

- [../README.md](../README.md)
- [../ROADMAP.md](../ROADMAP.md)
- [../CONTRIBUTING.md](../CONTRIBUTING.md)
- [api.md](api.md)
- [faq.md](faq.md)
