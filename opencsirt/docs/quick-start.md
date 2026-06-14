# OpenCSIRT Quick Start

Get OpenCSIRT v1.0.0 coordinating an incident and drafting an
advisory locally in about five minutes: clone, build, compose up, log
in to the dashboard, register a constituency, open an incident, draft
an advisory.

For the full configuration reference, see
[configuration.md](configuration.md). For production deployment, see
[deployment.md](deployment.md). For the operations runbook, see
[operator-handbook.md](operator-handbook.md).

## What you'll get

- OpenCSIRT Go API on `:8088` with `/api/v1/health` reporting
  `db: true` and `advisory_service: true`
- Python advisory subsystem on `:8089`
- React dashboard on `:3088`
- PostgreSQL 16 on `127.0.0.1:5432`
- One operator login (`operator`/`operator`) backed by
  `OPENCSIRT_USERS`
- One registered constituency, one open incident, one CSAF 2.0
  advisory in `draft` state

## Prerequisites

- **Docker + Docker Compose** for the local stack
- **Go 1.22+**, **Python 3.11+**, **Node 20+** if you want to build
  from source rather than pull the published images
- **PostgreSQL 16** if you intend to run migrations against your own
  database (the compose file brings one up otherwise)
- `curl` and `jq` for the smoke test

## Clone and build

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/opencsirt

cp .env.example .env
# The .env.example ships with safe DEV-ONLY defaults:
#   OPENCSIRT_DEV_MODE=true
#   OPENCSIRT_USERS=operator:operator:40a487...   (password "operator")
#   OPENCSIRT_PASSWORD_PEPPER=dev-pepper-do-not-use-in-prod
#   OPENCSIRT_JWT_SECRET=dev-secret-...           (32+ bytes)
# Optional in dev — leave empty to disable:
#   OPENCSIRT_CITADEL_*       (CITADEL_DRY_RUN defaults true)
#   OPENCSIRT_THREATFLOW_*
#   OPENCSIRT_IRFLOW_WEBHOOK_SECRET
#   OPENCSIRT_NIS2COMPASS_API_URL
#   OPENCSIRT_VERTGUARD_API_URL
```

Build everything (Go API + Python wheel + web bundle):

```bash
make build
```

Or pull the published v1.0.0 images and skip the build:

```bash
docker compose -f deploy/docker-compose.yml pull
```

## Bring up the stack

```bash
make dev
# equivalent to: docker compose -f deploy/docker-compose.yml up -d
```

Wait ~15 seconds for Postgres migrations and the advisory subsystem
to come up, then verify:

```bash
curl -sf http://localhost:8088/api/v1/health | jq .
# {
#   "status":           "ok",
#   "db":               true,
#   "advisory_service": true,
#   "uptime_seconds":   12
# }
```

If `advisory_service: false`, jump to
[troubleshooting.md § "advisory generation timeouts"](troubleshooting.md).

## Open the dashboard and log in

Browse to `http://localhost:3088`. Use the seeded credentials:

- Username: `operator`
- Password: `operator`

The dashboard shows an empty incidents board, an empty constituency
directory, and a metrics overview reading from
`/api/v1/metrics/snapshot`.

## Mint an operator JWT (curl path)

If you want to drive the API from a script instead of the UI:

```bash
TOKEN=$(curl -sf -X POST http://localhost:8088/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"operator","password":"operator"}' \
  | jq -r .token)

echo "$TOKEN" | cut -c1-40   # sanity check
```

The token is valid for `OPENCSIRT_TOKEN_TTL` (default 12 hours). Pass
it as `Authorization: Bearer $TOKEN` for every mutating call.

## Register a constituency

```bash
curl -sf -X POST http://localhost:8088/api/v1/constituencies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":                  "Example Energy Co",
    "sector":                "energy",
    "country":               "AL",
    "nis2_status":           "essential",
    "primary_contact_email": "soc@example-energy.al"
  }' | jq .
```

Expected `201` with the constituency `id` echoed back. The dashboard
*Directory* tab updates immediately.

## Open an incident

```bash
CONSTITUENCY_ID=…   # from the previous response

curl -sf -X POST http://localhost:8088/api/v1/incidents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"constituency_id\": \"$CONSTITUENCY_ID\",
    \"source\":          \"abuse_mailbox\",
    \"severity\":        \"high\",
    \"title\":           \"Suspected ransomware activity on OT segment\",
    \"description\":     \"Reporter saw lateral SMB scanning from 10.40.5.0/24.\"
  }" | jq .
```

Expected `201`. The state machine starts at `open`. The incident
appears on the dashboard board and a `citadel_outbox` row is queued
(if CITADEL is configured; with the dev defaults, the outbox row is
in `dryRun=true` mode and never POSTed).

## Draft an advisory

```bash
INCIDENT_ID=…   # from the previous response

curl -sf -X POST http://localhost:8088/api/v1/advisories \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"incident_id\": \"$INCIDENT_ID\",
    \"title\":       \"Ransomware pre-cursor activity in AL energy sector\",
    \"summary\":     \"Lateral SMB scanning observed; recommend segment isolation.\",
    \"tlp\":         \"AMBER\"
  }" | jq .
```

The Go API calls the Python advisory subsystem at
`OPENCSIRT_ADVISORY_SERVICE_URL` to render a CSAF 2.0 document; the
draft advisory comes back with a `csaf_doc` JSON block. The dashboard
*Advisories* tab shows it in the `draft` column.

## Publish (csirt_lead role required)

If you want to exercise the full publish path, swap to a `csirt_lead`
user (add another `OPENCSIRT_USERS` entry and re-login), then:

```bash
ADVISORY_ID=…   # from the previous response

curl -sf -X POST "http://localhost:8088/api/v1/advisories/$ADVISORY_ID/publish" \
  -H "Authorization: Bearer $TOKEN"
```

Expected `200`. The advisory transitions `draft → published`,
`published_at` is set, and an `opencsirt.advisory_published` event is
queued in the CITADEL outbox.

## Bring it down

```bash
docker compose -f deploy/docker-compose.yml down -v
```

The `-v` drops the Postgres volume too. Omit it to preserve state.

## Troubleshooting

If something didn't work:

- `503 issuer_disabled` on login — `OPENCSIRT_USERS` is empty or the
  pepper changed. Re-run `make dev` after fixing `.env`.
- `advisory_service: false` in `/api/v1/health` — the Python
  subsystem isn't reachable; the Go API falls back to NoopClient and
  rejects new advisory drafts. See
  [troubleshooting.md § "advisory generation timeouts"](troubleshooting.md).
- CITADEL outbox not draining — expected with dev defaults
  (`OPENCSIRT_CITADEL_DRY_RUN=true`). Set the API URL and HMAC
  secret to wire it for real.

Full symptom-driven guide: [troubleshooting.md](troubleshooting.md).

## Next steps

- Configure for your environment: [configuration.md](configuration.md)
- Deploy on Kubernetes via Helm: [deployment.md](deployment.md)
- Wire ThreatFlow IOC ingest:
  [threatflow-integration.md](threatflow-integration.md)
- Wire IRFlow incident handoff:
  [irflow-integration.md](irflow-integration.md)
- Wire NIS2 Compass:
  [nis2-integration.md](nis2-integration.md)
- Wire CITADEL evidence:
  [citadel-integration.md](citadel-integration.md)
- Operator runbook: [operator-handbook.md](operator-handbook.md)
- Architecture: [architecture.md](architecture.md)
- Peer handshake: [peer-csirt-handshake-protocol.md](peer-csirt-handshake-protocol.md)

## See also

- [README.md](../README.md)
- [ROADMAP.md](../ROADMAP.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [api.md](api.md)
- [faq.md](faq.md)
