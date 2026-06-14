# OpenCSIRT Troubleshooting

> Common operational issues and resolution. v1.0.0.

## Login returns 503 issuer_disabled

**Symptom:** `POST /api/v1/auth/login` returns
`503 issuer_disabled`.

**Cause:** `OPENCSIRT_USERS` is empty. Without at least one user
entry, the auth package has no credentials to verify against and
disables the issuer entirely
([`internal/auth/auth.go`](../internal/auth/auth.go) — see
`ErrIssuerDisabled`).

**Fix:** populate `OPENCSIRT_USERS` and restart the API. The format
is comma-separated `username:role:sha256hex` triples; the hash is
`sha256(${OPENCSIRT_PASSWORD_PEPPER}:<plaintext>)`. Worked example:

```bash
# Set a real pepper outside dev mode
PEPPER='dev-pepper-do-not-use-in-prod'
PWD='operator'
HASH=$(printf '%s' "${PEPPER}:${PWD}" | sha256sum | awk '{print $1}')
echo "$HASH"
# 40a487e69bfd2b64adc205cdd1f91de6e85a1aeb309f9bde4dc4e780c131cd26

export OPENCSIRT_USERS="operator:operator:$HASH"
docker compose -f deploy/docker-compose.yml restart opencsirt-api
```

Diagnostic:

```bash
docker logs deploy_opencsirt-api_1 2>&1 | grep -i 'issuer disabled\|users loaded'
```

If you see `auth: issuer disabled (no users configured)` the env
var did not propagate to the container.

---

## CITADEL events stuck pending

**Symptom:** `opencsirt_citadel_queue_depth` rising without bound;
`opencsirt_citadel_events_total{outcome="error"}` advancing.

**Causes:**

1. **HMAC secret rotation mismatch.** The signing secret in
   `OPENCSIRT_CITADEL_HMAC_SECRETS[0]` does not match what CITADEL
   has provisioned for this `OPENCSIRT_CITADEL_KEY_ID`. CITADEL
   rejects with `bad_signature` and the watcher leaves the row
   `pending` with `attempts++`.
2. **Dry-run flag.** `OPENCSIRT_CITADEL_DRY_RUN=true` (the default).
   Events are logged as "would-be POSTs" and **never** sent.
   Production deployments must explicitly set this to `false`.
3. **Clock drift.** CITADEL enforces a ±5-minute replay window on
   `X-Timestamp`. A clock skew on the API host past 5 minutes
   produces `replay_window_violation` rejections.
4. **CITADEL ingress unreachable.** Network path from the API to
   `OPENCSIRT_CITADEL_API_URL` blocked.

**Diagnostic commands:**

```bash
# Confirm the dry-run flag
docker exec deploy_opencsirt-api_1 \
  printenv OPENCSIRT_CITADEL_DRY_RUN

# Watcher logs for the rejection cause
docker logs deploy_opencsirt-api_1 2>&1 \
  | grep -E 'citadel.*(error|bad_signature|replay_window|503)'

# Direct connectivity check
docker exec deploy_opencsirt-api_1 \
  curl -sf -o /dev/null -w '%{http_code}\n' \
  "${OPENCSIRT_CITADEL_API_URL}/api/v1/health"

# Clock drift
docker exec deploy_opencsirt-api_1 date -u
date -u   # compare against host
```

**Fix:**

- For rotation mismatch: prepend the correct secret to the
  comma-separated list and roll the API.
- For dry-run: set `OPENCSIRT_CITADEL_DRY_RUN=false` and roll.
- For clock drift: fix host NTP (`chronyd` / `systemd-timesyncd`).
- For ingress: check network policy / firewall.

The outbox is durable. Once the cause is fixed the watcher catches
up automatically; rows do not need manual reset (subject to
CITADEL's replay window — events older than 5 min are permanently
rejected and need either a wider server-side window or an out-of-
band reconcile).

---

## Advisory generation timeouts

**Symptom:** `POST /api/v1/advisories` returns
`504 advisory_service_timeout` or `503 advisory_service_unavailable`;
`/api/v1/health` shows `advisory_service: false`.

**Cause:** the Python advisory subsystem at
`OPENCSIRT_ADVISORY_SERVICE_URL` is unreachable, slow, or crashed.
The Go core falls back to `NoopClient` in
[`internal/advisory/`](../internal/advisory/) — incident triage
continues, but new advisory drafts are blocked.

**Diagnostic commands:**

```bash
# Direct check from inside the API container
docker exec deploy_opencsirt-api_1 \
  curl -sf -o /dev/null -w '%{http_code} %{time_total}s\n' \
  "${OPENCSIRT_ADVISORY_SERVICE_URL}/health"

# Advisory subsystem logs
docker logs deploy_opencsirt-advisory_1 2>&1 | tail -50

# CSAF schema-validation crashes are the usual cause
docker logs deploy_opencsirt-advisory_1 2>&1 | grep -iE 'traceback|error'
```

**Fix:**

1. **Restart the advisory service:**

   ```bash
   docker compose -f deploy/docker-compose.yml restart opencsirt-advisory
   ```

2. **Wrong URL.** If the Go core is reaching a stale endpoint
   (typo, port mismatch, missing service name in the compose
   network), set `OPENCSIRT_ADVISORY_SERVICE_URL` to the correct
   value. The default is `http://localhost:8089` which is correct
   only for local-dev co-located runs; in compose the service name
   is `http://opencsirt-advisory:8089`.

3. **NoopClient fallback.** While the subsystem is down, the
   dashboard *Advisories* tab shows a banner and the API rejects
   `POST /api/v1/advisories` with 503. Existing drafts and published
   advisories remain readable — only new drafts block.

---

## IRFlow webhook returns 401

**Symptom:** IRFlow logs show OpenCSIRT rejecting incident pushes
with `401 invalid_signature` or `401 stale_request`.

**Causes:**

1. **HMAC drift > 5 minutes.** The webhook handler enforces a
   ±5-minute replay window on the request timestamp. IRFlow's host
   clock and OpenCSIRT's host clock have skewed past that.
2. **Wrong shared secret.** `OPENCSIRT_IRFLOW_WEBHOOK_SECRET` does
   not match the value IRFlow signs with.
3. **Empty secret.** With `OPENCSIRT_IRFLOW_WEBHOOK_SECRET` unset,
   the endpoint rejects every request.

**Diagnostic commands:**

```bash
# Confirm both sides agree on the secret
docker exec deploy_opencsirt-api_1 \
  sh -c 'echo -n "$OPENCSIRT_IRFLOW_WEBHOOK_SECRET" | sha256sum'
# … compare with the same on the IRFlow side.

# Confirm clock alignment between IRFlow and OpenCSIRT
docker exec deploy_opencsirt-api_1 date -u
ssh irflow-host date -u

# OpenCSIRT-side rejection cause
docker logs deploy_opencsirt-api_1 2>&1 \
  | grep -E 'irflow.*(invalid_signature|stale_request|missing_secret)'
```

**Fix:**

- For clock drift: fix NTP on whichever host drifted.
- For secret mismatch: rotate the shared secret on both sides
  simultaneously; IRFlow and OpenCSIRT do not negotiate the secret.
- For empty secret: provision one and restart both services.

---

## ThreatFlow IOC ingest empty

**Symptom:** `opencsirt_iocs_ingested_total{source="threatflow"}` is
flat for longer than `2 × OPENCSIRT_THREATFLOW_INTERVAL`.

**Causes:**

1. **URL misconfig.** `OPENCSIRT_THREATFLOW_API_URL` is unset or
   points to the wrong host. When unset, the puller goroutine
   doesn't start.
2. **ThreatFlow returning empty bundles.** Legitimate, but
   surfaces as a flat counter. Confirm against ThreatFlow's own
   metrics.
3. **Network path blocked.** Firewall / NetworkPolicy.

**Diagnostic commands:**

```bash
# Confirm the URL is set
docker exec deploy_opencsirt-api_1 \
  printenv OPENCSIRT_THREATFLOW_API_URL

# Direct probe from the API container
docker exec deploy_opencsirt-api_1 \
  curl -sf -o /dev/null -w '%{http_code}\n' \
  "${OPENCSIRT_THREATFLOW_API_URL}/api/v1/health"

# Puller logs
docker logs deploy_opencsirt-api_1 2>&1 | grep -i threatflow | tail -20
```

**Fix:**

- For URL misconfig: set the value, restart the API. The first
  pull tick fires immediately on boot.
- For empty bundles: check ThreatFlow's own dashboards — this is
  not an OpenCSIRT bug.
- For network blocking: open the path or move ThreatFlow into the
  same network namespace.

---

## Dashboard shows 401 on every request

The JWT secret was rotated (intentional or accidental). Operators
must re-login. Sessions live in `sessionStorage`; closing the tab
also clears them, by design.

If re-login itself fails with `503 issuer_disabled`, see the first
section above.

---

## Migrations fail on startup

**Symptom:** `opencsirt-api` container restart-loops with a
migration error in logs.

**Diagnostic:**

```bash
docker logs deploy_opencsirt-api_1 2>&1 | grep -iE 'migrat|sql'
```

**Common causes:**

- **Schema drift from a manual edit.** Restore from backup or
  drop the broken object and re-run.
- **Database user lacks `CREATE` rights.** The first migration
  needs `CREATE TABLE` and `CREATE EXTENSION` (`uuid-ossp`).
- **Old migration partial-applied.** Run `make migrate-down` once
  and re-run `make migrate-up`.

---

## How to wipe state for a clean restart

```bash
docker compose -f deploy/docker-compose.yml down -v
# Drops the Postgres volume, the advisory subsystem state (none),
# and any cached web build.
docker compose -f deploy/docker-compose.yml up -d
```

The `-v` flag is destructive; preserve volumes by omitting it.

In Kubernetes:

```bash
helm uninstall opencsirt -n opencsirt
kubectl -n opencsirt delete pvc --all   # only if you want to drop data
```

---

## Where to file issues

- Operational bugs and feature requests: GitHub issues on
  `opensecstack/opensecstack`, label `module/opencsirt`.
- Security issues: see [../SECURITY.md](../SECURITY.md). Do **not**
  open public issues for incident-data-leak, advisory-tampering,
  CITADEL-HMAC-bypass, JWT-forgery, or webhook-spoofing findings.

## Related

- [operator-handbook.md](operator-handbook.md)
- [configuration.md](configuration.md)
- [api.md](api.md)
- [faq.md](faq.md)
- [citadel-integration.md](citadel-integration.md)
- [irflow-integration.md](irflow-integration.md)
- [threatflow-integration.md](threatflow-integration.md)
- [../SECURITY.md](../SECURITY.md)
