#!/usr/bin/env bash
# OpenScrub end-to-end integration test.
# Brings up the docker-compose stack, creates a rule, fires packets,
# and asserts the drop counter increases.
#
# Requires: docker, curl, jq, hping3 (sudo).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker-compose.yml"
API_BASE="${API_BASE:-http://localhost:8087}"
# Dev-only credentials matching the defaults in deploy/docker-compose.yml.
# Override via env if your .env supplies a different OPENSCRUB_USERS spec.
USERNAME="${OPENSCRUB_TEST_USER:-operator}"
PASSWORD="${OPENSCRUB_TEST_PASS:-operator-dev-only}"
TARGET_CIDR="${TARGET_CIDR:-203.0.113.7/32}"
TARGET_IP="${TARGET_CIDR%/*}"

log() { echo "[itest] $*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
  log "tearing down compose stack"
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}

if [ "${KEEP_STACK:-0}" != "1" ]; then
  trap cleanup EXIT
fi

log "bringing up compose stack"
docker compose -f "$COMPOSE_FILE" up -d --wait

log "waiting for API health"
for i in $(seq 1 60); do
  if curl -fsS "$API_BASE/api/v1/health" >/dev/null 2>&1; then
    log "API healthy"
    break
  fi
  sleep 1
  if [ "$i" = "60" ]; then
    fail "API never became healthy"
  fi
done

log "logging in as $USERNAME"
TOKEN="$(curl -fsS -X POST "$API_BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" | jq -r .access_token)"

[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "no access token"

log "creating blocklist rule for $TARGET_CIDR"
RULE_ID="$(curl -fsS -X POST "$API_BASE/api/v1/rules" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"cidr\":\"$TARGET_CIDR\",\"type\":\"blocklist\",\"ttl_seconds\":120}" | jq -r .id)"

[ -n "$RULE_ID" ] && [ "$RULE_ID" != "null" ] || fail "rule not created"
log "rule id $RULE_ID"

# /api/v1/metrics returns Prometheus text exposition; the JSON snapshot
# lives at /api/v1/metrics/snapshot (see api/openapi.yaml MetricsSnapshot).
BEFORE="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$API_BASE/api/v1/metrics/snapshot" | jq -r .pps_dropped)"
log "pps_dropped before: $BEFORE"

if ! command -v hping3 >/dev/null 2>&1; then
  fail "hping3 is required to fire packets at the dataplane (apt install hping3 / brew install hping)"
fi
log "firing 100 packets from spoofed source $TARGET_IP (requires sudo + suitable test bench)"
sudo hping3 -c 100 -i u100 -a "$TARGET_IP" -S -p 80 127.0.0.1 >/dev/null 2>&1 || true

sleep 3

AFTER="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$API_BASE/api/v1/metrics/snapshot" | jq -r .pps_dropped)"
log "pps_dropped after: $AFTER"

if [ "$AFTER" -le "$BEFORE" ]; then
  fail "drop counter did not increase ($BEFORE -> $AFTER)"
fi

log "verifying mitigation row visible"
COUNT="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$API_BASE/api/v1/mitigations?limit=10" | jq "[.mitigations[] | select(.src_ip==\"$TARGET_IP\")] | length")"

if [ "$COUNT" -lt 1 ]; then
  fail "no mitigation row for $TARGET_IP"
fi

log "PASS: rule created, drops registered, mitigation row visible"
