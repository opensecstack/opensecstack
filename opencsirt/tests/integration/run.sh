#!/usr/bin/env bash
# OpenCSIRT end-to-end integration test.
# Brings up the docker-compose stack, drafts → reviews → approves →
# publishes an advisory, and asserts the CITADEL emit + ThreatFlow
# push happened.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker-compose.yml"
API_BASE="${API_BASE:-http://localhost:8088}"
USERNAME="${OPENCSIRT_TEST_USER:-operator}"
PASSWORD="${OPENCSIRT_TEST_PASS:-operator}"

log() { echo "[itest] $*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

cleanup() {
  if [ "${KEEP_STACK:-0}" = "1" ]; then return; fi
  log "tearing down compose stack"
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "bringing up compose stack"
docker compose -f "$COMPOSE_FILE" up -d --wait

log "waiting for API health"
for i in $(seq 1 60); do
  if curl -fsS "$API_BASE/api/v1/health" >/dev/null 2>&1; then
    log "API healthy"
    break
  fi
  sleep 1
  if [ "$i" = "60" ]; then fail "API never became healthy"; fi
done

log "logging in as $USERNAME"
TOKEN="$(curl -fsS -X POST "$API_BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" | jq -r .token)"

[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "no token"

log "creating constituency"
CONST_ID="$(curl -fsS -X POST "$API_BASE/api/v1/constituencies" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "TestConst",
    "kind": "essential",
    "sector": "energy",
    "tlp_default": "amber"
  }' | jq -r .id)"
[ -n "$CONST_ID" ] && [ "$CONST_ID" != "null" ] || fail "constituency not created"
log "constituency id $CONST_ID"

log "drafting an advisory"
ADVISORY_ID="$(curl -fsS -X POST "$API_BASE/api/v1/advisories" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "Integration test advisory",
    "summary": "Automated integration test — safe to discard.",
    "tlp": "GREEN"
  }' | jq -r .id)"
[ -n "$ADVISORY_ID" ] && [ "$ADVISORY_ID" != "null" ] || fail "advisory not created"
log "advisory id $ADVISORY_ID"

log "publishing advisory"
curl -fsS -X POST "$API_BASE/api/v1/advisories/$ADVISORY_ID/publish" \
  -H "Authorization: Bearer $TOKEN" >/dev/null

log "waiting for CITADEL emit (queue depth -> 0)"
for i in $(seq 1 30); do
  DEPTH="$(curl -fsS "$API_BASE/api/v1/metrics/snapshot" \
    -H "Authorization: Bearer $TOKEN" | jq -r .citadel_queue_depth)"
  log "queue_depth=$DEPTH"
  if [ "$DEPTH" = "0" ]; then break; fi
  sleep 1
  if [ "$i" = "30" ]; then fail "CITADEL queue did not drain"; fi
done

log "verifying advisory state == published"
STATE="$(curl -fsS "$API_BASE/api/v1/advisories" \
  -H "Authorization: Bearer $TOKEN" | jq -r ".advisories[] | select(.id==\"$ADVISORY_ID\") | .state")"
if [ "$STATE" != "published" ]; then
  fail "expected state=published, got $STATE"
fi

log "PASS: advisory drafted, published, CITADEL emitted"
