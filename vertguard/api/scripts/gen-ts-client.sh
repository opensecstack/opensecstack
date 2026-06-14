#!/usr/bin/env bash
# Generates web/src/lib/api-generated.ts from api/openapi.yaml.
#
# Why openapi-typescript (not openapi-typescript-codegen):
#   - Single-file output of pure types + a tiny `paths` map. No runtime
#     dependency, no class hierarchy, no fetch-client lock-in. Pairs
#     cleanly with @tanstack/react-query, which the dashboard already uses.
#   - Simplest npx invocation: `npx openapi-typescript <in> -o <out>`.
#
# Idempotent: re-runs produce byte-identical output for an unchanged spec.
# Pass --check to diff against the existing file (CI drift gate).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$API_DIR/.." && pwd)"

SPEC="$API_DIR/openapi.yaml"
OUT="$REPO_DIR/web/src/lib/api-generated.ts"
PKG="openapi-typescript@^7"

CHECK_MODE=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK_MODE=1
fi

mkdir -p "$(dirname "$OUT")"

# Stable header so diffs only reflect spec changes, not generator metadata.
HEADER="// AUTO-GENERATED FILE — DO NOT EDIT.
// Source: api/openapi.yaml
// Regenerate: npm run api:generate (from vertguard/web)
"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

printf '%s' "$HEADER" > "$TMP"
npx --yes -p "$PKG" openapi-typescript "$SPEC" >> "$TMP"

if [[ "$CHECK_MODE" -eq 1 ]]; then
  if [[ ! -f "$OUT" ]] || ! diff -u "$OUT" "$TMP" > /dev/null; then
    echo "ERROR: api-generated.ts is out of sync with openapi.yaml" >&2
    if [[ -f "$OUT" ]]; then
      diff -u "$OUT" "$TMP" >&2 || true
    fi
    echo "Run: npm run api:generate" >&2
    exit 1
  fi
  echo "OK: api-generated.ts matches openapi.yaml"
  exit 0
fi

mv "$TMP" "$OUT"
trap - EXIT
echo "Wrote $OUT"
