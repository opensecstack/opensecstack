#!/usr/bin/env bash
# download.sh — fetch and verify VertGuard training datasets.
#
# Usage:
#   bash datasets/download.sh [--dry-run] [--dataset <name>]
#
# Options:
#   --dry-run           Print what would be downloaded without downloading.
#   --dataset <name>    Download only the named dataset (default: all).
#
# Environment:
#   VERTGUARD_DATASET_MIRROR  Override the source URL prefix (air-gapped installs).
#
# The script reads datasets/datasets.yaml and, for each entry, downloads
# the dataset archive, verifies the SHA-256 checksum, and extracts it into
# the configured path.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="${REPO_ROOT}/datasets/datasets.yaml"
DRY_RUN=false
FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)   DRY_RUN=true ;;
    --dataset)   FILTER="$2"; shift ;;
    *)           echo "unknown flag: $1" >&2; exit 1 ;;
  esac
  shift
done

# Require yq or python3 for YAML parsing.
if command -v yq &>/dev/null; then
  _yaml_names()  { yq e '.datasets[].name'    "$REGISTRY"; }
  _yaml_field()  { yq e ".datasets[] | select(.name == \"$1\") | .$2" "$REGISTRY"; }
elif command -v python3 &>/dev/null; then
  _yaml_names()  { python3 -c "
import sys, yaml
data = yaml.safe_load(open('${REGISTRY}'))
for d in data['datasets']: print(d['name'])
"; }
  _yaml_field()  { python3 -c "
import sys, yaml
data = yaml.safe_load(open('${REGISTRY}'))
d = next(x for x in data['datasets'] if x['name'] == sys.argv[1])
print(d.get(sys.argv[2], ''))
" "$1" "$2"; }
else
  echo "error: yq or python3 required to parse datasets.yaml" >&2
  exit 1
fi

# Checksum helper.
_sha256() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

download_dataset() {
  local name="$1"
  local version source path sha256 size_mb dest mirror_prefix

  version=$(_yaml_field "$name" version)
  source=$(_yaml_field "$name" source)
  path=$(_yaml_field "$name" path)
  sha256=$(_yaml_field "$name" sha256)
  size_mb=$(_yaml_field "$name" size_mb)
  dest="${REPO_ROOT}/${path}"
  mirror_prefix="${VERTGUARD_DATASET_MIRROR:-}"

  if [[ -n "$mirror_prefix" ]]; then
    source="${mirror_prefix}/$(echo "$source" | sed 's|https://huggingface.co/datasets/||')"
  fi

  echo "==> dataset: ${name} v${version} (~${size_mb} MiB compressed)"
  echo "    source:  ${source}"
  echo "    dest:    ${dest}"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "    [dry-run] skipping download"
    return
  fi

  mkdir -p "$dest"

  local archive="${dest}/.download.tar.gz"
  local dl_url="${source}/resolve/main/data.tar.gz"

  echo "    downloading..."
  if command -v curl &>/dev/null; then
    curl -fsSL --retry 3 -o "$archive" "$dl_url"
  elif command -v wget &>/dev/null; then
    wget -q --tries=3 -O "$archive" "$dl_url"
  else
    echo "error: curl or wget is required" >&2
    exit 1
  fi

  if [[ "$sha256" != placeholder* ]]; then
    echo "    verifying checksum..."
    local actual
    actual=$(_sha256 "$archive")
    if [[ "$actual" != "$sha256" ]]; then
      echo "error: checksum mismatch for ${name}" >&2
      echo "  expected: ${sha256}" >&2
      echo "  got:      ${actual}" >&2
      rm -f "$archive"
      exit 1
    fi
    echo "    checksum OK"
  else
    echo "    warning: placeholder checksum — skipping verification"
  fi

  echo "    extracting..."
  tar -xzf "$archive" -C "$dest" --strip-components=1
  rm -f "$archive"
  echo "    done: ${name}"
}

mapfile -t ALL_NAMES < <(_yaml_names)

for name in "${ALL_NAMES[@]}"; do
  if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
    continue
  fi
  download_dataset "$name"
done

echo ""
echo "All requested datasets downloaded successfully."
