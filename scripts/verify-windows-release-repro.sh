#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct HEAD)"
fi
export SOURCE_DATE_EPOCH

OUT_DIR="$TMP/one" "$ROOT/scripts/build-windows-release.sh" >/dev/null
OUT_DIR="$TMP/two" "$ROOT/scripts/build-windows-release.sh" >/dev/null

for name in wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe VERSION.txt SHA256SUMS.txt; do
  if ! cmp -s "$TMP/one/$name" "$TMP/two/$name"; then
    printf 'reproducibility failure: %s differs between builds\n' "$name" >&2
    exit 1
  fi
done

(
  cd "$TMP/one"
  sha256sum -c SHA256SUMS.txt
)

printf 'Reproducible Windows release bundle verified.\n'
