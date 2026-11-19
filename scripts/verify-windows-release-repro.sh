#!/usr/bin/env bash
set -euo pipefail
unset WEDECENT_PAIRING_SECRET || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct HEAD)"
fi
export SOURCE_DATE_EPOCH
commit="$(git -C "$ROOT" rev-parse --verify HEAD)"
source_sha256="$(git -C "$ROOT" archive --format=tar "$commit" | sha256sum | awk '{print $1}')"

OUT_DIR="$TMP/one" "$ROOT/scripts/build-windows-release.sh" >/dev/null
OUT_DIR="$TMP/two" "$ROOT/scripts/build-windows-release.sh" >/dev/null

for name in wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe VERSION.txt SHA256SUMS.txt; do
  if ! cmp -s "$TMP/one/$name" "$TMP/two/$name"; then
    printf 'reproducibility failure: %s differs between builds\n' "$name" >&2
    exit 1
  fi
done

grep -Fxq "commit=$commit" "$TMP/one/VERSION.txt"
grep -Fxq "source_sha256=$source_sha256" "$TMP/one/VERSION.txt"
(
  cd "$TMP/one"
  sha256sum -c SHA256SUMS.txt
)

printf 'Reproducible Windows release bundle verified.\n'
