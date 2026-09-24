#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-update-public-key-build: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
KEY_FILE="$WORK/update-public-key.txt"
OUT="$WORK/release"
KEY='QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI'
FINGERPRINT='425ed4e4a36b30ea21b90e21c712c649e8214c29b7eaf68089d1039c6e55384c'
printf '%s\n' "$KEY" > "$KEY_FILE"

OUT_DIR="$OUT" SOURCE_DATE_EPOCH=1700000000 WEDECENT_BUILD_COMMIT=fixture \
  "$ROOT/scripts/build-windows-release.sh" --update-public-key "$KEY_FILE" >/dev/null

grep -Fxq "update_public_key_fingerprint=$FINGERPRINT" "$OUT/VERSION.txt" ||
  fail 'release metadata does not contain expected update-key fingerprint'
grep -aFq -- "$KEY" "$OUT/wd-ui.exe" || fail 'wd-ui does not contain provisioned key'
for binary in wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe; do
  if grep -aFq -- "$KEY" "$OUT/$binary"; then
    fail "update public key leaked into $binary"
  fi
done

printf 'not-a-canonical-key\n' > "$WORK/bad-key.txt"
if OUT_DIR="$WORK/bad-release" SOURCE_DATE_EPOCH=1700000000 WEDECENT_BUILD_COMMIT=fixture \
   "$ROOT/scripts/build-windows-release.sh" --update-public-key "$WORK/bad-key.txt" >/dev/null 2>&1; then
  fail 'malformed update public key unexpectedly built a release'
fi

printf 'Windows update public-key build injection verified.\n'
