#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'build-windows-installer-package: %s\n' "$*" >&2
  exit 1
}

command -v realpath >/dev/null 2>&1 || fail 'realpath is required'

ROOT="$(realpath -m -- "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)")"
DIST_ROOT="$(realpath -m -- "$ROOT/dist")"
RELEASE_DIR="$(realpath -m -- "${RELEASE_DIR:-$DIST_ROOT/wedecent-windows-amd64}")"
OUT_DIR="$(realpath -m -- "${OUT_DIR:-$DIST_ROOT/wedecent-windows-installer}")"

case "$OUT_DIR" in
  "$DIST_ROOT"/*) ;;
  *) fail "OUT_DIR must be a child of $DIST_ROOT; got $OUT_DIR" ;;
esac

if [[ "$OUT_DIR" == "$RELEASE_DIR" || "$RELEASE_DIR" == "$OUT_DIR"/* || "$OUT_DIR" == "$RELEASE_DIR"/* ]]; then
  fail "OUT_DIR and RELEASE_DIR must not be equal or nested: OUT_DIR=$OUT_DIR RELEASE_DIR=$RELEASE_DIR"
fi

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
installer_scripts=(Install-WeDecent.ps1 Uninstall-WeDecent.ps1 Test-WeDecentInstall.ps1 Update-WeDecent.ps1)
for name in "${binaries[@]}" VERSION.txt SHA256SUMS.txt; do
  [[ -f "$RELEASE_DIR/$name" ]] || fail "release bundle is missing $name; run scripts/build-windows-release.sh first"
done
for name in "${installer_scripts[@]}" README.md; do
  [[ -f "$ROOT/installer/windows/$name" && ! -L "$ROOT/installer/windows/$name" ]] || fail "installer source is missing or invalid: $name"
done

(
  cd "$RELEASE_DIR"
  sha256sum -c SHA256SUMS.txt
)

rm -rf -- "$OUT_DIR"
mkdir -p -- "$OUT_DIR"

for name in "${binaries[@]}"; do
  cp -- "$RELEASE_DIR/$name" "$OUT_DIR/$name"
done
cp -- "$RELEASE_DIR/VERSION.txt" "$OUT_DIR/VERSION.txt"
cp -- "$RELEASE_DIR/SHA256SUMS.txt" "$OUT_DIR/SHA256SUMS.txt"
for name in "${installer_scripts[@]}" README.md; do
  cp -- "$ROOT/installer/windows/$name" "$OUT_DIR/$name"
done

(
  cd "$OUT_DIR"
  sha256sum \
    "${binaries[@]}" VERSION.txt SHA256SUMS.txt \
    "${installer_scripts[@]}" README.md \
    | LC_ALL=C sort -k2 > PACKAGE_SHA256SUMS.txt
  sha256sum -c PACKAGE_SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)

printf 'Built WeDecent Windows installer package:\n  %s\n' "$OUT_DIR"
