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

for name in wd.exe wd-agent.exe VERSION.txt SHA256SUMS.txt; do
  [[ -f "$RELEASE_DIR/$name" ]] || fail "release bundle is missing $name; run scripts/build-windows-release.sh first"
done

(
  cd "$RELEASE_DIR"
  sha256sum -c SHA256SUMS.txt
)

rm -rf -- "$OUT_DIR"
mkdir -p -- "$OUT_DIR"

cp -- "$RELEASE_DIR/wd.exe" "$OUT_DIR/wd.exe"
cp -- "$RELEASE_DIR/wd-agent.exe" "$OUT_DIR/wd-agent.exe"
cp -- "$RELEASE_DIR/VERSION.txt" "$OUT_DIR/VERSION.txt"
cp -- "$RELEASE_DIR/SHA256SUMS.txt" "$OUT_DIR/SHA256SUMS.txt"
cp -- "$ROOT/installer/windows/Install-WeDecent.ps1" "$OUT_DIR/Install-WeDecent.ps1"
cp -- "$ROOT/installer/windows/Uninstall-WeDecent.ps1" "$OUT_DIR/Uninstall-WeDecent.ps1"
cp -- "$ROOT/installer/windows/Test-WeDecentInstall.ps1" "$OUT_DIR/Test-WeDecentInstall.ps1"
cp -- "$ROOT/installer/windows/README.md" "$OUT_DIR/README.md"

(
  cd "$OUT_DIR"
  sha256sum \
    wd.exe wd-agent.exe VERSION.txt SHA256SUMS.txt \
    Install-WeDecent.ps1 Uninstall-WeDecent.ps1 Test-WeDecentInstall.ps1 README.md \
    | LC_ALL=C sort -k2 > PACKAGE_SHA256SUMS.txt
  sha256sum -c PACKAGE_SHA256SUMS.txt
)

printf 'Built WeDecent Windows installer package:\n  %s\n' "$OUT_DIR"
