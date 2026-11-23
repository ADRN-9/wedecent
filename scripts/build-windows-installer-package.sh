#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'build-windows-installer-package: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ -L "$ROOT/dist" ]]; then
  fail "dist must not be a symlink"
fi
mkdir -p -- "$ROOT/dist"
DIST_ROOT="$ROOT/dist"
[[ "$(cd "$DIST_ROOT" && pwd -P)" == "$DIST_ROOT" ]] || fail "dist path is not canonical"

RELEASE_DIR="${RELEASE_DIR:-$DIST_ROOT/wedecent-windows-amd64}"
if [[ "$RELEASE_DIR" != /* ]]; then
  RELEASE_DIR="$ROOT/$RELEASE_DIR"
fi
case "$RELEASE_DIR" in
  *"/../"*|*/..|*"/./"*|*/.) fail "release input path contains a non-canonical component" ;;
esac
[[ -d "$RELEASE_DIR" && ! -L "$RELEASE_DIR" ]] || fail "release input must be a regular directory"
[[ "$(cd "$RELEASE_DIR" && pwd -P)" == "$RELEASE_DIR" ]] || fail "release input path contains a symlink component"

OUT_DIR="${OUT_DIR:-$DIST_ROOT/wedecent-windows-installer}"
if [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$ROOT/$OUT_DIR"
fi
OUT_PARENT="$(dirname -- "$OUT_DIR")"
OUT_NAME="$(basename -- "$OUT_DIR")"
[[ -n "$OUT_NAME" && "$OUT_NAME" != "." && "$OUT_NAME" != ".." ]] || fail "unsafe installer output path"
[[ -d "$OUT_PARENT" && ! -L "$OUT_PARENT" ]] || fail "installer output parent must exist and must not be a symlink"
case "$OUT_PARENT" in
  *"/../"*|*/..|*"/./"*|*/.) fail "installer output path contains a non-canonical component" ;;
esac
[[ "$(cd "$OUT_PARENT" && pwd -P)" == "$OUT_PARENT" ]] || fail "installer output path contains a symlink component"
case "$OUT_PARENT" in
  "$DIST_ROOT"|"$DIST_ROOT"/*) ;;
  *) fail "installer output must remain inside canonical $DIST_ROOT" ;;
esac
OUT_DIR="$OUT_PARENT/$OUT_NAME"
[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] || fail "installer output already exists; refusing to overwrite: $OUT_DIR"
case "$OUT_DIR" in
  "$RELEASE_DIR"|"$RELEASE_DIR"/*) fail "installer output must not contain or replace the release input" ;;
esac
case "$RELEASE_DIR" in
  "$OUT_DIR"|"$OUT_DIR"/*) fail "installer output must not contain or replace the release input" ;;
esac

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
[[ -f "$RELEASE_DIR/VERSION.txt" && ! -L "$RELEASE_DIR/VERSION.txt" ]] || fail "release VERSION.txt is missing or is a symlink"
[[ -f "$RELEASE_DIR/SHA256SUMS.txt" && ! -L "$RELEASE_DIR/SHA256SUMS.txt" ]] || fail "release SHA256SUMS.txt is missing or is a symlink"
for name in "${binaries[@]}"; do
  [[ -f "$RELEASE_DIR/$name" && ! -L "$RELEASE_DIR/$name" ]] || fail "release binary is missing or is a symlink: $name"
done
(
  cd "$RELEASE_DIR"
  sha256sum -c SHA256SUMS.txt
) || fail "release bundle checksum verification failed"

[[ -d "$ROOT/installer" && ! -L "$ROOT/installer" ]] || fail "installer assets directory must not be a symlink"
[[ -d "$ROOT/installer/windows" && ! -L "$ROOT/installer/windows" ]] || fail "Windows installer assets directory must not be a symlink"
[[ "$(cd "$ROOT/installer/windows" && pwd -P)" == "$ROOT/installer/windows" ]] || fail "Windows installer assets path contains a symlink component"
installer_files=(install.ps1 uninstall.ps1 hardware-diagnostics.ps1)
for name in "${installer_files[@]}"; do
  [[ -f "$ROOT/installer/windows/$name" && ! -L "$ROOT/installer/windows/$name" ]] ||
    fail "installer asset is missing or is a symlink: $name"
done
[[ -f "$ROOT/installer/README.windows.md" && ! -L "$ROOT/installer/README.windows.md" ]] ||
  fail "Windows installer README is missing or is a symlink"

STAGE="$(mktemp -d "$OUT_PARENT/.wedecent-installer.XXXXXX")" || fail "cannot create installer staging directory"
cleanup() {
  if [[ -n "${STAGE:-}" ]]; then
    case "$STAGE" in
      "$OUT_PARENT"/.wedecent-installer.*)
        [[ ! -L "$STAGE" ]] && rm -rf -- "$STAGE"
        ;;
      *)
        printf 'build-windows-installer-package: refusing to clean an unrecognized staging path: %s\n' "$STAGE" >&2
        ;;
    esac
  fi
}
trap cleanup EXIT
[[ -d "$STAGE" && ! -L "$STAGE" ]] || fail "installer staging path is not a regular directory"

for name in "${binaries[@]}" VERSION.txt SHA256SUMS.txt; do
  cp -- "$RELEASE_DIR/$name" "$STAGE/$name"
done
for name in "${installer_files[@]}"; do
  cp -- "$ROOT/installer/windows/$name" "$STAGE/$name"
done
cat "$ROOT/installer/README.windows.md" > "$STAGE/README.txt"

(
  cd "$STAGE"
  sha256sum "${binaries[@]}" VERSION.txt SHA256SUMS.txt "${installer_files[@]}" README.txt > PACKAGE_SHA256SUMS.txt
  sha256sum -c PACKAGE_SHA256SUMS.txt
) || fail "installer package checksum verification failed"

[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] || fail "installer output appeared during build; refusing publication"
[[ -d "$STAGE" && ! -L "$STAGE" ]] || fail "installer staging directory changed before publication"
mv -- "$STAGE" "$OUT_DIR" || fail "atomic installer package publication failed"
STAGE=""
trap - EXIT

printf 'Built WeDecent Windows installer package:\n  %s\n' "$OUT_DIR"
