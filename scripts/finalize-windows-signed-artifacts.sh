#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'finalize-windows-signed-artifacts: %s\n' "$*" >&2
  exit 1
}

for tool in realpath sha256sum cmp cp find sort mktemp mv; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

ROOT="$(realpath -m -- "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)")"
DIST_ROOT="$(realpath -m -- "$ROOT/dist")"
UNSIGNED_RELEASE_DIR="$(realpath -m -- "${UNSIGNED_RELEASE_DIR:-$DIST_ROOT/wedecent-windows-amd64}")"
UNSIGNED_PACKAGE_DIR="$(realpath -m -- "${UNSIGNED_PACKAGE_DIR:-$DIST_ROOT/wedecent-windows-installer}")"
OUT_DIR="$(realpath -m -- "${OUT_DIR:-$DIST_ROOT/wedecent-windows-signed}")"
SIGNER="${WEDECENT_WINDOWS_AUTHENTICODE_SIGNER:-}"
VERIFIER="${WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER:-}"

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
installer_scripts=(Install-WeDecent.ps1 Uninstall-WeDecent.ps1 Test-WeDecentInstall.ps1)
release_files=("${binaries[@]}" VERSION.txt SHA256SUMS.txt)
package_payload=("${binaries[@]}" VERSION.txt SHA256SUMS.txt "${installer_scripts[@]}" README.md)
package_files=("${package_payload[@]}" PACKAGE_SHA256SUMS.txt)

assert_dist_child() {
  local path="$1"
  local label="$2"
  case "$path" in
    "$DIST_ROOT"/*) ;;
    *) fail "$label must be a child of $DIST_ROOT; got $path" ;;
  esac
}

assert_input_dir() {
  local path="$1"
  local label="$2"
  assert_dist_child "$path" "$label"
  [[ -d "$path" && ! -L "$path" ]] || fail "$label is not a regular directory: $path"
}

canonical_hook() {
  local raw="$1"
  local label="$2"
  [[ -n "$raw" ]] || fail "$label is required"
  [[ "$raw" = /* ]] || fail "$label must be an absolute executable path"
  [[ ! -L "$raw" ]] || fail "$label must not be a symlink: $raw"
  local resolved
  resolved="$(realpath -e -- "$raw")" || fail "$label cannot be resolved: $raw"
  [[ -f "$resolved" && -x "$resolved" ]] || fail "$label must resolve to a regular executable file: $resolved"
  case "$resolved" in
    "$UNSIGNED_RELEASE_DIR"/*|"$UNSIGNED_PACKAGE_DIR"/*|"$OUT_DIR"/*)
      fail "$label must not live inside release/package artifact directories: $resolved"
      ;;
  esac
  printf '%s\n' "$resolved"
}

assert_exact_files() {
  local dir="$1"
  local label="$2"
  shift 2
  local expected=("$@")
  local actual expected_text
  actual="$(find "$dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
  expected_text="$(printf '%s\n' "${expected[@]}" | LC_ALL=C sort)"
  [[ "$actual" == "$expected_text" ]] || fail "$label contains an unexpected or missing top-level entry"

  local name
  for name in "${expected[@]}"; do
    [[ -f "$dir/$name" && ! -L "$dir/$name" ]] || fail "$label entry must be a regular non-symlink file: $name"
  done
}

assert_unsigned() {
  local path="$1"
  if "$VERIFIER" "$path" >/dev/null 2>&1; then
    fail "source artifact already satisfies the signature verifier; refusing to re-sign: $path"
  fi
}

sign_and_verify() {
  local path="$1"
  "$SIGNER" "$path" || fail "signer failed for $path"
  [[ -f "$path" && ! -L "$path" ]] || fail "signer did not leave a regular artifact: $path"
  "$VERIFIER" "$path" || fail "signature verification failed for $path"
}

write_release_checksums() {
  local dir="$1"
  local temp
  temp="$(mktemp "$dir/.SHA256SUMS.XXXXXX")"
  (
    cd "$dir"
    sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > "$temp"
  )
  mv -- "$temp" "$dir/SHA256SUMS.txt"
}

write_package_checksums() {
  local dir="$1"
  local temp
  temp="$(mktemp "$dir/.PACKAGE_SHA256SUMS.XXXXXX")"
  (
    cd "$dir"
    sha256sum "${package_payload[@]}" | LC_ALL=C sort -k2 > "$temp"
  )
  mv -- "$temp" "$dir/PACKAGE_SHA256SUMS.txt"
}

assert_input_dir "$UNSIGNED_RELEASE_DIR" "UNSIGNED_RELEASE_DIR"
assert_input_dir "$UNSIGNED_PACKAGE_DIR" "UNSIGNED_PACKAGE_DIR"
assert_dist_child "$OUT_DIR" "OUT_DIR"
[[ "${OUT_DIR%/*}" == "$DIST_ROOT" ]] || fail "OUT_DIR must be a direct child of $DIST_ROOT for atomic publication"
[[ "$UNSIGNED_RELEASE_DIR" != "$UNSIGNED_PACKAGE_DIR" ]] || fail 'unsigned release and package directories must be distinct'
[[ "$OUT_DIR" != "$UNSIGNED_RELEASE_DIR" && "$OUT_DIR" != "$UNSIGNED_PACKAGE_DIR" ]] || fail 'OUT_DIR must be distinct from unsigned inputs'
[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] || fail "OUT_DIR already exists; refusing to overwrite signed output: $OUT_DIR"

SIGNER="$(canonical_hook "$SIGNER" 'WEDECENT_WINDOWS_AUTHENTICODE_SIGNER')"
VERIFIER="$(canonical_hook "$VERIFIER" 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER')"
[[ "$SIGNER" != "$VERIFIER" ]] || fail 'signer and verifier must be distinct executables'

assert_exact_files "$UNSIGNED_RELEASE_DIR" 'unsigned release directory' "${release_files[@]}"
assert_exact_files "$UNSIGNED_PACKAGE_DIR" 'unsigned installer package directory' "${package_files[@]}"

(
  cd "$UNSIGNED_RELEASE_DIR"
  sha256sum -c SHA256SUMS.txt
)
(
  cd "$UNSIGNED_PACKAGE_DIR"
  sha256sum -c SHA256SUMS.txt
  sha256sum -c PACKAGE_SHA256SUMS.txt
)

for name in "${release_files[@]}"; do
  cmp -s -- "$UNSIGNED_RELEASE_DIR/$name" "$UNSIGNED_PACKAGE_DIR/$name" || fail "unsigned package does not match release input: $name"
done

for name in "${binaries[@]}"; do
  assert_unsigned "$UNSIGNED_RELEASE_DIR/$name"
done
for name in "${installer_scripts[@]}"; do
  assert_unsigned "$UNSIGNED_PACKAGE_DIR/$name"
done

TEMP_ROOT="$(mktemp -d "$DIST_ROOT/.wedecent-windows-signed.XXXXXX")"
cleanup() {
  if [[ -n "${TEMP_ROOT:-}" && -d "$TEMP_ROOT" ]]; then
    rm -rf -- "$TEMP_ROOT"
  fi
}
trap cleanup EXIT

SIGNED_RELEASE_DIR="$TEMP_ROOT/release"
SIGNED_PACKAGE_DIR="$TEMP_ROOT/installer"
mkdir -p -- "$SIGNED_RELEASE_DIR" "$SIGNED_PACKAGE_DIR"
for name in "${release_files[@]}"; do
  cp -p -- "$UNSIGNED_RELEASE_DIR/$name" "$SIGNED_RELEASE_DIR/$name"
done
for name in "${package_files[@]}"; do
  cp -p -- "$UNSIGNED_PACKAGE_DIR/$name" "$SIGNED_PACKAGE_DIR/$name"
done

for name in "${binaries[@]}"; do
  sign_and_verify "$SIGNED_RELEASE_DIR/$name"
done
write_release_checksums "$SIGNED_RELEASE_DIR"

for name in "${release_files[@]}"; do
  cp -p -- "$SIGNED_RELEASE_DIR/$name" "$SIGNED_PACKAGE_DIR/$name"
done
for name in "${installer_scripts[@]}"; do
  sign_and_verify "$SIGNED_PACKAGE_DIR/$name"
done
for name in "${binaries[@]}"; do
  "$VERIFIER" "$SIGNED_PACKAGE_DIR/$name" || fail "signature verification failed for packaged binary $name"
done
write_package_checksums "$SIGNED_PACKAGE_DIR"

(
  cd "$SIGNED_RELEASE_DIR"
  sha256sum -c SHA256SUMS.txt
)
(
  cd "$SIGNED_PACKAGE_DIR"
  sha256sum -c SHA256SUMS.txt
  sha256sum -c PACKAGE_SHA256SUMS.txt
)
for name in "${binaries[@]}"; do
  cmp -s -- "$SIGNED_RELEASE_DIR/$name" "$SIGNED_PACKAGE_DIR/$name" || fail "signed package binary differs from signed release: $name"
  "$VERIFIER" "$SIGNED_RELEASE_DIR/$name" || fail "final signature verification failed for release binary $name"
  "$VERIFIER" "$SIGNED_PACKAGE_DIR/$name" || fail "final signature verification failed for packaged binary $name"
done
for name in "${installer_scripts[@]}"; do
  "$VERIFIER" "$SIGNED_PACKAGE_DIR/$name" || fail "final signature verification failed for installer script $name"
done

assert_exact_files "$SIGNED_RELEASE_DIR" 'signed release directory' "${release_files[@]}"
assert_exact_files "$SIGNED_PACKAGE_DIR" 'signed installer package directory' "${package_files[@]}"

mv -- "$TEMP_ROOT" "$OUT_DIR"
TEMP_ROOT=''
trap - EXIT

printf 'Finalized signed Windows artifacts:\n  release:   %s\n  installer: %s\n' "$OUT_DIR/release" "$OUT_DIR/installer"
