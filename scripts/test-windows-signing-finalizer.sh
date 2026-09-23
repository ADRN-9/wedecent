#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-windows-signing-finalizer: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_ROOT="$ROOT/dist"
FINALIZER="$ROOT/scripts/finalize-windows-signed-artifacts.sh"
mkdir -p -- "$DIST_ROOT"
WORK="$(mktemp -d "$DIST_ROOT/.signing-finalizer-test.XXXXXX")"
OUT_DIR="$DIST_ROOT/$(basename "$WORK").signed"
OUT_DIR_2="$DIST_ROOT/$(basename "$WORK").unexpected"
FAILED_OUT="$DIST_ROOT/$(basename "$WORK").failed"
NESTED_OUT="$DIST_ROOT/nested/$(basename "$WORK").signed"
cleanup() {
  rm -rf -- "$WORK" "$OUT_DIR" "$OUT_DIR_2" "$FAILED_OUT" "$DIST_ROOT/nested"
}
trap cleanup EXIT

RELEASE="$WORK/release"
PACKAGE="$WORK/package"
mkdir -p -- "$RELEASE" "$PACKAGE"

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
installer_scripts=(Install-WeDecent.ps1 Uninstall-WeDecent.ps1 Test-WeDecentInstall.ps1)
package_payload=("${binaries[@]}" VERSION.txt SHA256SUMS.txt "${installer_scripts[@]}" README.md)

for name in "${binaries[@]}"; do
  printf 'unsigned fixture: %s\n' "$name" > "$RELEASE/$name"
done
cat > "$RELEASE/VERSION.txt" <<'EOF_VERSION'
version=0.0.0-test
commit=test
built_at=1970-01-01T00:00:00Z
go=test
platform=windows/amd64
EOF_VERSION
OUT_DIR="$RELEASE" "$ROOT/scripts/refresh-windows-release-checksums.sh" >/dev/null
[[ "$(wc -l < "$RELEASE/SHA256SUMS.txt" | tr -d '[:space:]')" == '5' ]] || fail 'checksum refresh did not emit five binary entries'
for name in "${binaries[@]}"; do
  [[ "$(awk -v file="$name" '$2 == file { count++ } END { print count + 0 }' "$RELEASE/SHA256SUMS.txt")" == '1' ]] ||
    fail "checksum refresh did not emit exactly one entry for $name"
done

for name in "${binaries[@]}" VERSION.txt SHA256SUMS.txt; do
  cp -p -- "$RELEASE/$name" "$PACKAGE/$name"
done
for name in "${installer_scripts[@]}"; do
  printf 'Write-Host "unsigned fixture: %s"\n' "$name" > "$PACKAGE/$name"
done
printf 'fixture readme\n' > "$PACKAGE/README.md"
(
  cd "$PACKAGE"
  sha256sum "${package_payload[@]}" | LC_ALL=C sort -k2 > PACKAGE_SHA256SUMS.txt
)

SIGN_LOG="$WORK/sign.log"
SIGNER="$WORK/fake-signer"
VERIFIER="$WORK/fake-verifier"
SIGNER_LINK="$WORK/fake-signer-link"
cat > "$SIGNER" <<'EOF_SIGNER'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || exit 64
[[ -f "$1" && ! -L "$1" ]] || exit 65
printf '\nWEDECENT_FAKE_AUTHENTICODE_SIGNATURE\n' >> "$1"
printf '%s\n' "$1" >> "$WEDECENT_FAKE_SIGN_LOG"
if [[ -n "${WEDECENT_FAKE_SIGN_FAIL_AT:-}" ]]; then
  count="$(wc -l < "$WEDECENT_FAKE_SIGN_LOG" | tr -d '[:space:]')"
  [[ "$count" != "$WEDECENT_FAKE_SIGN_FAIL_AT" ]] || exit 70
fi
EOF_SIGNER
cat > "$VERIFIER" <<'EOF_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || exit 64
[[ -f "$1" && ! -L "$1" ]] || exit 65
[[ "$(tail -n 1 -- "$1")" == 'WEDECENT_FAKE_AUTHENTICODE_SIGNATURE' ]]
EOF_VERIFIER
chmod 0700 "$SIGNER" "$VERIFIER"
ln -s -- "$SIGNER" "$SIGNER_LINK"

snapshot_sources() {
  (
    cd "$WORK"
    sha256sum release/* package/* | LC_ALL=C sort
  )
}
BEFORE="$(snapshot_sources)"

if UNSIGNED_RELEASE_DIR="$RELEASE" \
   UNSIGNED_PACKAGE_DIR="$PACKAGE" \
   OUT_DIR="$OUT_DIR" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER='relative-signer' \
   WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" \
   "$FINALIZER" >/dev/null 2>&1; then
  fail 'relative signer path unexpectedly succeeded'
fi
[[ ! -e "$OUT_DIR" ]] || fail 'failed hook validation published output'
[[ ! -e "$SIGN_LOG" ]] || fail 'failed hook validation invoked the signer'

if UNSIGNED_RELEASE_DIR="$RELEASE" \
   UNSIGNED_PACKAGE_DIR="$PACKAGE" \
   OUT_DIR="$OUT_DIR" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER_LINK" \
   WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" \
   "$FINALIZER" >/dev/null 2>&1; then
  fail 'symlink signer path unexpectedly succeeded'
fi
[[ ! -e "$OUT_DIR" ]] || fail 'symlink hook validation published output'
[[ ! -e "$SIGN_LOG" ]] || fail 'symlink hook validation invoked the signer'

mkdir -p -- "$DIST_ROOT/nested"
if UNSIGNED_RELEASE_DIR="$RELEASE" \
   UNSIGNED_PACKAGE_DIR="$PACKAGE" \
   OUT_DIR="$NESTED_OUT" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER" \
   WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" \
   "$FINALIZER" >/dev/null 2>&1; then
  fail 'nested signed output path unexpectedly succeeded'
fi
[[ ! -e "$NESTED_OUT" ]] || fail 'nested output validation published output'
[[ ! -e "$SIGN_LOG" ]] || fail 'nested output validation invoked the signer'
rm -rf -- "$DIST_ROOT/nested"

if UNSIGNED_RELEASE_DIR="$RELEASE" \
   UNSIGNED_PACKAGE_DIR="$PACKAGE" \
   OUT_DIR="$FAILED_OUT" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER" \
   WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" \
   WEDECENT_FAKE_SIGN_FAIL_AT=3 \
   "$FINALIZER" >/dev/null 2>&1; then
  fail 'intentional signer failure unexpectedly succeeded'
fi
[[ ! -e "$FAILED_OUT" ]] || fail 'failed signer published partial output'
[[ "$(snapshot_sources)" == "$BEFORE" ]] || fail 'failed signer mutated unsigned source artifacts'
[[ "$(wc -l < "$SIGN_LOG" | tr -d '[:space:]')" == '3' ]] || fail 'intentional signer failure did not occur at invocation 3'
rm -f -- "$SIGN_LOG"

UNSIGNED_RELEASE_DIR="$RELEASE" \
UNSIGNED_PACKAGE_DIR="$PACKAGE" \
OUT_DIR="$OUT_DIR" \
WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER" \
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" \
"$FINALIZER" >/dev/null

AFTER="$(snapshot_sources)"
[[ "$BEFORE" == "$AFTER" ]] || fail 'finalizer mutated unsigned source artifacts'
[[ -d "$OUT_DIR/release" && -d "$OUT_DIR/installer" ]] || fail 'signed output tree is incomplete'

sign_count="$(wc -l < "$SIGN_LOG" | tr -d '[:space:]')"
[[ "$sign_count" == '8' ]] || fail "signer invocation count = $sign_count; want 8"

for name in "${binaries[@]}"; do
  "$VERIFIER" "$OUT_DIR/release/$name" || fail "release binary did not verify: $name"
  "$VERIFIER" "$OUT_DIR/installer/$name" || fail "packaged binary did not verify: $name"
  cmp -s -- "$OUT_DIR/release/$name" "$OUT_DIR/installer/$name" || fail "packaged binary differs from release: $name"
done
for name in "${installer_scripts[@]}"; do
  "$VERIFIER" "$OUT_DIR/installer/$name" || fail "installer script did not verify: $name"
done
cmp -s -- "$RELEASE/VERSION.txt" "$OUT_DIR/release/VERSION.txt" || fail 'release metadata changed during signing'
cmp -s -- "$PACKAGE/README.md" "$OUT_DIR/installer/README.md" || fail 'installer README changed during signing'

[[ "$(wc -l < "$OUT_DIR/release/SHA256SUMS.txt" | tr -d '[:space:]')" == '5' ]] || fail 'signed release manifest does not contain five binaries'
(
  cd "$OUT_DIR/release"
  sha256sum -c SHA256SUMS.txt >/dev/null
)
(
  cd "$OUT_DIR/installer"
  sha256sum -c SHA256SUMS.txt >/dev/null
  sha256sum -c PACKAGE_SHA256SUMS.txt >/dev/null
)

if UNSIGNED_RELEASE_DIR="$RELEASE" \
   UNSIGNED_PACKAGE_DIR="$PACKAGE" \
   OUT_DIR="$OUT_DIR" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER" \
   WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" \
   "$FINALIZER" >/dev/null 2>&1; then
  fail 'existing signed output was overwritten'
fi
[[ "$(wc -l < "$SIGN_LOG" | tr -d '[:space:]')" == '8' ]] || fail 'existing-output failure invoked signer'

printf 'unexpected\n' > "$PACKAGE/unexpected.txt"
if UNSIGNED_RELEASE_DIR="$RELEASE" \
   UNSIGNED_PACKAGE_DIR="$PACKAGE" \
   OUT_DIR="$OUT_DIR_2" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER" \
   WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" \
   "$FINALIZER" >/dev/null 2>&1; then
  fail 'unexpected package payload entry was accepted'
fi
[[ ! -e "$OUT_DIR_2" ]] || fail 'invalid package payload published signed output'
[[ "$(wc -l < "$SIGN_LOG" | tr -d '[:space:]')" == '8' ]] || fail 'invalid package payload invoked signer'
rm -f -- "$PACKAGE/unexpected.txt"

printf 'Windows signing finalizer behavior verified.\n'
