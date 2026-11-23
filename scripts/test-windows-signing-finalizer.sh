#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-windows-signing-finalizer: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/release-trust.sh"
source "$ROOT/scripts/testlib/release-tag-fixture.sh"
TEST_REPLAY_HOSTNAME='replay.example.test'
TEST_REPLAY_PINS='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
TEST_REPLAY_APPROVAL="$(wedecent_replay_authority_approval_digest "$TEST_REPLAY_HOSTNAME" "$TEST_REPLAY_PINS")"
TEST_SOURCE_SHA="${GITHUB_SHA:-$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')}"
TEST_TREE_SHA="$(git -C "$ROOT" rev-parse --verify "${TEST_SOURCE_SHA}^{tree}")"
export GITHUB_ACTIONS=true
export GITHUB_REPOSITORY='ADRN-9/wedecent'
export GITHUB_SHA="$TEST_SOURCE_SHA"
export GITHUB_REF_TYPE=tag
export GITHUB_REF_NAME='v0.0.0-test'
export WEDECENT_PRODUCTION_RELEASE_APPROVED=true
export WEDECENT_REPLAY_AUTHORITY_HOSTNAME="$TEST_REPLAY_HOSTNAME"
export WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256="$TEST_REPLAY_PINS"
export WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256="$TEST_REPLAY_APPROVAL"
export WEDECENT_EXPECTED_SOURCE_SHA="$TEST_SOURCE_SHA"
DIST_ROOT="$ROOT/dist"
FINALIZER="$ROOT/scripts/finalize-windows-signed-artifacts.sh"
mkdir -p -- "$DIST_ROOT"
WORK="$(mktemp -d "$DIST_ROOT/.signing-finalizer-test.XXXXXX")"
wedecent_test_release_tags_init "$ROOT" "$WORK"
wedecent_test_release_tag_add "$GITHUB_REF_NAME" "$TEST_SOURCE_SHA"
OUT_DIR="$DIST_ROOT/$(basename "$WORK").signed"
OUT_DIR_2="$DIST_ROOT/$(basename "$WORK").unexpected"
FAILED_OUT="$DIST_ROOT/$(basename "$WORK").failed"
NESTED_OUT="$DIST_ROOT/nested/$(basename "$WORK").signed"
cleanup() {
  wedecent_test_release_tags_cleanup
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
  printf 'unsigned fixture: %s\n%s\n%s\n' "$name" "$TEST_REPLAY_HOSTNAME" "$TEST_REPLAY_PINS" > "$RELEASE/$name"
done
cat > "$RELEASE/VERSION.txt" <<EOF_VERSION
version=0.0.0-test
commit=$TEST_SOURCE_SHA
source_commit=$TEST_SOURCE_SHA
source_tree=$TEST_TREE_SHA
built_at=1970-01-01T00:00:00Z
go=go1.27.0
platform=windows/amd64
build_mode=production
replay_authority_hostname=$TEST_REPLAY_HOSTNAME
replay_authority_spki_sha256=$TEST_REPLAY_PINS
replay_authority_approval_sha256=$TEST_REPLAY_APPROVAL
EOF_VERSION
OUT_DIR="$RELEASE" "$ROOT/scripts/refresh-windows-release-checksums.sh" >/dev/null
[[ "$(wc -l < "$RELEASE/SHA256SUMS.txt" | tr -d '[:space:]')" == '5' ]] || fail 'checksum refresh did not emit five binary entries'

BUILT_PACKAGE="$WORK/built-package"
RELEASE_DIR="$RELEASE" OUT_DIR="$BUILT_PACKAGE" "$ROOT/scripts/build-windows-installer-package.sh" >/dev/null
[[ -f "$BUILT_PACKAGE/README.md" && ! -e "$BUILT_PACKAGE/README.txt" ]] ||
  fail 'installer package builder did not produce the README.md expected by signing and publication'
(
  cd "$BUILT_PACKAGE"
  sha256sum -c PACKAGE_SHA256SUMS.txt >/dev/null
) || fail 'built installer package checksums did not verify'
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

cp "$RELEASE/VERSION.txt" "$WORK/VERSION.production"
sed 's/^build_mode=production$/build_mode=diagnostic/' "$WORK/VERSION.production" > "$RELEASE/VERSION.txt"
if UNSIGNED_RELEASE_DIR="$RELEASE" UNSIGNED_PACKAGE_DIR="$PACKAGE" OUT_DIR="$OUT_DIR" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER" WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" "$FINALIZER" >/dev/null 2>&1; then
  fail 'signing finalizer accepted a diagnostic artifact'
fi
[[ ! -e "$OUT_DIR" && ! -e "$SIGN_LOG" ]] || fail 'diagnostic signing rejection reached signer or published output'
mv "$WORK/VERSION.production" "$RELEASE/VERSION.txt"

if env -u WEDECENT_REPLAY_AUTHORITY_HOSTNAME -u WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256 \
   -u WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256 \
   UNSIGNED_RELEASE_DIR="$RELEASE" UNSIGNED_PACKAGE_DIR="$PACKAGE" OUT_DIR="$OUT_DIR" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER" WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" "$FINALIZER" >/dev/null 2>&1; then
  fail 'signing finalizer accepted missing production trust anchors'
fi
[[ ! -e "$OUT_DIR" && ! -e "$SIGN_LOG" ]] || fail 'missing-anchor rejection reached signer or published output'

cp "$RELEASE/VERSION.txt" "$WORK/VERSION.tree-good"
sed "s/^source_tree=$TEST_TREE_SHA$/source_tree=cccccccccccccccccccccccccccccccccccccccc/" \
  "$WORK/VERSION.tree-good" > "$RELEASE/VERSION.txt"
if UNSIGNED_RELEASE_DIR="$RELEASE" UNSIGNED_PACKAGE_DIR="$PACKAGE" OUT_DIR="$OUT_DIR" \
   WEDECENT_WINDOWS_AUTHENTICODE_SIGNER="$SIGNER" WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_SIGN_LOG="$SIGN_LOG" "$FINALIZER" >/dev/null 2>&1; then
  fail 'signing finalizer accepted forged source-tree metadata'
fi
[[ ! -e "$OUT_DIR" && ! -e "$SIGN_LOG" ]] || fail 'forged source-tree rejection reached signer or published output'
mv "$WORK/VERSION.tree-good" "$RELEASE/VERSION.txt"

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
