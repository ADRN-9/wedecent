#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-windows-public-installer: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/release-trust.sh"
TEST_REPLAY_HOSTNAME='replay.example.test'
TEST_REPLAY_PINS='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
TEST_REPLAY_APPROVAL="$(wedecent_replay_authority_approval_digest "$TEST_REPLAY_HOSTNAME" "$TEST_REPLAY_PINS")"
TEST_SOURCE_SHA="${GITHUB_SHA:-$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')}"
TEST_TREE_SHA="$(git -C "$ROOT" rev-parse --verify "${TEST_SOURCE_SHA}^{tree}")"
export GITHUB_ACTIONS=true
export GITHUB_REPOSITORY='ADRN-9/wedecent'
export GITHUB_SHA="$TEST_SOURCE_SHA"
export GITHUB_REF_TYPE=tag
export GITHUB_REF_NAME='v0.4.0'
export WEDECENT_PRODUCTION_RELEASE_APPROVED=true
export WEDECENT_REPLAY_AUTHORITY_HOSTNAME="$TEST_REPLAY_HOSTNAME"
export WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256="$TEST_REPLAY_PINS"
export WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256="$TEST_REPLAY_APPROVAL"
export WEDECENT_EXPECTED_SOURCE_SHA="$TEST_SOURCE_SHA"
PREPARE="$ROOT/scripts/prepare-windows-public-installer.sh"
VERIFY="$ROOT/scripts/verify-public-windows-download.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
RELEASE="$WORK/release"
INSTALLER="$WORK/installer"
PUBLIC="$WORK/public"
PUBLIC_SECOND="$WORK/public-second"
BIN="$WORK/bin"
mkdir -p -- "$RELEASE" "$INSTALLER" "$BIN"

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
scripts=(Install-WeDecent.ps1 Uninstall-WeDecent.ps1 Test-WeDecentInstall.ps1)
for name in "${binaries[@]}"; do
  printf 'signed fixture: %s\n%s\n%s\nWEDECENT_FAKE_AUTHENTICODE_SIGNATURE\n' "$name" "$TEST_REPLAY_HOSTNAME" "$TEST_REPLAY_PINS" > "$RELEASE/$name"
done
cat > "$RELEASE/VERSION.txt" <<EOF_VERSION
version=0.4.0
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
(
  cd "$RELEASE"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > SHA256SUMS.txt
)

for name in "${binaries[@]}" VERSION.txt SHA256SUMS.txt; do
  cp -- "$RELEASE/$name" "$INSTALLER/$name"
done
for name in "${scripts[@]}"; do
  printf 'signed installer fixture: %s\nWEDECENT_FAKE_AUTHENTICODE_SIGNATURE\n' "$name" > "$INSTALLER/$name"
done
printf 'WeDecent signed installer fixture.\n' > "$INSTALLER/README.md"
(
  cd "$INSTALLER"
  sha256sum \
    "${binaries[@]}" VERSION.txt SHA256SUMS.txt \
    "${scripts[@]}" README.md \
    | LC_ALL=C sort -k2 > PACKAGE_SHA256SUMS.txt
)

VERIFIER="$WORK/verifier"
cat > "$VERIFIER" <<'EOF_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || exit 64
[[ -f "$1" && ! -L "$1" ]] || exit 65
if [[ -n "${WEDECENT_FAKE_VERIFIER_REJECT_BASENAME:-}" && "$(basename -- "$1")" == "$WEDECENT_FAKE_VERIFIER_REJECT_BASENAME" ]]; then
  exit 66
fi
[[ "$(tail -n 1 -- "$1")" == 'WEDECENT_FAKE_AUTHENTICODE_SIGNATURE' ]]
EOF_VERIFIER
chmod 0700 "$VERIFIER"

cp "$RELEASE/VERSION.txt" "$WORK/VERSION.production"
sed 's/^build_mode=production$/build_mode=diagnostic/' "$WORK/VERSION.production" > "$RELEASE/VERSION.txt"
cp "$RELEASE/VERSION.txt" "$INSTALLER/VERSION.txt"
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.4.0 --signed-release "$RELEASE" --signed-installer "$INSTALLER" \
   --out-dir "$WORK/diagnostic-output" >/dev/null 2>&1; then
  fail 'installer preparation accepted a diagnostic artifact'
fi
[[ ! -e "$WORK/diagnostic-output" ]] || fail 'diagnostic installer preparation published output'
mv "$WORK/VERSION.production" "$RELEASE/VERSION.txt"
cp "$RELEASE/VERSION.txt" "$INSTALLER/VERSION.txt"

if env -u WEDECENT_REPLAY_AUTHORITY_HOSTNAME -u WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256 \
   -u WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256 WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.4.0 --signed-release "$RELEASE" --signed-installer "$INSTALLER" \
   --out-dir "$WORK/missing-anchor-output" >/dev/null 2>&1; then
  fail 'installer preparation accepted missing production trust anchors'
fi
[[ ! -e "$WORK/missing-anchor-output" ]] || fail 'missing-anchor installer preparation published output'

WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
  "$PREPARE" \
    --version v0.4.0 \
    --signed-release "$RELEASE" \
    --signed-installer "$INSTALLER" \
    --out-dir "$PUBLIC" >/dev/null
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
  "$PREPARE" \
    --version v0.4.0 \
    --signed-release "$RELEASE" \
    --signed-installer "$INSTALLER" \
    --out-dir "$PUBLIC_SECOND" >/dev/null

ARCHIVE='wedecent-v0.4.0-windows-installer.zip'
cmp -s "$PUBLIC/$ARCHIVE" "$PUBLIC_SECOND/$ARCHIVE" || fail 'installer archive is not deterministic'
cmp -s "$PUBLIC/INSTALLER_SHA256SUMS.txt" "$PUBLIC_SECOND/INSTALLER_SHA256SUMS.txt" || fail 'installer public checksum manifest is not deterministic'

CURL_LOG="$WORK/curl.log"
cat > "$BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$WEDECENT_FAKE_CURL_LOG"
out=''
url=''
while (($#)); do
  case "$1" in
    -o)
      out="$2"
      shift 2
      ;;
    --retry)
      shift 2
      ;;
    --retry-all-errors|-f|-s|-S|-L|-fsS|-fsSL)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done
[[ -n "$out" && -n "$url" ]] || exit 64
case "$url" in
  */INSTALLER_SHA256SUMS.txt) cp -- "$WEDECENT_FAKE_PUBLIC_DIR/INSTALLER_SHA256SUMS.txt" "$out" ;;
  */wedecent-v0.4.0-windows-installer.zip) cp -- "$WEDECENT_FAKE_PUBLIC_DIR/wedecent-v0.4.0-windows-installer.zip" "$out" ;;
  *) exit 22 ;;
esac
EOF_CURL
chmod 0700 "$BIN/curl"

run_verify() {
  PATH="$BIN:$PATH" \
  WEDECENT_FAKE_CURL_LOG="$CURL_LOG" \
  WEDECENT_FAKE_PUBLIC_DIR="$PUBLIC" \
    "$VERIFY" --version v0.4.0 --installer --base-url https://example.invalid
}

: > "$CURL_LOG"
output="$(run_verify)"
grep -Fq 'Artifact:     installer' <<<"$output" || fail 'installer verification did not report artifact type'
grep -Fq 'Authenticode: not requested' <<<"$output" || fail 'integrity-only installer verification did not report signature status'
[[ "$(wc -l < "$CURL_LOG" | tr -d '[:space:]')" == '2' ]] || fail 'installer verifier should download exactly manifest and archive'

: > "$CURL_LOG"
output="$(WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" run_verify)"
grep -Fq 'Authenticode: verified' <<<"$output" || fail 'installer Authenticode verification did not report success'

: > "$CURL_LOG"
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_VERIFIER_REJECT_BASENAME='Install-WeDecent.ps1' \
   run_verify >/dev/null 2>&1; then
  fail 'rejected installer script signature unexpectedly succeeded'
fi
[[ "$(wc -l < "$CURL_LOG" | tr -d '[:space:]')" == '2' ]] || fail 'signature failure used unexpected network requests'

cp -- "$PUBLIC/$ARCHIVE" "$WORK/installer.good.zip"
python3 - "$PUBLIC/$ARCHIVE" "$WORK/installer.bad.zip" <<'PY'
import pathlib
import sys
import zipfile
source = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
with zipfile.ZipFile(source, 'r') as src, zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_STORED) as dst:
    for info in src.infolist():
        data = src.read(info)
        if info.filename == 'PACKAGE_SHA256SUMS.txt':
            data += b'\n'
        dst.writestr(info, data)
PY
mv -- "$WORK/installer.bad.zip" "$PUBLIC/$ARCHIVE"
(
  cd "$PUBLIC"
  sha256sum "$ARCHIVE" > INSTALLER_SHA256SUMS.txt
)
if run_verify >/dev/null 2>&1; then
  fail 'tampered internal installer package manifest was accepted'
fi
mv -- "$WORK/installer.good.zip" "$PUBLIC/$ARCHIVE"
(
  cd "$PUBLIC"
  sha256sum "$ARCHIVE" > INSTALLER_SHA256SUMS.txt
)

cp -- "$INSTALLER/wd-core.exe" "$WORK/wd-core.good"
printf 'different signed bytes\n%s\n%s\nWEDECENT_FAKE_AUTHENTICODE_SIGNATURE\n' "$TEST_REPLAY_HOSTNAME" "$TEST_REPLAY_PINS" > "$INSTALLER/wd-core.exe"
(
  cd "$INSTALLER"
  sha256sum \
    "${binaries[@]}" VERSION.txt SHA256SUMS.txt \
    "${scripts[@]}" README.md \
    | LC_ALL=C sort -k2 > PACKAGE_SHA256SUMS.txt
)
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" \
     --version v0.4.0 \
     --signed-release "$RELEASE" \
     --signed-installer "$INSTALLER" \
     --out-dir "$WORK/mismatch-output" >/dev/null 2>&1; then
  fail 'preparer accepted installer release bytes that differ from the signed release'
fi
mv -- "$WORK/wd-core.good" "$INSTALLER/wd-core.exe"

printf 'Public Windows installer preparation and verification verified.\n'
