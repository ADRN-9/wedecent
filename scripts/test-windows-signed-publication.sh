#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-windows-signed-publication: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISH="$ROOT/scripts/publish-windows-downloads.sh"
DIST_ROOT="$ROOT/dist"
mkdir -p -- "$DIST_ROOT"
WORK="$(mktemp -d "$DIST_ROOT/.signed-publication-test.XXXXXX")"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT

RELEASE="$WORK/release"
BIN="$WORK/bin"
REMOTE="$WORK/remote"
mkdir -p -- "$RELEASE" "$BIN" "$REMOTE"
binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
ARCHIVE='wedecent-v0.3.0-rc.9-windows-amd64.zip'
for name in "${binaries[@]}"; do
  printf 'signed fixture: %s\nWEDECENT_FAKE_AUTHENTICODE_SIGNATURE\n' "$name" > "$RELEASE/$name"
done
cat > "$RELEASE/VERSION.txt" <<'EOF_VERSION'
version=0.3.0-rc.9
commit=test
built_at=1970-01-01T00:00:00Z
go=test
platform=windows/amd64
EOF_VERSION
(
  cd "$RELEASE"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > SHA256SUMS.txt
)

VERIFIER="$WORK/verifier"
cat > "$VERIFIER" <<'EOF_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || exit 64
[[ -f "$1" && ! -L "$1" ]] || exit 65
[[ "$(tail -n 1 -- "$1")" == 'WEDECENT_FAKE_AUTHENTICODE_SIGNATURE' ]]
EOF_VERIFIER
chmod 0700 "$VERIFIER"

CURL_LOG="$WORK/curl.log"
cat > "$BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$WEDECENT_FAKE_CURL_LOG"
mode="${WEDECENT_FAKE_CURL_MODE:-normal}"
if [[ "$mode" == 'transport-error' ]]; then
  exit 7
fi
head_request=0
out=''
url=''
while (($#)); do
  case "$1" in
    -I)
      head_request=1
      shift
      ;;
    -o)
      out="$2"
      shift 2
      ;;
    -w|--retry)
      shift 2
      ;;
    --retry-all-errors|-f|-s|-S|-L|-fsS|-fsSL|-sS)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done
[[ -n "$url" ]] || exit 64
case "$url" in
  */"$WEDECENT_FAKE_ARCHIVE") remote="$WEDECENT_FAKE_REMOTE_DIR/$WEDECENT_FAKE_ARCHIVE" ;;
  */SHA256SUMS.txt) remote="$WEDECENT_FAKE_REMOTE_DIR/SHA256SUMS.txt" ;;
  *) exit 22 ;;
esac
if ((head_request)); then
  if [[ "$mode" == 'http500' ]]; then
    printf '500'
  elif [[ -f "$remote" ]]; then
    printf '200'
  else
    printf '404'
  fi
  exit 0
fi
[[ "$mode" != 'http500' ]] || exit 22
[[ -f "$remote" ]] || exit 22
if [[ -n "$out" ]]; then
  cp -- "$remote" "$out"
else
  cat -- "$remote"
fi
EOF_CURL
chmod 0700 "$BIN/curl"

UPLOAD_LOG="$WORK/upload.log"
UPLOADER="$WORK/create-only-uploader"
UPLOADER_LINK="$WORK/create-only-uploader-link"
cat > "$UPLOADER" <<'EOF_UPLOADER'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 6 ]] || exit 64
bucket="$1"
key="$2"
file="$3"
content_type="$4"
content_disposition="$5"
cache_control="$6"
[[ -n "$bucket" && -n "$key" && -f "$file" ]] || exit 65
printf '%s\t%s\t%s\t%s\t%s\n' "$bucket" "$key" "$content_type" "$content_disposition" "$cache_control" >> "$WEDECENT_FAKE_UPLOAD_LOG"
case "$key" in
  */"$WEDECENT_FAKE_ARCHIVE") dest="$WEDECENT_FAKE_REMOTE_DIR/$WEDECENT_FAKE_ARCHIVE" ;;
  */SHA256SUMS.txt) dest="$WEDECENT_FAKE_REMOTE_DIR/SHA256SUMS.txt" ;;
  *) exit 66 ;;
esac
if [[ "${WEDECENT_FAKE_UPLOAD_MODE:-normal}" == 'conflict' ]]; then
  (set -o noclobber; printf 'concurrent different bytes\n' > "$dest") 2>/dev/null || true
  exit 73
fi
(set -o noclobber; cat -- "$file" > "$dest") 2>/dev/null || exit 73
EOF_UPLOADER
chmod 0700 "$UPLOADER"
ln -s -- "$UPLOADER" "$UPLOADER_LINK"

common_env=(
  "PATH=$BIN:$PATH"
  "WEDECENT_FAKE_CURL_LOG=$CURL_LOG"
  "WEDECENT_FAKE_REMOTE_DIR=$REMOTE"
  "WEDECENT_FAKE_ARCHIVE=$ARCHIVE"
  "WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER=$VERIFIER"
)

run_publish() {
  local -a extra_env=()
  while (($#)) && [[ "$1" == *=* ]]; do
    extra_env+=("$1")
    shift
  done
  env "${common_env[@]}" "${extra_env[@]}" "$PUBLISH" \
    --version v0.3.0-rc.9 \
    --signed-release "$RELEASE" \
    --base-url https://example.invalid \
    "$@"
}

OUTPUT="$WORK/output.txt"
: > "$CURL_LOG"
run_publish WEDECENT_FAKE_CURL_MODE=normal --dry-run > "$OUTPUT"
grep -Fq 'Dry run: signed release verified; no upload performed.' "$OUTPUT" ||
  fail 'publisher did not report signed dry-run success'
[[ "$(wc -l < "$CURL_LOG" | tr -d '[:space:]')" == '2' ]] ||
  fail 'absent-object dry-run should perform exactly two remote-state probes'

for failure_mode in http500 transport-error; do
  : > "$CURL_LOG"
  if run_publish WEDECENT_FAKE_CURL_MODE="$failure_mode" --dry-run >/dev/null 2>&1; then
    fail "ambiguous public-state mode unexpectedly succeeded: $failure_mode"
  fi
  [[ "$(wc -l < "$CURL_LOG" | tr -d '[:space:]')" == '1' ]] ||
    fail "ambiguous public-state mode did not abort at first probe: $failure_mode"
done

if run_publish WEDECENT_FAKE_CURL_MODE=normal --archive "$WORK/arbitrary.zip" --dry-run >/dev/null 2>&1; then
  fail 'legacy arbitrary --archive input unexpectedly succeeded'
fi

: > "$CURL_LOG"
cp -- "$RELEASE/wd-ui.exe" "$WORK/wd-ui.good"
printf 'not signed\n' > "$RELEASE/wd-ui.exe"
(
  cd "$RELEASE"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > SHA256SUMS.txt
)
if run_publish WEDECENT_FAKE_CURL_MODE=normal --dry-run >/dev/null 2>&1; then
  fail 'publisher accepted a release with an invalid signature'
fi
[[ ! -s "$CURL_LOG" ]] || fail 'publisher performed a network check before rejecting invalid signatures'
mv -- "$WORK/wd-ui.good" "$RELEASE/wd-ui.exe"
(
  cd "$RELEASE"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > SHA256SUMS.txt
)

rm -f -- "$REMOTE"/* "$UPLOAD_LOG"
: > "$CURL_LOG"
if run_publish WEDECENT_FAKE_CURL_MODE=normal >/dev/null 2>&1; then
  fail 'missing public objects unexpectedly published without create-only uploader'
fi
[[ ! -s "$UPLOAD_LOG" ]] || fail 'missing-uploader failure invoked an uploader'
[[ ! -e "$REMOTE/$ARCHIVE" && ! -e "$REMOTE/SHA256SUMS.txt" ]] || fail 'missing-uploader failure changed remote fixtures'

for bad_uploader in relative-uploader "$UPLOADER_LINK"; do
  rm -f -- "$REMOTE"/* "$UPLOAD_LOG"
  if run_publish WEDECENT_FAKE_CURL_MODE=normal WEDECENT_R2_CREATE_ONLY_UPLOADER="$bad_uploader" >/dev/null 2>&1; then
    fail "invalid create-only uploader unexpectedly succeeded: $bad_uploader"
  fi
  [[ ! -s "$UPLOAD_LOG" ]] || fail 'invalid uploader path invoked uploader'
  [[ ! -e "$REMOTE/$ARCHIVE" && ! -e "$REMOTE/SHA256SUMS.txt" ]] || fail 'invalid uploader path changed remote fixtures'
done

rm -f -- "$REMOTE"/* "$UPLOAD_LOG"
: > "$CURL_LOG"
run_publish \
  WEDECENT_FAKE_CURL_MODE=normal \
  WEDECENT_R2_CREATE_ONLY_UPLOADER="$UPLOADER" \
  WEDECENT_FAKE_UPLOAD_LOG="$UPLOAD_LOG" >/dev/null
[[ "$(wc -l < "$UPLOAD_LOG" | tr -d '[:space:]')" == '2' ]] || fail 'publisher did not create exactly two missing public objects'
[[ -f "$REMOTE/$ARCHIVE" && -f "$REMOTE/SHA256SUMS.txt" ]] || fail 'create-only publication did not produce both public objects'
(
  cd "$REMOTE"
  sha256sum -c SHA256SUMS.txt >/dev/null
) || fail 'published remote fixtures do not match public checksum manifest'
grep -Fq $'application/zip\tattachment; filename="'"$ARCHIVE"$'"\tpublic, max-age=31536000, immutable' "$UPLOAD_LOG" ||
  fail 'archive upload metadata was not passed to create-only uploader'
grep -Fq $'text/plain; charset=utf-8\t\tpublic, max-age=31536000, immutable' "$UPLOAD_LOG" ||
  fail 'checksum upload metadata was not passed to create-only uploader'

upload_count="$(wc -l < "$UPLOAD_LOG" | tr -d '[:space:]')"
run_publish WEDECENT_FAKE_CURL_MODE=normal >/dev/null
[[ "$(wc -l < "$UPLOAD_LOG" | tr -d '[:space:]')" == "$upload_count" ]] || fail 'identical existing publication invoked uploader'

rm -f -- "$REMOTE"/* "$UPLOAD_LOG"
if run_publish \
   WEDECENT_FAKE_CURL_MODE=normal \
   WEDECENT_R2_CREATE_ONLY_UPLOADER="$UPLOADER" \
   WEDECENT_FAKE_UPLOAD_LOG="$UPLOAD_LOG" \
   WEDECENT_FAKE_UPLOAD_MODE=conflict >/dev/null 2>&1; then
  fail 'concurrent create-only conflict unexpectedly succeeded'
fi
[[ "$(wc -l < "$UPLOAD_LOG" | tr -d '[:space:]')" == '1' ]] || fail 'concurrent conflict should stop after first uploader failure'
[[ "$(cat "$REMOTE/$ARCHIVE")" == 'concurrent different bytes' ]] || fail 'publisher overwrote concurrent object after create-only conflict'
[[ ! -e "$REMOTE/SHA256SUMS.txt" ]] || fail 'publisher continued after create-only archive conflict'

printf 'Windows signed-publication boundary verified.\n'
