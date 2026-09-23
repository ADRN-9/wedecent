#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-windows-public-verifier: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREPARE="$ROOT/scripts/prepare-windows-public-download.sh"
VERIFY="$ROOT/scripts/verify-public-windows-download.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
RELEASE="$WORK/release"
PUBLIC="$WORK/public"
BIN="$WORK/bin"
mkdir -p -- "$RELEASE" "$BIN"

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
for name in "${binaries[@]}"; do
  printf 'signed fixture: %s\nWEDECENT_FAKE_AUTHENTICODE_SIGNATURE\n' "$name" > "$RELEASE/$name"
done
cat > "$RELEASE/VERSION.txt" <<'EOF_VERSION'
version=0.4.0
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
if [[ -n "${WEDECENT_FAKE_VERIFIER_REJECT_BASENAME:-}" && "$(basename -- "$1")" == "$WEDECENT_FAKE_VERIFIER_REJECT_BASENAME" ]]; then
  exit 66
fi
[[ "$(tail -n 1 -- "$1")" == 'WEDECENT_FAKE_AUTHENTICODE_SIGNATURE' ]]
EOF_VERIFIER
chmod 0700 "$VERIFIER"

WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
  "$PREPARE" --version v0.4.0 --signed-release "$RELEASE" --out-dir "$PUBLIC" >/dev/null

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
  */SHA256SUMS.txt) cp -- "$WEDECENT_FAKE_PUBLIC_DIR/SHA256SUMS.txt" "$out" ;;
  */wedecent-v0.4.0-windows-amd64.zip) cp -- "$WEDECENT_FAKE_PUBLIC_DIR/wedecent-v0.4.0-windows-amd64.zip" "$out" ;;
  *) exit 22 ;;
esac
EOF_CURL
chmod 0700 "$BIN/curl"

run_verify() {
  PATH="$BIN:$PATH" \
  WEDECENT_FAKE_CURL_LOG="$CURL_LOG" \
  WEDECENT_FAKE_PUBLIC_DIR="$PUBLIC" \
    "$VERIFY" --version v0.4.0 --base-url https://example.invalid
}

: > "$CURL_LOG"
output="$(run_verify)"
grep -Fq 'Authenticode: not requested' <<<"$output" || fail 'integrity-only verification did not report signature status'
[[ "$(wc -l < "$CURL_LOG" | tr -d '[:space:]')" == '2' ]] || fail 'public verifier should download exactly manifest and archive'

: > "$CURL_LOG"
output="$(WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" run_verify)"
grep -Fq 'Authenticode: verified' <<<"$output" || fail 'signature verification did not report success'

: > "$CURL_LOG"
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER='relative-verifier' run_verify >/dev/null 2>&1; then
  fail 'relative Authenticode verifier unexpectedly succeeded'
fi
[[ ! -s "$CURL_LOG" ]] || fail 'invalid verifier path performed network requests'

: > "$CURL_LOG"
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   WEDECENT_FAKE_VERIFIER_REJECT_BASENAME='wd-core.exe' \
   run_verify >/dev/null 2>&1; then
  fail 'rejected Authenticode signature unexpectedly succeeded'
fi
[[ "$(wc -l < "$CURL_LOG" | tr -d '[:space:]')" == '2' ]] || fail 'signature failure used unexpected network requests'

ARCHIVE="$PUBLIC/wedecent-v0.4.0-windows-amd64.zip"
SUMS="$PUBLIC/SHA256SUMS.txt"
printf '%064d  unexpected.zip\n' 0 >> "$SUMS"
if run_verify >/dev/null 2>&1; then
  fail 'public checksum manifest with extra entry was accepted'
fi
(
  cd "$PUBLIC"
  sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS.txt
)

cp -- "$ARCHIVE" "$WORK/archive.good"
printf 'tampered outer archive\n' >> "$ARCHIVE"
: > "$CURL_LOG"
if run_verify >/dev/null 2>&1; then
  fail 'outer ZIP checksum mismatch unexpectedly succeeded'
fi
mv -- "$WORK/archive.good" "$ARCHIVE"

python3 - "$ARCHIVE" "$WORK/archive.bad-shape" <<'PY'
import pathlib, sys, zipfile
source = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
with zipfile.ZipFile(source, 'r') as src, zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_STORED) as dst:
    for info in src.infolist():
        dst.writestr(info, src.read(info))
    dst.writestr('unexpected.txt', b'unexpected\n')
PY
mv -- "$WORK/archive.bad-shape" "$ARCHIVE"
(
  cd "$PUBLIC"
  sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS.txt
)
if run_verify >/dev/null 2>&1; then
  fail 'unexpected archive member was accepted'
fi

printf 'Public Windows archive verifier behavior verified.\n'
