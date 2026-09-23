#!/usr/bin/env bash
set -euo pipefail

BASE_URL="https://downloads.wedecent.com"
VERSION=""
AUTHENTICODE_VERIFIER="${WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER:-}"

usage() {
  cat <<'EOF'
Usage:
  verify-public-windows-download.sh --version VERSION [--base-url URL]

Example:
  verify-public-windows-download.sh --version v0.4.0

The verifier always checks the public ZIP checksum, exact seven-file archive shape,
internal five-binary checksum manifest, and VERSION.txt. If
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER is set, it must be an absolute non-symlink
executable and all five extracted Windows binaries must pass that verifier too.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die '--version requires a value'
      VERSION="$2"
      shift 2
      ;;
    --base-url)
      (($# >= 2)) || die '--base-url requires a value'
      BASE_URL="${2%/}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$VERSION" ]] || die '--version is required'
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  die 'version must look like v0.3.0 or v0.3.0-rc.3'
[[ "$BASE_URL" == https://* ]] || die '--base-url must use https://'

for command in curl sha256sum awk mktemp python3 realpath rm wc tr; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

if [[ -n "$AUTHENTICODE_VERIFIER" ]]; then
  [[ "$AUTHENTICODE_VERIFIER" = /* ]] || die 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must be an absolute executable path'
  [[ ! -L "$AUTHENTICODE_VERIFIER" ]] || die 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must not be a symlink'
  AUTHENTICODE_VERIFIER="$(realpath -e -- "$AUTHENTICODE_VERIFIER")" || die 'cannot resolve Authenticode verifier'
  [[ -f "$AUTHENTICODE_VERIFIER" && -x "$AUTHENTICODE_VERIFIER" ]] || die 'Authenticode verifier must be a regular executable file'
fi

ARCHIVE="wedecent-${VERSION}-windows-amd64.zip"
PREFIX="windows/${VERSION}"
ARCHIVE_URL="${BASE_URL}/${PREFIX}/${ARCHIVE}"
SUMS_URL="${BASE_URL}/${PREFIX}/SHA256SUMS.txt"

tmpdir="$(mktemp -d)"
trap 'rm -rf -- "$tmpdir"' EXIT
PUBLIC_SUMS="$tmpdir/public-SHA256SUMS.txt"
ARCHIVE_PATH="$tmpdir/$ARCHIVE"
EXTRACTED="$tmpdir/extracted"

curl -fsS --retry 3 --retry-all-errors "$SUMS_URL" -o "$PUBLIC_SUMS"
line_count="$(wc -l < "$PUBLIC_SUMS" | tr -d '[:space:]')"
[[ "$line_count" == '1' ]] || die 'public checksum manifest must contain exactly one line'
expected="$(
  awk -v file="$ARCHIVE" '
    NR == 1 && $1 ~ /^[0-9A-Fa-f]{64}$/ && $2 == file && NF == 2 {
      print tolower($1)
      count++
    }
    END {
      if (count != 1) exit 1
    }
  ' "$PUBLIC_SUMS"
)" || die "checksum manifest must contain exactly one SHA-256 entry for $ARCHIVE"

curl -fsSL --retry 3 --retry-all-errors "$ARCHIVE_URL" -o "$ARCHIVE_PATH"
[[ -f "$ARCHIVE_PATH" && ! -L "$ARCHIVE_PATH" ]] || die 'public archive download is missing or invalid'
actual="$(sha256sum "$ARCHIVE_PATH" | awk '{print tolower($1)}')"
[[ "$actual" == "$expected" ]] ||
  die "public archive SHA-256 mismatch: expected $expected, got $actual"

mkdir -p -- "$EXTRACTED"
python3 - "$ARCHIVE_PATH" "$EXTRACTED" "$VERSION" <<'PY'
import hashlib
import pathlib
import re
import sys
import zipfile

archive = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
version = sys.argv[3]
binaries = ["wd.exe", "wd-agent.exe", "wd-routerctl.exe", "wd-core.exe", "wd-ui.exe"]
expected = sorted(binaries + ["VERSION.txt", "SHA256SUMS.txt"])

with zipfile.ZipFile(archive, "r") as zf:
    infos = zf.infolist()
    names = [info.filename for info in infos]
    if sorted(names) != expected or len(names) != len(expected) or len(set(names)) != len(names):
        raise SystemExit("public archive must contain exactly the seven signed release files")
    for info in infos:
        if info.is_dir() or "/" in info.filename or "\\" in info.filename:
            raise SystemExit(f"invalid archive member path: {info.filename}")
        data = zf.read(info)
        (out / info.filename).write_bytes(data)

version_lines = [line for line in (out / "VERSION.txt").read_text(encoding="utf-8").splitlines() if line.startswith("version=")]
if version_lines != [f"version={version.removeprefix('v')}"]:
    raise SystemExit("VERSION.txt does not match requested public version")

manifest_lines = (out / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
if len(manifest_lines) != len(binaries):
    raise SystemExit("internal SHA256SUMS.txt must contain exactly five entries")
parsed = {}
pattern = re.compile(r"^([0-9A-Fa-f]{64})  ([A-Za-z0-9_.-]+)$")
for line in manifest_lines:
    match = pattern.fullmatch(line)
    if not match:
        raise SystemExit("malformed internal SHA256SUMS.txt entry")
    digest, name = match.groups()
    if name not in binaries or name in parsed:
        raise SystemExit("internal SHA256SUMS.txt contains an unexpected or duplicate file")
    parsed[name] = digest.lower()
if sorted(parsed) != sorted(binaries):
    raise SystemExit("internal SHA256SUMS.txt does not cover all five binaries")
for name in binaries:
    actual = hashlib.sha256((out / name).read_bytes()).hexdigest()
    if actual != parsed[name]:
        raise SystemExit(f"internal checksum mismatch: {name}")
PY

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
if [[ -n "$AUTHENTICODE_VERIFIER" ]]; then
  for name in "${binaries[@]}"; do
    "$AUTHENTICODE_VERIFIER" "$EXTRACTED/$name" >/dev/null || die "Authenticode verification failed for $name"
  done
  signature_status='verified'
else
  signature_status='not requested'
fi

printf 'Public Windows download verification PASS\n'
printf 'URL:          %s\n' "$ARCHIVE_URL"
printf 'SHA256:       %s\n' "$actual"
printf 'Authenticode: %s\n' "$signature_status"
