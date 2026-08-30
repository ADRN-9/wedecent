#!/usr/bin/env bash
set -euo pipefail

BASE_URL="https://downloads.wedecent.com"
VERSION=""

usage() {
  cat <<'EOF'
Usage:
  verify-public-windows-download.sh --version VERSION [--base-url URL]

Example:
  verify-public-windows-download.sh --version v0.3.0-rc.3
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --base-url)
      (($# >= 2)) || die "--base-url requires a value"
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

[[ -n "$VERSION" ]] || die "--version is required"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  die "version must look like v0.3.0 or v0.3.0-rc.3"
[[ "$BASE_URL" == https://* ]] || die "--base-url must use https://"

for command in curl sha256sum awk mktemp; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

ARCHIVE="wedecent-${VERSION}-windows-amd64.zip"
PREFIX="windows/${VERSION}"
ARCHIVE_URL="${BASE_URL}/${PREFIX}/${ARCHIVE}"
SUMS_URL="${BASE_URL}/${PREFIX}/SHA256SUMS.txt"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

curl -fsS --retry 3 --retry-all-errors "$SUMS_URL" -o "$tmpdir/SHA256SUMS.txt"

expected="$(
  awk -v file="$ARCHIVE" '
    $1 ~ /^[0-9A-Fa-f]{64}$/ && $2 == file {
      print tolower($1)
      count++
    }
    END {
      if (count != 1) exit 1
    }
  ' "$tmpdir/SHA256SUMS.txt"
)" || die "checksum manifest must contain exactly one SHA-256 entry for $ARCHIVE"

actual="$(
  curl -fsSL --retry 3 --retry-all-errors "$ARCHIVE_URL" |
    sha256sum |
    awk '{print tolower($1)}'
)"

[[ "$actual" == "$expected" ]] ||
  die "public archive SHA-256 mismatch: expected $expected, got $actual"

printf 'Public Windows download verification PASS\n'
printf 'URL:    %s\n' "$ARCHIVE_URL"
printf 'SHA256: %s\n' "$actual"
