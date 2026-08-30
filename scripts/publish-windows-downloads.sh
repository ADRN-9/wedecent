#!/usr/bin/env bash
set -euo pipefail

BUCKET="wedecent-downloads"
BASE_URL="https://downloads.wedecent.com"
VERSION=""
ARCHIVE_PATH=""
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  publish-windows-downloads.sh \
    --version VERSION \
    --archive PATH \
    [--bucket NAME] \
    [--base-url URL] \
    [--dry-run]

The archive must already exist and must be named:
  wedecent-VERSION-windows-amd64.zip

This script never rebuilds release binaries and never overwrites a public version with
different bytes.
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
    --archive)
      (($# >= 2)) || die "--archive requires a value"
      ARCHIVE_PATH="$2"
      shift 2
      ;;
    --bucket)
      (($# >= 2)) || die "--bucket requires a value"
      BUCKET="$2"
      shift 2
      ;;
    --base-url)
      (($# >= 2)) || die "--base-url requires a value"
      BASE_URL="${2%/}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
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
[[ -n "$ARCHIVE_PATH" ]] || die "--archive is required"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  die "version must look like v0.3.0 or v0.3.0-rc.3"
[[ "$BASE_URL" == https://* ]] || die "--base-url must use https://"
[[ -f "$ARCHIVE_PATH" ]] || die "archive not found: $ARCHIVE_PATH"

for command in curl sha256sum awk mktemp basename cmp; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

ARCHIVE="$(basename "$ARCHIVE_PATH")"
EXPECTED_ARCHIVE="wedecent-${VERSION}-windows-amd64.zip"
[[ "$ARCHIVE" == "$EXPECTED_ARCHIVE" ]] ||
  die "archive must be named $EXPECTED_ARCHIVE"

PREFIX="windows/${VERSION}"
ARCHIVE_KEY="${PREFIX}/${ARCHIVE}"
SUMS_KEY="${PREFIX}/SHA256SUMS.txt"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE_KEY}"
SUMS_URL="${BASE_URL}/${SUMS_KEY}"

LOCAL_SHA="$(sha256sum "$ARCHIVE_PATH" | awk '{print tolower($1)}')"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
SUMS_PATH="$tmpdir/SHA256SUMS.txt"
printf '%s  %s\n' "$LOCAL_SHA" "$ARCHIVE" >"$SUMS_PATH"

printf 'Version: %s\n' "$VERSION"
printf 'Archive: %s\n' "$ARCHIVE_PATH"
printf 'SHA256:  %s\n' "$LOCAL_SHA"
printf 'Target:  %s\n' "$ARCHIVE_URL"

remote_archive_state="missing"
if curl -fsSI --retry 2 "$ARCHIVE_URL" >/dev/null 2>&1; then
  remote_sha="$(
    curl -fsSL --retry 3 --retry-all-errors "$ARCHIVE_URL" |
      sha256sum |
      awk '{print tolower($1)}'
  )"
  [[ "$remote_sha" == "$LOCAL_SHA" ]] ||
    die "refusing overwrite: public archive exists with different SHA-256 ($remote_sha)"
  remote_archive_state="identical"
fi

remote_sums_state="missing"
if curl -fsS --retry 2 "$SUMS_URL" -o "$tmpdir/remote-SHA256SUMS.txt" 2>/dev/null; then
  if cmp -s "$SUMS_PATH" "$tmpdir/remote-SHA256SUMS.txt"; then
    remote_sums_state="identical"
  else
    die "refusing overwrite: public SHA256SUMS.txt already exists with different content"
  fi
fi

printf 'Remote archive: %s\n' "$remote_archive_state"
printf 'Remote sums:    %s\n' "$remote_sums_state"

if ((DRY_RUN)); then
  printf 'Dry run: no upload performed.\n'
  exit 0
fi

if [[ "$remote_archive_state" == "missing" || "$remote_sums_state" == "missing" ]]; then
  command -v wrangler >/dev/null 2>&1 ||
    die "wrangler is required for upload; authenticate it separately and retry"
fi

if [[ "$remote_archive_state" == "missing" ]]; then
  wrangler r2 object put "${BUCKET}/${ARCHIVE_KEY}" \
    --file "$ARCHIVE_PATH" \
    --remote \
    --content-type "application/zip" \
    --content-disposition "attachment; filename=\"${ARCHIVE}\"" \
    --cache-control "public, max-age=31536000, immutable"
else
  printf 'Archive already published with identical bytes; skipping upload.\n'
fi

if [[ "$remote_sums_state" == "missing" ]]; then
  wrangler r2 object put "${BUCKET}/${SUMS_KEY}" \
    --file "$SUMS_PATH" \
    --remote \
    --content-type "text/plain; charset=utf-8" \
    --cache-control "public, max-age=31536000, immutable"
else
  printf 'Checksum manifest already published with identical content; skipping upload.\n'
fi

remote_sha="$(
  curl -fsSL --retry 5 --retry-all-errors "$ARCHIVE_URL" |
    sha256sum |
    awk '{print tolower($1)}'
)"
[[ "$remote_sha" == "$LOCAL_SHA" ]] ||
  die "post-upload archive verification failed: expected $LOCAL_SHA, got $remote_sha"

curl -fsS --retry 5 --retry-all-errors "$SUMS_URL" -o "$tmpdir/public-SHA256SUMS.txt"
cmp -s "$SUMS_PATH" "$tmpdir/public-SHA256SUMS.txt" ||
  die "post-upload checksum manifest verification failed"

printf 'Public Windows release publication PASS\n'
printf 'Archive URL: %s\n' "$ARCHIVE_URL"
printf 'SHA256 URL:  %s\n' "$SUMS_URL"
