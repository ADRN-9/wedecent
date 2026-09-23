#!/usr/bin/env bash
set -euo pipefail

BUCKET="wedecent-downloads"
BASE_URL="https://downloads.wedecent.com"
VERSION=""
SIGNED_RELEASE_DIR=""
DRY_RUN=0
CREATE_ONLY_UPLOADER="${WEDECENT_R2_CREATE_ONLY_UPLOADER:-}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREPARE="$ROOT/scripts/prepare-windows-public-download.sh"
CACHE_CONTROL='public, max-age=31536000, immutable'

usage() {
  cat <<'EOF'
Usage:
  publish-windows-downloads.sh \
    --version VERSION \
    --signed-release DIR \
    [--bucket NAME] \
    [--base-url URL] \
    [--dry-run]

The signed release must contain the finalized five-binary Windows release. The script
verifies Authenticode through WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER, builds the
canonical archive itself, and never accepts an arbitrary pre-built ZIP.

When a public object is missing, WEDECENT_R2_CREATE_ONLY_UPLOADER must name an absolute,
non-symlink executable. It is invoked as:

  uploader BUCKET KEY FILE CONTENT_TYPE CONTENT_DISPOSITION CACHE_CONTROL

The uploader MUST perform an atomic create-only write and return nonzero if KEY already
exists. For Cloudflare R2, use a conditional PutObject equivalent to If-None-Match: *.
The publisher never falls back to an unconditional write.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

probe_public_object() {
  local url="$1"
  local status
  if ! status="$(curl -sS -I --retry 2 -o /dev/null -w '%{http_code}' "$url")"; then
    die "failed to determine public object state: $url"
  fi
  case "$status" in
    200) printf 'present\n' ;;
    404) printf 'missing\n' ;;
    *) die "refusing ambiguous public object state: HTTP $status for $url" ;;
  esac
}

resolve_create_only_uploader() {
  local path="$CREATE_ONLY_UPLOADER"
  [[ -n "$path" ]] || die 'WEDECENT_R2_CREATE_ONLY_UPLOADER is required when a public object is missing'
  [[ "$path" = /* ]] || die 'WEDECENT_R2_CREATE_ONLY_UPLOADER must be an absolute executable path'
  [[ ! -L "$path" ]] || die 'WEDECENT_R2_CREATE_ONLY_UPLOADER must not be a symlink'
  path="$(realpath -e -- "$path")" || die 'cannot resolve create-only uploader'
  [[ -f "$path" && -x "$path" ]] || die 'create-only uploader must be a regular executable file'
  printf '%s\n' "$path"
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die '--version requires a value'
      VERSION="$2"
      shift 2
      ;;
    --signed-release)
      (($# >= 2)) || die '--signed-release requires a value'
      SIGNED_RELEASE_DIR="$2"
      shift 2
      ;;
    --bucket)
      (($# >= 2)) || die '--bucket requires a value'
      BUCKET="$2"
      shift 2
      ;;
    --base-url)
      (($# >= 2)) || die '--base-url requires a value'
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

[[ -n "$VERSION" ]] || die '--version is required'
[[ -n "$SIGNED_RELEASE_DIR" ]] || die '--signed-release is required'
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  die 'version must look like v0.3.0 or v0.3.0-rc.3'
[[ "$BASE_URL" == https://* ]] || die '--base-url must use https://'
[[ -x "$PREPARE" && ! -L "$PREPARE" ]] || die "signed-download preparer is missing or invalid: $PREPARE"

for command in curl sha256sum awk mktemp cmp realpath; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

tmpdir="$(mktemp -d)"
chmod 0700 "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT
PREPARED="$tmpdir/prepared"
"$PREPARE" --version "$VERSION" --signed-release "$SIGNED_RELEASE_DIR" --out-dir "$PREPARED" >/dev/null

ARCHIVE="wedecent-${VERSION}-windows-amd64.zip"
ARCHIVE_PATH="$PREPARED/$ARCHIVE"
SUMS_PATH="$PREPARED/SHA256SUMS.txt"
[[ -f "$ARCHIVE_PATH" && ! -L "$ARCHIVE_PATH" ]] || die 'prepared archive is missing'
[[ -f "$SUMS_PATH" && ! -L "$SUMS_PATH" ]] || die 'prepared checksum manifest is missing'
(
  cd "$PREPARED"
  sha256sum -c SHA256SUMS.txt >/dev/null
) || die 'prepared public payload checksum verification failed'

LOCAL_SHA="$(
  awk -v file="$ARCHIVE" '
    length($1) == 64 && $1 !~ /[^0-9A-Fa-f]/ && $2 == file && NF == 2 {
      print tolower($1)
      count++
    }
    END {
      if (count != 1) exit 1
    }
  ' "$SUMS_PATH"
)" || die "prepared checksum manifest must contain exactly one canonical entry for $ARCHIVE"
[[ "$(wc -l < "$SUMS_PATH" | tr -d '[:space:]')" == '1' ]] || die 'prepared checksum manifest must contain exactly one line'

PREFIX="windows/${VERSION}"
ARCHIVE_KEY="${PREFIX}/${ARCHIVE}"
SUMS_KEY="${PREFIX}/SHA256SUMS.txt"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE_KEY}"
SUMS_URL="${BASE_URL}/${SUMS_KEY}"

printf 'Version: %s\n' "$VERSION"
printf 'Signed release: %s\n' "$SIGNED_RELEASE_DIR"
printf 'Archive: %s\n' "$ARCHIVE_PATH"
printf 'SHA256:  %s\n' "$LOCAL_SHA"
printf 'Target:  %s\n' "$ARCHIVE_URL"

archive_presence="$(probe_public_object "$ARCHIVE_URL")"
remote_archive_state="missing"
if [[ "$archive_presence" == 'present' ]]; then
  remote_sha="$(
    curl -fsSL --retry 3 --retry-all-errors "$ARCHIVE_URL" |
      sha256sum |
      awk '{print tolower($1)}'
  )" || die 'failed to download existing public archive for verification'
  [[ "$remote_sha" == "$LOCAL_SHA" ]] ||
    die "refusing overwrite: public archive exists with different SHA-256 ($remote_sha)"
  remote_archive_state="identical"
fi

sums_presence="$(probe_public_object "$SUMS_URL")"
remote_sums_state="missing"
if [[ "$sums_presence" == 'present' ]]; then
  curl -fsS --retry 3 --retry-all-errors "$SUMS_URL" -o "$tmpdir/remote-SHA256SUMS.txt" ||
    die 'failed to download existing public checksum manifest for verification'
  if cmp -s "$SUMS_PATH" "$tmpdir/remote-SHA256SUMS.txt"; then
    remote_sums_state="identical"
  else
    die 'refusing overwrite: public SHA256SUMS.txt already exists with different content'
  fi
fi

printf 'Remote archive: %s\n' "$remote_archive_state"
printf 'Remote sums:    %s\n' "$remote_sums_state"

if ((DRY_RUN)); then
  printf 'Dry run: signed release verified; no upload performed.\n'
  exit 0
fi

UPLOADER=''
if [[ "$remote_archive_state" == 'missing' || "$remote_sums_state" == 'missing' ]]; then
  UPLOADER="$(resolve_create_only_uploader)"
fi

if [[ "$remote_archive_state" == 'missing' ]]; then
  "$UPLOADER" \
    "$BUCKET" \
    "$ARCHIVE_KEY" \
    "$ARCHIVE_PATH" \
    'application/zip' \
    "attachment; filename=\"${ARCHIVE}\"" \
    "$CACHE_CONTROL" || die 'create-only archive upload failed'
else
  printf 'Archive already published with identical bytes; skipping upload.\n'
fi

if [[ "$remote_sums_state" == 'missing' ]]; then
  "$UPLOADER" \
    "$BUCKET" \
    "$SUMS_KEY" \
    "$SUMS_PATH" \
    'text/plain; charset=utf-8' \
    '' \
    "$CACHE_CONTROL" || die 'create-only checksum upload failed'
else
  printf 'Checksum manifest already published with identical content; skipping upload.\n'
fi

remote_sha="$(
  curl -fsSL --retry 5 --retry-all-errors "$ARCHIVE_URL" |
    sha256sum |
    awk '{print tolower($1)}'
)" || die 'post-upload archive download failed'
[[ "$remote_sha" == "$LOCAL_SHA" ]] ||
  die "post-upload archive verification failed: expected $LOCAL_SHA, got $remote_sha"

curl -fsS --retry 5 --retry-all-errors "$SUMS_URL" -o "$tmpdir/public-SHA256SUMS.txt" ||
  die 'post-upload checksum manifest download failed'
cmp -s "$SUMS_PATH" "$tmpdir/public-SHA256SUMS.txt" ||
  die 'post-upload checksum manifest verification failed'

printf 'Public Windows release publication PASS\n'
printf 'Archive URL: %s\n' "$ARCHIVE_URL"
printf 'SHA256 URL:  %s\n' "$SUMS_URL"
