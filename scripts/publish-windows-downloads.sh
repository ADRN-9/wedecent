#!/usr/bin/env bash
set -euo pipefail

BUCKET="wedecent-downloads"
BASE_URL="https://downloads.wedecent.com"
VERSION=""
SIGNED_RELEASE_DIR=""
SIGNED_INSTALLER_DIR=""
DRY_RUN=0
CREATE_ONLY_UPLOADER="${WEDECENT_R2_CREATE_ONLY_UPLOADER:-}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREPARE_RELEASE="$ROOT/scripts/prepare-windows-public-download.sh"
PREPARE_INSTALLER="$ROOT/scripts/prepare-windows-public-installer.sh"
CACHE_CONTROL='public, max-age=31536000, immutable'

usage() {
  cat <<'EOF'
Usage:
  publish-windows-downloads.sh \
    --version VERSION \
    --signed-release DIR \
    --signed-installer DIR \
    [--bucket NAME] \
    [--base-url URL] \
    [--dry-run]

The signed installer must be the finalized package for the same signed release. The
script verifies Authenticode through WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER, prepares
the canonical release and installer ZIPs itself, probes all four immutable public
objects before any write, and never accepts arbitrary pre-built archives.

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

manifest_sha() {
  local manifest="$1"
  local archive="$2"
  local label="$3"
  [[ "$(wc -l < "$manifest" | tr -d '[:space:]')" == '1' ]] || die "$label must contain exactly one line"
  awk -v file="$archive" '
    length($1) == 64 && $1 !~ /[^0-9A-Fa-f]/ && $2 == file && NF == 2 {
      print tolower($1)
      count++
    }
    END {
      if (count != 1) exit 1
    }
  ' "$manifest" || die "$label must contain exactly one canonical entry for $archive"
}

inspect_archive() {
  local path="$1"
  local url="$2"
  local expected_sha="$3"
  local label="$4"
  local presence remote_sha
  if ! presence="$(probe_public_object "$url")"; then
    return 1
  fi
  if [[ "$presence" == 'missing' ]]; then
    printf 'missing\n'
    return
  fi
  remote_sha="$(
    curl -fsSL --retry 3 --retry-all-errors "$url" |
      sha256sum |
      awk '{print tolower($1)}'
  )" || die "failed to download existing $label for verification"
  [[ "$remote_sha" == "$expected_sha" ]] ||
    die "refusing overwrite: $label exists with different SHA-256 ($remote_sha)"
  printf 'identical\n'
}

inspect_manifest() {
  local path="$1"
  local url="$2"
  local temp_name="$3"
  local label="$4"
  local presence remote_path
  if ! presence="$(probe_public_object "$url")"; then
    return 1
  fi
  if [[ "$presence" == 'missing' ]]; then
    printf 'missing\n'
    return
  fi
  remote_path="$tmpdir/$temp_name"
  curl -fsS --retry 3 --retry-all-errors "$url" -o "$remote_path" ||
    die "failed to download existing $label for verification"
  cmp -s "$path" "$remote_path" || die "refusing overwrite: $label already exists with different content"
  printf 'identical\n'
}

upload_if_missing() {
  local state="$1"
  local key="$2"
  local path="$3"
  local content_type="$4"
  local content_disposition="$5"
  local label="$6"
  if [[ "$state" == 'missing' ]]; then
    "$UPLOADER" "$BUCKET" "$key" "$path" "$content_type" "$content_disposition" "$CACHE_CONTROL" ||
      die "create-only $label upload failed"
  else
    printf '%s already published with identical bytes; skipping upload.\n' "$label"
  fi
}

verify_public_archive() {
  local url="$1"
  local expected_sha="$2"
  local label="$3"
  local remote_sha
  remote_sha="$(
    curl -fsSL --retry 5 --retry-all-errors "$url" |
      sha256sum |
      awk '{print tolower($1)}'
  )" || die "post-upload $label download failed"
  [[ "$remote_sha" == "$expected_sha" ]] ||
    die "post-upload $label verification failed: expected $expected_sha, got $remote_sha"
}

verify_public_manifest() {
  local url="$1"
  local expected_path="$2"
  local temp_name="$3"
  local label="$4"
  local remote_path="$tmpdir/$temp_name"
  curl -fsS --retry 5 --retry-all-errors "$url" -o "$remote_path" || die "post-upload $label download failed"
  cmp -s "$expected_path" "$remote_path" || die "post-upload $label verification failed"
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
    --signed-installer)
      (($# >= 2)) || die '--signed-installer requires a value'
      SIGNED_INSTALLER_DIR="$2"
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
[[ -n "$SIGNED_INSTALLER_DIR" ]] || die '--signed-installer is required'
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  die 'version must look like v0.3.0 or v0.3.0-rc.3'
[[ "$BASE_URL" == https://* ]] || die '--base-url must use https://'
[[ -x "$PREPARE_RELEASE" && ! -L "$PREPARE_RELEASE" ]] || die "signed-release preparer is missing or invalid: $PREPARE_RELEASE"
[[ -x "$PREPARE_INSTALLER" && ! -L "$PREPARE_INSTALLER" ]] || die "signed-installer preparer is missing or invalid: $PREPARE_INSTALLER"

for command in curl sha256sum awk mktemp cmp realpath wc tr rm; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

tmpdir="$(mktemp -d)"
chmod 0700 "$tmpdir"
trap 'rm -rf -- "$tmpdir"' EXIT
PREPARED_RELEASE="$tmpdir/prepared-release"
PREPARED_INSTALLER="$tmpdir/prepared-installer"
"$PREPARE_RELEASE" --version "$VERSION" --signed-release "$SIGNED_RELEASE_DIR" --out-dir "$PREPARED_RELEASE" >/dev/null
"$PREPARE_INSTALLER" \
  --version "$VERSION" \
  --signed-release "$SIGNED_RELEASE_DIR" \
  --signed-installer "$SIGNED_INSTALLER_DIR" \
  --out-dir "$PREPARED_INSTALLER" >/dev/null

RELEASE_ARCHIVE="wedecent-${VERSION}-windows-amd64.zip"
RELEASE_ARCHIVE_PATH="$PREPARED_RELEASE/$RELEASE_ARCHIVE"
RELEASE_SUMS_PATH="$PREPARED_RELEASE/SHA256SUMS.txt"
INSTALLER_ARCHIVE="wedecent-${VERSION}-windows-installer.zip"
INSTALLER_ARCHIVE_PATH="$PREPARED_INSTALLER/$INSTALLER_ARCHIVE"
INSTALLER_SUMS_PATH="$PREPARED_INSTALLER/INSTALLER_SHA256SUMS.txt"

for path in "$RELEASE_ARCHIVE_PATH" "$RELEASE_SUMS_PATH" "$INSTALLER_ARCHIVE_PATH" "$INSTALLER_SUMS_PATH"; do
  [[ -f "$path" && ! -L "$path" ]] || die "prepared public payload is missing or invalid: $path"
done
(
  cd "$PREPARED_RELEASE"
  sha256sum -c SHA256SUMS.txt >/dev/null
) || die 'prepared release payload checksum verification failed'
(
  cd "$PREPARED_INSTALLER"
  sha256sum -c INSTALLER_SHA256SUMS.txt >/dev/null
) || die 'prepared installer payload checksum verification failed'

RELEASE_SHA="$(manifest_sha "$RELEASE_SUMS_PATH" "$RELEASE_ARCHIVE" 'prepared release checksum manifest')"
INSTALLER_SHA="$(manifest_sha "$INSTALLER_SUMS_PATH" "$INSTALLER_ARCHIVE" 'prepared installer checksum manifest')"

PREFIX="windows/${VERSION}"
RELEASE_ARCHIVE_KEY="${PREFIX}/${RELEASE_ARCHIVE}"
RELEASE_SUMS_KEY="${PREFIX}/SHA256SUMS.txt"
INSTALLER_ARCHIVE_KEY="${PREFIX}/${INSTALLER_ARCHIVE}"
INSTALLER_SUMS_KEY="${PREFIX}/INSTALLER_SHA256SUMS.txt"
RELEASE_ARCHIVE_URL="${BASE_URL}/${RELEASE_ARCHIVE_KEY}"
RELEASE_SUMS_URL="${BASE_URL}/${RELEASE_SUMS_KEY}"
INSTALLER_ARCHIVE_URL="${BASE_URL}/${INSTALLER_ARCHIVE_KEY}"
INSTALLER_SUMS_URL="${BASE_URL}/${INSTALLER_SUMS_KEY}"

printf 'Version: %s\n' "$VERSION"
printf 'Signed release:   %s\n' "$SIGNED_RELEASE_DIR"
printf 'Signed installer: %s\n' "$SIGNED_INSTALLER_DIR"
printf 'Release target:   %s\n' "$RELEASE_ARCHIVE_URL"
printf 'Release SHA256:   %s\n' "$RELEASE_SHA"
printf 'Installer target: %s\n' "$INSTALLER_ARCHIVE_URL"
printf 'Installer SHA256: %s\n' "$INSTALLER_SHA"

# Resolve every remote state before the first possible write. Do not rely on Bash's
# errexit behavior inside command substitutions: propagate each inspection failure
# explicitly so an ambiguous HEAD cannot fall through to a GET or a later key.
if ! RELEASE_ARCHIVE_STATE="$(inspect_archive "$RELEASE_ARCHIVE_PATH" "$RELEASE_ARCHIVE_URL" "$RELEASE_SHA" 'public release archive')"; then
  exit 1
fi
if ! RELEASE_SUMS_STATE="$(inspect_manifest "$RELEASE_SUMS_PATH" "$RELEASE_SUMS_URL" 'remote-release-SHA256SUMS.txt' 'public release checksum manifest')"; then
  exit 1
fi
if ! INSTALLER_ARCHIVE_STATE="$(inspect_archive "$INSTALLER_ARCHIVE_PATH" "$INSTALLER_ARCHIVE_URL" "$INSTALLER_SHA" 'public installer archive')"; then
  exit 1
fi
if ! INSTALLER_SUMS_STATE="$(inspect_manifest "$INSTALLER_SUMS_PATH" "$INSTALLER_SUMS_URL" 'remote-INSTALLER_SHA256SUMS.txt' 'public installer checksum manifest')"; then
  exit 1
fi

printf 'Remote release archive:   %s\n' "$RELEASE_ARCHIVE_STATE"
printf 'Remote release sums:      %s\n' "$RELEASE_SUMS_STATE"
printf 'Remote installer archive: %s\n' "$INSTALLER_ARCHIVE_STATE"
printf 'Remote installer sums:    %s\n' "$INSTALLER_SUMS_STATE"

if ((DRY_RUN)); then
  printf 'Dry run: signed release and installer verified; no upload performed.\n'
  exit 0
fi

UPLOADER=''
if [[ "$RELEASE_ARCHIVE_STATE" == 'missing' || "$RELEASE_SUMS_STATE" == 'missing' ||
      "$INSTALLER_ARCHIVE_STATE" == 'missing' || "$INSTALLER_SUMS_STATE" == 'missing' ]]; then
  UPLOADER="$(resolve_create_only_uploader)"
fi

upload_if_missing "$RELEASE_ARCHIVE_STATE" "$RELEASE_ARCHIVE_KEY" "$RELEASE_ARCHIVE_PATH" \
  'application/zip' "attachment; filename=\"${RELEASE_ARCHIVE}\"" 'Release archive'
upload_if_missing "$RELEASE_SUMS_STATE" "$RELEASE_SUMS_KEY" "$RELEASE_SUMS_PATH" \
  'text/plain; charset=utf-8' '' 'Release checksum manifest'
upload_if_missing "$INSTALLER_ARCHIVE_STATE" "$INSTALLER_ARCHIVE_KEY" "$INSTALLER_ARCHIVE_PATH" \
  'application/zip' "attachment; filename=\"${INSTALLER_ARCHIVE}\"" 'Installer archive'
upload_if_missing "$INSTALLER_SUMS_STATE" "$INSTALLER_SUMS_KEY" "$INSTALLER_SUMS_PATH" \
  'text/plain; charset=utf-8' '' 'Installer checksum manifest'

verify_public_archive "$RELEASE_ARCHIVE_URL" "$RELEASE_SHA" 'release archive'
verify_public_manifest "$RELEASE_SUMS_URL" "$RELEASE_SUMS_PATH" 'public-release-SHA256SUMS.txt' 'release checksum manifest'
verify_public_archive "$INSTALLER_ARCHIVE_URL" "$INSTALLER_SHA" 'installer archive'
verify_public_manifest "$INSTALLER_SUMS_URL" "$INSTALLER_SUMS_PATH" 'public-INSTALLER_SHA256SUMS.txt' 'installer checksum manifest'

printf 'Public Windows release publication PASS\n'
printf 'Release archive URL:   %s\n' "$RELEASE_ARCHIVE_URL"
printf 'Release SHA256 URL:    %s\n' "$RELEASE_SUMS_URL"
printf 'Installer archive URL: %s\n' "$INSTALLER_ARCHIVE_URL"
printf 'Installer SHA256 URL:  %s\n' "$INSTALLER_SUMS_URL"
