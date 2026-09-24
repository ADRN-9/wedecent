#!/usr/bin/env bash
set -euo pipefail

BASE_URL='https://downloads.wedecent.com'
BUCKET='wedecent-downloads'
MANIFEST_KEY='windows/stable/manifest-v1.json'
SIGNATURE_KEY='windows/stable/manifest-v1.sig'
VERSION=''
SEQUENCE=''
PUBLISHED_AT=''
PUBLIC_KEY=''
DRY_RUN=0

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNER="${WEDECENT_UPDATE_MANIFEST_SIGNER:-}"
PAIR_PUBLISHER="${WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER:-}"

usage() {
  cat <<'EOF'
Usage:
  publish-windows-stable-update.sh \
    --version vMAJOR.MINOR.PATCH \
    --sequence N \
    --published-at YYYY-MM-DDTHH:MM:SSZ \
    --public-key FILE \
    [--dry-run]

The immutable release and installer archives must already exist at their canonical
https://downloads.wedecent.com/windows/VERSION/ URLs. Their bytes are downloaded and
hashed; caller-supplied artifact hashes are never accepted.

WEDECENT_UPDATE_MANIFEST_SIGNER must be an absolute non-symlink executable. It is
invoked as:

  signer MANIFEST_PATH SIGNATURE_PATH

It must sign the exact manifest bytes and create SIGNATURE_PATH using the canonical
unpadded URL-safe-base64 signature representation accepted by internal/updateinfo.
The private signing key remains outside this repository and outside release artifacts.

For a non-dry-run publication, WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER must be an
absolute non-symlink executable. It is invoked as:

  publisher BUCKET MANIFEST_KEY SIGNATURE_KEY MANIFEST_PATH SIGNATURE_PATH \
    EXPECTED_MANIFEST_SHA256 EXPECTED_SIGNATURE_SHA256

EXPECTED_* is '-' only when both stable objects are absent. Otherwise each value is the
SHA-256 of the previously verified object. The publisher MUST atomically compare both
expected states and replace the manifest/signature pair as one logical operation. It must
return nonzero without changing either object if the comparison fails. This script does
not implement two independent mutable R2 writes because that can strand a mismatched pair.
EOF
}

die() {
  printf 'publish-windows-stable-update: %s\n' "$*" >&2
  exit 1
}

resolve_hook() {
  local value="$1"
  local label="$2"
  [[ -n "$value" ]] || die "$label is required"
  [[ "$value" = /* ]] || die "$label must be an absolute executable path"
  [[ ! -L "$value" ]] || die "$label must not be a symlink"
  value="$(realpath -e -- "$value")" || die "cannot resolve $label"
  [[ -f "$value" && -x "$value" ]] || die "$label must be a regular executable file"
  printf '%s\n' "$value"
}

probe() {
  local url="$1"
  local status
  status="$(curl -sS -I --retry 2 -o /dev/null -w '%{http_code}' "$url")" ||
    die "failed to determine remote object state: $url"
  case "$status" in
    200|404) printf '%s\n' "$status" ;;
    *) die "refusing ambiguous remote object state: HTTP $status for $url" ;;
  esac
}

fetch_file() {
  local url="$1"
  local out="$2"
  curl -fsS --retry 3 --retry-all-errors --proto '=https' "$url" -o "$out" ||
    die "failed to download $url"
  [[ -f "$out" && ! -L "$out" ]] || die "download did not produce a regular file: $url"
}

remote_sha256() {
  local url="$1"
  local hash
  hash="$(curl -fsS --retry 3 --retry-all-errors --proto '=https' "$url" | sha256sum | awk '{print tolower($1)}')" ||
    die "failed to hash $url"
  [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || die "invalid SHA-256 result for $url"
  printf '%s\n' "$hash"
}

parse_verified_fields() {
  local output="$1"
  local sequence='' version='' line
  while IFS= read -r line; do
    case "$line" in
      sequence=*) sequence="${line#sequence=}" ;;
      version=*) version="${line#version=}" ;;
      '') ;;
      *) die 'manifest verifier returned unexpected output' ;;
    esac
  done <<< "$output"
  [[ "$sequence" =~ ^[1-9][0-9]*$ ]] || die 'verified manifest sequence output is invalid'
  [[ "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die 'verified manifest version output is invalid'
  printf '%s %s\n' "$sequence" "$version"
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die '--version requires a value'
      VERSION="$2"; shift 2 ;;
    --sequence)
      (($# >= 2)) || die '--sequence requires a value'
      SEQUENCE="$2"; shift 2 ;;
    --published-at)
      (($# >= 2)) || die '--published-at requires a value'
      PUBLISHED_AT="$2"; shift 2 ;;
    --public-key)
      (($# >= 2)) || die '--public-key requires a value'
      PUBLIC_KEY="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "unknown argument: $1" ;;
  esac
done

[[ "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  die '--version must be canonical stable vMAJOR.MINOR.PATCH'
[[ "$SEQUENCE" =~ ^[1-9][0-9]*$ ]] || die '--sequence must be a positive integer'
[[ -n "$PUBLISHED_AT" ]] || die '--published-at is required'
[[ -n "$PUBLIC_KEY" ]] || die '--public-key is required'
[[ -f "$PUBLIC_KEY" && ! -L "$PUBLIC_KEY" ]] || die '--public-key must be a regular non-symlink file'

for command in curl sha256sum awk mktemp cmp realpath rm go; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

SIGNER="$(resolve_hook "$SIGNER" 'WEDECENT_UPDATE_MANIFEST_SIGNER')"
if ((DRY_RUN == 0)); then
  PAIR_PUBLISHER="$(resolve_hook "$PAIR_PUBLISHER" 'WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER')"
fi

tmpdir="$(mktemp -d)"
chmod 0700 "$tmpdir"
trap 'rm -rf -- "$tmpdir"' EXIT

RELEASE_URL="$BASE_URL/windows/$VERSION/wedecent-$VERSION-windows-amd64.zip"
INSTALLER_URL="$BASE_URL/windows/$VERSION/wedecent-$VERSION-windows-installer.zip"
MANIFEST_URL="$BASE_URL/$MANIFEST_KEY"
SIGNATURE_URL="$BASE_URL/$SIGNATURE_KEY"

RELEASE_SHA="$(remote_sha256 "$RELEASE_URL")"
INSTALLER_SHA="$(remote_sha256 "$INSTALLER_URL")"
MANIFEST="$tmpdir/manifest-v1.json"
SIGNATURE="$tmpdir/manifest-v1.sig"

(
  cd "$ROOT"
  go run ./cmd/wd-update-manifest create \
    --sequence "$SEQUENCE" \
    --version "$VERSION" \
    --published-at "$PUBLISHED_AT" \
    --release-sha256 "$RELEASE_SHA" \
    --installer-sha256 "$INSTALLER_SHA" \
    --out "$MANIFEST" >/dev/null
)

"$SIGNER" "$MANIFEST" "$SIGNATURE" || die 'manifest signer failed'
[[ -f "$SIGNATURE" && ! -L "$SIGNATURE" ]] || die 'signer did not create a regular signature file'
(
  cd "$ROOT"
  go run ./cmd/wd-update-manifest verify \
    --public-key "$PUBLIC_KEY" \
    --manifest "$MANIFEST" \
    --signature "$SIGNATURE" >/dev/null
) || die 'locally signed candidate failed verification'

manifest_status="$(probe "$MANIFEST_URL")"
signature_status="$(probe "$SIGNATURE_URL")"
EXPECTED_MANIFEST_SHA='-'
EXPECTED_SIGNATURE_SHA='-'

if [[ "$manifest_status" == 200 && "$signature_status" == 200 ]]; then
  old_manifest="$tmpdir/old-manifest-v1.json"
  old_signature="$tmpdir/old-manifest-v1.sig"
  fetch_file "$MANIFEST_URL" "$old_manifest"
  fetch_file "$SIGNATURE_URL" "$old_signature"
  verifier_output="$(
    cd "$ROOT"
    go run ./cmd/wd-update-manifest verify \
      --public-key "$PUBLIC_KEY" \
      --manifest "$old_manifest" \
      --signature "$old_signature"
  )" || die 'existing stable manifest pair failed verification'
  read -r old_sequence old_version <<< "$(parse_verified_fields "$verifier_output")"
  (
    cd "$ROOT"
    go run ./cmd/wd-update-manifest verify \
      --public-key "$PUBLIC_KEY" \
      --manifest "$MANIFEST" \
      --signature "$SIGNATURE" \
      --current-version "$old_version" \
      --current-sequence "$old_sequence" >/dev/null
  ) || die 'candidate does not advance the currently published stable manifest'
  EXPECTED_MANIFEST_SHA="$(sha256sum "$old_manifest" | awk '{print tolower($1)}')"
  EXPECTED_SIGNATURE_SHA="$(sha256sum "$old_signature" | awk '{print tolower($1)}')"
elif [[ "$manifest_status" == 404 && "$signature_status" == 404 ]]; then
  :
else
  die 'stable channel is inconsistent: manifest and signature presence differ'
fi

printf 'Prepared stable update %s sequence %s\n' "$VERSION" "$SEQUENCE"
printf '  release_sha256=%s\n' "$RELEASE_SHA"
printf '  installer_sha256=%s\n' "$INSTALLER_SHA"

if ((DRY_RUN == 1)); then
  printf 'Dry run: stable manifest/signature pair verified; no publication performed.\n'
  exit 0
fi

"$PAIR_PUBLISHER" \
  "$BUCKET" "$MANIFEST_KEY" "$SIGNATURE_KEY" \
  "$MANIFEST" "$SIGNATURE" \
  "$EXPECTED_MANIFEST_SHA" "$EXPECTED_SIGNATURE_SHA" ||
  die 'atomic stable-pair publisher failed'

published_manifest="$tmpdir/published-manifest-v1.json"
published_signature="$tmpdir/published-manifest-v1.sig"
fetch_file "$MANIFEST_URL" "$published_manifest"
fetch_file "$SIGNATURE_URL" "$published_signature"
cmp -s "$MANIFEST" "$published_manifest" || die 'published stable manifest differs from prepared bytes'
cmp -s "$SIGNATURE" "$published_signature" || die 'published stable signature differs from prepared bytes'
(
  cd "$ROOT"
  go run ./cmd/wd-update-manifest verify \
    --public-key "$PUBLIC_KEY" \
    --manifest "$published_manifest" \
    --signature "$published_signature" >/dev/null
) || die 'post-publication stable pair verification failed'

printf 'Published verified stable update pair for %s sequence %s.\n' "$VERSION" "$SEQUENCE"
