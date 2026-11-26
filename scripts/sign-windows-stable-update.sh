#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$ROOT/scripts/lib/release-trust.sh"

VERSION=""
SEQUENCE=""
PUBLISHED_AT=""
OUT_DIR=""
SIGNER="${WEDECENT_UPDATE_MANIFEST_SIGNER:-}"
SIGNER_SHA_EXPECTED="${WEDECENT_UPDATE_MANIFEST_SIGNER_SHA256:-}"
PUBLIC_KEY="${WEDECENT_UPDATE_PUBLIC_KEY_PATH:-}"

die() { printf 'sign-windows-stable-update: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --version) (($# >= 2)) || die '--version requires a value'; VERSION="$2"; shift 2 ;;
    --sequence) (($# >= 2)) || die '--sequence requires a value'; SEQUENCE="$2"; shift 2 ;;
    --published-at) (($# >= 2)) || die '--published-at requires a value'; PUBLISHED_AT="$2"; shift 2 ;;
    --out-dir) (($# >= 2)) || die '--out-dir requires a value'; OUT_DIR="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die 'version must be canonical stable vMAJOR.MINOR.PATCH'
[[ "$SEQUENCE" =~ ^[1-9][0-9]*$ ]] || die 'sequence must be positive'
[[ "$PUBLISHED_AT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || die 'published-at must be canonical UTC seconds'
[[ -n "$OUT_DIR" && "$OUT_DIR" == /* ]] || die 'out-dir must be an absolute path'
[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] || die 'out-dir must not already exist'
[[ "$SIGNER" == /* && -f "$SIGNER" && -x "$SIGNER" && ! -L "$SIGNER" ]] || die 'signer must be an absolute regular executable, not a symlink'
SIGNER="$(realpath -e -- "$SIGNER")" || die 'cannot resolve signer'
[[ "$SIGNER_SHA_EXPECTED" =~ ^[0-9a-f]{64}$ ]] || die 'signer SHA-256 pin is required'
SIGNER_SHA_ACTUAL="$(sha256sum "$SIGNER" | awk '{print tolower($1)}')"
[[ "$SIGNER_SHA_ACTUAL" == "$SIGNER_SHA_EXPECTED" ]] || die 'signer executable does not match its pinned SHA-256'
SIGNER_MODE="$(stat -c '%a' "$SIGNER")"
[[ "$SIGNER_MODE" =~ ^[0-7]{3,4}$ ]] || die 'invalid signer file mode'
[[ ! "$SIGNER_MODE" =~ [2367][0-7]$ && ! "$SIGNER_MODE" =~ [0-7][2367]$ ]] || die 'signer executable is group/world writable'
[[ "$PUBLIC_KEY" == /* && -f "$PUBLIC_KEY" && ! -L "$PUBLIC_KEY" ]] || die 'public key path must be an absolute regular file'

wedecent_require_production_release_context "${VERSION#v}" || die 'release context validation failed'
wedecent_require_approved_replay_trust || die 'replay trust validation failed'
wedecent_require_approved_checkpoint_audit_trust || die 'checkpoint audit trust validation failed'

for command in curl sha256sum awk go realpath mkdir chmod stat; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

BASE_URL='https://downloads.wedecent.com'
RELEASE_URL="$BASE_URL/windows/$VERSION/wedecent-$VERSION-windows-amd64.zip"
INSTALLER_URL="$BASE_URL/windows/$VERSION/wedecent-$VERSION-windows-installer.zip"
remote_sha256() {
  local hash
  hash="$(curl -fsS --retry 3 --retry-all-errors --proto '=https' "$1" | sha256sum | awk '{print tolower($1)}')" ||
    die "cannot fetch/hash immutable artifact: $1"
  [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || die 'invalid artifact SHA-256'
  printf '%s\n' "$hash"
}

RELEASE_SHA="$(remote_sha256 "$RELEASE_URL")"
INSTALLER_SHA="$(remote_sha256 "$INSTALLER_URL")"
mkdir -m 0700 -- "$OUT_DIR"
MANIFEST="$OUT_DIR/manifest-v1.json"
SIGNATURE="$OUT_DIR/manifest-v1.sig"

"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" ||
  die 'release tag changed before manifest creation'
(
  cd "$ROOT"
  go run ./cmd/wd-update-manifest create \
    --sequence "$SEQUENCE" --version "$VERSION" --published-at "$PUBLISHED_AT" \
    --release-sha256 "$RELEASE_SHA" --installer-sha256 "$INSTALLER_SHA" --out "$MANIFEST" >/dev/null
) || die 'canonical manifest creation failed'

"$SIGNER" "$MANIFEST" "$SIGNATURE" || die 'external manifest signer failed'
[[ -f "$SIGNATURE" && ! -L "$SIGNATURE" ]] || die 'signer did not produce a regular signature file'
(
  cd "$ROOT"
  go run ./cmd/wd-update-manifest verify --public-key "$PUBLIC_KEY" --manifest "$MANIFEST" --signature "$SIGNATURE" >/dev/null
) || die 'signer output failed local public-key verification'

"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" ||
  die 'release tag changed after signing'
printf 'Signed stable update candidate prepared; manifest and signature only.\n'
