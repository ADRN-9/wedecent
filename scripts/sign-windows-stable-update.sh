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
ROOT_KEY_ID="${WEDECENT_UPDATE_ROOT_KEY_ID:-}"
ROOT_PUBLIC_KEY="${WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH:-}"
KEYSET="${WEDECENT_UPDATE_KEYSET_PATH:-}"
KEYSET_SIGNATURE="${WEDECENT_UPDATE_KEYSET_SIGNATURE_PATH:-}"
SIGNING_KEY_ID="${WEDECENT_UPDATE_SIGNING_KEY_ID:-}"
KEYSET_EPOCH="${WEDECENT_UPDATE_KEYSET_EPOCH:-}"

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
[[ "$ROOT_KEY_ID" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] || die 'root key ID is required'
[[ "$ROOT_PUBLIC_KEY" == /* && -f "$ROOT_PUBLIC_KEY" && ! -L "$ROOT_PUBLIC_KEY" ]] || die 'root public key must be an absolute regular file'
[[ "$KEYSET" == /* && -f "$KEYSET" && ! -L "$KEYSET" ]] || die 'root-signed keyset must be an absolute regular file'
[[ "$KEYSET_SIGNATURE" == /* && -f "$KEYSET_SIGNATURE" && ! -L "$KEYSET_SIGNATURE" ]] || die 'keyset signature must be an absolute regular file'
[[ "$SIGNING_KEY_ID" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] || die 'active manifest signing key ID is required'
[[ "$KEYSET_EPOCH" =~ ^[1-9][0-9]*$ ]] || die 'root-signed keyset epoch is required'

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
  local url="$1"
  local tmp status hash
  tmp="$(mktemp)"
  if ! status="$(curl --disable -sS --connect-timeout 10 --max-time 120 --proto '=https' -o "$tmp" -w '%{http_code}' "$url")"; then
    rm -f -- "$tmp"
    die "cannot fetch immutable artifact: $url"
  fi
  if [[ "$status" != 200 ]]; then
    rm -f -- "$tmp"
    die "unexpected HTTP $status for immutable artifact: $url"
  fi
  hash="$(sha256sum "$tmp" | awk '{print tolower($1)}')"
  rm -f -- "$tmp"
  [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || die 'invalid artifact SHA-256'
  printf '%s\n' "$hash"
}

RELEASE_SHA="$(remote_sha256 "$RELEASE_URL")"
INSTALLER_SHA="$(remote_sha256 "$INSTALLER_URL")"
mkdir -m 0700 -- "$OUT_DIR"
MANIFEST="$OUT_DIR/manifest-v2.json"
SIGNATURE="$OUT_DIR/manifest-v2.sig"
cp -- "$KEYSET" "$OUT_DIR/keyset-v1.json"
cp -- "$KEYSET_SIGNATURE" "$OUT_DIR/keyset-v1.sig"
chmod 0600 "$OUT_DIR/keyset-v1.json" "$OUT_DIR/keyset-v1.sig"

"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" ||
  die 'release tag changed before manifest creation'
(
  cd "$ROOT"
  go run ./cmd/wd-update-manifest create \
    --schema 2 --signing-key-id "$SIGNING_KEY_ID" --keyset-epoch "$KEYSET_EPOCH" \
    --sequence "$SEQUENCE" --version "$VERSION" --published-at "$PUBLISHED_AT" \
    --release-sha256 "$RELEASE_SHA" --installer-sha256 "$INSTALLER_SHA" --out "$MANIFEST" >/dev/null
) || die 'canonical manifest creation failed'

"$SIGNER" "$MANIFEST" "$SIGNATURE" || die 'external manifest signer failed'
[[ -f "$SIGNATURE" && ! -L "$SIGNATURE" ]] || die 'signer did not produce a regular signature file'
(
  cd "$ROOT"
  go run ./cmd/wd-update-manifest verify-v2 --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" --keyset "$OUT_DIR/keyset-v1.json" --keyset-signature "$OUT_DIR/keyset-v1.sig" --manifest "$MANIFEST" --signature "$SIGNATURE" >/dev/null
) || die 'signer output failed local public-key verification'

"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" ||
  die 'release tag changed after signing'
printf 'Signed stable update candidate prepared; manifest and signature only.\n'
