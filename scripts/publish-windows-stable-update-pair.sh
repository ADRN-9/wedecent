#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PUBLIC_KEY="${WEDECENT_UPDATE_PUBLIC_KEY_PATH:-}"
PUBLISHER="${WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER:-}"
PUBLISHER_SHA_EXPECTED="${WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER_SHA256:-}"
MANIFEST=""
SIGNATURE=""
RECEIPT=""

die() { printf 'publish-windows-stable-update-pair: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --public-key) (($# >= 2)) || die '--public-key requires a value'; PUBLIC_KEY="$2"; shift 2 ;;
    --manifest) (($# >= 2)) || die '--manifest requires a value'; MANIFEST="$2"; shift 2 ;;
    --signature) (($# >= 2)) || die '--signature requires a value'; SIGNATURE="$2"; shift 2 ;;
    --receipt) (($# >= 2)) || die '--receipt requires a value'; RECEIPT="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$PUBLIC_KEY" == /* && -f "$PUBLIC_KEY" && ! -L "$PUBLIC_KEY" ]] || die 'public key must be an absolute regular file'
[[ "$PUBLISHER" == /* && -f "$PUBLISHER" && -x "$PUBLISHER" && ! -L "$PUBLISHER" ]] || die 'publisher must be an absolute regular executable, not a symlink'
PUBLISHER="$(realpath -e -- "$PUBLISHER")" || die 'cannot resolve publisher'
[[ "$PUBLISHER_SHA_EXPECTED" =~ ^[0-9a-f]{64}$ ]] || die 'publisher SHA-256 pin is required'
PUBLISHER_SHA_ACTUAL="$(sha256sum "$PUBLISHER" | awk '{print tolower($1)}')"
[[ "$PUBLISHER_SHA_ACTUAL" == "$PUBLISHER_SHA_EXPECTED" ]] || die 'publisher executable does not match its pinned SHA-256'
PUBLISHER_MODE="$(stat -c '%a' "$PUBLISHER")"
[[ "$PUBLISHER_MODE" =~ ^[0-7]{3,4}$ ]] || die 'invalid publisher file mode'
[[ ! "$PUBLISHER_MODE" =~ [2367][0-7]$ && ! "$PUBLISHER_MODE" =~ [0-7][2367]$ ]] || die 'publisher executable is group/world writable'
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || die 'manifest must be a regular non-symlink file'
[[ -f "$SIGNATURE" && ! -L "$SIGNATURE" ]] || die 'signature must be a regular non-symlink file'
[[ -f "$RECEIPT" && ! -L "$RECEIPT" ]] || die 'verification receipt must be a regular non-symlink file'

VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
wedecent_require_production_release_context "$VERSION" || die 'production release context invalid'
wedecent_require_approved_replay_trust || die 'replay trust validation failed'
wedecent_require_approved_checkpoint_audit_trust || die 'checkpoint audit trust validation failed'
for command in curl sha256sum awk go realpath cmp stat; do command -v "$command" >/dev/null 2>&1 || die "missing command: $command"; done

declare -A fields=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" == *=* ]] || die 'malformed verification receipt line'
  key="${line%%=*}"
  value="${line#*=}"
  case "$key" in
    manifest_sha256|signature_sha256|public_key_sha256|expected_manifest_sha256|expected_signature_sha256|sequence|version) ;;
    *) die "unknown receipt field: $key" ;;
  esac
  [[ -z "${fields[$key]+x}" ]] || die "duplicate receipt field: $key"
  fields[$key]="$value"
done < "$RECEIPT"
for key in manifest_sha256 signature_sha256 public_key_sha256 expected_manifest_sha256 expected_signature_sha256 sequence version; do
  [[ -n "${fields[$key]:-}" ]] || die "missing receipt field: $key"
done
for key in manifest_sha256 signature_sha256 public_key_sha256; do
  [[ "${fields[$key]}" =~ ^[0-9a-f]{64}$ ]] || die "invalid receipt digest: $key"
done
for key in expected_manifest_sha256 expected_signature_sha256; do
  [[ "${fields[$key]}" == '-' || "${fields[$key]}" =~ ^[0-9a-f]{64}$ ]] || die "invalid expected digest: $key"
done
[[ "${fields[sequence]}" =~ ^[1-9][0-9]*$ ]] || die 'invalid receipt sequence'
[[ "${fields[version]}" == "$GITHUB_REF_NAME" ]] || die 'receipt version does not match release tag'

sha_file() { sha256sum "$1" | awk '{print tolower($1)}'; }
[[ "$(sha_file "$MANIFEST")" == "${fields[manifest_sha256]}" ]] || die 'manifest digest differs from verifier receipt'
[[ "$(sha_file "$SIGNATURE")" == "${fields[signature_sha256]}" ]] || die 'signature digest differs from verifier receipt'
[[ "$(sha_file "$PUBLIC_KEY")" == "${fields[public_key_sha256]}" ]] || die 'public key differs from independent verifier receipt'

tmpdir="$(mktemp -d)"
chmod 0700 "$tmpdir"
trap 'rm -rf -- "$tmpdir"' EXIT
candidate_output="$tmpdir/candidate.txt"
old_output="$tmpdir/old.txt"
old_manifest="$tmpdir/old-manifest.json"
old_signature="$tmpdir/old-manifest.sig"
base='https://downloads.wedecent.com/windows/stable'

(cd "$ROOT" && go run ./cmd/wd-update-manifest verify --public-key "$PUBLIC_KEY" --manifest "$MANIFEST" --signature "$SIGNATURE") > "$candidate_output" ||
  die 'candidate signature or canonical manifest invalid'
mapfile -t candidate_fields < "$candidate_output"
[[ "${#candidate_fields[@]}" == 2 && "${candidate_fields[0]}" == "sequence=${fields[sequence]}" && "${candidate_fields[1]}" == "version=${fields[version]}" ]] ||
  die 'candidate manifest fields differ from independent verification receipt'

probe() {
  local status
  status="$(curl -sS -I --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$1")" || die "cannot determine stable object state: $1"
  case "$status" in 200|404) printf '%s\n' "$status" ;; *) die "ambiguous stable object HTTP status $status" ;; esac
}
manifest_status="$(probe "$base/manifest-v1.json")"
signature_status="$(probe "$base/manifest-v1.sig")"
if [[ "${fields[expected_manifest_sha256]}" == '-' && "${fields[expected_signature_sha256]}" == '-' ]]; then
  [[ "$manifest_status" == 404 && "$signature_status" == 404 ]] || die 'stable channel changed after verification'
elif [[ "${fields[expected_manifest_sha256]}" =~ ^[0-9a-f]{64}$ && "${fields[expected_signature_sha256]}" =~ ^[0-9a-f]{64}$ ]]; then
  [[ "$manifest_status" == 200 && "$signature_status" == 200 ]] || die 'stable channel presence changed after verification'
  curl -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v1.json" -o "$old_manifest" || die 'cannot fetch prior manifest'
  curl -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v1.sig" -o "$old_signature" || die 'cannot fetch prior signature'
  [[ "$(sha_file "$old_manifest")" == "${fields[expected_manifest_sha256]}" ]] || die 'prior manifest changed since independent verification'
  [[ "$(sha_file "$old_signature")" == "${fields[expected_signature_sha256]}" ]] || die 'prior signature changed since independent verification'
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify --public-key "$PUBLIC_KEY" --manifest "$old_manifest" --signature "$old_signature") > "$old_output" ||
    die 'current stable pair is invalid'
  mapfile -t old_fields < "$old_output"
  [[ "${#old_fields[@]}" == 2 && "${old_fields[0]}" == sequence=* && "${old_fields[1]}" == version=* ]] || die 'current stable manifest verifier output malformed'
  old_sequence="${old_fields[0]#sequence=}"
  old_version="${old_fields[1]#version=}"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify --public-key "$PUBLIC_KEY" --manifest "$MANIFEST" --signature "$SIGNATURE" --current-version "$old_version" --current-sequence "$old_sequence") >/dev/null ||
    die 'candidate no longer advances current stable manifest'
else
  die 'verification receipt has an inconsistent prior-pair state'
fi

"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" || die 'release tag changed before stable publication'
"$PUBLISHER" \
  'wedecent-downloads' 'windows/stable/manifest-v1.json' 'windows/stable/manifest-v1.sig' \
  "$MANIFEST" "$SIGNATURE" \
  "${fields[expected_manifest_sha256]}" "${fields[expected_signature_sha256]}" ||
  die 'atomic compare-and-swap stable pair publisher failed'

published_manifest="$tmpdir/published-manifest.json"
published_signature="$tmpdir/published-manifest.sig"
curl -fsS --retry 5 --retry-all-errors --proto '=https' "$base/manifest-v1.json" -o "$published_manifest" || die 'published manifest read-back failed'
curl -fsS --retry 5 --retry-all-errors --proto '=https' "$base/manifest-v1.sig" -o "$published_signature" || die 'published signature read-back failed'
cmp -s "$MANIFEST" "$published_manifest" || die 'published manifest bytes differ from verified candidate'
cmp -s "$SIGNATURE" "$published_signature" || die 'published signature bytes differ from verified candidate'
(cd "$ROOT" && go run ./cmd/wd-update-manifest verify --public-key "$PUBLIC_KEY" --manifest "$published_manifest" --signature "$published_signature") >/dev/null ||
  die 'published stable pair failed independent signature verification'
printf 'Stable update pair published atomically and verified by read-back.\n'
