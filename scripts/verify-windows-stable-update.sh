#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PUBLIC_KEY="${WEDECENT_UPDATE_PUBLIC_KEY_PATH:-}"
MANIFEST=""
SIGNATURE=""
RECEIPT=""

die() { printf 'verify-windows-stable-update: %s\n' "$*" >&2; exit 1; }

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
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]] || die 'manifest must be a regular non-symlink file'
[[ -f "$SIGNATURE" && ! -L "$SIGNATURE" ]] || die 'signature must be a regular non-symlink file'
[[ "$RECEIPT" == /* && ! -e "$RECEIPT" && ! -L "$RECEIPT" ]] || die 'receipt must be a new absolute path'
for command in curl sha256sum awk go; do command -v "$command" >/dev/null 2>&1 || die "missing command: $command"; done
[[ "${GITHUB_REF_TYPE:-}" == tag && "${GITHUB_REPOSITORY:-}" == ADRN-9/wedecent && "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || die 'verification job is not bound to the expected immutable GitHub release'
"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" || die 'live release tag does not match workflow commit'

verify_pair() {
  local manifest="$1" signature="$2" output="$3"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify --public-key "$PUBLIC_KEY" --manifest "$manifest" --signature "$signature") > "$output"
}

candidate_output="$(mktemp)"
old_output="$(mktemp)"
old_manifest="$(mktemp)"
old_signature="$(mktemp)"
trap 'rm -f -- "$candidate_output" "$old_output" "$old_manifest" "$old_signature"' EXIT

verify_pair "$MANIFEST" "$SIGNATURE" "$candidate_output" || die 'candidate signature/canonical manifest invalid'
mapfile -t candidate_fields < "$candidate_output"
[[ "${#candidate_fields[@]}" == 2 && "${candidate_fields[0]}" =~ ^sequence=[1-9][0-9]*$ && "${candidate_fields[1]}" =~ ^version=v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die 'candidate verifier output malformed'
sequence="${candidate_fields[0]#sequence=}"
version="${candidate_fields[1]#version=}"

base='https://downloads.wedecent.com/windows/stable'
probe() {
  local status
  status="$(curl --disable -sS -I --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$1")" || die "cannot determine stable object state: $1"
  case "$status" in 200|404) printf '%s\n' "$status" ;; *) die "ambiguous stable object HTTP status $status" ;; esac
}
manifest_status="$(probe "$base/manifest-v1.json")"
signature_status="$(probe "$base/manifest-v1.sig")"
expected_manifest='-'
expected_signature='-'

if [[ "$manifest_status" == 200 && "$signature_status" == 200 ]]; then
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v1.json" -o "$old_manifest" || die 'cannot fetch current stable manifest'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v1.sig" -o "$old_signature" || die 'cannot fetch current stable signature'
  verify_pair "$old_manifest" "$old_signature" "$old_output" || die 'existing stable pair is invalid'
  mapfile -t old_fields < "$old_output"
  [[ "${#old_fields[@]}" == 2 && "${old_fields[0]}" =~ ^sequence=[1-9][0-9]*$ && "${old_fields[1]}" =~ ^version=v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die 'existing verifier output malformed'
  old_sequence="${old_fields[0]#sequence=}"
  old_version="${old_fields[1]#version=}"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify --public-key "$PUBLIC_KEY" --manifest "$MANIFEST" --signature "$SIGNATURE" --current-version "$old_version" --current-sequence "$old_sequence") >/dev/null ||
    die 'candidate does not advance current stable version and sequence'
  expected_manifest="$(sha256sum "$old_manifest" | awk '{print tolower($1)}')"
  expected_signature="$(sha256sum "$old_signature" | awk '{print tolower($1)}')"
elif [[ "$manifest_status" == 404 && "$signature_status" == 404 ]]; then
  :
else
  die 'stable manifest/signature presence is inconsistent'
fi

manifest_sha="$(sha256sum "$MANIFEST" | awk '{print tolower($1)}')"
signature_sha="$(sha256sum "$SIGNATURE" | awk '{print tolower($1)}')"
public_key_sha="$(sha256sum "$PUBLIC_KEY" | awk '{print tolower($1)}')"
[[ "$manifest_sha" =~ ^[0-9a-f]{64}$ && "$signature_sha" =~ ^[0-9a-f]{64}$ && "$public_key_sha" =~ ^[0-9a-f]{64}$ ]] || die 'invalid receipt digest'
(
  set -o noclobber
  printf 'manifest_sha256=%s\nsignature_sha256=%s\npublic_key_sha256=%s\nexpected_manifest_sha256=%s\nexpected_signature_sha256=%s\nsequence=%s\nversion=%s\n' \
    "$manifest_sha" "$signature_sha" "$public_key_sha" "$expected_manifest" "$expected_signature" "$sequence" "$version" > "$RECEIPT"
) || die 'cannot create exclusive verification receipt'
printf 'Stable update candidate verified independently; rollback policy passed.\n'
