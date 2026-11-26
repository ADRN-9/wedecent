#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROOT_KEY_ID="${WEDECENT_UPDATE_ROOT_KEY_ID:-}"
ROOT_PUBLIC_KEY="${WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH:-}"
KEYSET=""
KEYSET_SIGNATURE=""
MANIFEST=""
SIGNATURE=""
RECEIPT=""

die() { printf 'verify-windows-stable-update: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --root-key-id) (($# >= 2)) || die '--root-key-id requires a value'; ROOT_KEY_ID="$2"; shift 2 ;;
    --root-public-key) (($# >= 2)) || die '--root-public-key requires a value'; ROOT_PUBLIC_KEY="$2"; shift 2 ;;
    --keyset) (($# >= 2)) || die '--keyset requires a value'; KEYSET="$2"; shift 2 ;;
    --keyset-signature) (($# >= 2)) || die '--keyset-signature requires a value'; KEYSET_SIGNATURE="$2"; shift 2 ;;
    --manifest) (($# >= 2)) || die '--manifest requires a value'; MANIFEST="$2"; shift 2 ;;
    --signature) (($# >= 2)) || die '--signature requires a value'; SIGNATURE="$2"; shift 2 ;;
    --receipt) (($# >= 2)) || die '--receipt requires a value'; RECEIPT="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$ROOT_KEY_ID" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] || die 'root key ID is invalid'
for path in "$ROOT_PUBLIC_KEY" "$KEYSET" "$KEYSET_SIGNATURE" "$MANIFEST" "$SIGNATURE"; do
  [[ "$path" == /* && -f "$path" && ! -L "$path" ]] || die "input must be an absolute regular non-symlink file: $path"
done
[[ "$RECEIPT" == /* && ! -e "$RECEIPT" && ! -L "$RECEIPT" ]] || die 'receipt must be a new absolute path'
for command in curl sha256sum awk go python3; do command -v "$command" >/dev/null 2>&1 || die "missing command: $command"; done
[[ "${GITHUB_REF_TYPE:-}" == tag && "${GITHUB_REPOSITORY:-}" == ADRN-9/wedecent && "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || die 'verification job is not bound to the expected immutable GitHub release'
"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" || die 'live release tag does not match workflow commit'

verify_pair() {
  local keyset="$1" keyset_signature="$2" manifest="$3" signature="$4" output="$5"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify-v2 \
    --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" \
    --keyset "$keyset" --keyset-signature "$keyset_signature" \
    --manifest "$manifest" --signature "$signature") > "$output"
}

manifest_before="$(sha256sum "$MANIFEST" | awk '{print tolower($1)}')"
signature_before="$(sha256sum "$SIGNATURE" | awk '{print tolower($1)}')"
keyset_before="$(sha256sum "$KEYSET" | awk '{print tolower($1)}')"
keyset_signature_before="$(sha256sum "$KEYSET_SIGNATURE" | awk '{print tolower($1)}')"
candidate_output="$(mktemp)"
old_output="$(mktemp)"
old_pair="$(mktemp)"
old_manifest="$(mktemp)"
old_signature="$(mktemp)"
old_keyset="$(mktemp)"
old_keyset_signature="$(mktemp)"
rm -f -- "$old_manifest" "$old_signature" "$old_keyset" "$old_keyset_signature"
candidate_pair="${MANIFEST%/*}/current-v2.json"
trap 'rm -f -- "$candidate_output" "$old_output" "$old_pair" "$old_manifest" "$old_signature" "$old_keyset" "$old_keyset_signature"' EXIT

verify_pair "$KEYSET" "$KEYSET_SIGNATURE" "$MANIFEST" "$SIGNATURE" "$candidate_output" || die 'candidate root keyset or v2 manifest invalid'
[[ "$(sha256sum "$MANIFEST" | awk '{print tolower($1)}')" == "$manifest_before" ]] || die 'verifier modified candidate manifest bytes'
[[ "$(sha256sum "$SIGNATURE" | awk '{print tolower($1)}')" == "$signature_before" ]] || die 'verifier modified candidate signature bytes'
[[ "$(sha256sum "$KEYSET" | awk '{print tolower($1)}')" == "$keyset_before" ]] || die 'verifier modified candidate keyset bytes'
[[ "$(sha256sum "$KEYSET_SIGNATURE" | awk '{print tolower($1)}')" == "$keyset_signature_before" ]] || die 'verifier modified candidate keyset signature bytes'
mapfile -t candidate_fields < "$candidate_output"
[[ "${#candidate_fields[@]}" == 4 && "${candidate_fields[0]}" =~ ^sequence=[1-9][0-9]*$ && "${candidate_fields[1]}" =~ ^version=v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ && "${candidate_fields[2]}" =~ ^keyset_epoch=[1-9][0-9]*$ && "${candidate_fields[3]}" =~ ^keyset_digest=[0-9a-f]{64}$ ]] || die 'candidate verifier output malformed'
sequence="${candidate_fields[0]#sequence=}"
version="${candidate_fields[1]#version=}"
keyset_epoch="${candidate_fields[2]#keyset_epoch=}"
keyset_digest="${candidate_fields[3]#keyset_digest=}"

(cd "$ROOT" && go run ./cmd/wd-update-manifest create-pair --manifest "$MANIFEST" --signature "$SIGNATURE" --out "$candidate_pair") >/dev/null || die 'cannot create canonical atomic stable-pair envelope'
candidate_pair_sha="$(sha256sum "$candidate_pair" | awk '{print tolower($1)}')"

base='https://downloads.wedecent.com/windows/stable'
status="$(curl --disable -sS --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$base/current-v2.json")" || die 'cannot probe current stable-pair envelope'
expected_pair='-'
if [[ "$status" == 200 ]]; then
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/current-v2.json" -o "$old_pair" || die 'cannot fetch current stable-pair envelope'
  old_pair_sha="$(sha256sum "$old_pair" | awk '{print tolower($1)}')"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest unpack-pair --pair "$old_pair" --manifest-out "$old_manifest" --signature-out "$old_signature") >/dev/null || die 'current stable-pair envelope is malformed'
  old_epoch="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); e=d.get("keyset_epoch"); assert d.get("schema")==2 and isinstance(e,int) and e>0; print(e)' "$old_manifest")" || die 'current stable manifest has invalid keyset epoch'
  old_keyset_url="$base/keysets/$old_epoch/keyset.json"
  old_keyset_signature_url="$base/keysets/$old_epoch/keyset.sig"
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$old_keyset_url" -o "$old_keyset" || die 'cannot fetch current root-signed keyset'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$old_keyset_signature_url" -o "$old_keyset_signature" || die 'cannot fetch current keyset signature'
  verify_pair "$old_keyset" "$old_keyset_signature" "$old_manifest" "$old_signature" "$old_output" || die 'existing stable v2 pair is invalid'
  mapfile -t old_fields < "$old_output"
  [[ "${#old_fields[@]}" == 4 ]] || die 'existing verifier output malformed'
  old_sequence="${old_fields[0]#sequence=}"
  old_version="${old_fields[1]#version=}"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify-v2 \
    --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" \
    --keyset "$KEYSET" --keyset-signature "$KEYSET_SIGNATURE" \
    --manifest "$MANIFEST" --signature "$SIGNATURE" \
    --current-version "$old_version" --current-sequence "$old_sequence") >/dev/null || die 'candidate does not advance current stable version and sequence'
  expected_pair="$old_pair_sha"
elif [[ "$status" != 404 ]]; then
  die "ambiguous stable-pair HTTP status $status"
fi

root_public_sha="$(sha256sum "$ROOT_PUBLIC_KEY" | awk '{print tolower($1)}')"
keyset_sha="$(sha256sum "$KEYSET" | awk '{print tolower($1)}')"
keyset_signature_sha="$(sha256sum "$KEYSET_SIGNATURE" | awk '{print tolower($1)}')"
(
  set -o noclobber
  printf 'candidate_pair_sha256=%s\nexpected_pair_sha256=%s\nkeyset_sha256=%s\nkeyset_signature_sha256=%s\nroot_public_key_sha256=%s\nsequence=%s\nversion=%s\nkeyset_epoch=%s\nkeyset_digest=%s\n' \
    "$candidate_pair_sha" "$expected_pair" "$keyset_sha" "$keyset_signature_sha" "$root_public_sha" \
    "$sequence" "$version" "$keyset_epoch" "$keyset_digest" > "$RECEIPT"
) || die 'cannot create exclusive verification receipt'
printf 'Stable v2 manifest/signature envelope independently verified; current generation and rollback policy checked.\n'
