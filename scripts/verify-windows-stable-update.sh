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

candidate_output="$(mktemp)"
old_output="$(mktemp)"
old_keyset="$(mktemp)"
old_keyset_signature="$(mktemp)"
old_manifest="$(mktemp)"
old_signature="$(mktemp)"
trap 'rm -f -- "$candidate_output" "$old_output" "$old_keyset" "$old_keyset_signature" "$old_manifest" "$old_signature"' EXIT
manifest_before="$(sha256sum "$MANIFEST" | awk '{print tolower($1)}')"
signature_before="$(sha256sum "$SIGNATURE" | awk '{print tolower($1)}')"
keyset_before="$(sha256sum "$KEYSET" | awk '{print tolower($1)}')"
keyset_signature_before="$(sha256sum "$KEYSET_SIGNATURE" | awk '{print tolower($1)}')"
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

base='https://downloads.wedecent.com/windows/stable'
probe() {
  local status
  status="$(curl --disable -sS -I --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$1")" || die "cannot determine stable object state: $1"
  case "$status" in 200|404) printf '%s\n' "$status" ;; *) die "ambiguous stable object HTTP status $status" ;; esac
}
manifest_status="$(probe "$base/manifest-v2.json")"
signature_status="$(probe "$base/manifest-v2.sig")"
expected_manifest='-'
expected_signature='-'
expected_keyset='-'
expected_keyset_signature='-'
if [[ "$manifest_status" == 200 && "$signature_status" == 200 ]]; then
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v2.json" -o "$old_manifest" || die 'cannot fetch current stable manifest'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v2.sig" -o "$old_signature" || die 'cannot fetch current stable signature'
  old_epoch="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); e=d.get("keyset_epoch"); assert d.get("schema")==2 and isinstance(e,int) and e>0; print(e)' "$old_manifest")" || die 'current manifest does not identify a valid keyset epoch'
  old_keyset_url="${base}/keysets/${old_epoch}/keyset.json"
  old_keyset_signature_url="${base}/keysets/${old_epoch}/keyset.sig"
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$old_keyset_url" -o "$old_keyset" || die 'cannot fetch current root-signed keyset'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$old_keyset_signature_url" -o "$old_keyset_signature" || die 'cannot fetch current keyset signature'
  verify_pair "$old_keyset" "$old_keyset_signature" "$old_manifest" "$old_signature" "$old_output" || die 'existing stable v2 pair is invalid'
  mapfile -t old_fields < "$old_output"
  [[ "${#old_fields[@]}" == 4 ]] || die 'existing verifier output malformed'
  old_sequence="${old_fields[0]#sequence=}"
  old_version="${old_fields[1]#version=}"
  old_verified_epoch="${old_fields[2]#keyset_epoch=}"
  old_verified_digest="${old_fields[3]#keyset_digest=}"
  [[ "$old_verified_epoch" =~ ^[1-9][0-9]*$ && "$old_verified_digest" =~ ^[0-9a-f]{64}$ ]] || die 'existing keyset verification output malformed'
  if ((keyset_epoch < old_verified_epoch)); then
    die 'candidate keyset epoch rolls back the current stable channel'
  fi
  if ((keyset_epoch == old_verified_epoch)) && [[ "$keyset_digest" != "$old_verified_digest" ]]; then
    die 'candidate keyset equivocates at the current stable epoch'
  fi
  if ((keyset_epoch > old_verified_epoch)) && [[ "$keyset_digest" == "$old_verified_digest" ]]; then
    die 'new keyset epoch reuses the previous keyset digest'
  fi
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify-v2 \
    --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" \
    --keyset "$KEYSET" --keyset-signature "$KEYSET_SIGNATURE" \
    --manifest "$MANIFEST" --signature "$SIGNATURE" \
    --current-version "$old_version" --current-sequence "$old_sequence") >/dev/null || die 'candidate does not advance current stable version and sequence'
  expected_manifest="$(sha256sum "$old_manifest" | awk '{print tolower($1)}')"
  expected_signature="$(sha256sum "$old_signature" | awk '{print tolower($1)}')"
  expected_keyset="$(sha256sum "$old_keyset" | awk '{print tolower($1)}')"
  expected_keyset_signature="$(sha256sum "$old_keyset_signature" | awk '{print tolower($1)}')"
elif [[ "$manifest_status" == 404 && "$signature_status" == 404 ]]; then
  :
else
  die 'stable manifest/signature presence is inconsistent'
fi

manifest_sha="$(sha256sum "$MANIFEST" | awk '{print tolower($1)}')"
signature_sha="$(sha256sum "$SIGNATURE" | awk '{print tolower($1)}')"
keyset_sha="$(sha256sum "$KEYSET" | awk '{print tolower($1)}')"
keyset_signature_sha="$(sha256sum "$KEYSET_SIGNATURE" | awk '{print tolower($1)}')"
root_public_sha="$(sha256sum "$ROOT_PUBLIC_KEY" | awk '{print tolower($1)}')"
(
  set -o noclobber
  printf 'manifest_sha256=%s\nsignature_sha256=%s\nkeyset_sha256=%s\nkeyset_signature_sha256=%s\nroot_public_key_sha256=%s\nexpected_manifest_sha256=%s\nexpected_signature_sha256=%s\nexpected_keyset_sha256=%s\nexpected_keyset_signature_sha256=%s\nsequence=%s\nversion=%s\nkeyset_epoch=%s\nkeyset_digest=%s\n' \
    "$manifest_sha" "$signature_sha" "$keyset_sha" "$keyset_signature_sha" "$root_public_sha" \
    "$expected_manifest" "$expected_signature" "$expected_keyset" "$expected_keyset_signature" \
    "$sequence" "$version" "$keyset_epoch" "$keyset_digest" > "$RECEIPT"
) || die 'cannot create exclusive verification receipt'
printf 'Stable schema-v2 update candidate independently verified; root keyset and rollback policy passed.\n'
