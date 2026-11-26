#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROOT_KEY_ID="${WEDECENT_UPDATE_ROOT_KEY_ID:-}"
ROOT_PUBLIC_KEY="${WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH:-}"
PUBLISHER="${WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER:-}"
PUBLISHER_SHA_EXPECTED="${WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER_SHA256:-}"
UPLOADER="${WEDECENT_R2_CREATE_ONLY_UPLOADER:-}"
UPLOADER_SHA_EXPECTED="${WEDECENT_R2_CREATE_ONLY_UPLOADER_SHA256:-}"
KEYSET=""
KEYSET_SIGNATURE=""
MANIFEST=""
SIGNATURE=""
RECEIPT=""

die() { printf 'publish-windows-stable-update-pair: %s\n' "$*" >&2; exit 1; }

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
for path in "$ROOT_PUBLIC_KEY" "$KEYSET" "$KEYSET_SIGNATURE" "$MANIFEST" "$SIGNATURE" "$RECEIPT"; do
  [[ "$path" == /* && -f "$path" && ! -L "$path" ]] || die "input must be an absolute regular non-symlink file: $path"
done
for spec in "publisher:$PUBLISHER:$PUBLISHER_SHA_EXPECTED" "uploader:$UPLOADER:$UPLOADER_SHA_EXPECTED"; do
  IFS=: read -r label executable expected <<< "$spec"
  [[ "$executable" == /* && -f "$executable" && -x "$executable" && ! -L "$executable" ]] || die "$label must be an absolute regular executable"
  actual="$(sha256sum "$executable" | awk '{print tolower($1)}')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || die "$label executable digest pin mismatch"
  mode="$(stat -c '%a' "$executable")"
  [[ "$mode" =~ ^[0-7]{3,4}$ && ! "$mode" =~ [2367][0-7]$ && ! "$mode" =~ [0-7][2367]$ ]] || die "$label executable permissions are unsafe"
done
PUBLISHER="$(realpath -e -- "$PUBLISHER")"
UPLOADER="$(realpath -e -- "$UPLOADER")"

VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
wedecent_require_production_release_context "$VERSION" || die 'production release context invalid'
wedecent_require_approved_replay_trust || die 'replay trust validation failed'
wedecent_require_approved_checkpoint_audit_trust || die 'checkpoint audit trust validation failed'
for command in curl sha256sum awk go realpath cmp stat python3; do command -v "$command" >/dev/null 2>&1 || die "missing command: $command"; done

declare -A fields=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" == *=* ]] || die 'malformed verification receipt line'
  key="${line%%=*}"
  value="${line#*=}"
  case "$key" in
    manifest_sha256|signature_sha256|keyset_sha256|keyset_signature_sha256|root_public_key_sha256|expected_manifest_sha256|expected_signature_sha256|expected_keyset_sha256|expected_keyset_signature_sha256|sequence|version|keyset_epoch|keyset_digest) ;;
    *) die "unknown receipt field: $key" ;;
  esac
  [[ -z "${fields[$key]+x}" ]] || die "duplicate receipt field: $key"
  fields[$key]="$value"
done < "$RECEIPT"
for key in manifest_sha256 signature_sha256 keyset_sha256 keyset_signature_sha256 root_public_key_sha256 expected_manifest_sha256 expected_signature_sha256 expected_keyset_sha256 expected_keyset_signature_sha256 sequence version keyset_epoch keyset_digest; do
  [[ -n "${fields[$key]:-}" ]] || die "missing receipt field: $key"
done
for key in manifest_sha256 signature_sha256 keyset_sha256 keyset_signature_sha256 root_public_key_sha256 keyset_digest; do
  [[ "${fields[$key]}" =~ ^[0-9a-f]{64}$ ]] || die "invalid receipt digest: $key"
done
for key in expected_manifest_sha256 expected_signature_sha256 expected_keyset_sha256 expected_keyset_signature_sha256; do
  [[ "${fields[$key]}" == '-' || "${fields[$key]}" =~ ^[0-9a-f]{64}$ ]] || die "invalid expected digest: $key"
done
[[ "${fields[sequence]}" =~ ^[1-9][0-9]*$ && "${fields[keyset_epoch]}" =~ ^[1-9][0-9]*$ ]] || die 'invalid receipt sequence or keyset epoch'
[[ "${fields[version]}" == "$GITHUB_REF_NAME" ]] || die 'receipt version does not match release tag'

sha_file() { sha256sum "$1" | awk '{print tolower($1)}'; }
[[ "$(sha_file "$MANIFEST")" == "${fields[manifest_sha256]}" ]] || die 'manifest digest differs from verifier receipt'
[[ "$(sha_file "$SIGNATURE")" == "${fields[signature_sha256]}" ]] || die 'manifest signature digest differs from verifier receipt'
[[ "$(sha_file "$KEYSET")" == "${fields[keyset_sha256]}" ]] || die 'keyset digest differs from verifier receipt'
[[ "$(sha_file "$KEYSET_SIGNATURE")" == "${fields[keyset_signature_sha256]}" ]] || die 'keyset signature digest differs from verifier receipt'
[[ "$(sha_file "$ROOT_PUBLIC_KEY")" == "${fields[root_public_key_sha256]}" ]] || die 'root public key differs from verifier receipt'

tmpdir="$(mktemp -d)"
chmod 0700 "$tmpdir"
trap 'rm -rf -- "$tmpdir"' EXIT
candidate_output="$tmpdir/candidate.txt"
old_output="$tmpdir/old.txt"
old_keyset="$tmpdir/old-keyset.json"
old_keyset_signature="$tmpdir/old-keyset.sig"
old_manifest="$tmpdir/old-manifest.json"
old_signature="$tmpdir/old-manifest.sig"
base='https://downloads.wedecent.com/windows/stable'

verify_pair() {
  local keyset="$1" keyset_signature="$2" manifest="$3" signature="$4" output="$5"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify-v2 \
    --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" \
    --keyset "$keyset" --keyset-signature "$keyset_signature" \
    --manifest "$manifest" --signature "$signature") > "$output"
}
verify_pair "$KEYSET" "$KEYSET_SIGNATURE" "$MANIFEST" "$SIGNATURE" "$candidate_output" || die 'candidate root keyset or v2 manifest invalid'
mapfile -t candidate_fields < "$candidate_output"
[[ "${#candidate_fields[@]}" == 4 && "${candidate_fields[0]}" == "sequence=${fields[sequence]}" && "${candidate_fields[1]}" == "version=${fields[version]}" && "${candidate_fields[2]}" == "keyset_epoch=${fields[keyset_epoch]}" && "${candidate_fields[3]}" == "keyset_digest=${fields[keyset_digest]}" ]] || die 'candidate differs from independent verification receipt'

# Publish the immutable epoch keyset before moving the stable manifest pointer.
# Existing objects are accepted only when their bytes exactly match this candidate.
epoch="${fields[keyset_epoch]}"
for item in "keyset.json:$KEYSET:application/json" "keyset.sig:$KEYSET_SIGNATURE:text/plain"; do
  IFS=: read -r name source content_type <<< "$item"
  key="windows/stable/keysets/$epoch/$name"
  url="$base/keysets/$epoch/$name"
  status="$(curl --disable -sS -I --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$url")" || die "cannot probe immutable keyset object: $url"
  case "$status" in
    404)
      "$UPLOADER" 'wedecent-downloads' "$key" "$source" "$content_type" 'attachment' 'public, max-age=31536000, immutable' || die "create-only keyset upload failed: $key"
      ;;
    200)
      remote="$tmpdir/$name.remote"
      curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$url" -o "$remote" || die "cannot read existing immutable keyset object: $url"
      cmp -s "$source" "$remote" || die "immutable keyset object already exists with different bytes: $key"
      ;;
    *) die "ambiguous immutable keyset HTTP status $status for $url" ;;
  esac
done

manifest_status="$(curl --disable -sS -I --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$base/manifest-v2.json")" || die 'cannot probe current stable manifest'
signature_status="$(curl --disable -sS -I --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$base/manifest-v2.sig")" || die 'cannot probe current stable signature'
if [[ "${fields[expected_manifest_sha256]}" == '-' && "${fields[expected_signature_sha256]}" == '-' ]]; then
  [[ "$manifest_status" == 404 && "$signature_status" == 404 ]] || die 'stable channel changed after independent verification'
elif [[ "${fields[expected_manifest_sha256]}" =~ ^[0-9a-f]{64}$ && "${fields[expected_signature_sha256]}" =~ ^[0-9a-f]{64}$ ]]; then
  [[ "$manifest_status" == 200 && "$signature_status" == 200 ]] || die 'stable channel presence changed after verification'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v2.json" -o "$old_manifest" || die 'cannot fetch prior stable manifest'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v2.sig" -o "$old_signature" || die 'cannot fetch prior stable signature'
  old_epoch="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); e=d.get("keyset_epoch"); assert d.get("schema")==2 and isinstance(e,int) and e>0; print(e)' "$old_manifest")" || die 'prior stable manifest has invalid keyset epoch'
  old_base="$base/keysets/$old_epoch"
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$old_base/keyset.json" -o "$old_keyset" || die 'cannot fetch prior root-signed keyset'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$old_base/keyset.sig" -o "$old_keyset_signature" || die 'cannot fetch prior keyset signature'
  [[ "$(sha_file "$old_manifest")" == "${fields[expected_manifest_sha256]}" ]] || die 'prior manifest changed after verification'
  [[ "$(sha_file "$old_signature")" == "${fields[expected_signature_sha256]}" ]] || die 'prior signature changed after verification'
  [[ "$(sha_file "$old_keyset")" == "${fields[expected_keyset_sha256]}" ]] || die 'prior keyset changed after verification'
  [[ "$(sha_file "$old_keyset_signature")" == "${fields[expected_keyset_signature_sha256]}" ]] || die 'prior keyset signature changed after verification'
  verify_pair "$old_keyset" "$old_keyset_signature" "$old_manifest" "$old_signature" "$old_output" || die 'current stable v2 pair is invalid'
  mapfile -t old_fields < "$old_output"
  [[ "${#old_fields[@]}" == 4 ]] || die 'current stable verifier output malformed'
  old_sequence="${old_fields[0]#sequence=}"
  old_version="${old_fields[1]#version=}"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify-v2 \
    --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" \
    --keyset "$KEYSET" --keyset-signature "$KEYSET_SIGNATURE" \
    --manifest "$MANIFEST" --signature "$SIGNATURE" \
    --current-version "$old_version" --current-sequence "$old_sequence") >/dev/null || die 'candidate no longer advances stable version and sequence'
else
  die 'verification receipt has inconsistent prior-pair state'
fi

"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" || die 'release tag changed before stable publication'
"$PUBLISHER" \
  'wedecent-downloads' 'windows/stable/manifest-v2.json' 'windows/stable/manifest-v2.sig' \
  "$MANIFEST" "$SIGNATURE" \
  "${fields[expected_manifest_sha256]}" "${fields[expected_signature_sha256]}" || die 'atomic compare-and-swap stable pair publisher failed'

published_manifest="$tmpdir/published-manifest.json"
published_signature="$tmpdir/published-manifest.sig"
curl --disable -fsS --retry 5 --retry-all-errors --proto '=https' "$base/manifest-v2.json" -o "$published_manifest" || die 'published manifest read-back failed'
curl --disable -fsS --retry 5 --retry-all-errors --proto '=https' "$base/manifest-v2.sig" -o "$published_signature" || die 'published signature read-back failed'
cmp -s "$MANIFEST" "$published_manifest" || die 'published manifest bytes differ from verified candidate'
cmp -s "$SIGNATURE" "$published_signature" || die 'published signature bytes differ from verified candidate'
verify_pair "$KEYSET" "$KEYSET_SIGNATURE" "$published_manifest" "$published_signature" "$candidate_output" || die 'published stable v2 pair failed independent verification'
printf 'Stable v2 manifest pair published atomically; epoch keyset immutable and read-back verified.\n'
