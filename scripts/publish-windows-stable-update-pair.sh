#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROOT_KEY_ID="${WEDECENT_UPDATE_ROOT_KEY_ID:-}"
ROOT_PUBLIC_KEY="${WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH:-}"
PUBLISHER="${WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER:-}"
PUBLISHER_SHA_EXPECTED="${WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER_SHA256:-}"
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
[[ "$PUBLISHER" == /* && -f "$PUBLISHER" && -x "$PUBLISHER" && ! -L "$PUBLISHER" ]] || die 'publisher must be an absolute regular executable, not a symlink'
PUBLISHER="$(realpath -e -- "$PUBLISHER")" || die 'cannot resolve publisher'
[[ "$PUBLISHER_SHA_EXPECTED" =~ ^[0-9a-f]{64}$ ]] || die 'publisher SHA-256 pin is required'
PUBLISHER_SHA_ACTUAL="$(sha256sum "$PUBLISHER" | awk '{print tolower($1)}')"
[[ "$PUBLISHER_SHA_ACTUAL" == "$PUBLISHER_SHA_EXPECTED" ]] || die 'publisher executable does not match its pinned SHA-256'
PUBLISHER_MODE="$(stat -c '%a' "$PUBLISHER")"
[[ "$PUBLISHER_MODE" =~ ^[0-7]{3,4}$ ]] || die 'invalid publisher file mode'
[[ ! "$PUBLISHER_MODE" =~ [2367][0-7]$ && ! "$PUBLISHER_MODE" =~ [0-7][2367]$ ]] || die 'publisher executable is group/world writable'

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
[[ "${fields[sequence]}" =~ ^[1-9][0-9]*$ ]] || die 'invalid receipt sequence'
[[ "${fields[keyset_epoch]}" =~ ^[1-9][0-9]*$ ]] || die 'invalid receipt keyset epoch'
[[ "${fields[version]}" == "$GITHUB_REF_NAME" ]] || die 'receipt version does not match release tag'

sha_file() { sha256sum "$1" | awk '{print tolower($1)}'; }
[[ "$(sha_file "$MANIFEST")" == "${fields[manifest_sha256]}" ]] || die 'manifest digest differs from verifier receipt'
[[ "$(sha_file "$SIGNATURE")" == "${fields[signature_sha256]}" ]] || die 'signature digest differs from verifier receipt'
[[ "$(sha_file "$KEYSET")" == "${fields[keyset_sha256]}" ]] || die 'keyset digest differs from verifier receipt'
[[ "$(sha_file "$KEYSET_SIGNATURE")" == "${fields[keyset_signature_sha256]}" ]] || die 'keyset signature digest differs from verifier receipt'
[[ "$(sha_file "$ROOT_PUBLIC_KEY")" == "${fields[root_public_key_sha256]}" ]] || die 'root public key differs from independent verifier receipt'

tmpdir="$(mktemp -d)"
chmod 0700 "$tmpdir"
trap 'rm -rf -- "$tmpdir"' EXIT
candidate_output="$tmpdir/candidate.txt"
old_output="$tmpdir/old.txt"
old_manifest="$tmpdir/old-manifest.json"
old_signature="$tmpdir/old-manifest.sig"
old_keyset="$tmpdir/old-keyset.json"
old_keyset_signature="$tmpdir/old-keyset.sig"
published_keyset="$tmpdir/published-keyset.json"
published_keyset_signature="$tmpdir/published-keyset.sig"
base='https://downloads.wedecent.com/windows/stable'

verify_pair() {
  local keyset="$1" keyset_signature="$2" manifest="$3" signature="$4" output="$5"
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify-v2 \
    --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" \
    --keyset "$keyset" --keyset-signature "$keyset_signature" \
    --manifest "$manifest" --signature "$signature") > "$output"
}

verify_pair "$KEYSET" "$KEYSET_SIGNATURE" "$MANIFEST" "$SIGNATURE" "$candidate_output" ||
  die 'candidate root keyset or v2 manifest invalid'
mapfile -t candidate_fields < "$candidate_output"
[[ "${#candidate_fields[@]}" == 4 &&
   "${candidate_fields[0]}" == "sequence=${fields[sequence]}" &&
   "${candidate_fields[1]}" == "version=${fields[version]}" &&
   "${candidate_fields[2]}" == "keyset_epoch=${fields[keyset_epoch]}" &&
   "${candidate_fields[3]}" == "keyset_digest=${fields[keyset_digest]}" ]] ||
  die 'candidate fields differ from independent verification receipt'

candidate_keyset_url="$base/keysets/${fields[keyset_epoch]}/keyset.json"
candidate_keyset_signature_url="$base/keysets/${fields[keyset_epoch]}/keyset.sig"
curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$candidate_keyset_url" -o "$published_keyset" ||
  die 'root-signed candidate keyset is not prepublished at its immutable epoch URL'
curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$candidate_keyset_signature_url" -o "$published_keyset_signature" ||
  die 'candidate keyset signature is not prepublished'
cmp -s "$KEYSET" "$published_keyset" || die 'published keyset bytes differ from the verified candidate'
cmp -s "$KEYSET_SIGNATURE" "$published_keyset_signature" || die 'published keyset signature differs from the verified candidate'

probe() {
  local status
  status="$(curl --disable -sS -I --connect-timeout 10 --max-time 30 -o /dev/null -w '%{http_code}' "$1")" ||
    die "cannot determine stable object state: $1"
  case "$status" in 200|404) printf '%s\n' "$status" ;; *) die "ambiguous stable object HTTP status $status" ;; esac
}
manifest_status="$(probe "$base/manifest-v2.json")"
signature_status="$(probe "$base/manifest-v2.sig")"
if [[ "${fields[expected_manifest_sha256]}" == '-' &&
      "${fields[expected_signature_sha256]}" == '-' &&
      "${fields[expected_keyset_sha256]}" == '-' &&
      "${fields[expected_keyset_signature_sha256]}" == '-' ]]; then
  [[ "$manifest_status" == 404 && "$signature_status" == 404 ]] || die 'stable channel changed after independent verification'
elif [[ "${fields[expected_manifest_sha256]}" =~ ^[0-9a-f]{64}$ &&
        "${fields[expected_signature_sha256]}" =~ ^[0-9a-f]{64}$ &&
        "${fields[expected_keyset_sha256]}" =~ ^[0-9a-f]{64}$ &&
        "${fields[expected_keyset_signature_sha256]}" =~ ^[0-9a-f]{64}$ ]]; then
  [[ "$manifest_status" == 200 && "$signature_status" == 200 ]] || die 'stable channel presence changed after independent verification'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v2.json" -o "$old_manifest" || die 'cannot fetch prior stable manifest'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$base/manifest-v2.sig" -o "$old_signature" || die 'cannot fetch prior stable signature'
  [[ "$(sha_file "$old_manifest")" == "${fields[expected_manifest_sha256]}" ]] || die 'prior manifest changed since independent verification'
  [[ "$(sha_file "$old_signature")" == "${fields[expected_signature_sha256]}" ]] || die 'prior signature changed since independent verification'
  old_epoch="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); e=d.get("keyset_epoch"); assert d.get("schema")==2 and isinstance(e,int) and e>0; print(e)' "$old_manifest")" ||
    die 'prior manifest does not identify a valid keyset epoch'
  old_keyset_url="$base/keysets/$old_epoch/keyset.json"
  old_keyset_signature_url="$base/keysets/$old_epoch/keyset.sig"
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$old_keyset_url" -o "$old_keyset" || die 'cannot fetch prior root-signed keyset'
  curl --disable -fsS --retry 3 --retry-all-errors --proto '=https' "$old_keyset_signature_url" -o "$old_keyset_signature" || die 'cannot fetch prior keyset signature'
  [[ "$(sha_file "$old_keyset")" == "${fields[expected_keyset_sha256]}" ]] || die 'prior keyset changed since independent verification'
  [[ "$(sha_file "$old_keyset_signature")" == "${fields[expected_keyset_signature_sha256]}" ]] || die 'prior keyset signature changed since independent verification'
  verify_pair "$old_keyset" "$old_keyset_signature" "$old_manifest" "$old_signature" "$old_output" ||
    die 'current stable v2 pair is invalid'
  mapfile -t old_fields < "$old_output"
  [[ "${#old_fields[@]}" == 4 && "${old_fields[0]}" == sequence=* && "${old_fields[1]}" == version=* &&
     "${old_fields[2]}" == keyset_epoch=* && "${old_fields[3]}" == keyset_digest=* ]] || die 'prior verifier output malformed'
  old_sequence="${old_fields[0]#sequence=}"
  old_version="${old_fields[1]#version=}"
  old_epoch="${old_fields[2]#keyset_epoch=}"
  old_digest="${old_fields[3]#keyset_digest=}"
  candidate_epoch="${fields[keyset_epoch]}"
  candidate_digest="${fields[keyset_digest]}"
  if ((candidate_epoch < old_epoch)); then
    die 'candidate keyset epoch rolls back the current stable channel'
  fi
  if ((candidate_epoch == old_epoch)) && [[ "$candidate_digest" != "$old_digest" ]]; then
    die 'candidate keyset equivocates at the current stable epoch'
  fi
  if ((candidate_epoch > old_epoch)) && [[ "$candidate_digest" == "$old_digest" ]]; then
    die 'new keyset epoch reuses the previous keyset digest'
  fi
  (cd "$ROOT" && go run ./cmd/wd-update-manifest verify-v2 \
    --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" \
    --keyset "$KEYSET" --keyset-signature "$KEYSET_SIGNATURE" \
    --manifest "$MANIFEST" --signature "$SIGNATURE" \
    --current-version "$old_version" --current-sequence "$old_sequence") >/dev/null ||
    die 'candidate no longer advances the current stable version and sequence'
else
  die 'verification receipt has an inconsistent prior-pair state'
fi

"$ROOT/scripts/verify-live-release-tag.sh" "$ROOT" "$GITHUB_REF_NAME" "$GITHUB_SHA" ||
  die 'release tag changed before stable publication'
"$PUBLISHER" \
  'wedecent-downloads' 'windows/stable/manifest-v2.json' 'windows/stable/manifest-v2.sig' \
  "$MANIFEST" "$SIGNATURE" \
  "${fields[expected_manifest_sha256]}" "${fields[expected_signature_sha256]}" ||
  die 'atomic compare-and-swap stable v2 pair publisher failed'

published_manifest="$tmpdir/published-manifest.json"
published_signature="$tmpdir/published-manifest.sig"
curl --disable -fsS --retry 5 --retry-all-errors --proto '=https' "$base/manifest-v2.json" -o "$published_manifest" ||
  die 'published stable manifest read-back failed'
curl --disable -fsS --retry 5 --retry-all-errors --proto '=https' "$base/manifest-v2.sig" -o "$published_signature" ||
  die 'published stable signature read-back failed'
cmp -s "$MANIFEST" "$published_manifest" || die 'published manifest differs from verified candidate'
cmp -s "$SIGNATURE" "$published_signature" || die 'published signature differs from verified candidate'
verify_pair "$KEYSET" "$KEYSET_SIGNATURE" "$published_manifest" "$published_signature" "$tmpdir/published-verification.txt" ||
  die 'published stable pair failed root-keyset and manifest verification'
printf 'Stable schema-v2 manifest pair published atomically and verified by read-back.\n'
