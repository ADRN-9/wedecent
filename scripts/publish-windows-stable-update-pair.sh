#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROOT_KEY_ID="${WEDECENT_UPDATE_ROOT_KEY_ID:-}"
ROOT_PUBLIC_KEY="${WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH:-}"
R2_ACCOUNT_ID="${WEDECENT_R2_ACCOUNT_ID:-}"
R2_BUCKET="${WEDECENT_R2_BUCKET:-wedecent-downloads}"
KEYSET=""
KEYSET_SIGNATURE=""
MANIFEST=""
SIGNATURE=""
PAIR=""
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
    --pair) (($# >= 2)) || die '--pair requires a value'; PAIR="$2"; shift 2 ;;
    --receipt) (($# >= 2)) || die '--receipt requires a value'; RECEIPT="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$ROOT_KEY_ID" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] || die 'root key ID is invalid'
[[ "$R2_ACCOUNT_ID" =~ ^[a-f0-9]{32}$ ]] || die 'R2 account ID is required'
[[ "$R2_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || die 'R2 bucket name is invalid'
for path in "$ROOT_PUBLIC_KEY" "$KEYSET" "$KEYSET_SIGNATURE" "$MANIFEST" "$SIGNATURE" "$PAIR" "$RECEIPT"; do
  [[ "$path" == /* && -f "$path" && ! -L "$path" ]] || die "input must be an absolute regular non-symlink file: $path"
done
[[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]] || die 'publisher-only R2 credentials are required'
export AWS_DEFAULT_REGION=auto AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
command -v aws >/dev/null 2>&1 || die 'AWS CLI v2 is required for conditional R2 writes'
aws --version 2>&1 | grep -q '^aws-cli/2\.' || die 'AWS CLI v2 is required for conditional R2 writes'
for command in curl sha256sum awk go realpath cmp stat python3; do command -v "$command" >/dev/null 2>&1 || die "missing command: $command"; done

VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
wedecent_require_production_release_context "$VERSION" || die 'production release context invalid'
wedecent_require_approved_replay_trust || die 'replay trust validation failed'
wedecent_require_approved_checkpoint_audit_trust || die 'checkpoint audit trust validation failed'

declare -A fields=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" == *=* ]] || die 'malformed verification receipt line'
  key="${line%%=*}"
  value="${line#*=}"
  case "$key" in
    candidate_pair_sha256|expected_pair_sha256|keyset_sha256|keyset_signature_sha256|root_public_key_sha256|sequence|version|keyset_epoch|keyset_digest) ;;
    *) die "unknown receipt field: $key" ;;
  esac
  [[ -z "${fields[$key]+x}" ]] || die "duplicate receipt field: $key"
  fields[$key]="$value"
done < "$RECEIPT"
for key in candidate_pair_sha256 expected_pair_sha256 keyset_sha256 keyset_signature_sha256 root_public_key_sha256 sequence version keyset_epoch keyset_digest; do
  [[ -n "${fields[$key]:-}" ]] || die "missing receipt field: $key"
done
for key in candidate_pair_sha256 keyset_sha256 keyset_signature_sha256 root_public_key_sha256 keyset_digest; do
  [[ "${fields[$key]}" =~ ^[0-9a-f]{64}$ ]] || die "invalid receipt digest: $key"
done
[[ "${fields[expected_pair_sha256]}" == '-' || "${fields[expected_pair_sha256]}" =~ ^[0-9a-f]{64}$ ]] || die 'invalid expected pair digest'
[[ "${fields[sequence]}" =~ ^[1-9][0-9]*$ && "${fields[keyset_epoch]}" =~ ^[1-9][0-9]*$ ]] || die 'invalid receipt sequence or keyset epoch'
[[ "${fields[version]}" == "$GITHUB_REF_NAME" ]] || die 'receipt version does not match release tag'

sha_file() { sha256sum "$1" | awk '{print tolower($1)}'; }
[[ "$(sha_file "$PAIR")" == "${fields[candidate_pair_sha256]}" ]] || die 'candidate pair digest differs from verifier receipt'
[[ "$(sha_file "$KEYSET")" == "${fields[keyset_sha256]}" ]] || die 'keyset digest differs from verifier receipt'
[[ "$(sha_file "$KEYSET_SIGNATURE")" == "${fields[keyset_signature_sha256]}" ]] || die 'keyset signature digest differs from verifier receipt'
[[ "$(sha_file "$ROOT_PUBLIC_KEY")" == "${fields[root_public_key_sha256]}" ]] || die 'root public key differs from verifier receipt'

tmpdir="$(mktemp -d)"
chmod 0700 "$tmpdir"
trap 'rm -rf -- "$tmpdir"' EXIT
candidate_output="$tmpdir/candidate.txt"
pair_manifest="$tmpdir/pair-manifest.json"
pair_signature="$tmpdir/pair-manifest.sig"
(cd "$ROOT" && go run ./cmd/wd-update-manifest unpack-pair --pair "$PAIR" --manifest-out "$pair_manifest" --signature-out "$pair_signature") >/dev/null || die 'candidate atomic pair envelope is invalid'
cmp -s "$MANIFEST" "$pair_manifest" || die 'pair manifest differs from independently verified manifest'
cmp -s "$SIGNATURE" "$pair_signature" || die 'pair signature differs from independently verified signature'
(cd "$ROOT" && go run ./cmd/wd-update-manifest verify-v2 \
  --root-key-id "$ROOT_KEY_ID" --root-public-key "$ROOT_PUBLIC_KEY" \
  --keyset "$KEYSET" --keyset-signature "$KEYSET_SIGNATURE" \
  --manifest "$MANIFEST" --signature "$SIGNATURE") > "$candidate_output" || die 'candidate root keyset or v2 manifest invalid'
mapfile -t candidate_fields < "$candidate_output"
[[ "${#candidate_fields[@]}" == 4 && "${candidate_fields[0]}" == "sequence=${fields[sequence]}" && "${candidate_fields[1]}" == "version=${fields[version]}" && "${candidate_fields[2]}" == "keyset_epoch=${fields[keyset_epoch]}" && "${candidate_fields[3]}" == "keyset_digest=${fields[keyset_digest]}" ]] || die 'candidate differs from independent verifier receipt'

ENDPOINT="https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com"
STABLE_KEY='windows/stable/current-v2.json'
KEYSET_PREFIX="windows/stable/keysets/${fields[keyset_epoch]}"
get_object() {
  local key="$1" output="$2"
  aws s3api get-object --endpoint-url "$ENDPOINT" --bucket "$R2_BUCKET" --key "$key" "$output" >/dev/null 2>"$tmpdir/aws-get.err"
}
head_etag() {
  local key="$1" output_name="$2"
  local value
  if value="$(aws s3api head-object --endpoint-url "$ENDPOINT" --bucket "$R2_BUCKET" --key "$key" --query ETag --output text 2>"$tmpdir/aws-head.err")"; then
    printf '%s\n' "$value"
    return 0
  fi
  if grep -Eqi '404|Not Found|NoSuchKey' "$tmpdir/aws-head.err"; then
    printf '%s\n' '-'
    return 0
  fi
  cat "$tmpdir/aws-head.err" >&2
  die "R2 HeadObject failed for $key"
}
put_create_only() {
  local key="$1" source="$2" content_type="$3" existing="$tmpdir/existing-$(basename "$key")"
  local etag
  etag="$(head_etag "$key" unused)"
  if [[ "$etag" != '-' ]]; then
    get_object "$key" "$existing" || die "cannot read existing immutable object $key"
    cmp -s "$source" "$existing" || die "immutable keyset object already exists with different bytes: $key"
    return 0
  fi
  if ! aws s3api put-object --endpoint-url "$ENDPOINT" --bucket "$R2_BUCKET" --key "$key" \
      --body "$source" --content-type "$content_type" --cache-control 'public, max-age=31536000, immutable' \
      --if-none-match '*' >/dev/null 2>"$tmpdir/aws-put-create.err"; then
    # A competing create is harmless only if the committed object is byte-identical.
    if get_object "$key" "$existing" && cmp -s "$source" "$existing"; then return 0; fi
    cat "$tmpdir/aws-put-create.err" >&2
    die "atomic create-only R2 write failed for $key"
  fi
  get_object "$key" "$existing" || die "R2 immutable-object read-back failed for $key"
  cmp -s "$source" "$existing" || die "R2 immutable-object read-back differs for $key"
}
put_create_only "$KEYSET_PREFIX/keyset.json" "$KEYSET" 'application/json'
put_create_only "$KEYSET_PREFIX/keyset.sig" "$KEYSET_SIGNATURE" 'text/plain'

# Compare the exact previously verified bytes, then use the R2 ETag as the
# conditional-write token. R2 evaluates If-Match/If-None-Match atomically at
# object commit, so competing writers cannot both replace this single envelope.
current="$tmpdir/current-v2.json"
etag="$(head_etag "$STABLE_KEY" unused)"
expected="${fields[expected_pair_sha256]}"
if [[ "$etag" == '-' ]]; then
  [[ "$expected" == '-' ]] || die 'stable pair disappeared after independent verification'
else
  [[ "$expected" != '-' ]] || die 'stable pair appeared after independent verification'
  get_object "$STABLE_KEY" "$current" || die 'cannot read current R2 stable pair'
  [[ "$(sha_file "$current")" == "$expected" ]] || die 'stable pair changed after independent verification'
fi

if [[ "$etag" == '-' ]]; then
  put_args=(--if-none-match '*')
else
  put_args=(--if-match "$etag")
fi
if ! aws s3api put-object --endpoint-url "$ENDPOINT" --bucket "$R2_BUCKET" --key "$STABLE_KEY" \
    --body "$PAIR" --content-type 'application/json' --content-disposition 'inline' \
    --cache-control 'public, max-age=30, must-revalidate' "${put_args[@]}" \
    >/dev/null 2>"$tmpdir/aws-put-cas.err"; then
  # Reconcile an ambiguous response or a competing identical publication.
  if get_object "$STABLE_KEY" "$current" && cmp -s "$PAIR" "$current"; then
    printf 'Stable pair already committed with identical bytes.\n'
  else
    cat "$tmpdir/aws-put-cas.err" >&2
    die 'atomic R2 stable-pair CAS failed; concurrent update preserved'
  fi
fi
get_object "$STABLE_KEY" "$current" || die 'R2 stable-pair read-back failed'
cmp -s "$PAIR" "$current" || die 'R2 stable-pair read-back differs from verified candidate'
printf 'Stable v2 pair committed as one R2 object with conditional CAS and exact read-back.\n'
