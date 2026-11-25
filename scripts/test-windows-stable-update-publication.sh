#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-windows-stable-update-publication: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/release-trust.sh"
TEST_HOSTNAME='replay.example.test'
TEST_PINS='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
TEST_APPROVAL="$(wedecent_replay_authority_approval_digest "$TEST_HOSTNAME" "$TEST_PINS")"
TEST_SOURCE_SHA="${GITHUB_SHA:-$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')}"
TARGET="$ROOT/scripts/publish-windows-stable-update.sh"
WORK="$(mktemp -d)"
source "$ROOT/scripts/testlib/release-tag-fixture.sh"
wedecent_test_release_tags_init "$ROOT" "$WORK"
trap 'wedecent_test_release_tags_cleanup; rm -rf -- "$WORK"' EXIT
BIN="$WORK/bin"
REMOTE="$WORK/remote"
HEAD_RETRY_MARKER="$WORK/head-retry-marker"
HEAD_CALLS="$WORK/head-calls"
printf '0\n' > "$HEAD_CALLS"
mkdir -p "$BIN" "$REMOTE/versioned" "$REMOTE/stable"

cat > "$WORK/signer.go" <<'EOF_GO'
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	seed := sha256.Sum256([]byte("wedecent deterministic update publication fixture"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if len(os.Args) == 3 && os.Args[1] == "--public-key" {
		text := base64.RawURLEncoding.EncodeToString(publicKey) + "\n"
		if err := os.WriteFile(os.Args[2], []byte(text), 0600); err != nil { panic(err) }
		return
	}
	if len(os.Args) != 3 { panic("expected manifest and signature paths") }
	manifest, err := os.ReadFile(os.Args[1])
	if err != nil { panic(err) }
	signature := ed25519.Sign(privateKey, manifest)
	text := base64.RawURLEncoding.EncodeToString(signature) + "\n"
	if err := os.WriteFile(os.Args[2], []byte(text), 0600); err != nil { panic(err) }
	fmt.Print("signed\n")
}
EOF_GO
go build -o "$BIN/signer" "$WORK/signer.go"
PUBLIC_KEY="$WORK/update-public-key.txt"
"$BIN/signer" --public-key "$PUBLIC_KEY"

cat > "$BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
out=''
head_only=0
write_status=0
url=''
while (($#)); do
  case "$1" in
    -o)
      out="$2"; shift 2 ;;
    -w)
      write_status=1; shift 2 ;;
    --retry|--proto|--connect-timeout|--max-time)
      shift 2 ;;
    -I)
      head_only=1; shift ;;
    -sS|-fsS|-fsSL|--retry-all-errors)
      shift ;;
    https://*)
      url="$1"; shift ;;
    *)
      shift ;;
  esac
done
[[ -n "$url" ]] || exit 64
prefix='https://downloads.wedecent.com/'
[[ "$url" == "$prefix"* ]] || exit 65
key="${url#"$prefix"}"
case "$key" in
  windows/stable/manifest-v1.json)
    path="$WEDECENT_FIXTURE_REMOTE/stable/current/manifest-v1.json" ;;
  windows/stable/manifest-v1.sig)
    path="$WEDECENT_FIXTURE_REMOTE/stable/current/manifest-v1.sig" ;;
  windows/v*/wedecent-v*-windows-amd64.zip)
    version="${key#windows/}"; version="${version%%/*}"
    path="$WEDECENT_FIXTURE_REMOTE/versioned/$version/release.zip" ;;
  windows/v*/wedecent-v*-windows-installer.zip)
    version="${key#windows/}"; version="${version%%/*}"
    path="$WEDECENT_FIXTURE_REMOTE/versioned/$version/installer.zip" ;;
  *)
    exit 66 ;;
esac
if [[ -f "$path" ]]; then status=200; else status=404; fi
if ((head_only)); then
  count="$(cat "$WEDECENT_FIXTURE_HEAD_CALLS")"
  printf '%d\n' "$((count + 1))" > "$WEDECENT_FIXTURE_HEAD_CALLS"
  if [[ "${WEDECENT_FIXTURE_HEAD_ALWAYS_503:-0}" == 1 ]]; then
    status=503
  elif [[ "${WEDECENT_FIXTURE_HEAD_TRANSIENT_ONCE:-0}" == 1 && ! -e "$WEDECENT_FIXTURE_HEAD_RETRY_MARKER" ]]; then
    : > "$WEDECENT_FIXTURE_HEAD_RETRY_MARKER"
    status=503
  fi
  ((write_status)) && printf '%s' "$status"
  exit 0
fi
[[ "$status" == 200 ]] || exit 22
if [[ -n "$out" ]]; then
  cp -- "$path" "$out"
else
  cat -- "$path"
fi
EOF_CURL
chmod 0700 "$BIN/curl"

cat > "$BIN/publisher" <<'EOF_PUBLISHER'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" == 7 ]] || exit 70
bucket="$1"; manifest_key="$2"; signature_key="$3"; manifest="$4"; signature="$5"; expected_manifest="$6"; expected_signature="$7"
[[ "$bucket" == 'wedecent-downloads' ]] || exit 71
[[ "$manifest_key" == 'windows/stable/manifest-v1.json' ]] || exit 72
[[ "$signature_key" == 'windows/stable/manifest-v1.sig' ]] || exit 73
current="$WEDECENT_FIXTURE_REMOTE/stable/current"
if [[ "${WEDECENT_FIXTURE_PUBLISH_CONFLICT:-0}" == 1 ]]; then
  printf 'concurrent writer changed stable manifest\n' >> "$current/manifest-v1.json"
fi
current_manifest='-'; current_signature='-'
if [[ -f "$current/manifest-v1.json" ]]; then
  current_manifest="$(sha256sum "$current/manifest-v1.json" | awk '{print tolower($1)}')"
fi
if [[ -f "$current/manifest-v1.sig" ]]; then
  current_signature="$(sha256sum "$current/manifest-v1.sig" | awk '{print tolower($1)}')"
fi
[[ "$current_manifest" == "$expected_manifest" && "$current_signature" == "$expected_signature" ]] || exit 74
tmp="$WEDECENT_FIXTURE_REMOTE/stable/pairs/.pair.$RANDOM"
link="$WEDECENT_FIXTURE_REMOTE/stable/.current.$RANDOM"
mkdir -p "$WEDECENT_FIXTURE_REMOTE/stable/pairs"
mkdir "$tmp"
trap 'rm -rf -- "$tmp"; rm -f -- "$link"' EXIT
cp -- "$manifest" "$tmp/manifest-v1.json"
cp -- "$signature" "$tmp/manifest-v1.sig"
[[ "${WEDECENT_FIXTURE_PUBLISH_FAIL:-0}" != after-stage ]] || exit 75
generation="$(sha256sum "$manifest" | awk '{print tolower($1)}')"
mv -- "$tmp" "$WEDECENT_FIXTURE_REMOTE/stable/pairs/$generation"
ln -s "pairs/$generation" "$link"
mv -Tf -- "$link" "$current"
count=0
[[ ! -f "$WEDECENT_FIXTURE_COUNTER" ]] || count="$(cat "$WEDECENT_FIXTURE_COUNTER")"
printf '%d\n' "$((count + 1))" > "$WEDECENT_FIXTURE_COUNTER"
EOF_PUBLISHER
chmod 0700 "$BIN/publisher"

make_version() {
  local version="$1"
  mkdir -p "$REMOTE/versioned/$version"
  printf 'release bytes for %s\n' "$version" > "$REMOTE/versioned/$version/release.zip"
  printf 'installer bytes for %s\n' "$version" > "$REMOTE/versioned/$version/installer.zip"
}

COUNTER="$WORK/publisher-count"
printf '0\n' > "$COUNTER"
run_publish() {
  local ref_name=''
  local -a args=("$@")
  local i
  for ((i = 0; i + 1 < ${#args[@]}; i++)); do
    if [[ "${args[$i]}" == '--version' ]]; then
      ref_name="${args[$((i + 1))]}"
      break
    fi
  done
  [[ -n "$ref_name" ]] || fail 'test invocation omitted --version'
  wedecent_test_release_tag_add "$ref_name" "$TEST_SOURCE_SHA"
  PATH="$BIN:$PATH" \
  GITHUB_ACTIONS=true \
  GITHUB_REPOSITORY='ADRN-9/wedecent' \
  GITHUB_SHA="$TEST_SOURCE_SHA" \
  GITHUB_REF_TYPE=tag \
  GITHUB_REF_NAME="$ref_name" \
  WEDECENT_PRODUCTION_RELEASE_APPROVED=true \
  WEDECENT_REPLAY_AUTHORITY_HOSTNAME="$TEST_HOSTNAME" \
  WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256="$TEST_PINS" \
  WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256="$TEST_APPROVAL" \
  WEDECENT_FIXTURE_REMOTE="$REMOTE" \
  WEDECENT_FIXTURE_COUNTER="$COUNTER" \
  WEDECENT_FIXTURE_HEAD_RETRY_MARKER="$HEAD_RETRY_MARKER" \
  WEDECENT_FIXTURE_HEAD_CALLS="$HEAD_CALLS" \
  WEDECENT_UPDATE_MANIFEST_SIGNER="$BIN/signer" \
  WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER="$BIN/publisher" \
    bash "$TARGET" "${args[@]}"
}

make_version v1.0.0
WEDECENT_FIXTURE_HEAD_TRANSIENT_ONCE=1 run_publish --version v1.0.0 --sequence 1 --published-at 2026-09-24T12:00:00Z --public-key "$PUBLIC_KEY" >/dev/null
[[ -f "$HEAD_RETRY_MARKER" ]] || fail 'transient HTTP 503 was not retried'
[[ "$(cat "$COUNTER")" == 1 ]] || fail 'bootstrap publication did not invoke publisher once'
[[ -f "$REMOTE/stable/current/manifest-v1.json" && -f "$REMOTE/stable/current/manifest-v1.sig" ]] || fail 'bootstrap pair missing'
cp "$REMOTE/stable/current/manifest-v1.json" "$WORK/first-manifest"
cp "$REMOTE/stable/current/manifest-v1.sig" "$WORK/first-signature"

make_version v1.0.1
before_head_calls="$(cat "$HEAD_CALLS")"
if WEDECENT_FIXTURE_HEAD_ALWAYS_503=1 run_publish --version v1.0.1 --sequence 2 --published-at 2026-09-24T12:04:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'repeated HTTP 503 unexpectedly passed the bounded retry gate'
fi
[[ "$(cat "$HEAD_CALLS")" == "$((before_head_calls + 3))" ]] || fail 'transient HEAD failure did not stop after exactly three attempts'
[[ "$(cat "$COUNTER")" == 1 ]] || fail 'retry exhaustion reached the publisher'
run_publish --version v1.0.1 --sequence 2 --published-at 2026-09-24T12:05:00Z --public-key "$PUBLIC_KEY" >/dev/null
[[ "$(cat "$COUNTER")" == 2 ]] || fail 'advancing publication did not invoke publisher'
cmp -s "$WORK/first-manifest" "$REMOTE/stable/current/manifest-v1.json" && fail 'advancing manifest did not change'

if run_publish --version v1.0.1 --sequence 2 --published-at 2026-09-24T12:06:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'equal sequence/version unexpectedly published'
fi
[[ "$(cat "$COUNTER")" == 2 ]] || fail 'rollback rejection reached publisher'

cp "$REMOTE/stable/current/manifest-v1.json" "$WORK/stable-before-dry"
make_version v1.0.2
wedecent_test_release_tag_add v1.0.2 "$TEST_SOURCE_SHA"
WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER='' \
PATH="$BIN:$PATH" \
GITHUB_ACTIONS=true GITHUB_REPOSITORY='ADRN-9/wedecent' GITHUB_SHA="$TEST_SOURCE_SHA" \
GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.0.2 WEDECENT_PRODUCTION_RELEASE_APPROVED=true \
WEDECENT_REPLAY_AUTHORITY_HOSTNAME="$TEST_HOSTNAME" \
WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256="$TEST_PINS" \
WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256="$TEST_APPROVAL" \
WEDECENT_FIXTURE_REMOTE="$REMOTE" WEDECENT_FIXTURE_COUNTER="$COUNTER" \
WEDECENT_FIXTURE_HEAD_RETRY_MARKER="$HEAD_RETRY_MARKER" WEDECENT_FIXTURE_HEAD_CALLS="$HEAD_CALLS" \
WEDECENT_UPDATE_MANIFEST_SIGNER="$BIN/signer" \
  bash "$TARGET" --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:10:00Z --public-key "$PUBLIC_KEY" --dry-run >/dev/null
cmp -s "$WORK/stable-before-dry" "$REMOTE/stable/current/manifest-v1.json" || fail 'dry run mutated stable manifest'
[[ "$(cat "$COUNTER")" == 2 ]] || fail 'dry run invoked publisher'

rm -f "$REMOTE/stable/current/manifest-v1.sig"
if run_publish --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:11:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'inconsistent remote stable pair unexpectedly accepted'
fi
cp "$WORK/first-signature" "$REMOTE/stable/current/manifest-v1.sig"
if run_publish --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:12:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'invalid existing stable signature unexpectedly accepted'
fi

# Restore a valid sequence-2 pair by publishing again from a clean fixture.
rm -f "$REMOTE/stable/current"
rm -rf "$REMOTE/stable/pairs"
printf '0\n' > "$COUNTER"
run_publish --version v1.0.1 --sequence 2 --published-at 2026-09-24T12:05:00Z --public-key "$PUBLIC_KEY" >/dev/null
before_manifest_sha="$(sha256sum "$REMOTE/stable/current/manifest-v1.json" | awk '{print $1}')"
before_signature_sha="$(sha256sum "$REMOTE/stable/current/manifest-v1.sig" | awk '{print $1}')"
before_pointer="$(readlink "$REMOTE/stable/current")"
if WEDECENT_FIXTURE_PUBLISH_FAIL=after-stage run_publish --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:15:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'publisher failure after staging unexpectedly succeeded'
fi
[[ "$(readlink "$REMOTE/stable/current")" == "$before_pointer" ]] || fail 'failed atomic commit changed the stable pair pointer'
[[ "$(sha256sum "$REMOTE/stable/current/manifest-v1.json" | awk '{print $1}')" == "$before_manifest_sha" ]] || fail 'failed atomic commit changed manifest'
[[ "$(sha256sum "$REMOTE/stable/current/manifest-v1.sig" | awk '{print $1}')" == "$before_signature_sha" ]] || fail 'failed atomic commit changed signature'

if WEDECENT_FIXTURE_PUBLISH_CONFLICT=1 run_publish --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:16:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'concurrent stable-pair update unexpectedly passed compare-and-swap'
fi
[[ "$(sha256sum "$REMOTE/stable/current/manifest-v1.sig" | awk '{print $1}')" == "$before_signature_sha" ]] || fail 'CAS conflict overwrote the concurrent signature'
grep -q 'concurrent writer changed stable manifest' "$REMOTE/stable/current/manifest-v1.json" || fail 'CAS conflict did not preserve the concurrent writer state'

printf 'Stable signed update retry, atomic-pair and compare-and-swap regressions passed.\n'
