#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-windows-stable-update-publication: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$ROOT/scripts/publish-windows-stable-update.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
BIN="$WORK/bin"
REMOTE="$WORK/remote"
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
    --retry|--proto)
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
    path="$WEDECENT_FIXTURE_REMOTE/stable/manifest-v1.json" ;;
  windows/stable/manifest-v1.sig)
    path="$WEDECENT_FIXTURE_REMOTE/stable/manifest-v1.sig" ;;
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
current_manifest='-'; current_signature='-'
if [[ -f "$WEDECENT_FIXTURE_REMOTE/stable/manifest-v1.json" ]]; then
  current_manifest="$(sha256sum "$WEDECENT_FIXTURE_REMOTE/stable/manifest-v1.json" | awk '{print tolower($1)}')"
fi
if [[ -f "$WEDECENT_FIXTURE_REMOTE/stable/manifest-v1.sig" ]]; then
  current_signature="$(sha256sum "$WEDECENT_FIXTURE_REMOTE/stable/manifest-v1.sig" | awk '{print tolower($1)}')"
fi
[[ "$current_manifest" == "$expected_manifest" && "$current_signature" == "$expected_signature" ]] || exit 74
[[ "${WEDECENT_FIXTURE_PUBLISH_FAIL:-0}" != 1 ]] || exit 75
tmp="$WEDECENT_FIXTURE_REMOTE/stable/.pair.$$"
mkdir -p "$tmp"
cp -- "$manifest" "$tmp/manifest-v1.json"
cp -- "$signature" "$tmp/manifest-v1.sig"
mv -- "$tmp/manifest-v1.json" "$WEDECENT_FIXTURE_REMOTE/stable/manifest-v1.json"
mv -- "$tmp/manifest-v1.sig" "$WEDECENT_FIXTURE_REMOTE/stable/manifest-v1.sig"
rmdir "$tmp"
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
  PATH="$BIN:$PATH" \
  WEDECENT_FIXTURE_REMOTE="$REMOTE" \
  WEDECENT_FIXTURE_COUNTER="$COUNTER" \
  WEDECENT_UPDATE_MANIFEST_SIGNER="$BIN/signer" \
  WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER="$BIN/publisher" \
    bash "$TARGET" "$@"
}

make_version v1.0.0
run_publish --version v1.0.0 --sequence 1 --published-at 2026-09-24T12:00:00Z --public-key "$PUBLIC_KEY" >/dev/null
[[ "$(cat "$COUNTER")" == 1 ]] || fail 'bootstrap publication did not invoke publisher once'
[[ -f "$REMOTE/stable/manifest-v1.json" && -f "$REMOTE/stable/manifest-v1.sig" ]] || fail 'bootstrap pair missing'
cp "$REMOTE/stable/manifest-v1.json" "$WORK/first-manifest"
cp "$REMOTE/stable/manifest-v1.sig" "$WORK/first-signature"

make_version v1.0.1
run_publish --version v1.0.1 --sequence 2 --published-at 2026-09-24T12:05:00Z --public-key "$PUBLIC_KEY" >/dev/null
[[ "$(cat "$COUNTER")" == 2 ]] || fail 'advancing publication did not invoke publisher'
cmp -s "$WORK/first-manifest" "$REMOTE/stable/manifest-v1.json" && fail 'advancing manifest did not change'

if run_publish --version v1.0.1 --sequence 2 --published-at 2026-09-24T12:06:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'equal sequence/version unexpectedly published'
fi
[[ "$(cat "$COUNTER")" == 2 ]] || fail 'rollback rejection reached publisher'

cp "$REMOTE/stable/manifest-v1.json" "$WORK/stable-before-dry"
make_version v1.0.2
WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER='' \
PATH="$BIN:$PATH" WEDECENT_FIXTURE_REMOTE="$REMOTE" WEDECENT_FIXTURE_COUNTER="$COUNTER" \
WEDECENT_UPDATE_MANIFEST_SIGNER="$BIN/signer" \
  bash "$TARGET" --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:10:00Z --public-key "$PUBLIC_KEY" --dry-run >/dev/null
cmp -s "$WORK/stable-before-dry" "$REMOTE/stable/manifest-v1.json" || fail 'dry run mutated stable manifest'
[[ "$(cat "$COUNTER")" == 2 ]] || fail 'dry run invoked publisher'

rm -f "$REMOTE/stable/manifest-v1.sig"
if run_publish --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:11:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'inconsistent remote stable pair unexpectedly accepted'
fi
cp "$WORK/first-signature" "$REMOTE/stable/manifest-v1.sig"
# The restored signature intentionally mismatches the current manifest, so verification must fail.
if run_publish --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:12:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'invalid existing stable signature unexpectedly accepted'
fi

# Restore a valid sequence-2 pair by publishing again from a clean bootstrap fixture.
rm -f "$REMOTE/stable/manifest-v1.json" "$REMOTE/stable/manifest-v1.sig"
printf '0\n' > "$COUNTER"
run_publish --version v1.0.1 --sequence 2 --published-at 2026-09-24T12:05:00Z --public-key "$PUBLIC_KEY" >/dev/null
before_manifest_sha="$(sha256sum "$REMOTE/stable/manifest-v1.json" | awk '{print $1}')"
before_signature_sha="$(sha256sum "$REMOTE/stable/manifest-v1.sig" | awk '{print $1}')"
if WEDECENT_FIXTURE_PUBLISH_FAIL=1 run_publish --version v1.0.2 --sequence 3 --published-at 2026-09-24T12:15:00Z --public-key "$PUBLIC_KEY" >/dev/null 2>&1; then
  fail 'publisher failure unexpectedly succeeded'
fi
[[ "$(sha256sum "$REMOTE/stable/manifest-v1.json" | awk '{print $1}')" == "$before_manifest_sha" ]] || fail 'failed publisher changed manifest'
[[ "$(sha256sum "$REMOTE/stable/manifest-v1.sig" | awk '{print $1}')" == "$before_signature_sha" ]] || fail 'failed publisher changed signature'

printf 'Stable signed update publication boundary verified.\n'
