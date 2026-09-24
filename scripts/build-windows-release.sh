#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO:-go}"
OUT_DIR="${OUT_DIR:-$ROOT/dist/wedecent-windows-amd64}"
VERSION_FILE="$ROOT/VERSION"
UPDATE_PUBLIC_KEY_FILE=''

fail() {
  printf 'build-windows-release: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: build-windows-release.sh [--update-public-key FILE]

--update-public-key FILE injects the canonical Ed25519 stable-update public key
into wd-ui at link time. The key is a public trust anchor, not a secret, but it
must come from an authenticated release-provisioning path. There is no runtime
file/environment fallback in wd-ui.
EOF
}

while (($#)); do
  case "$1" in
    --update-public-key)
      (($# >= 2)) || fail '--update-public-key requires a value'
      UPDATE_PUBLIC_KEY_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -f "$VERSION_FILE" ]] || fail "VERSION file is missing"
VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || fail "VERSION is not release-like: $VERSION"

COMMIT="${WEDECENT_BUILD_COMMIT:-$(git -C "$ROOT" rev-parse HEAD)}"
DIRTY=0
if ! git -C "$ROOT" diff --quiet --ignore-submodules -- || ! git -C "$ROOT" diff --cached --quiet --ignore-submodules --; then
  DIRTY=1
fi
if [[ -n "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]]; then
  DIRTY=1
fi
if [[ "$DIRTY" == 1 ]]; then
  [[ "${WEDECENT_ALLOW_DIRTY:-0}" == 1 ]] || fail "working tree is dirty; commit/stash changes or set WEDECENT_ALLOW_DIRTY=1 for a local diagnostic build"
  COMMIT="${COMMIT}-dirty"
fi

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct HEAD)"
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || fail "SOURCE_DATE_EPOCH must be an integer Unix timestamp"
BUILT_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
GO_VERSION="$($GO_BIN env GOVERSION)"

UPDATE_PUBLIC_KEY_TEXT=''
UPDATE_PUBLIC_KEY_FINGERPRINT='unprovisioned'
if [[ -n "$UPDATE_PUBLIC_KEY_FILE" ]]; then
  [[ -f "$UPDATE_PUBLIC_KEY_FILE" && ! -L "$UPDATE_PUBLIC_KEY_FILE" ]] ||
    fail '--update-public-key must be a regular non-symlink file'
  key_info="$(
    cd "$ROOT"
    "$GO_BIN" run ./cmd/wd-update-manifest key-info --public-key "$UPDATE_PUBLIC_KEY_FILE"
  )" || fail 'update public key validation failed'
  [[ "$key_info" =~ ^fingerprint=sha256:([0-9a-f]{64})$ ]] || fail 'unexpected update public key validation output'
  UPDATE_PUBLIC_KEY_FINGERPRINT="${BASH_REMATCH[1]}"
  UPDATE_PUBLIC_KEY_TEXT="$(tr -d '\r\n' < "$UPDATE_PUBLIC_KEY_FILE")"
  [[ "$UPDATE_PUBLIC_KEY_TEXT" =~ ^[A-Za-z0-9_-]+$ ]] || fail 'update public key text is not canonical base64url'
fi

case "$OUT_DIR" in
  ""|"/") fail "unsafe OUT_DIR: $OUT_DIR" ;;
esac
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

LDFLAGS="-buildid= -X=wedecent.com/wedecent/internal/buildinfo.Version=$VERSION -X=wedecent.com/wedecent/internal/buildinfo.Commit=$COMMIT -X=wedecent.com/wedecent/internal/buildinfo.BuiltAt=$BUILT_AT"
UI_LDFLAGS="$LDFLAGS"
if [[ -n "$UPDATE_PUBLIC_KEY_TEXT" ]]; then
  UI_LDFLAGS="$UI_LDFLAGS -X=wedecent.com/wedecent/internal/updateinfo.provisionedPublicKeyText=$UPDATE_PUBLIC_KEY_TEXT"
fi

build_one() {
  local package="$1"
  local output="$2"
  local ldflags="${3:-$LDFLAGS}"
  (
    cd "$ROOT"
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
      "$GO_BIN" build \
        -mod=readonly \
        -trimpath \
        -buildvcs=false \
        -ldflags "$ldflags" \
        -o "$OUT_DIR/$output" \
        "$package"
  )
}

build_one ./cmd/wd wd.exe
build_one ./cmd/wd-agent wd-agent.exe
build_one ./cmd/wd-routerctl wd-routerctl.exe
build_one ./cmd/wd-core wd-core.exe
build_one ./cmd/wd-ui wd-ui.exe "$UI_LDFLAGS"

if [[ -n "$UPDATE_PUBLIC_KEY_TEXT" ]]; then
  grep -aFq -- "$UPDATE_PUBLIC_KEY_TEXT" "$OUT_DIR/wd-ui.exe" ||
    fail 'compiled wd-ui does not contain the provisioned update public key'
fi

cat > "$OUT_DIR/VERSION.txt" <<EOF_VERSION
version=$VERSION
commit=$COMMIT
built_at=$BUILT_AT
go=$GO_VERSION
platform=windows/amd64
update_public_key_fingerprint=$UPDATE_PUBLIC_KEY_FINGERPRINT
EOF_VERSION

(
  cd "$OUT_DIR"
  sha256sum wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe | LC_ALL=C sort -k2 > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)

printf 'Built WeDecent %s Windows amd64 release bundle:\n  %s\n' "$VERSION" "$OUT_DIR"
printf 'Update public key fingerprint: %s\n' "$UPDATE_PUBLIC_KEY_FINGERPRINT"
