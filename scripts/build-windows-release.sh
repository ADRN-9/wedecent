#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO:-go}"
OUT_DIR="${OUT_DIR:-$ROOT/dist/wedecent-windows-amd64}"
VERSION_FILE="$ROOT/VERSION"

fail() {
  printf 'build-windows-release: %s\n' "$*" >&2
  exit 1
}

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

case "$OUT_DIR" in
  ""|"/") fail "unsafe OUT_DIR: $OUT_DIR" ;;
esac
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

LDFLAGS="-buildid= -X=wedecent.com/wedecent/internal/buildinfo.Version=$VERSION -X=wedecent.com/wedecent/internal/buildinfo.Commit=$COMMIT -X=wedecent.com/wedecent/internal/buildinfo.BuiltAt=$BUILT_AT"

build_one() {
  local package="$1"
  local output="$2"
  (
    cd "$ROOT"
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
      "$GO_BIN" build \
        -mod=readonly \
        -trimpath \
        -buildvcs=false \
        -ldflags "$LDFLAGS" \
        -o "$OUT_DIR/$output" \
        "$package"
  )
}

build_one ./cmd/wd wd.exe
build_one ./cmd/wd-agent wd-agent.exe
build_one ./cmd/wd-routerctl wd-routerctl.exe
build_one ./cmd/wd-core wd-core.exe
build_one ./cmd/wd-ui wd-ui.exe

cat > "$OUT_DIR/VERSION.txt" <<EOF_VERSION
version=$VERSION
commit=$COMMIT
built_at=$BUILT_AT
go=$GO_VERSION
platform=windows/amd64
EOF_VERSION

(
  cd "$OUT_DIR"
  sha256sum wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe | LC_ALL=C sort -k2 > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)

printf 'Built WeDecent %s Windows amd64 release bundle:\n  %s\n' "$VERSION" "$OUT_DIR"
