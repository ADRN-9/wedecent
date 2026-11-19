#!/usr/bin/env bash
set -euo pipefail
unset WEDECENT_PAIRING_SECRET || true
export GOFLAGS=

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

HEAD_COMMIT="$(git -C "$ROOT" rev-parse --verify HEAD)" || fail "cannot resolve source HEAD"
COMMIT="${WEDECENT_BUILD_COMMIT:-$HEAD_COMMIT}"
[[ "$COMMIT" == "$HEAD_COMMIT" ]] || fail "WEDECENT_BUILD_COMMIT must match the exact checked-out HEAD"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "source commit must be a full lowercase 40-character Git SHA"
git_status="$(git -C "$ROOT" status --porcelain --untracked-files=all)" || fail "cannot inspect source working tree"
[[ -z "$git_status" ]] || fail "working tree is dirty; reproducible release builds require a clean checkout"
SOURCE_SHA256="$(git -C "$ROOT" archive --format=tar "$COMMIT" | sha256sum | awk '{print $1}')" || fail "cannot hash exact source archive"
[[ "$SOURCE_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "source archive SHA-256 is malformed"
COMMIT_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$COMMIT")"
if [[ -n "${SOURCE_DATE_EPOCH:-}" && "$SOURCE_DATE_EPOCH" != "$COMMIT_EPOCH" ]]; then
  fail "SOURCE_DATE_EPOCH must equal the exact source commit timestamp"
fi
SOURCE_DATE_EPOCH="$COMMIT_EPOCH"
BUILT_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
GO_VERSION="$("$GO_BIN" env GOVERSION)"

case "$OUT_DIR" in
  ""|"/") fail "unsafe OUT_DIR: $OUT_DIR" ;;
esac
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

LDFLAGS="-buildid= -X=wedecent.com/wedecent/internal/buildinfo.Version=$VERSION -X=wedecent.com/wedecent/internal/buildinfo.Commit=$COMMIT -X=wedecent.com/wedecent/internal/buildinfo.BuiltAt=$BUILT_AT -X=wedecent.com/wedecent/internal/buildinfo.SourceSHA256=$SOURCE_SHA256"

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
source_sha256=$SOURCE_SHA256
go=$GO_VERSION
platform=windows/amd64
EOF_VERSION

(
  cd "$OUT_DIR"
  sha256sum wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe | LC_ALL=C sort -k2 > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)

printf 'Built WeDecent %s Windows amd64 release bundle:\n  %s\n' "$VERSION" "$OUT_DIR"
