#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$ROOT/scripts/lib/release-trust.sh"

GO_BIN="${GO:-go}"
GOARCH="${GOARCH:-arm64}"
OUT_DIR="${OUT_DIR:-$ROOT/dist/wedecent-macos-$GOARCH}"
RELEASE_BINARIES=(wd wd-agent wd-routerctl wd-core wd-ui)

case "$GOARCH" in amd64|arm64) ;; *) printf 'build-macos-release: unsupported GOARCH %s\n' "$GOARCH" >&2; exit 1 ;; esac

wedecent_release_init "$ROOT" darwin "$GOARCH" "$OUT_DIR"

build_one() {
  local package="$1"
  local output="$2"
  (
    cd "$ROOT"
    CGO_ENABLED=0 GOOS=darwin GOARCH="$GOARCH" \
      "$GO_BIN" build \
        -mod=readonly \
        -trimpath \
        -buildvcs=false \
        -ldflags "$RELEASE_LDFLAGS" \
        -o "$WEDECENT_RELEASE_STAGE/$output" \
        "$package"
  )
}

build_one ./cmd/wd wd
build_one ./cmd/wd-agent wd-agent
build_one ./cmd/wd-routerctl wd-routerctl
build_one ./cmd/wd-core wd-core
build_one ./cmd/wd-ui wd-ui

wedecent_release_finish
