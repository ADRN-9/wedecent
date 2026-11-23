#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$ROOT/scripts/lib/release-trust.sh"

GO_BIN="${GO:-go}"
OUT_DIR="${OUT_DIR:-$ROOT/dist/wedecent-windows-amd64}"
RELEASE_BINARIES=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)

wedecent_release_init "$ROOT" windows amd64 "$OUT_DIR"

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
        -ldflags "$RELEASE_LDFLAGS" \
        -o "$WEDECENT_RELEASE_STAGE/$output" \
        "$package"
  )
}

build_one ./cmd/wd wd.exe
build_one ./cmd/wd-agent wd-agent.exe
build_one ./cmd/wd-routerctl wd-routerctl.exe
build_one ./cmd/wd-core wd-core.exe
build_one ./cmd/wd-ui wd-ui.exe

wedecent_release_finish
