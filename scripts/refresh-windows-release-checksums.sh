#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/dist/wedecent-windows-amd64}"
binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)

for name in "${binaries[@]}"; do
  [[ -f "$OUT_DIR/$name" && ! -L "$OUT_DIR/$name" ]] || {
    printf 'refresh-windows-release-checksums: release binary is missing or invalid: %s\n' "$OUT_DIR/$name" >&2
    exit 1
  }
done

(
  cd "$OUT_DIR"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)
