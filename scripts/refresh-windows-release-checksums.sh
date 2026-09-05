#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/dist/wedecent-windows-amd64}"

[[ -f "$OUT_DIR/wd.exe" && -f "$OUT_DIR/wd-agent.exe" ]] || {
  printf 'refresh-windows-release-checksums: release binaries are missing from %s\n' "$OUT_DIR" >&2
  exit 1
}

(
  cd "$OUT_DIR"
  sha256sum wd.exe wd-agent.exe | LC_ALL=C sort -k2 > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)
