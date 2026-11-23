#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DIST_ROOT="$ROOT/dist"
mkdir -p -- "$DIST_ROOT"
WORK="$(mktemp -d "$DIST_ROOT/.release-build-safety.XXXXXX")"
OUTSIDE="$(mktemp -d)"
cleanup() {
  rm -rf -- "$WORK" "$OUTSIDE"
}
trap cleanup EXIT

FAKE_GO="$WORK/fake-go"
cat > "$FAKE_GO" <<'EOF_GO'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "env" && "$2" == "GOVERSION" ]]; then
  printf 'go1.27.0\n'
  exit 0
fi
[[ "$1" == "build" ]] || exit 64
output=''
while (($#)); do
  if [[ "$1" == "-o" ]]; then
    output="$2"
    shift 2
  else
    shift
  fi
done
[[ -n "$output" ]] || exit 65
printf 'diagnostic fake executable\n' > "$output"
EOF_GO
chmod 0700 "$FAKE_GO"

run_builder() {
  WEDECENT_BUILD_MODE=diagnostic \
  WEDECENT_ALLOW_DIRTY=1 \
  GO="$FAKE_GO" \
  OUT_DIR="$1" \
    "$ROOT/scripts/build-windows-release.sh" >/dev/null
}

run_builder "$WORK/success"
[[ -f "$WORK/success/VERSION.txt" ]] || {
  printf 'test-release-build-safety: successful diagnostic build did not publish metadata\n' >&2
  exit 1
}
grep -Fq 'build_mode=diagnostic' "$WORK/success/VERSION.txt" || {
  printf 'test-release-build-safety: diagnostic metadata marker is missing\n' >&2
  exit 1
}
(
  cd "$WORK/success"
  sha256sum -c SHA256SUMS.txt >/dev/null
)

mkdir -p "$WORK/existing"
printf 'preserve me\n' > "$WORK/existing/sentinel"
if run_builder "$WORK/existing"; then
  printf 'test-release-build-safety: existing output directory was overwritten\n' >&2
  exit 1
fi
[[ "$(cat "$WORK/existing/sentinel")" == 'preserve me' ]] || {
  printf 'test-release-build-safety: existing output was modified\n' >&2
  exit 1
}

mkdir -p "$WORK/link-target"
ln -s "$WORK/link-target" "$WORK/output-link"
if run_builder "$WORK/output-link"; then
  printf 'test-release-build-safety: symlink output path was accepted\n' >&2
  exit 1
fi
ln -s "$WORK/link-target" "$WORK/parent-link"
if run_builder "$WORK/parent-link/nested"; then
  printf 'test-release-build-safety: symlink parent path was accepted\n' >&2
  exit 1
fi

mkdir -p "$OUTSIDE/release"
printf 'outside sentinel\n' > "$OUTSIDE/release/sentinel"
if run_builder "$OUTSIDE/release"; then
  printf 'test-release-build-safety: output outside dist was accepted\n' >&2
  exit 1
fi
[[ "$(cat "$OUTSIDE/release/sentinel")" == 'outside sentinel' ]] || {
  printf 'test-release-build-safety: outside caller path was modified\n' >&2
  exit 1
}

if WEDECENT_BUILD_MODE=diagnostic WEDECENT_ALLOW_DIRTY=1 WEDECENT_BUILD_COMMIT=forged \
   GO="$FAKE_GO" OUT_DIR="$WORK/forged" "$ROOT/scripts/build-windows-release.sh" >/dev/null 2>&1; then
  printf 'test-release-build-safety: overridden commit provenance was accepted\n' >&2
  exit 1
fi
[[ ! -e "$WORK/forged" ]] || {
  printf 'test-release-build-safety: forged build published output\n' >&2
  exit 1
}

printf 'Release build output containment and overwrite regressions passed.\n'
