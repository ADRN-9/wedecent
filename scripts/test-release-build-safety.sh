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


RELEASE_FIXTURE="$WORK/installer-release"
mkdir -p "$RELEASE_FIXTURE"
INSTALLER_BINARIES=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
for name in "${INSTALLER_BINARIES[@]}"; do
  printf 'installer fixture: %s\n' "$name" > "$RELEASE_FIXTURE/$name"
done
printf 'version=0.0.0-diagnostic\nbuild_mode=diagnostic\n' > "$RELEASE_FIXTURE/VERSION.txt"
(
  cd "$RELEASE_FIXTURE"
  sha256sum "${INSTALLER_BINARIES[@]}" > SHA256SUMS.txt
)
PACKAGE_OUT="$WORK/installer-package"
RELEASE_DIR="$RELEASE_FIXTURE" OUT_DIR="$PACKAGE_OUT" \
  "$ROOT/scripts/build-windows-installer-package.sh" >/dev/null
(
  cd "$PACKAGE_OUT"
  sha256sum -c PACKAGE_SHA256SUMS.txt >/dev/null
)

mkdir -p "$WORK/existing-installer-package"
printf 'preserve installer output\n' > "$WORK/existing-installer-package/sentinel"
if RELEASE_DIR="$RELEASE_FIXTURE" OUT_DIR="$WORK/existing-installer-package" \
   "$ROOT/scripts/build-windows-installer-package.sh" >/dev/null 2>&1; then
  printf 'test-release-build-safety: installer builder overwrote an existing output\n' >&2
  exit 1
fi
[[ "$(cat "$WORK/existing-installer-package/sentinel")" == 'preserve installer output' ]] || {
  printf 'test-release-build-safety: existing installer output was modified\n' >&2
  exit 1
}

ln -s "$WORK/link-target" "$WORK/installer-output-link"
if RELEASE_DIR="$RELEASE_FIXTURE" OUT_DIR="$WORK/installer-output-link" \
   "$ROOT/scripts/build-windows-installer-package.sh" >/dev/null 2>&1; then
  printf 'test-release-build-safety: installer builder accepted a symlink output\n' >&2
  exit 1
fi
if RELEASE_DIR="$RELEASE_FIXTURE" OUT_DIR="$WORK/parent-link/nested-package" \
   "$ROOT/scripts/build-windows-installer-package.sh" >/dev/null 2>&1; then
  printf 'test-release-build-safety: installer builder accepted a symlink parent\n' >&2
  exit 1
fi

ln -s "$RELEASE_FIXTURE" "$WORK/release-link"
if RELEASE_DIR="$WORK/release-link" OUT_DIR="$WORK/symlink-input-package" \
   "$ROOT/scripts/build-windows-installer-package.sh" >/dev/null 2>&1; then
  printf 'test-release-build-safety: installer builder accepted a symlink release input\n' >&2
  exit 1
fi

mkdir -p "$OUTSIDE/installer-package"
printf 'preserve outside installer output\n' > "$OUTSIDE/installer-package/sentinel"
if RELEASE_DIR="$RELEASE_FIXTURE" OUT_DIR="$OUTSIDE/installer-package" \
   "$ROOT/scripts/build-windows-installer-package.sh" >/dev/null 2>&1; then
  printf 'test-release-build-safety: installer builder accepted an output outside dist\n' >&2
  exit 1
fi
[[ "$(cat "$OUTSIDE/installer-package/sentinel")" == 'preserve outside installer output' ]] || {
  printf 'test-release-build-safety: outside installer output was modified\n' >&2
  exit 1
}

printf 'Release build and installer output containment and overwrite regressions passed.\n'
