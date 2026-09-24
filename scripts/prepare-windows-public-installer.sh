#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'prepare-windows-public-installer: %s\n' "$*" >&2
  exit 1
}

VERSION=""
SIGNED_RELEASE_DIR=""
SIGNED_INSTALLER_DIR=""
OUT_DIR=""
VERIFIER="${WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER:-}"

usage() {
  cat <<'EOF'
Usage:
  prepare-windows-public-installer.sh \
    --version VERSION \
    --signed-release DIR \
    --signed-installer DIR \
    --out-dir DIR

The signed installer must contain the finalized installer package for the same signed
release. WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must name an absolute, non-symlink
executable and must enforce the production Authenticode publisher/chain/timestamp policy.
EOF
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || fail '--version requires a value'
      VERSION="$2"
      shift 2
      ;;
    --signed-release)
      (($# >= 2)) || fail '--signed-release requires a value'
      SIGNED_RELEASE_DIR="$2"
      shift 2
      ;;
    --signed-installer)
      (($# >= 2)) || fail '--signed-installer requires a value'
      SIGNED_INSTALLER_DIR="$2"
      shift 2
      ;;
    --out-dir)
      (($# >= 2)) || fail '--out-dir requires a value'
      OUT_DIR="$2"
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

[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  fail 'version must look like v0.3.0 or v0.3.0-rc.3'
[[ -n "$SIGNED_RELEASE_DIR" ]] || fail '--signed-release is required'
[[ -n "$SIGNED_INSTALLER_DIR" ]] || fail '--signed-installer is required'
[[ -n "$OUT_DIR" ]] || fail '--out-dir is required'
[[ -n "$VERIFIER" ]] || fail 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER is required'

for tool in realpath sha256sum python3 mktemp mv find sort cmp awk dirname rm cp mkdir chmod; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

[[ "$VERIFIER" = /* ]] || fail 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must be an absolute executable path'
[[ ! -L "$VERIFIER" ]] || fail 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must not be a symlink'
VERIFIER="$(realpath -e -- "$VERIFIER")" || fail 'cannot resolve Authenticode verifier'
[[ -f "$VERIFIER" && -x "$VERIFIER" ]] || fail 'Authenticode verifier must be a regular executable file'

resolve_source_dir() {
  local value="$1"
  local label="$2"
  [[ ! -L "$value" ]] || fail "$label directory must not be a symlink"
  value="$(realpath -e -- "$value")" || fail "cannot resolve $label directory"
  [[ -d "$value" && ! -L "$value" ]] || fail "$label must be a regular directory"
  printf '%s\n' "$value"
}

SIGNED_RELEASE_DIR="$(resolve_source_dir "$SIGNED_RELEASE_DIR" 'signed release')"
SIGNED_INSTALLER_DIR="$(resolve_source_dir "$SIGNED_INSTALLER_DIR" 'signed installer')"
[[ "$SIGNED_RELEASE_DIR" != "$SIGNED_INSTALLER_DIR" ]] || fail 'signed release and installer directories must differ'

OUT_DIR="$(realpath -m -- "$OUT_DIR")"
[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] || fail "output directory already exists: $OUT_DIR"
OUT_PARENT="$(dirname -- "$OUT_DIR")"
OUT_PARENT="$(realpath -e -- "$OUT_PARENT")" || fail 'output parent directory does not exist'
[[ -d "$OUT_PARENT" ]] || fail 'output parent must be a directory'

for source in "$SIGNED_RELEASE_DIR" "$SIGNED_INSTALLER_DIR"; do
  [[ "$OUT_DIR" != "$source" ]] || fail 'output directory must differ from signed inputs'
  case "$OUT_DIR" in "$source"/*) fail 'output directory must not be nested inside signed inputs' ;; esac
  case "$source" in "$OUT_DIR"/*) fail 'signed inputs must not be nested inside output directory' ;; esac
done

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
scripts=(Install-WeDecent.ps1 Uninstall-WeDecent.ps1 Test-WeDecentInstall.ps1 Update-WeDecent.ps1)
release_files=("${binaries[@]}" VERSION.txt SHA256SUMS.txt)
package_payload=("${binaries[@]}" VERSION.txt SHA256SUMS.txt "${scripts[@]}" README.md)
installer_files=("${package_payload[@]}" PACKAGE_SHA256SUMS.txt)

assert_exact_top_level() {
  local directory="$1"
  local label="$2"
  shift 2
  local -a expected_files=("$@")
  local actual expected
  actual="$(find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
  expected="$(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)"
  [[ "$actual" == "$expected" ]] || fail "$label contains an unexpected or missing top-level entry"
  local name
  for name in "${expected_files[@]}"; do
    [[ -f "$directory/$name" && ! -L "$directory/$name" ]] ||
      fail "$label entry must be a regular non-symlink file: $name"
  done
}

assert_exact_top_level "$SIGNED_RELEASE_DIR" 'signed release' "${release_files[@]}"
assert_exact_top_level "$SIGNED_INSTALLER_DIR" 'signed installer' "${installer_files[@]}"

WORK_ROOT="$(mktemp -d "$OUT_PARENT/.wedecent-public-installer-work.XXXXXX")"
chmod 0700 "$WORK_ROOT"
cleanup() {
  if [[ -n "${WORK_ROOT:-}" && -d "$WORK_ROOT" ]]; then
    rm -rf -- "$WORK_ROOT"
  fi
}
trap cleanup EXIT
RELEASE_SNAPSHOT="$WORK_ROOT/release"
INSTALLER_SNAPSHOT="$WORK_ROOT/installer"
PUBLISH_DIR="$WORK_ROOT/output"
mkdir -p -- "$RELEASE_SNAPSHOT" "$INSTALLER_SNAPSHOT" "$PUBLISH_DIR"

snapshot_files() {
  local source="$1"
  local destination="$2"
  shift 2
  local name
  for name in "$@"; do
    cp -p -- "$source/$name" "$destination/$name"
    [[ -f "$destination/$name" && ! -L "$destination/$name" ]] || fail "snapshot entry is invalid: $name"
  done
}

snapshot_files "$SIGNED_RELEASE_DIR" "$RELEASE_SNAPSHOT" "${release_files[@]}"
snapshot_files "$SIGNED_INSTALLER_DIR" "$INSTALLER_SNAPSHOT" "${installer_files[@]}"

for name in "${release_files[@]}"; do
  cmp -s "$RELEASE_SNAPSHOT/$name" "$INSTALLER_SNAPSHOT/$name" ||
    fail "signed installer release payload differs from signed release: $name"
done

EXPECTED_RELEASE_SUMS="$WORK_ROOT/expected-release-SHA256SUMS.txt"
(
  cd "$RELEASE_SNAPSHOT"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > "$EXPECTED_RELEASE_SUMS"
)
cmp -s "$EXPECTED_RELEASE_SUMS" "$RELEASE_SNAPSHOT/SHA256SUMS.txt" ||
  fail 'signed release SHA256SUMS.txt is not the canonical five-binary manifest'
(
  cd "$RELEASE_SNAPSHOT"
  sha256sum -c SHA256SUMS.txt >/dev/null
) || fail 'signed release checksum verification failed'

EXPECTED_PACKAGE_SUMS="$WORK_ROOT/expected-PACKAGE_SHA256SUMS.txt"
(
  cd "$INSTALLER_SNAPSHOT"
  sha256sum "${package_payload[@]}" | LC_ALL=C sort -k2 > "$EXPECTED_PACKAGE_SUMS"
)
cmp -s "$EXPECTED_PACKAGE_SUMS" "$INSTALLER_SNAPSHOT/PACKAGE_SHA256SUMS.txt" ||
  fail 'signed installer PACKAGE_SHA256SUMS.txt is not the canonical package manifest'
(
  cd "$INSTALLER_SNAPSHOT"
  sha256sum -c PACKAGE_SHA256SUMS.txt >/dev/null
  sha256sum -c SHA256SUMS.txt >/dev/null
) || fail 'signed installer checksum verification failed'

release_version="$(awk -F= '$1 == "version" { print $2; count++ } END { if (count != 1) exit 1 }' "$RELEASE_SNAPSHOT/VERSION.txt")" ||
  fail 'VERSION.txt must contain exactly one version= line'
[[ "$release_version" == "${VERSION#v}" ]] ||
  fail "requested version $VERSION does not match signed release version $release_version"

for name in "${binaries[@]}" "${scripts[@]}"; do
  "$VERIFIER" "$INSTALLER_SNAPSHOT/$name" >/dev/null || fail "Authenticode verification failed for $name"
done

ARCHIVE="wedecent-${VERSION}-windows-installer.zip"
ARCHIVE_PATH="$PUBLISH_DIR/$ARCHIVE"

python3 - "$INSTALLER_SNAPSHOT" "$ARCHIVE_PATH" "${installer_files[@]}" <<'PY'
import pathlib
import sys
import zipfile

source = pathlib.Path(sys.argv[1])
archive = pathlib.Path(sys.argv[2])
names = sorted(sys.argv[3:])
fixed_time = (1980, 1, 1, 0, 0, 0)

with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
    for name in names:
        data = (source / name).read_bytes()
        info = zipfile.ZipInfo(name, fixed_time)
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 3
        info.external_attr = (0o100644 & 0xFFFF) << 16
        zf.writestr(info, data)

with zipfile.ZipFile(archive, "r") as zf:
    archived = sorted(zf.namelist())
    if archived != names:
        raise SystemExit("installer archive file set mismatch")
    for name in names:
        if zf.read(name) != (source / name).read_bytes():
            raise SystemExit(f"installer archive payload mismatch: {name}")
PY

[[ -f "$ARCHIVE_PATH" && ! -L "$ARCHIVE_PATH" ]] || fail 'installer archive creation failed'
ARCHIVE_SHA="$(sha256sum "$ARCHIVE_PATH" | awk '{print tolower($1)}')"
printf '%s  %s\n' "$ARCHIVE_SHA" "$ARCHIVE" > "$PUBLISH_DIR/INSTALLER_SHA256SUMS.txt"
(
  cd "$PUBLISH_DIR"
  sha256sum -c INSTALLER_SHA256SUMS.txt >/dev/null
) || fail 'prepared installer archive checksum verification failed'

mv -- "$PUBLISH_DIR" "$OUT_DIR"
rm -rf -- "$WORK_ROOT"
WORK_ROOT=''
trap - EXIT

printf 'Prepared signed Windows public installer:\n  archive: %s\n  sums:    %s\n' \
  "$OUT_DIR/$ARCHIVE" "$OUT_DIR/INSTALLER_SHA256SUMS.txt"
