#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'prepare-windows-public-download: %s\n' "$*" >&2
  exit 1
}

VERSION=""
SIGNED_RELEASE_DIR=""
OUT_DIR=""
VERIFIER="${WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER:-}"

usage() {
  cat <<'EOF'
Usage:
  prepare-windows-public-download.sh \
    --version VERSION \
    --signed-release DIR \
    --out-dir DIR

WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must name an absolute, non-symlink executable.
The verifier receives exactly one executable path per invocation and must enforce the
production Authenticode publisher/chain/timestamp policy.
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
[[ -n "$OUT_DIR" ]] || fail '--out-dir is required'
[[ -n "$VERIFIER" ]] || fail 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER is required'

for tool in realpath sha256sum python3 mktemp mv find sort awk wc tr dirname rm cp mkdir; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

[[ "$VERIFIER" = /* ]] || fail 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must be an absolute executable path'
[[ ! -L "$VERIFIER" ]] || fail 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must not be a symlink'
VERIFIER="$(realpath -e -- "$VERIFIER")" || fail 'cannot resolve Authenticode verifier'
[[ -f "$VERIFIER" && -x "$VERIFIER" ]] || fail 'Authenticode verifier must be a regular executable file'

[[ ! -L "$SIGNED_RELEASE_DIR" ]] || fail 'signed release directory must not be a symlink'
SIGNED_RELEASE_DIR="$(realpath -e -- "$SIGNED_RELEASE_DIR")" || fail 'cannot resolve signed release directory'
[[ -d "$SIGNED_RELEASE_DIR" && ! -L "$SIGNED_RELEASE_DIR" ]] || fail 'signed release must be a regular directory'

OUT_DIR="$(realpath -m -- "$OUT_DIR")"
[[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] || fail "output directory already exists: $OUT_DIR"
OUT_PARENT="$(dirname -- "$OUT_DIR")"
OUT_PARENT="$(realpath -e -- "$OUT_PARENT")" || fail 'output parent directory does not exist'
[[ -d "$OUT_PARENT" ]] || fail 'output parent must be a directory'
[[ "$OUT_DIR" != "$SIGNED_RELEASE_DIR" ]] || fail 'output directory must differ from signed release'
case "$OUT_DIR" in "$SIGNED_RELEASE_DIR"/*) fail 'output directory must not be nested inside signed release' ;; esac
case "$SIGNED_RELEASE_DIR" in "$OUT_DIR"/*) fail 'signed release must not be nested inside output directory' ;; esac

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
release_files=("${binaries[@]}" VERSION.txt SHA256SUMS.txt)

actual="$(find "$SIGNED_RELEASE_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
expected="$(printf '%s\n' "${release_files[@]}" | LC_ALL=C sort)"
[[ "$actual" == "$expected" ]] || fail 'signed release contains an unexpected or missing top-level entry'
for name in "${release_files[@]}"; do
  [[ -f "$SIGNED_RELEASE_DIR/$name" && ! -L "$SIGNED_RELEASE_DIR/$name" ]] ||
    fail "signed release entry must be a regular non-symlink file: $name"
done

WORK_ROOT="$(mktemp -d "$OUT_PARENT/.wedecent-public-download-work.XXXXXX")"
chmod 0700 "$WORK_ROOT"
cleanup() {
  if [[ -n "${WORK_ROOT:-}" && -d "$WORK_ROOT" ]]; then
    rm -rf -- "$WORK_ROOT"
  fi
}
trap cleanup EXIT
SNAPSHOT_DIR="$WORK_ROOT/release"
PUBLISH_DIR="$WORK_ROOT/output"
mkdir -p -- "$SNAPSHOT_DIR" "$PUBLISH_DIR"

for name in "${release_files[@]}"; do
  cp -p -- "$SIGNED_RELEASE_DIR/$name" "$SNAPSHOT_DIR/$name"
  [[ -f "$SNAPSHOT_DIR/$name" && ! -L "$SNAPSHOT_DIR/$name" ]] ||
    fail "signed release snapshot entry is invalid: $name"
done

# Trust only the private snapshot below this point. A concurrent source mutation cannot
# change the bytes that are signature/checksum verified and later archived.
MANIFEST="$SNAPSHOT_DIR/SHA256SUMS.txt"
manifest_count="$(wc -l < "$MANIFEST" | tr -d '[:space:]')"
[[ "$manifest_count" == '5' ]] || fail 'signed release SHA256SUMS.txt must contain exactly five entries'
for name in "${binaries[@]}"; do
  count="$(awk -v file="$name" '
    length($1) == 64 && $1 !~ /[^0-9A-Fa-f]/ && $2 == file && NF == 2 { count++ }
    END { print count + 0 }
  ' "$MANIFEST")"
  [[ "$count" == '1' ]] || fail "signed release manifest must contain exactly one canonical entry for $name"
done
(
  cd "$SNAPSHOT_DIR"
  sha256sum -c SHA256SUMS.txt >/dev/null
) || fail 'signed release checksum verification failed'

for name in "${binaries[@]}"; do
  "$VERIFIER" "$SNAPSHOT_DIR/$name" >/dev/null || fail "Authenticode verification failed for $name"
done

release_version="$(awk -F= '$1 == "version" { print $2; count++ } END { if (count != 1) exit 1 }' "$SNAPSHOT_DIR/VERSION.txt")" ||
  fail 'VERSION.txt must contain exactly one version= line'
[[ "$release_version" == "${VERSION#v}" ]] ||
  fail "requested version $VERSION does not match signed release version $release_version"

ARCHIVE="wedecent-${VERSION}-windows-amd64.zip"
ARCHIVE_PATH="$PUBLISH_DIR/$ARCHIVE"

python3 - "$SNAPSHOT_DIR" "$ARCHIVE_PATH" "${release_files[@]}" <<'PY'
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
        raise SystemExit("archive file set mismatch")
    for name in names:
        if zf.read(name) != (source / name).read_bytes():
            raise SystemExit(f"archive payload mismatch: {name}")
PY

[[ -f "$ARCHIVE_PATH" && ! -L "$ARCHIVE_PATH" ]] || fail 'archive creation failed'
ARCHIVE_SHA="$(sha256sum "$ARCHIVE_PATH" | awk '{print tolower($1)}')"
printf '%s  %s\n' "$ARCHIVE_SHA" "$ARCHIVE" > "$PUBLISH_DIR/SHA256SUMS.txt"
(
  cd "$PUBLISH_DIR"
  sha256sum -c SHA256SUMS.txt >/dev/null
) || fail 'prepared archive checksum verification failed'

mv -- "$PUBLISH_DIR" "$OUT_DIR"
rm -rf -- "$WORK_ROOT"
WORK_ROOT=''
trap - EXIT

printf 'Prepared signed Windows public download:\n  archive: %s\n  sums:    %s\n' "$OUT_DIR/$ARCHIVE" "$OUT_DIR/SHA256SUMS.txt"
