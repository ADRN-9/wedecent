#!/usr/bin/env bash
set -euo pipefail

BASE_URL="https://downloads.wedecent.com"
VERSION=""
ARTIFACT="release"
AUTHENTICODE_VERIFIER="${WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER:-}"

usage() {
  cat <<'EOF'
Usage:
  verify-public-windows-download.sh --version VERSION [--installer] [--base-url URL]

Examples:
  verify-public-windows-download.sh --version v0.4.0
  verify-public-windows-download.sh --version v0.4.0 --installer

Release mode checks the public release ZIP checksum, exact seven-file archive shape,
internal five-binary checksum manifest, and VERSION.txt. Installer mode checks the
separate public installer ZIP, exact thirteen-file package shape, the five-binary release
manifest, the complete installer-package manifest, and VERSION.txt.

If WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER is set, it must be an absolute non-symlink
executable. Release mode verifies the five binaries; installer mode verifies those five
binaries plus all four packaged PowerShell scripts.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die '--version requires a value'
      VERSION="$2"
      shift 2
      ;;
    --installer)
      ARTIFACT="installer"
      shift
      ;;
    --base-url)
      (($# >= 2)) || die '--base-url requires a value'
      BASE_URL="${2%/}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$VERSION" ]] || die '--version is required'
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
  die 'version must look like v0.3.0 or v0.3.0-rc.3'
[[ "$BASE_URL" == https://* ]] || die '--base-url must use https://'

for command in curl sha256sum awk mktemp python3 realpath rm wc tr mkdir; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

if [[ -n "$AUTHENTICODE_VERIFIER" ]]; then
  [[ "$AUTHENTICODE_VERIFIER" = /* ]] || die 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must be an absolute executable path'
  [[ ! -L "$AUTHENTICODE_VERIFIER" ]] || die 'WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER must not be a symlink'
  AUTHENTICODE_VERIFIER="$(realpath -e -- "$AUTHENTICODE_VERIFIER")" || die 'cannot resolve Authenticode verifier'
  [[ -f "$AUTHENTICODE_VERIFIER" && -x "$AUTHENTICODE_VERIFIER" ]] || die 'Authenticode verifier must be a regular executable file'
fi

PREFIX="windows/${VERSION}"
if [[ "$ARTIFACT" == 'installer' ]]; then
  ARCHIVE="wedecent-${VERSION}-windows-installer.zip"
  SUMS_NAME="INSTALLER_SHA256SUMS.txt"
else
  ARCHIVE="wedecent-${VERSION}-windows-amd64.zip"
  SUMS_NAME="SHA256SUMS.txt"
fi
ARCHIVE_URL="${BASE_URL}/${PREFIX}/${ARCHIVE}"
SUMS_URL="${BASE_URL}/${PREFIX}/${SUMS_NAME}"

tmpdir="$(mktemp -d)"
trap 'rm -rf -- "$tmpdir"' EXIT
PUBLIC_SUMS="$tmpdir/public-sums.txt"
ARCHIVE_PATH="$tmpdir/$ARCHIVE"
EXTRACTED="$tmpdir/extracted"

curl -fsS --retry 3 --retry-all-errors "$SUMS_URL" -o "$PUBLIC_SUMS"
line_count="$(wc -l < "$PUBLIC_SUMS" | tr -d '[:space:]')"
[[ "$line_count" == '1' ]] || die 'public checksum manifest must contain exactly one line'
expected="$(
  awk -v file="$ARCHIVE" '
    NR == 1 && length($1) == 64 && $1 !~ /[^0-9A-Fa-f]/ && $2 == file && NF == 2 {
      print tolower($1)
      count++
    }
    END {
      if (count != 1) exit 1
    }
  ' "$PUBLIC_SUMS"
)" || die "checksum manifest must contain exactly one SHA-256 entry for $ARCHIVE"

curl -fsSL --retry 3 --retry-all-errors "$ARCHIVE_URL" -o "$ARCHIVE_PATH"
[[ -f "$ARCHIVE_PATH" && ! -L "$ARCHIVE_PATH" ]] || die 'public archive download is missing or invalid'
actual="$(sha256sum "$ARCHIVE_PATH" | awk '{print tolower($1)}')"
[[ "$actual" == "$expected" ]] ||
  die "public archive SHA-256 mismatch: expected $expected, got $actual"

mkdir -p -- "$EXTRACTED"
python3 - "$ARCHIVE_PATH" "$EXTRACTED" "$VERSION" "$ARTIFACT" <<'PY'
import hashlib
import pathlib
import re
import sys
import zipfile

archive = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
version = sys.argv[3]
artifact = sys.argv[4]
binaries = ["wd.exe", "wd-agent.exe", "wd-routerctl.exe", "wd-core.exe", "wd-ui.exe"]
scripts = ["Install-WeDecent.ps1", "Uninstall-WeDecent.ps1", "Test-WeDecentInstall.ps1", "Update-WeDecent.ps1"]
release_files = binaries + ["VERSION.txt", "SHA256SUMS.txt"]
package_payload = binaries + ["VERSION.txt", "SHA256SUMS.txt"] + scripts + ["README.md"]
installer_files = package_payload + ["PACKAGE_SHA256SUMS.txt"]
expected_files = release_files if artifact == "release" else installer_files

with zipfile.ZipFile(archive, "r") as zf:
    infos = zf.infolist()
    names = [info.filename for info in infos]
    if sorted(names) != sorted(expected_files) or len(names) != len(expected_files) or len(set(names)) != len(names):
        expected_label = "seven signed release files" if artifact == "release" else "thirteen signed installer-package files"
        raise SystemExit(f"public archive must contain exactly the {expected_label}")
    for info in infos:
        if info.is_dir() or "/" in info.filename or "\\" in info.filename:
            raise SystemExit(f"invalid archive member path: {info.filename}")
        data = zf.read(info)
        (out / info.filename).write_bytes(data)

version_lines = [line for line in (out / "VERSION.txt").read_text(encoding="utf-8").splitlines() if line.startswith("version=")]
if version_lines != [f"version={version.removeprefix('v')}"]:
    raise SystemExit("VERSION.txt does not match requested public version")

pattern = re.compile(r"^([0-9A-Fa-f]{64})  ([A-Za-z0-9_.-]+)$")

def verify_manifest(path: pathlib.Path, expected_names: list[str], label: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != len(expected_names):
        raise SystemExit(f"{label} must contain exactly {len(expected_names)} entries")
    parsed: dict[str, str] = {}
    for line in lines:
        match = pattern.fullmatch(line)
        if not match:
            raise SystemExit(f"malformed {label} entry")
        digest, name = match.groups()
        if name not in expected_names or name in parsed:
            raise SystemExit(f"{label} contains an unexpected or duplicate file")
        parsed[name] = digest.lower()
    if sorted(parsed) != sorted(expected_names):
        raise SystemExit(f"{label} does not cover the expected files")
    for name in expected_names:
        actual_digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
        if actual_digest != parsed[name]:
            raise SystemExit(f"checksum mismatch in {label}: {name}")

verify_manifest(out / "SHA256SUMS.txt", binaries, "internal SHA256SUMS.txt")
if artifact == "installer":
    verify_manifest(out / "PACKAGE_SHA256SUMS.txt", package_payload, "PACKAGE_SHA256SUMS.txt")
PY

binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
scripts=(Install-WeDecent.ps1 Uninstall-WeDecent.ps1 Test-WeDecentInstall.ps1 Update-WeDecent.ps1)
if [[ -n "$AUTHENTICODE_VERIFIER" ]]; then
  signed_files=("${binaries[@]}")
  if [[ "$ARTIFACT" == 'installer' ]]; then
    signed_files+=("${scripts[@]}")
  fi
  for name in "${signed_files[@]}"; do
    "$AUTHENTICODE_VERIFIER" "$EXTRACTED/$name" >/dev/null || die "Authenticode verification failed for $name"
  done
  signature_status='verified'
else
  signature_status='not requested'
fi

printf 'Public Windows download verification PASS\n'
printf 'Artifact:     %s\n' "$ARTIFACT"
printf 'URL:          %s\n' "$ARCHIVE_URL"
printf 'SHA256:       %s\n' "$actual"
printf 'Authenticode: %s\n' "$signature_status"
