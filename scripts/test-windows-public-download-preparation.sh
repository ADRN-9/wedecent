#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-windows-public-download-preparation: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREPARE="$ROOT/scripts/prepare-windows-public-download.sh"
DIST_ROOT="$ROOT/dist"
mkdir -p -- "$DIST_ROOT"
WORK="$(mktemp -d "$DIST_ROOT/.public-download-test.XXXXXX")"
cleanup() {
  rm -rf -- "$WORK" "$DIST_ROOT/$(basename "$WORK").one" "$DIST_ROOT/$(basename "$WORK").two" "$DIST_ROOT/$(basename "$WORK").bad"
}
trap cleanup EXIT

RELEASE="$WORK/release"
RELEASE_LINK="$WORK/release-link"
mkdir -p -- "$RELEASE"
binaries=(wd.exe wd-agent.exe wd-routerctl.exe wd-core.exe wd-ui.exe)
release_files=("${binaries[@]}" VERSION.txt SHA256SUMS.txt)

for name in "${binaries[@]}"; do
  printf 'signed fixture: %s\nWEDECENT_FAKE_AUTHENTICODE_SIGNATURE\n' "$name" > "$RELEASE/$name"
done
cat > "$RELEASE/VERSION.txt" <<'EOF_VERSION'
version=0.3.0-rc.9
commit=test
built_at=1970-01-01T00:00:00Z
go=test
platform=windows/amd64
EOF_VERSION
(
  cd "$RELEASE"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > SHA256SUMS.txt
)
ln -s -- "$RELEASE" "$RELEASE_LINK"

VERIFIER="$WORK/verifier"
VERIFIER_LINK="$WORK/verifier-link"
cat > "$VERIFIER" <<'EOF_VERIFIER'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || exit 64
[[ -f "$1" && ! -L "$1" ]] || exit 65
[[ "$(tail -n 1 -- "$1")" == 'WEDECENT_FAKE_AUTHENTICODE_SIGNATURE' ]]
EOF_VERIFIER
chmod 0700 "$VERIFIER"
ln -s -- "$VERIFIER" "$VERIFIER_LINK"

snapshot_release() {
  (
    cd "$RELEASE"
    sha256sum * | LC_ALL=C sort
  )
}
BEFORE="$(snapshot_release)"

ONE="$DIST_ROOT/$(basename "$WORK").one"
TWO="$DIST_ROOT/$(basename "$WORK").two"
BAD="$DIST_ROOT/$(basename "$WORK").bad"

if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER='relative-verifier' \
   "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$BAD" >/dev/null 2>&1; then
  fail 'relative verifier path unexpectedly succeeded'
fi
[[ ! -e "$BAD" ]] || fail 'relative verifier failure published output'

if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER_LINK" \
   "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$BAD" >/dev/null 2>&1; then
  fail 'symlink verifier path unexpectedly succeeded'
fi
[[ ! -e "$BAD" ]] || fail 'symlink verifier failure published output'

if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE_LINK" --out-dir "$BAD" >/dev/null 2>&1; then
  fail 'signed release symlink unexpectedly succeeded'
fi
[[ ! -e "$BAD" ]] || fail 'signed release symlink failure published output'

if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.3.0 --signed-release "$RELEASE" --out-dir "$BAD" >/dev/null 2>&1; then
  fail 'version mismatch unexpectedly succeeded'
fi
[[ ! -e "$BAD" ]] || fail 'version mismatch published output'

cp -- "$RELEASE/SHA256SUMS.txt" "$WORK/SHA256SUMS.good"
awk '{ if ($2 == "wd.exe") print $0 " extra-field"; else print }' \
  "$WORK/SHA256SUMS.good" > "$RELEASE/SHA256SUMS.txt"
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$BAD" >/dev/null 2>&1; then
  fail 'malformed signed checksum manifest unexpectedly succeeded'
fi
[[ ! -e "$BAD" ]] || fail 'malformed signed checksum manifest published output'
mv -- "$WORK/SHA256SUMS.good" "$RELEASE/SHA256SUMS.txt"

cp -- "$RELEASE/wd-ui.exe" "$WORK/wd-ui.good"
printf 'tampered\n' >> "$RELEASE/wd-ui.exe"
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$BAD" >/dev/null 2>&1; then
  fail 'checksum-mismatched release unexpectedly succeeded'
fi
[[ ! -e "$BAD" ]] || fail 'checksum mismatch published output'
mv -- "$WORK/wd-ui.good" "$RELEASE/wd-ui.exe"

printf 'unexpected\n' > "$RELEASE/unexpected.txt"
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$BAD" >/dev/null 2>&1; then
  fail 'unexpected release payload entry was accepted'
fi
[[ ! -e "$BAD" ]] || fail 'unexpected payload published output'
rm -f -- "$RELEASE/unexpected.txt"

cp -- "$RELEASE/wd-core.exe" "$WORK/wd-core.good"
printf 'signed fixture without verifier marker\n' > "$RELEASE/wd-core.exe"
(
  cd "$RELEASE"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > SHA256SUMS.txt
)
if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$BAD" >/dev/null 2>&1; then
  fail 'invalid Authenticode fixture unexpectedly succeeded'
fi
[[ ! -e "$BAD" ]] || fail 'signature failure published output'
mv -- "$WORK/wd-core.good" "$RELEASE/wd-core.exe"
(
  cd "$RELEASE"
  sha256sum "${binaries[@]}" | LC_ALL=C sort -k2 > SHA256SUMS.txt
)

WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
  "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$ONE" >/dev/null
WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
  "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$TWO" >/dev/null

[[ "$(snapshot_release)" == "$BEFORE" ]] || fail 'preparation mutated signed release input'
ARCHIVE='wedecent-v0.3.0-rc.9-windows-amd64.zip'
[[ -f "$ONE/$ARCHIVE" && -f "$ONE/SHA256SUMS.txt" ]] || fail 'prepared public payload is incomplete'
(
  cd "$ONE"
  sha256sum -c SHA256SUMS.txt >/dev/null
)
cmp -s -- "$ONE/$ARCHIVE" "$TWO/$ARCHIVE" || fail 'canonical archive bytes are not deterministic for identical input'
cmp -s -- "$ONE/SHA256SUMS.txt" "$TWO/SHA256SUMS.txt" || fail 'public checksum manifest is not deterministic'

python3 - "$RELEASE" "$ONE/$ARCHIVE" "${release_files[@]}" <<'PY'
import pathlib
import sys
import zipfile
source = pathlib.Path(sys.argv[1])
archive = pathlib.Path(sys.argv[2])
expected = sorted(sys.argv[3:])
with zipfile.ZipFile(archive, 'r') as zf:
    if sorted(zf.namelist()) != expected:
        raise SystemExit('archive file set mismatch')
    for name in expected:
        if zf.read(name) != (source / name).read_bytes():
            raise SystemExit(f'archive payload mismatch: {name}')
PY

if WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER="$VERIFIER" \
   "$PREPARE" --version v0.3.0-rc.9 --signed-release "$RELEASE" --out-dir "$ONE" >/dev/null 2>&1; then
  fail 'existing output directory was overwritten'
fi

printf 'Windows signed public-download preparation verified.\n'
