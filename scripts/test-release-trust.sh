#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$ROOT/scripts/lib/release-trust.sh"

fail() {
  printf 'test-release-trust: %s\n' "$*" >&2
  exit 1
}

HOSTNAME='replay.example.test'
PINS='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
APPROVAL="$(wedecent_replay_authority_approval_digest "$HOSTNAME" "$PINS")"
SOURCE_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
TREE_SHA='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
FIXTURE="$WORK/release"
mkdir -p -- "$FIXTURE"

export WEDECENT_REPLAY_AUTHORITY_HOSTNAME="$HOSTNAME"
export WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256="$PINS"
export WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256="$APPROVAL"
export WEDECENT_EXPECTED_SOURCE_SHA="$SOURCE_SHA"

cat > "$FIXTURE/VERSION.txt" <<EOF_VERSION
version=0.0.0-test
commit=$SOURCE_SHA
source_commit=$SOURCE_SHA
source_tree=$TREE_SHA
built_at=1970-01-01T00:00:00Z
go=go1.27.0
platform=windows/amd64
build_mode=production
replay_authority_hostname=$HOSTNAME
replay_authority_spki_sha256=$PINS
replay_authority_approval_sha256=$APPROVAL
EOF_VERSION
for name in wd-core.exe wd-agent.exe; do
  printf 'binary fixture %s\n%s\n%s\n' "$name" "$HOSTNAME" "$PINS" > "$FIXTURE/$name"
done

wedecent_require_approved_replay_trust || fail 'approved test trust configuration was rejected'
wedecent_verify_release_metadata "$FIXTURE" || fail 'valid production release fixture was rejected'

if (unset WEDECENT_REPLAY_AUTHORITY_HOSTNAME; wedecent_require_approved_replay_trust); then
  fail 'missing hostname was accepted'
fi
if (unset WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256; wedecent_require_approved_replay_trust); then
  fail 'missing SPKI pins were accepted'
fi
if (WEDECENT_REPLAY_AUTHORITY_HOSTNAME='Replay.Example.test'; wedecent_require_approved_replay_trust); then
  fail 'non-canonical hostname was accepted'
fi
if (WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256='ABCDEF'; wedecent_require_approved_replay_trust); then
  fail 'malformed SPKI pins were accepted'
fi
DUPLICATE_PINS="$(
  printf '%s,%s' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
)"
DUPLICATE_APPROVAL="$(wedecent_replay_authority_approval_digest "$HOSTNAME" "$DUPLICATE_PINS")"
if (
  WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256="$DUPLICATE_PINS"
  WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256="$DUPLICATE_APPROVAL"
  wedecent_require_approved_replay_trust
); then
  fail 'duplicate SPKI pins were accepted'
fi
if (WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'; wedecent_require_approved_replay_trust); then
  fail 'unapproved trust configuration digest was accepted'
fi

sed 's/^build_mode=production$/build_mode=diagnostic/' "$FIXTURE/VERSION.txt" > "$WORK/diagnostic.txt"
cp "$FIXTURE/VERSION.txt" "$WORK/production.txt"
cp "$WORK/diagnostic.txt" "$FIXTURE/VERSION.txt"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'diagnostic artifact was accepted as a production release'
fi
mv "$WORK/production.txt" "$FIXTURE/VERSION.txt"

sed "s/^source_commit=$SOURCE_SHA$/source_commit=cccccccccccccccccccccccccccccccccccccccc/" \
  "$FIXTURE/VERSION.txt" > "$WORK/forged-source.txt"
cp "$FIXTURE/VERSION.txt" "$WORK/production.txt"
cp "$WORK/forged-source.txt" "$FIXTURE/VERSION.txt"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'forged source commit was accepted'
fi
mv "$WORK/production.txt" "$FIXTURE/VERSION.txt"

cp "$FIXTURE/wd-core.exe" "$WORK/wd-core.good"
printf 'binary without release trust\n' > "$FIXTURE/wd-core.exe"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'wd-core without embedded anchors was accepted'
fi
mv "$WORK/wd-core.good" "$FIXTURE/wd-core.exe"

cp "$FIXTURE/wd-agent.exe" "$WORK/wd-agent.good"
printf 'binary without release trust\n' > "$FIXTURE/wd-agent.exe"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'wd-agent without embedded anchors was accepted'
fi
mv "$WORK/wd-agent.good" "$FIXTURE/wd-agent.exe"

printf 'Production release trust and provenance regressions passed.\n'
