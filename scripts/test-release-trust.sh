#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$ROOT/scripts/lib/release-trust.sh"
source "$ROOT/scripts/testlib/release-tag-fixture.sh"

fail() {
  printf 'test-release-trust: %s\n' "$*" >&2
  exit 1
}

HOSTNAME='replay.example.test'
PINS='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
APPROVAL="$(wedecent_replay_authority_approval_digest "$HOSTNAME" "$PINS")"
AUDIT_HOSTNAME='audit.example.test'
AUDIT_PINS='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
AUDIT_APPROVAL="$(wedecent_checkpoint_audit_approval_digest "$AUDIT_HOSTNAME" "$AUDIT_PINS")"
SOURCE_SHA="${GITHUB_SHA:-$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')}"
TREE_SHA="$(git -C "$ROOT" rev-parse --verify "${SOURCE_SHA}^{tree}")"
export GITHUB_ACTIONS=true
export GITHUB_REPOSITORY='ADRN-9/wedecent'
export GITHUB_SHA="$SOURCE_SHA"
export GITHUB_REF_TYPE=tag
export GITHUB_REF_NAME='v0.0.0-test'
export WEDECENT_PRODUCTION_RELEASE_APPROVED=true
WORK="$(mktemp -d)"
wedecent_test_release_tags_init "$ROOT" "$WORK"
wedecent_test_release_tag_add "$GITHUB_REF_NAME" "$SOURCE_SHA"
trap 'wedecent_test_release_tags_cleanup; rm -rf -- "$WORK"' EXIT
FIXTURE="$WORK/release"
mkdir -p -- "$FIXTURE"

export WEDECENT_REPLAY_AUTHORITY_HOSTNAME="$HOSTNAME"
export WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256="$PINS"
export WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256="$APPROVAL"
export WEDECENT_CHECKPOINT_AUDIT_HOSTNAME="$AUDIT_HOSTNAME"
export WEDECENT_CHECKPOINT_AUDIT_SPKI_SHA256="$AUDIT_PINS"
export WEDECENT_CHECKPOINT_AUDIT_APPROVAL_SHA256="$AUDIT_APPROVAL"
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
checkpoint_audit_hostname=$AUDIT_HOSTNAME
checkpoint_audit_spki_sha256=$AUDIT_PINS
checkpoint_audit_approval_sha256=$AUDIT_APPROVAL
EOF_VERSION
for name in wd-core.exe wd-agent.exe; do
  printf 'binary fixture %s\n%s\n%s\n%s\n%s\n' "$name" "$HOSTNAME" "$PINS" "$AUDIT_HOSTNAME" "$AUDIT_PINS" > "$FIXTURE/$name"
done

wedecent_require_approved_replay_trust || fail 'approved test replay trust configuration was rejected'
wedecent_require_approved_checkpoint_audit_trust || fail 'approved test checkpoint audit trust configuration was rejected'
wedecent_verify_release_metadata "$FIXTURE" || fail 'valid production release fixture was rejected'

if (WEDECENT_EXPECTED_SOURCE_SHA='cccccccccccccccccccccccccccccccccccccccc'; wedecent_verify_release_metadata "$FIXTURE"); then
  fail 'caller-overridden expected source SHA was accepted'
fi
if (unset WEDECENT_PRODUCTION_RELEASE_APPROVED; wedecent_verify_release_metadata "$FIXTURE"); then
  fail 'release verification accepted a missing protected-environment approval marker'
fi

cp "$FIXTURE/VERSION.txt" "$WORK/VERSION.good"
sed 's/^replay_authority_hostname=replay.example.test$/replay_authority_hostname=other.example.test/' \
  "$WORK/VERSION.good" > "$FIXTURE/VERSION.txt"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'mismatched release hostname was accepted'
fi
mv "$WORK/VERSION.good" "$FIXTURE/VERSION.txt"

cp "$FIXTURE/VERSION.txt" "$WORK/VERSION.good"
sed "s|^replay_authority_spki_sha256=$PINS$|replay_authority_spki_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc|" \
  "$WORK/VERSION.good" > "$FIXTURE/VERSION.txt"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'mismatched release SPKI pins were accepted'
fi
mv "$WORK/VERSION.good" "$FIXTURE/VERSION.txt"

cp "$FIXTURE/VERSION.txt" "$WORK/VERSION.good"
sed "s|^checkpoint_audit_hostname=$AUDIT_HOSTNAME$|checkpoint_audit_hostname=other.example.test|" \
  "$WORK/VERSION.good" > "$FIXTURE/VERSION.txt"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'mismatched checkpoint audit hostname was accepted'
fi
mv "$WORK/VERSION.good" "$FIXTURE/VERSION.txt"

cp "$FIXTURE/VERSION.txt" "$WORK/VERSION.good"
sed "s|^checkpoint_audit_spki_sha256=$AUDIT_PINS$|checkpoint_audit_spki_sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd|" \
  "$WORK/VERSION.good" > "$FIXTURE/VERSION.txt"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'mismatched checkpoint audit SPKI pins were accepted'
fi
mv "$WORK/VERSION.good" "$FIXTURE/VERSION.txt"

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

if (unset WEDECENT_CHECKPOINT_AUDIT_HOSTNAME; wedecent_require_approved_checkpoint_audit_trust); then
  fail 'missing checkpoint audit hostname was accepted'
fi
if (unset WEDECENT_CHECKPOINT_AUDIT_SPKI_SHA256; wedecent_require_approved_checkpoint_audit_trust); then
  fail 'missing checkpoint audit SPKI pins were accepted'
fi
if (WEDECENT_CHECKPOINT_AUDIT_HOSTNAME='Audit.Example.test'; wedecent_require_approved_checkpoint_audit_trust); then
  fail 'non-canonical checkpoint audit hostname was accepted'
fi
if (WEDECENT_CHECKPOINT_AUDIT_SPKI_SHA256='ABCDEF'; wedecent_require_approved_checkpoint_audit_trust); then
  fail 'malformed checkpoint audit SPKI pins were accepted'
fi
if (WEDECENT_CHECKPOINT_AUDIT_APPROVAL_SHA256='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'; wedecent_require_approved_checkpoint_audit_trust); then
  fail 'unapproved checkpoint audit trust digest was accepted'
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

sed "s/^source_tree=$TREE_SHA$/source_tree=cccccccccccccccccccccccccccccccccccccccc/" \
  "$FIXTURE/VERSION.txt" > "$WORK/forged-tree.txt"
cp "$FIXTURE/VERSION.txt" "$WORK/production.txt"
cp "$WORK/forged-tree.txt" "$FIXTURE/VERSION.txt"
if wedecent_verify_release_metadata "$FIXTURE"; then
  fail 'forged source tree was accepted'
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
