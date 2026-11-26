#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
TAG="v$VERSION"
FIXTURES="$TMP/fixtures"
REPO="$TMP/repo"
MOCK_R2="$TMP/mock-r2"
BIN="$TMP/bin"
mkdir -m 0700 -p "$FIXTURES" "$REPO" "$MOCK_R2" "$BIN"

(cd "$ROOT" && go run ./cmd/test-r2-stable-pair-fixture "$FIXTURES" "$TAG")
cp -a "$ROOT/scripts" "$ROOT/internal" "$ROOT/cmd" "$ROOT/go.mod" "$ROOT/go.sum" "$ROOT/VERSION" "$REPO/"
cat > "$REPO/scripts/verify-live-release-tag.sh" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod 0700 "$REPO/scripts/verify-live-release-tag.sh"

cat > "$BIN/aws" <<'PY'
#!/usr/bin/env python3
import hashlib
import os
import pathlib
import sys

args = sys.argv[1:]
if args == ["--version"]:
    print("aws-cli/2.99.0 Python/3.12")
    raise SystemExit(0)
if args[:3] == ["s3api", "put-object", "--generate-cli-skeleton"]:
    print('{"IfMatch":"","IfNoneMatch":"","Metadata":{}}')
    raise SystemExit(0)
if len(args) < 2 or args[0] != "s3api":
    raise SystemExit(2)
action = args[1]
opts = args[2:]

def value(flag):
    try:
        return opts[opts.index(flag) + 1]
    except (ValueError, IndexError):
        raise SystemExit(f"missing {flag}")

root = pathlib.Path(os.environ["MOCK_R2_ROOT"])
bucket = value("--bucket")
key = value("--key")
obj = root / bucket / key
obj.parent.mkdir(parents=True, exist_ok=True)

def etag(data):
    return '"' + hashlib.sha256(data).hexdigest() + '"'

if action == "head-object":
    if not obj.exists():
        print("An error occurred (404) when calling the HeadObject operation: Not Found", file=sys.stderr)
        raise SystemExit(1)
    if value("--query") == "Metadata.writeid":
        metadata = pathlib.Path(str(obj) + ".writeid")
        print(metadata.read_text(encoding="utf-8") if metadata.exists() else "None")
    else:
        print(etag(obj.read_bytes()))
elif action == "get-object":
    output = pathlib.Path(opts[-1])
    if not obj.exists():
        print("NoSuchKey", file=sys.stderr)
        raise SystemExit(1)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(obj.read_bytes())
    print("{}")
elif action == "put-object":
    source = pathlib.Path(value("--body"))
    data = source.read_bytes()
    if "--if-match" in opts:
        expected = value("--if-match")
        if os.environ.get("MOCK_R2_RACE") == "1" and key == "windows/stable/current-v2.json":
            obj.write_bytes(b'{"concurrent_writer":"preserve-me"}\n')
        if not obj.exists() or etag(obj.read_bytes()) != expected:
            print("An error occurred (PreconditionFailed) when calling the PutObject operation", file=sys.stderr)
            raise SystemExit(1)
    elif "--if-none-match" in opts:
        if obj.exists():
            print("An error occurred (PreconditionFailed) when calling the PutObject operation", file=sys.stderr)
            raise SystemExit(1)
    else:
        print("unconditional writes are forbidden in this test adapter", file=sys.stderr)
        raise SystemExit(2)
    obj.write_bytes(data)
    if "--metadata" in opts:
        metadata_value = value("--metadata")
        if metadata_value.startswith("writeid="):
            pathlib.Path(str(obj) + ".writeid").write_text(metadata_value.split("=", 1)[1], encoding="utf-8")
    if os.environ.get("MOCK_R2_AMBIGUOUS") == "1" and key == "windows/stable/current-v2.json":
        print("simulated connection loss after R2 committed the object", file=sys.stderr)
        raise SystemExit(1)
    print("{}")
else:
    raise SystemExit(f"unsupported mock operation: {action}")
PY
chmod 0700 "$BIN/aws"

source "$ROOT/scripts/lib/release-trust.sh"
export PATH="$BIN:$PATH" MOCK_R2_ROOT="$MOCK_R2"
export AWS_ACCESS_KEY_ID='test-r2-publisher-access'
export AWS_SECRET_ACCESS_KEY='test-r2-publisher-secret'
export WEDECENT_R2_ACCOUNT_ID='0123456789abcdef0123456789abcdef'
export WEDECENT_R2_BUCKET='wedecent-test'
export WEDECENT_UPDATE_ROOT_KEY_ID='test-root-1'
export WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH="$FIXTURES/root.pub"
export WEDECENT_PRODUCTION_RELEASE_APPROVED='true'
export WEDECENT_REPLAY_AUTHORITY_HOSTNAME='replay.example.test'
export WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256="$(printf 'a%.0s' {1..64})"
export WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256="$(wedecent_replay_authority_approval_digest "$WEDECENT_REPLAY_AUTHORITY_HOSTNAME" "$WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256")"
export WEDECENT_CHECKPOINT_AUDIT_HOSTNAME='audit.example.test'
export WEDECENT_CHECKPOINT_AUDIT_SPKI_SHA256="$(printf 'b%.0s' {1..64})"
export WEDECENT_CHECKPOINT_AUDIT_APPROVAL_SHA256="$(wedecent_checkpoint_audit_approval_digest "$WEDECENT_CHECKPOINT_AUDIT_HOSTNAME" "$WEDECENT_CHECKPOINT_AUDIT_SPKI_SHA256")"
export GITHUB_ACTIONS='true'
export GITHUB_REPOSITORY='ADRN-9/wedecent'
export GITHUB_REF_TYPE='tag'
export GITHUB_REF_NAME="$TAG"
export GITHUB_SHA='0123456789abcdef0123456789abcdef01234567'

publish() {
  local sequence="$1"
  bash "$REPO/scripts/publish-windows-stable-update-pair.sh" \
    --root-key-id "$WEDECENT_UPDATE_ROOT_KEY_ID" \
    --root-public-key "$WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH" \
    --keyset "$FIXTURES/keyset.json" \
    --keyset-signature "$FIXTURES/keyset.sig" \
    --manifest "$FIXTURES/candidate-$sequence.json" \
    --signature "$FIXTURES/candidate-$sequence.sig" \
    --pair "$FIXTURES/candidate-$sequence.pair" \
    --receipt "$FIXTURES/candidate-$sequence.receipt"
}

publish 42
STABLE="$MOCK_R2/$WEDECENT_R2_BUCKET/windows/stable/current-v2.json"
cmp -s "$FIXTURES/candidate-42.pair" "$STABLE" || {
  printf 'initial conditional create did not publish the exact stable envelope\n' >&2
  exit 1
}

MOCK_R2_AMBIGUOUS=1 publish 43
cmp -s "$FIXTURES/candidate-43.pair" "$STABLE" || {
  printf 'ambiguous committed write was not reconciled by its write ID\n' >&2
  exit 1
}

if MOCK_R2_RACE=1 publish 44; then
  printf 'concurrent R2 writer conflict was not rejected\n' >&2
  exit 1
fi
printf '{"concurrent_writer":"preserve-me"}\n' > "$TMP/expected-concurrent.json"
cmp -s "$TMP/expected-concurrent.json" "$STABLE" || {
  printf 'CAS conflict overwrote the concurrent writer\n' >&2
  exit 1
}
printf 'R2 stable-pair CAS tests passed: create-only, ambiguous-write reconciliation, If-Match conflict and concurrent-writer preservation.\n'
