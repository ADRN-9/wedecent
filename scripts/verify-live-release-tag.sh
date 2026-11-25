#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'verify-live-release-tag: %s\n' "$*" >&2
  exit 1
}

if (($# < 3 || $# > 4)); then
  printf 'Usage: %s REPOSITORY_ROOT vMAJOR.MINOR.PATCH GITHUB_SHA [REMOTE]\n' "$0" >&2
  exit 64
fi

ROOT="$(cd "$1" && pwd -P)" || fail 'repository root is unavailable'
TAG="$2"
EXPECTED_SHA="$3"
REMOTE="${4:-origin}"
FULL_REF="refs/tags/$TAG"

[[ -d "$ROOT" && ! -L "$ROOT" ]] || fail 'repository root must be a regular directory'
[[ "$TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([.-][0-9A-Za-z.-]+)?$ ]] ||
  fail 'release tag must be canonical vMAJOR.MINOR.PATCH with optional prerelease'
[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]] || fail 'expected immutable commit SHA is malformed'

REMOTE_REFS="$(GIT_TERMINAL_PROMPT=0 git -C "$ROOT" ls-remote --refs "$REMOTE" "$FULL_REF")" ||
  fail 'cannot read the live release tag from the remote repository'
REMOTE_SHA="$(printf '%s\n' "$REMOTE_REFS" | awk -v ref="$FULL_REF" '
  NF == 2 && $2 == ref {
    count++
    value = $1
  }
  END {
    if (count != 1) exit 1
    print value
  }
')" || fail 'live release tag is missing or ambiguous'
[[ "$REMOTE_SHA" =~ ^[0-9a-f]{40}$ ]] || fail 'remote release tag object SHA is malformed'

LOCAL_SHA="$(git -C "$ROOT" rev-parse --verify "$FULL_REF")" ||
  fail 'release tag is missing from the checked-out repository'
[[ "$LOCAL_SHA" == "$REMOTE_SHA" ]] ||
  fail 'live remote release tag object differs from the checked-out tag; tag moved'

OBJECT_TYPE="$(git -C "$ROOT" cat-file -t "$REMOTE_SHA")" ||
  fail 'cannot inspect the live release tag object'
case "$OBJECT_TYPE" in
  commit)
    [[ "$REMOTE_SHA" == "$EXPECTED_SHA" ]] ||
      fail 'live lightweight release tag does not point to immutable GITHUB_SHA'
    ;;
  tag)
    HEADER="$(git -C "$ROOT" cat-file -p "$REMOTE_SHA" | awk 'NF == 0 { exit } { print }')" ||
      fail 'cannot read annotated release tag header'
    TARGET_SHA="$(awk '$1 == "object" { count++; value = $2 } END { if (count != 1) exit 1; print value }' <<<"$HEADER")" ||
      fail 'annotated release tag must contain exactly one target object'
    TARGET_TYPE="$(awk '$1 == "type" { count++; value = $2 } END { if (count != 1) exit 1; print value }' <<<"$HEADER")" ||
      fail 'annotated release tag must contain exactly one target type'
    EMBEDDED_TAG="$(awk '$1 == "tag" { count++; value = $2 } END { if (count != 1) exit 1; print value }' <<<"$HEADER")" ||
      fail 'annotated release tag must contain exactly one tag name'
    [[ "$TARGET_TYPE" == 'commit' && "$TARGET_SHA" == "$EXPECTED_SHA" ]] ||
      fail 'live annotated release tag does not directly target immutable GITHUB_SHA'
    [[ "$EMBEDDED_TAG" == "$TAG" ]] ||
      fail 'annotated tag object name does not match the requested release tag'
    ;;
  *)
    fail "unsupported live release tag object type: $OBJECT_TYPE"
    ;;
esac

RESOLVED_COMMIT="$(git -C "$ROOT" rev-parse --verify "$FULL_REF^{commit}")" ||
  fail 'live release tag cannot be peeled to a commit'
[[ "$RESOLVED_COMMIT" == "$EXPECTED_SHA" ]] ||
  fail 'live release tag does not resolve to immutable GITHUB_SHA'

printf 'Verified live release tag %s (%s) -> %s\n' "$TAG" "$OBJECT_TYPE" "$EXPECTED_SHA"
